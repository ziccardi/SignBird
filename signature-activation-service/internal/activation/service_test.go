package activation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type signerTransport func(*http.Request) (*http.Response, error)

func (send signerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return send(r)
}

func TestApprovalLifecycle(t *testing.T) {
	dsn := os.Getenv("SIGNBIRD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SIGNBIRD_TEST_DATABASE_URL to run the PostgreSQL integration test")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	namespace := "activation_test_" + hex.EncodeToString(randBytes(8))
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+namespace); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+namespace+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = namespace
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, schema, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(randBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	box, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	digest := base64.StdEncoding.EncodeToString(randBytes(64))
	const keyID = "00000000000000000000000000000001"
	const credentialID = "00000000000000000000000000000002"
	signed := 0
	s := service{pool: pool, box: box, signer: testSigner{client: &http.Client{
		Transport: signerTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPost {
				var payload map[string]string
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload["digest"] != digest || payload["keyId"] != keyID || payload["hashAlgorithm"] != "SHA-512" || payload["signatureScheme"] != "ECDSA" {
					t.Fatalf("signer received an unapproved payload: %v", payload)
				}
				signed++
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
				`{"keyId":"` + keyID + `","signature":"c2lnbmF0dXJl","signatureScheme":"ECDSA"}`))}, nil
		}),
	}}}
	handler := s.routes()
	call := func(subject, method, path, body string, status int, codes ...string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		for _, code := range codes {
			r.Header.Add("X-TOTP-Code", code)
		}
		r = r.WithContext(context.WithValue(ctx, actorKey{}, actor{"issuer", subject}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s returned %d, want %d: %s", method, path, w.Code, status, w.Body)
		}
		return w
	}
	read := func(w *httptest.ResponseRecorder, into any) {
		t.Helper()
		if err := json.NewDecoder(w.Body).Decode(into); err != nil {
			t.Fatal(err)
		}
	}
	var enrollment map[string]string
	read(call("alice", "POST", "/v1/activation/totp", "", 200), &enrollment)
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment["secret"])
	if err != nil {
		t.Fatal(err)
	}
	counter := time.Now().Unix() / 30
	approvalCode := otp(seed, counter+1)
	oldCode := otp(seed, counter-1)
	changeCode := otp(seed, counter)
	body := func(code string) string { return `{"code":"` + code + `"}` }
	call("alice", "POST", "/v1/activation/totp/confirm", body(oldCode), 200)
	call("alice", "POST", "/v1/activation/totp", "", 409)
	for _, check := range []struct {
		code   string
		status int
	}{{oldCode, 400}, {changeCode, 200}, {changeCode, 400}} {
		r := httptest.NewRequest(http.MethodPost, "/internal/activation/totp/consume", strings.NewReader(body(check.code)))
		r = r.WithContext(context.WithValue(ctx, actorKey{}, actor{"issuer", "alice"}))
		w := httptest.NewRecorder()
		s.consume(w, r)
		if w.Code != check.status {
			t.Fatalf("consume returned %d, want %d: %s", w.Code, check.status, w.Body)
		}
	}

	input := `{"credentialId":"` + credentialID + `","digest":"` + digest + `","hashAlgorithm":"SHA-512","signatureScheme":"ECDSA"}`
	const path = "/v1/signatures/digest"
	call("alice", "POST", path, input, 400)
	call("alice", "POST", path, input, 400, changeCode)
	call("alice", "POST", path, strings.Replace(input, "SHA-512", "SHA-256", 1), 400, approvalCode)
	call("alice", "POST", path, strings.Replace(input, "ECDSA", "RSASSA-PKCS1-v1_5", 1), 400, approvalCode)
	var result signatureRequest
	read(call("alice", "POST", path, input, 200, approvalCode), &result)
	if result.Status != "SIGNED" || result.HashAlgorithm != "SHA-512" || result.SignatureScheme != "ECDSA" || result.Signature == "" || signed != 1 {
		t.Fatalf("unexpected signature result: %+v, internal signing calls: %d", result, signed)
	}
	detailPath := path + "/" + result.ID
	call("bob", "GET", detailPath, "", 404)
	var stored signatureRequest
	read(call("alice", "GET", detailPath, "", 200), &stored)
	if stored.Signature != result.Signature {
		t.Fatal("stored signature did not match the synchronous response")
	}
	for range 5 {
		call("alice", "POST", path, input, 400, approvalCode)
	}
	call("alice", "POST", path, input, 429, approvalCode)
	if signed != 1 {
		t.Fatalf("expected a single invocation of the signer, got %d", signed)
	}
	const expiredID = "00000000000000000000000000000003"
	if _, err := pool.Exec(ctx, `INSERT INTO signature_requests (request_id,issuer,subject,credential_id,key_id,digest,expires_at)
		SELECT $1,issuer,subject,credential_id,key_id,digest,now()-interval '1 second'
		FROM signature_requests WHERE request_id=$2`, expiredID, result.ID); err != nil {
		t.Fatal(err)
	}
	read(call("alice", "GET", path+"/"+expiredID, "", 200), &stored)
	if stored.Status != "EXPIRED" {
		t.Fatalf("expected expired legacy request, got %s", stored.Status)
	}
	call("alice", "POST", path+"/"+expiredID+"/approve", body(approvalCode), 409)
}

func randBytes(length int) []byte {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}
