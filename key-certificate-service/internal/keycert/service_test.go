package keycert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"signbird/key-certificate-service/internal/db"
)

func TestKeyAndCertificateLifecycle(t *testing.T) {
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

	namespace := "signbird_test_" + newID()
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
	if _, err := pool.Exec(ctx, db.SchemaSQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}

	ca := makeTestCA(t)
	s := &service{pool: pool, queries: db.New(pool), store: keystore{password: "test-password"}, ca: ca, consumeCode: func(http.ResponseWriter, *http.Request) bool { return true }}
	handler := http.NewServeMux()
	handler.Handle("/v1/", s.routes())
	handler.Handle("/internal/", s.testSigner())
	call := func(subject, method, path, payload, idempotency string, want int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(payload))
		request = request.WithContext(context.WithValue(ctx, identityKey{}, identity{"test-issuer", subject}))
		if idempotency != "" {
			request.Header.Set("Idempotency-Key", idempotency)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s %s: got %d, want %d; %s", method, path, response.Code, want, response.Body)
		}
		return response
	}

	// Seed containers from the previous filesystem-backed version.
	owner, err := s.queries.EnsureUser(ctx, db.EnsureUserParams{Issuer: "test-issuer", Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	id := newID()
	ref := id + ".p12"
	if _, err := s.queries.ReserveKey(ctx, db.ReserveKeyParams{KeyID: id, OwnerUserID: owner, ObjectRef: ref, RequestID: "create-1", Algorithm: rsa2048}); err != nil {
		t.Fatal(err)
	}
	container, err := s.store.generate(rsa2048)
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.store.decode(container)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := publicKeyPEM(original)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, ref)
	if err := os.WriteFile(file, container, 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, pool, "", ""); err == nil {
		t.Fatal("migration should require legacy keystore configuration")
	}
	if err := migrate(ctx, pool, dir, "invalid"); err == nil {
		t.Fatal("migration should reject an invalid PKCS#12 password")
	}
	if err := migrate(ctx, pool, dir, s.store.password); err != nil {
		t.Fatal(err)
	}
	migrated, err := s.queries.GetPKCS12(ctx, ref)
	if err != nil || !bytes.Equal(migrated, container) {
		t.Fatalf("unexpected migrated container: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, pool, "", ""); err != nil {
		t.Fatal(err)
	}
	payload := `{"keystoreId":"pkcs12-test"}`
	result := call("alice", "POST", "/v1/keys", payload, "create-1", 201)
	keyBody := result.Body.String()
	var key keyResponse
	readResponse(t, result, &key)
	if key.KeyID != id || key.PublicKey != publicKey || key.Status != "ACTIVE" {
		t.Fatalf("pending key was not recovered: %+v", key)
	}
	if retry := call("alice", "POST", "/v1/keys", payload, "create-1", 201); retry.Body.String() != keyBody {
		t.Fatal("retry changed key response")
	}
	var other keyResponse
	readResponse(t, call("alice", "POST", "/v1/keys", payload, "create-2", 201), &other)
	if other.KeyID == id || other.Status != "ACTIVE" {
		t.Fatalf("a fresh operation should make a new active key: %+v", other)
	}
	fresh, err := s.queries.GetPKCS12(ctx, other.KeyID+".p12")
	if err != nil {
		t.Fatal(err)
	}
	freshKey, err := s.store.decode(fresh)
	if err != nil {
		t.Fatal(err)
	}
	freshPublicKey, err := publicKeyPEM(freshKey)
	if err != nil || freshPublicKey != other.PublicKey {
		t.Fatalf("new container does not match registered public key: %v", err)
	}
	path := "/v1/keys/" + id
	call("bob", "GET", path, "", "", 404)
	if result := call("bob", "GET", "/v1/keys", "", "", 200); result.Body.String() != "[]\n" {
		t.Fatal("another owner can see the key")
	}

	issue := `{"keyId":"` + id + `"}`
	call("bob", "POST", "/v1/certificates", issue, "issue-1", 404)
	result = call("alice", "POST", "/v1/certificates", issue, "issue-1", 201)
	if retry := call("alice", "POST", "/v1/certificates", issue, "issue-1", 201); retry.Body.String() != result.Body.String() {
		t.Fatal("retry changed certificate response")
	}
	var issued, renewed certificateResponse
	readResponse(t, result, &issued)
	readResponse(t, call("alice", "POST", "/v1/certificates", issue, "issue-2", 201), &renewed)
	if issued.CertificateID == renewed.CertificateID || issued.CredentialID == renewed.CredentialID {
		t.Fatal("renewal reused the previous certificate or credential")
	}
	for _, entry := range []certificateResponse{issued, renewed} {
		block, _ := pem.Decode([]byte(entry.CertificatePEM))
		if block == nil {
			t.Fatal("missing PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.CheckSignatureFrom(ca.cert); err != nil {
			t.Fatal(err)
		}
		if asPEM("PUBLIC KEY", cert.RawSubjectPublicKeyInfo) != key.PublicKey {
			t.Fatal("certificate public key differs from registered public key")
		}
	}
	readResponse(t, call("alice", "GET", path, "", "", 200), &key)
	if key.Certificates == nil || len(*key.Certificates) != 2 {
		t.Fatal("certificate history should contain both issuances")
	}

	var namedKey keyResponse
	readResponse(t, call("alice", "POST", "/v1/keys", `{"keystoreId":"pkcs12-test","alias":"  Contracts  "}`, "", 201), &namedKey)
	if namedKey.Alias != "Contracts" {
		t.Fatalf("unexpected alias: %q", namedKey.Alias)
	}
	var namedCert certificateResponse
	keyPath := "/v1/keys/" + namedKey.KeyID
	readResponse(t, call("alice", "POST", "/v1/certificates", `{"keyId":"`+namedKey.KeyID+`","alias":"Test CA"}`, "", 201), &namedCert)
	if namedCert.Alias != "Test CA" {
		t.Fatalf("unexpected certificate alias: %q", namedCert.Alias)
	}
	certPath := keyPath + "/certificates/" + namedCert.CertificateID
	call("bob", "PATCH", keyPath, `{"alias":"Unauthorized"}`, "", 404)
	call("bob", "PATCH", certPath, `{"alias":"Unauthorized"}`, "", 404)
	call("alice", "PATCH", "/v1/keys/"+id+"/certificates/"+namedCert.CertificateID, `{"alias":"Wrong key"}`, "", 404)
	call("alice", "PATCH", keyPath, `{"alias":"`+strings.Repeat("a", 81)+`"}`, "", 400)
	authorize := s.consumeCode
	s.consumeCode = func(w http.ResponseWriter, _ *http.Request) bool {
		fail(w, http.StatusBadRequest, "A six-digit X-TOTP-Code is required")
		return false
	}
	call("alice", "PATCH", keyPath, `{"alias":"Requires OTP"}`, "", 400)
	call("alice", "PATCH", certPath, `{"alias":"Requires OTP"}`, "", 400)
	s.consumeCode = authorize
	call("alice", "PATCH", keyPath, `{"alias":"Legal team"}`, "", 204)
	call("alice", "PATCH", certPath, `{"alias":"Production test certificate"}`, "", 204)
	var updated keyResponse
	readResponse(t, call("alice", "GET", keyPath, "", "", 200), &updated)
	if updated.Alias != "Legal team" || updated.PublicKey != namedKey.PublicKey ||
		updated.Certificates == nil || len(*updated.Certificates) != 1 {
		t.Fatalf("unexpected renamed key: %+v", updated)
	}
	updatedCert := (*updated.Certificates)[0]
	if updatedCert.Alias != "Production test certificate" || updatedCert.CertificatePEM != namedCert.CertificatePEM ||
		updatedCert.CredentialID != namedCert.CredentialID {
		t.Fatalf("unexpected renamed certificate: %+v", updatedCert)
	}
	call("alice", "PATCH", keyPath, `{"alias":""}`, "", 204)
	call("alice", "PATCH", certPath, `{"alias":""}`, "", 204)
	var cleared keyResponse
	readResponse(t, call("alice", "GET", keyPath, "", "", 200), &cleared)
	if cleared.Alias != "" || (*cleared.Certificates)[0].Alias != "" {
		t.Fatal("aliases were not cleared")
	}

	var profiles []keyCapability
	readResponse(t, call("alice", "GET", "/v1/keys/capabilities", "", "", 200), &profiles)
	if len(profiles) != 3 {
		t.Fatalf("expected three key profiles, got %d", len(profiles))
	}
	for _, profile := range profiles {
		t.Run(profile.Algorithm, func(t *testing.T) {
			var key keyResponse
			var cert certificateResponse
			create := `{"keystoreId":"pkcs12-test","algorithm":"` + profile.Algorithm + `"}`
			readResponse(t, call("alice", "POST", "/v1/keys", create, profile.Algorithm, 201), &key)
			if key.Algorithm != profile.Algorithm {
				t.Fatalf("got %s, want %s", key.Algorithm, profile.Algorithm)
			}
			readResponse(t, call("alice", "POST", "/v1/certificates", `{"keyId":"`+key.KeyID+`"}`, "", 201), &cert)
			block, _ := pem.Decode([]byte(cert.CertificatePEM))
			if block == nil {
				t.Fatal("missing certificate")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := leaf.CheckSignatureFrom(ca.cert); err != nil {
				t.Fatal(err)
			}
			for _, hash := range profile.HashAlgorithms {
				digest := bytes.Repeat([]byte{0xa5}, hash.DigestBytes)
				payload, err := json.Marshal(map[string]string{
					"keyId": key.KeyID, "digest": base64.StdEncoding.EncodeToString(digest),
					"hashAlgorithm": hash.Algorithm, "signatureScheme": profile.SignatureScheme,
				})
				if err != nil {
					t.Fatal(err)
				}
				var result map[string]string
				readResponse(t, call("alice", "POST", "/internal/signing-credentials/"+cert.CredentialID, string(payload), "", 200), &result)
				signature, err := base64.StdEncoding.DecodeString(result["signature"])
				if err != nil {
					t.Fatal(err)
				}
				switch publicKey := leaf.PublicKey.(type) {
				case *rsa.PublicKey:
					signingHash := crypto.SHA256
					if hash.Algorithm == "SHA-512" {
						signingHash = crypto.SHA512
					}
					if err := rsa.VerifyPKCS1v15(publicKey, signingHash, digest, signature); err != nil {
						t.Fatal(err)
					}
				case *ecdsa.PublicKey:
					if !ecdsa.VerifyASN1(publicKey, digest, signature) {
						t.Fatal("ECDSA signature verification failed")
					}
				default:
					t.Fatalf("unexpected public key type %T", publicKey)
				}
			}
		})
	}
}

func readResponse(t *testing.T, response *httptest.ResponseRecorder, value any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(value); err != nil {
		t.Fatal(err)
	}
}

func makeTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Integration Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, signer: key}
}

func TestMissingServiceToken(t *testing.T) {
	handler := authenticate("internal-test-secret", nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached a protected handler")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/v1/keys", nil))
	if response.Code != 401 {
		t.Fatalf("got %d, want 401", response.Code)
	}
}
