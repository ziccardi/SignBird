package activation

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var digestSizes = map[string]int{"SHA-256": 32, "SHA-512": 64}

var identifier = regexp.MustCompile("^[a-f0-9]{32}$")
var sixDigits = regexp.MustCompile("^[0-9]{6}$")

type service struct {
	pool   *pgxpool.Pool
	box    cipher.AEAD
	signer testSigner
}

type signatureRequest struct {
	ID              string    `json:"requestId"`
	CredentialID    string    `json:"credentialId"`
	KeyID           string    `json:"keyId"`
	Digest          string    `json:"digest"`
	HashAlgorithm   string    `json:"hashAlgorithm"`
	SignatureScheme string    `json:"signatureScheme"`
	ExpiresAt       time.Time `json:"expiresAt"`
	Status          string    `json:"status"`
	Signature       string    `json:"signature,omitempty"`
}

type scanner interface {
	Scan(...any) error
}

const requestColumns = "request_id, credential_id, key_id, digest, expires_at, signature, hash_algorithm, signature_scheme"

func scanRequest(row scanner) (signatureRequest, error) {
	item := signatureRequest{Status: "PENDING"}
	err := row.Scan(&item.ID, &item.CredentialID, &item.KeyID, &item.Digest, &item.ExpiresAt, &item.Signature, &item.HashAlgorithm, &item.SignatureScheme)
	if item.Signature != "" {
		item.Status = "SIGNED"
	} else if !time.Now().Before(item.ExpiresAt) {
		item.Status = "EXPIRED"
	}
	return item, err
}

func (s *service) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/activation/totp", s.totpStatus)
	mux.HandleFunc("POST /v1/activation/totp", s.enroll)
	mux.HandleFunc("POST /v1/activation/totp/confirm", s.confirm)
	mux.HandleFunc("POST /v1/signatures/digest", s.create)
	mux.HandleFunc("GET /v1/signatures/digest", s.list)
	mux.HandleFunc("GET /v1/signatures/digest/{requestId}", s.detail)
	mux.HandleFunc("POST /v1/signatures/digest/{requestId}/approve", s.approve)
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(into) == nil && d.Decode(new(any)) == io.EOF {
		return true
	}
	fail(w, http.StatusBadRequest, "Invalid JSON request")
	return false
}

func currentActor(r *http.Request) actor {
	return r.Context().Value(actorKey{}).(actor)
}

func (s *service) totpStatus(w http.ResponseWriter, r *http.Request) {
	a := currentActor(r)
	var enabled bool
	err := s.pool.QueryRow(r.Context(), "SELECT enabled FROM activation_accounts WHERE issuer=$1 AND subject=$2", a.issuer, a.subject).Scan(&enabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]bool{"enabled": enabled})
}

func (a actor) additionalData() []byte {
	data, _ := json.Marshal([2]string{a.issuer, a.subject})
	return data
}

func (s *service) enroll(w http.ResponseWriter, r *http.Request) {
	a := currentActor(r)
	seed := make([]byte, 20)
	rand.Read(seed)
	encrypted := s.box.Seal(nil, nil, seed, a.additionalData())
	ctx := r.Context()
	var stored []byte
	var enabled bool
	err := s.pool.QueryRow(ctx, `INSERT INTO activation_accounts (issuer, subject, encrypted_seed)
		VALUES ($1,$2,$3) ON CONFLICT (issuer,subject) DO UPDATE SET subject=EXCLUDED.subject
		RETURNING encrypted_seed, enabled`, a.issuer, a.subject, encrypted).Scan(&stored, &enabled)
	if err != nil {
		unexpected(w, err)
		return
	}
	if enabled {
		fail(w, http.StatusConflict, "TOTP is already enabled")
		return
	}
	seed, err = s.box.Open(nil, nil, stored, a.additionalData())
	if err != nil {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"secret": base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)})
}

func (s *service) verifyCode(w http.ResponseWriter, r *http.Request, tx pgx.Tx, code string, confirm bool) bool {
	ctx := r.Context()
	a := currentActor(r)
	var encrypted []byte
	var enabled bool
	var last int64
	var failures int
	var window time.Time
	err := tx.QueryRow(ctx, `SELECT encrypted_seed, enabled, last_counter, failures, failure_window
		FROM activation_accounts WHERE issuer=$1 AND subject=$2 FOR UPDATE`, a.issuer, a.subject).Scan(&encrypted, &enabled, &last, &failures, &window)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		fail(w, http.StatusConflict, "TOTP enrollment is required")
		return false
	case err != nil:
		unexpected(w, err)
		return false
	case confirm && enabled:
		fail(w, http.StatusConflict, "TOTP is already enabled")
		return false
	case !confirm && !enabled:
		fail(w, http.StatusConflict, "TOTP enrollment is required")
		return false
	}

	now := time.Now()
	if !now.Before(window.Add(5 * time.Minute)) {
		window, failures = now, 0
	}
	if failures >= 5 {
		fail(w, http.StatusTooManyRequests, "Too many attempts. Try again later")
		return false
	}
	seed, err := s.box.Open(nil, nil, encrypted, a.additionalData())
	if err != nil {
		unexpected(w, err)
		return false
	}
	counter, ok := matchOTP(seed, code, now, last)
	if !ok {
		if failures == 0 {
			window = now
		}
		_, err = tx.Exec(ctx, `UPDATE activation_accounts SET failures=$3, failure_window=$4 WHERE issuer=$1 AND subject=$2`, a.issuer, a.subject, failures+1, window)
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			unexpected(w, err)
			return false
		}
		fail(w, http.StatusBadRequest, "Invalid or already used TOTP code")
		return false
	}

	_, err = tx.Exec(ctx, `UPDATE activation_accounts SET enabled=true, last_counter=$3, failures=0
		WHERE issuer=$1 AND subject=$2`, a.issuer, a.subject, counter)
	if err != nil {
		unexpected(w, err)
		return false
	}
	return true
}

func readCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var input struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &input) {
		return "", false
	}
	if !sixDigits.MatchString(input.Code) {
		fail(w, http.StatusBadRequest, "TOTP must contain six digits")
		return "", false
	}
	return input.Code, true
}

func (s *service) confirm(w http.ResponseWriter, r *http.Request) {
	s.consumeCode(w, r, true)
}

func (s *service) consume(w http.ResponseWriter, r *http.Request) {
	s.consumeCode(w, r, false)
}

func (s *service) consumeCode(w http.ResponseWriter, r *http.Request, enrollment bool) {
	code, ok := readCode(w, r)
	if !ok {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		unexpected(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	if !s.verifyCode(w, r, tx, code, enrollment) {
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]bool{"enabled": true})
}

func (s *service) create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CredentialID    string `json:"credentialId"`
		Digest          string `json:"digest"`
		HashAlgorithm   string `json:"hashAlgorithm"`
		SignatureScheme string `json:"signatureScheme"`
	}
	if !decode(w, r, &input) {
		return
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(input.Digest)
	size, supported := digestSizes[input.HashAlgorithm]
	if err != nil || !supported || len(digest) != size || base64.StdEncoding.EncodeToString(digest) != input.Digest ||
		!identifier.MatchString(input.CredentialID) || (input.SignatureScheme != "RSASSA-PKCS1-v1_5" && input.SignatureScheme != "ECDSA") {
		fail(w, http.StatusBadRequest, "Expected a credential, a Base64 digest matching the hash algorithm, and a supported signature scheme")
		return
	}
	codes := r.Header.Values("X-TOTP-Code")
	if len(codes) != 1 || !sixDigits.MatchString(codes[0]) {
		fail(w, http.StatusBadRequest, "A six-digit X-TOTP-Code is required")
		return
	}

	ctx := r.Context()
	a := currentActor(r)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		unexpected(w, err)
		return
	}
	defer tx.Rollback(ctx)
	if !s.verifyCode(w, r, tx, codes[0], false) {
		return
	}
	var credential signerResponse
	if err := s.signer.call(r, http.MethodGet, input.CredentialID, nil, &credential); err != nil {
		signerError(w, err)
		return
	}
	if credential.SignatureScheme != input.SignatureScheme {
		fail(w, http.StatusBadRequest, "Signature scheme does not match the credential key")
		return
	}
	item := signatureRequest{
		CredentialID: input.CredentialID, KeyID: credential.KeyID, Digest: input.Digest,
		HashAlgorithm: input.HashAlgorithm, SignatureScheme: input.SignatureScheme,
	}
	if !s.signRequest(w, r, &item) {
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	item, err = scanRequest(tx.QueryRow(ctx, `INSERT INTO signature_requests
		(request_id,issuer,subject,credential_id,key_id,digest,expires_at,signature,hash_algorithm,signature_scheme)
		VALUES ($1,$2,$3,$4,$5,$6,now(),$7,$8,$9) RETURNING `+requestColumns,
		hex.EncodeToString(id), a.issuer, a.subject, item.CredentialID, item.KeyID, item.Digest, item.Signature, item.HashAlgorithm, item.SignatureScheme))
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, item)
}

func (s *service) list(w http.ResponseWriter, r *http.Request) {
	a := currentActor(r)
	rows, err := s.pool.Query(r.Context(), "SELECT "+requestColumns+
		" FROM signature_requests WHERE issuer=$1 AND subject=$2 ORDER BY created_at DESC LIMIT 50", a.issuer, a.subject)
	if err != nil {
		unexpected(w, err)
		return
	}
	defer rows.Close()
	result := []signatureRequest{}
	for rows.Next() {
		item, err := scanRequest(rows)
		if err != nil {
			unexpected(w, err)
			return
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, result)
}

func requestError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, http.StatusNotFound, "Signature request not found")
		return
	}
	unexpected(w, err)
}

const ownedRequest = "SELECT " + requestColumns + " FROM signature_requests WHERE request_id=$1 AND issuer=$2 AND subject=$3"

func (s *service) detail(w http.ResponseWriter, r *http.Request) {
	a := currentActor(r)
	item, err := scanRequest(s.pool.QueryRow(r.Context(), ownedRequest, r.PathValue("requestId"), a.issuer, a.subject))
	if err != nil {
		requestError(w, err)
		return
	}
	reply(w, http.StatusOK, item)
}

func (s *service) approve(w http.ResponseWriter, r *http.Request) {
	code, ok := readCode(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	a := currentActor(r)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		unexpected(w, err)
		return
	}
	defer tx.Rollback(ctx)
	item, err := scanRequest(tx.QueryRow(ctx, ownedRequest+" FOR UPDATE", r.PathValue("requestId"), a.issuer, a.subject))
	if err != nil {
		requestError(w, err)
		return
	}
	if item.Status == "SIGNED" {
		reply(w, http.StatusOK, item)
		return
	}
	if item.Status == "EXPIRED" {
		fail(w, http.StatusConflict, "Signature request has expired")
		return
	}
	if !s.verifyCode(w, r, tx, code, false) {
		return
	}
	if !time.Now().Before(item.ExpiresAt) {
		fail(w, http.StatusConflict, "Signature request has expired")
		return
	}

	if !s.signRequest(w, r, &item) {
		return
	}
	_, err = tx.Exec(ctx, "UPDATE signature_requests SET signature=$2 WHERE request_id=$1", item.ID, item.Signature)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, item)
}

func (s *service) signRequest(w http.ResponseWriter, r *http.Request, item *signatureRequest) bool {
	var signed signerResponse
	payload, _ := json.Marshal(map[string]string{"digest": item.Digest, "keyId": item.KeyID, "hashAlgorithm": item.HashAlgorithm, "signatureScheme": item.SignatureScheme})
	if err := s.signer.call(r, http.MethodPost, item.CredentialID, payload, &signed); err != nil {
		signerError(w, err)
		return false
	}
	if signed.Signature == "" || signed.KeyID != item.KeyID {
		fail(w, http.StatusBadGateway, "Invalid test signer response")
		return false
	}
	item.Signature, item.Status = signed.Signature, "SIGNED"
	return true
}

type testSigner struct {
	token  string
	client *http.Client
}

type signerResponse struct {
	SignatureScheme string `json:"signatureScheme"`
	KeyID           string `json:"keyId"`
	Signature       string `json:"signature"`
}

var errCredential = errors.New("signing credential unavailable")

func (s testSigner) call(r *http.Request, method, credential string, payload []byte, into *signerResponse) error {
	return s.send(r, method, "/internal/signing-credentials/"+credential, payload, into, func(req *http.Request) {
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
	})
}

func (s testSigner) queued(r *http.Request, a actor, credential string, payload []byte, into *signerResponse) error {
	return s.send(r, http.MethodPost, "/internal/queued-signing-credentials/"+credential, payload, into, func(req *http.Request) {
		req.Header.Set("X-SignBird-Owner-Issuer", base64.RawURLEncoding.EncodeToString([]byte(a.issuer)))
		req.Header.Set("X-SignBird-Owner-Subject", base64.RawURLEncoding.EncodeToString([]byte(a.subject)))
	})
}

func (s testSigner) send(r *http.Request, method, path string, payload []byte, into *signerResponse, headers func(*http.Request)) error {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:8081"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	headers(req)
	req.Header.Set("X-SignBird-Service-Token", s.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errCredential
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("test signer returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(into)
}

func signerError(w http.ResponseWriter, err error) {
	if errors.Is(err, errCredential) {
		fail(w, http.StatusNotFound, "Signing credential unavailable")
		return
	}
	fail(w, http.StatusBadGateway, "Test signer unavailable")
}
