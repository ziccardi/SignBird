package activation

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

var documentID = regexp.MustCompile("^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$")

func (s *service) documentRoutes(mux *http.ServeMux, token string, protect func(http.Handler) http.Handler) {
	mux.Handle("POST /internal/documents/{jobId}/approve", protect(http.HandlerFunc(s.approveDocument)))
	mux.HandleFunc("POST /internal/documents/{jobId}/sign", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SignBird-Service-Token")), []byte(token)) != 1 {
			fail(w, http.StatusUnauthorized, "Invalid document service credentials")
			return
		}
		s.signDocument(w, r)
	})
}

func (s *service) approveDocument(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CredentialID string `json:"credentialId"`
		KeyID        string `json:"keyId"`
		Digest       string `json:"digest"`
		Scheme       string `json:"signatureScheme"`
		Code         string `json:"code"`
	}
	if !decode(w, r, &input) {
		return
	}
	job := r.PathValue("jobId")
	digest, err := base64.StdEncoding.Strict().DecodeString(input.Digest)
	if !documentID.MatchString(job) || !identifier.MatchString(input.CredentialID) ||
		!identifier.MatchString(input.KeyID) || err != nil || len(digest) != 32 ||
		base64.StdEncoding.EncodeToString(digest) != input.Digest || !sixDigits.MatchString(input.Code) {
		fail(w, http.StatusBadRequest, "Invalid document approval")
		return
	}
	var credential signerResponse
	if err := s.signer.call(r, http.MethodGet, input.CredentialID, nil, &credential); err != nil {
		signerError(w, err)
		return
	}
	if credential.KeyID != input.KeyID || credential.SignatureScheme != input.Scheme {
		fail(w, http.StatusBadRequest, "Document preparation does not match the signing credential")
		return
	}

	ctx, a := r.Context(), currentActor(r)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		unexpected(w, err)
		return
	}
	defer tx.Rollback(ctx)
	// A retry after the document service loses its response can recover the same grant.
	var existing bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM document_grants WHERE job_id=$1
		AND issuer=$2 AND subject=$3 AND credential_id=$4 AND key_id=$5 AND digest=$6 AND scheme=$7
		AND expires_at>now())`, job, a.issuer, a.subject, input.CredentialID, input.KeyID, input.Digest, input.Scheme).Scan(&existing)
	if err != nil {
		unexpected(w, err)
		return
	}
	if existing {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.verifyCode(w, r, tx, input.Code, false) {
		return
	}
	_, err = tx.Exec(ctx, `INSERT INTO document_grants
		(job_id,issuer,subject,credential_id,key_id,digest,scheme,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now()+interval '15 minutes')`,
		job, a.issuer, a.subject, input.CredentialID, input.KeyID, input.Digest, input.Scheme)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		unexpected(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) signDocument(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	job := r.PathValue("jobId")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		unexpected(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var a actor
	var item signatureRequest
	var expiry time.Time
	err = tx.QueryRow(ctx, `SELECT issuer,subject,credential_id,key_id,digest,scheme,signature,expires_at
		FROM document_grants WHERE job_id=$1 FOR UPDATE`, job).Scan(
		&a.issuer, &a.subject, &item.CredentialID, &item.KeyID, &item.Digest, &item.SignatureScheme, &item.Signature, &expiry)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, http.StatusNotFound, "Document approval not found")
		return
	}
	if err != nil {
		unexpected(w, err)
		return
	}
	if !time.Now().Before(expiry) {
		fail(w, http.StatusConflict, "Document approval expired")
		return
	}
	if item.Signature == "" {
		payload, _ := json.Marshal(map[string]string{
			"digest": item.Digest, "keyId": item.KeyID, "hashAlgorithm": "SHA-256", "signatureScheme": item.SignatureScheme,
		})
		var result signerResponse
		if err := s.signer.queued(r, a, item.CredentialID, payload, &result); err != nil {
			signerError(w, err)
			return
		}
		if result.KeyID != item.KeyID || result.Signature == "" {
			fail(w, http.StatusBadGateway, "Invalid test signer response")
			return
		}
		item.Signature = result.Signature
		if _, err := tx.Exec(ctx, "UPDATE document_grants SET signature=$2 WHERE job_id=$1", job, item.Signature); err != nil {
			unexpected(w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		unexpected(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"signature": item.Signature})
}
