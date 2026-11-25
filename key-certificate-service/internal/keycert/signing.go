package keycert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"signbird/key-certificate-service/internal/db"
)

func (s *service) testSigner() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/signing-credentials/{credentialId}", s.signDigest)
	mux.HandleFunc("POST /internal/signing-credentials/{credentialId}", s.signDigest)
	return mux
}

func (s *service) signDigest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := ctx.Value(identityKey{}).(identity)
	credential, err := s.queries.GetOwnedSigningCredential(ctx, db.GetOwnedSigningCredentialParams{
		Issuer: actor.issuer, Subject: actor.subject, CredentialID: r.PathValue("credentialId"),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, http.StatusNotFound, "Signing credential unavailable")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		reply(w, http.StatusOK, map[string]string{"keyId": credential.KeyID, "signatureScheme": signingScheme(credential.Algorithm)})
		return
	}

	var input struct {
		KeyID           string `json:"keyId"`
		Digest          string `json:"digest"`
		HashAlgorithm   string `json:"hashAlgorithm"`
		SignatureScheme string `json:"signatureScheme"`
	}
	if !decodeRequest(w, r, &input) {
		fail(w, http.StatusBadRequest, "Invalid signing request")
		return
	}
	var hash crypto.Hash
	switch input.HashAlgorithm {
	case "SHA-256":
		hash = crypto.SHA256
	case "SHA-512":
		hash = crypto.SHA512
	default:
		fail(w, http.StatusBadRequest, "Unsupported hash algorithm")
		return
	}
	scheme := signingScheme(credential.Algorithm)
	digest, err := base64.StdEncoding.Strict().DecodeString(input.Digest)
	if err != nil || len(digest) != hash.Size() || scheme == "" || input.SignatureScheme != scheme || input.KeyID != credential.KeyID {
		fail(w, http.StatusBadRequest, "Signing request does not match the credential or algorithm")
		return
	}
	container, err := s.queries.GetPKCS12(ctx, credential.ObjectRef)
	if err != nil {
		internalError(w, err)
		return
	}
	key, err := s.store.decode(container)
	if err != nil {
		internalError(w, err)
		return
	}
	pem, err := publicKeyPEM(key)
	if err != nil || pem != credential.PublicKey || keyAlgorithm(key.Public()) != credential.Algorithm {
		internalError(w, errors.New("PKCS#12 public key differs from registered key"))
		return
	}
	signature, err := key.Sign(rand.Reader, digest, hash)
	if err != nil {
		internalError(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]string{"keyId": credential.KeyID, "signature": base64.StdEncoding.EncodeToString(signature)})
}

func trustedQueuedSigner(secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuer, issuerErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SignBird-Owner-Issuer"))
		subject, subjectErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SignBird-Owner-Subject"))
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SignBird-Service-Token")), []byte(secret)) != 1 ||
			issuerErr != nil || subjectErr != nil || len(issuer) == 0 || len(subject) == 0 {
			fail(w, http.StatusUnauthorized, "Invalid signing service credentials")
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, identity{string(issuer), string(subject)})
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
