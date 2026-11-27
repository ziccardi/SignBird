package keycert

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/ziccardi/SignBird/key-certificate-service/internal/db"
)

func (s *service) createCSR(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CommonName string `json:"commonName"`
	}
	if !decodeRequest(w, r, &request) || strings.ContainsFunc(request.CommonName, unicode.IsControl) {
		fail(w, http.StatusBadRequest, "Expected a valid common name")
		return
	}
	name := strings.TrimSpace(request.CommonName)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		fail(w, http.StatusBadRequest, "Common name must contain between 1 and 64 characters")
		return
	}
	key, ok := s.ownedKey(w, r, r.PathValue("keyId"))
	if !ok || !s.authorizeChange(w, r) {
		return
	}
	privateKey, err := s.loadSigningKey(r.Context(), s.queries, key)
	if err != nil {
		internalError(w, err)
		return
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name},
	}, privateKey)
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	reply(w, http.StatusOK, map[string]string{"csrPem": asPEM("CERTIFICATE REQUEST", der)})
}

func parseCertificatePEM(value string, limit int) ([]*x509.Certificate, error) {
	remaining := bytes.TrimSpace([]byte(value))
	var certificates []*x509.Certificate
	for len(remaining) > 0 {
		if len(certificates) >= limit || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid certificate PEM")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	return certificates, nil
}

func (s *service) importCertificate(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Alias          string `json:"alias"`
		CertificatePEM string `json:"certificatePem"`
		ChainPEM       string `json:"chainPem"`
	}
	if !decodeRequestLimit(w, r, &request, 128*1024) {
		fail(w, http.StatusBadRequest, "Invalid certificate import request")
		return
	}
	alias, ok := validateAlias(w, request.Alias)
	if !ok {
		return
	}
	requestID, ok := requestID(w, r)
	if !ok {
		return
	}
	key, ok := s.ownedKey(w, r, r.PathValue("keyId"))
	if !ok {
		return
	}
	leaves, err := parseCertificatePEM(request.CertificatePEM, 1)
	if err != nil || len(leaves) != 1 {
		fail(w, http.StatusBadRequest, "Expected a single PEM certificate")
		return
	}
	leaf := leaves[0]
	der, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || asPEM("PUBLIC KEY", der) != key.PublicKey {
		fail(w, http.StatusBadRequest, "Certificate public key does not match the selected key")
		return
	}
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		(leaf.KeyUsage != 0 && leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0) {
		fail(w, http.StatusBadRequest, "Certificate is not currently usable for signing")
		return
	}
	chain, err := parseCertificatePEM(request.ChainPEM, 10)
	if err != nil {
		fail(w, http.StatusBadRequest, "Invalid issuer certificate chain")
		return
	}
	var chainPEM strings.Builder
	child := leaf
	for _, issuer := range chain {
		if child.Equal(issuer) || !bytes.Equal(child.RawIssuer, issuer.RawSubject) || child.CheckSignatureFrom(issuer) != nil {
			fail(w, http.StatusBadRequest, "The chain must start with the certificate issuer and follow issuer order")
			return
		}
		chainPEM.WriteString(asPEM("CERTIFICATE", issuer.Raw))
		child = issuer
	}

	if !s.authorizeChange(w, r) {
		return
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	queries := s.queries.WithTx(tx)
	locked, err := queries.LockOwnedKey(ctx, db.LockOwnedKeyParams{KeyID: key.KeyID, OwnerUserID: key.OwnerUserID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (locked.Status != "ACTIVE" || locked.PublicKey != key.PublicKey) {
		fail(w, http.StatusNotFound, "Key not found")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	cert := certificateResponse{
		Alias: alias, CertificateID: newID(), CredentialID: newID(),
		CertificatePEM: asPEM("CERTIFICATE", leaf.Raw), ChainPEM: chainPEM.String(),
		NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(),
	}
	existing, err := queries.GetCredentialByRequest(ctx, db.GetCredentialByRequestParams{KeyID: key.KeyID, RequestID: requestID})
	if err == nil {
		if existing.CertificatePem != cert.CertificatePEM || existing.ChainPem != cert.ChainPEM {
			fail(w, http.StatusConflict, "Idempotency key already used for a different certificate")
			return
		}
		cert.Alias, cert.CertificateID, cert.CredentialID = existing.Alias, existing.CertificateID, existing.CredentialID
		reply(w, http.StatusCreated, cert)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		internalError(w, err)
		return
	}
	if err := saveCertificate(ctx, queries, key.KeyID, requestID, cert, ""); err != nil {
		internalError(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, err)
		return
	}
	reply(w, http.StatusCreated, cert)
}
