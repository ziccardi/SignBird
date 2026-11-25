package keycert

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/ziccardi/SignBird/key-certificate-service/internal/db"
)

type testCA struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

type certificateResponse struct {
	Alias          string    `json:"alias,omitempty"`
	CertificateID  string    `json:"certificateId"`
	CredentialID   string    `json:"credentialId"`
	CertificatePEM string    `json:"certificatePem"`
	ChainPEM       string    `json:"chainPem"`
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
}

func loadCA(certPath, keyPath string) (testCA, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return testCA{}, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || len(pair.Certificate) != 1 || !pair.Leaf.IsCA || pair.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 ||
		pair.Leaf.CheckSignatureFrom(pair.Leaf) != nil {
		return testCA{}, errors.New("expected one self-signed test CA certificate and its signing key")
	}
	return testCA{cert: pair.Leaf, signer: signer}, nil
}

func (ca testCA) issue(keyID string, key crypto.Signer) (certificateResponse, string, error) {
	now := time.Now().UTC().Truncate(time.Second)
	if now.Before(ca.cert.NotBefore) || !now.Before(ca.cert.NotAfter) {
		return certificateResponse{}, "", errors.New("test CA is outside its validity period")
	}
	subject := pkix.Name{CommonName: "SignBird test key " + keyID}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		return certificateResponse{}, "", err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return certificateResponse{}, "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return certificateResponse{}, "", err
	}
	certificateID := newID()
	serial, _ := new(big.Int).SetString(certificateID, 16)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: csr.Subject,
		NotBefore: now, NotAfter: now.AddDate(0, 1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if template.NotAfter.After(ca.cert.NotAfter) {
		template.NotAfter = ca.cert.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.signer)
	if err != nil {
		return certificateResponse{}, "", err
	}
	return certificateResponse{
		CertificateID: certificateID, CredentialID: newID(),
		CertificatePEM: asPEM("CERTIFICATE", der), ChainPEM: asPEM("CERTIFICATE", ca.cert.Raw),
		NotBefore: template.NotBefore, NotAfter: template.NotAfter,
	}, asPEM("CERTIFICATE REQUEST", csrDER), nil
}

func (s *service) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Alias string `json:"alias"`
		KeyID string `json:"keyId"`
	}
	if !decodeRequest(w, r, &request) || request.KeyID == "" {
		fail(w, http.StatusBadRequest, "Expected a JSON object with keyId")
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
	key, ok := s.ownedKey(w, r, request.KeyID)
	if !ok || !s.authorizeChange(w, r) {
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
	key, err = queries.LockOwnedKey(ctx, db.LockOwnedKeyParams{KeyID: key.KeyID, OwnerUserID: key.OwnerUserID})
	if err != nil {
		internalError(w, err)
		return
	}
	existing, err := queries.GetCredentialByRequest(ctx, db.GetCredentialByRequestParams{KeyID: key.KeyID, RequestID: requestID})
	if err == nil {
		reply(w, http.StatusCreated, certificateResponse{
			Alias: existing.Alias, CertificateID: existing.CertificateID, CredentialID: existing.CredentialID,
			CertificatePEM: existing.CertificatePem, ChainPEM: existing.ChainPem,
			NotBefore: existing.NotBefore.Time.UTC(), NotAfter: existing.NotAfter.Time.UTC(),
		})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		internalError(w, err)
		return
	}
	container, err := queries.GetPKCS12(ctx, key.ObjectRef)
	if err != nil {
		internalError(w, err)
		return
	}
	privateKey, err := s.store.decode(container)
	if err != nil {
		internalError(w, err)
		return
	}
	publicKey, err := publicKeyPEM(privateKey)
	if err != nil {
		internalError(w, err)
		return
	}
	if publicKey != key.PublicKey {
		internalError(w, errors.New("PKCS#12 public key differs from registered key"))
		return
	}
	cert, csr, err := s.ca.issue(key.KeyID, privateKey)
	if err != nil {
		internalError(w, err)
		return
	}
	cert.Alias = alias
	err = queries.InsertCertificate(ctx, db.InsertCertificateParams{
		CertificateID: cert.CertificateID, KeyID: key.KeyID, CertificatePem: cert.CertificatePEM,
		ChainPem: cert.ChainPEM, Alias: alias, CsrPem: csr, RequestID: requestID,
		NotBefore: pgtype.Timestamptz{Time: cert.NotBefore, Valid: true},
		NotAfter:  pgtype.Timestamptz{Time: cert.NotAfter, Valid: true},
	})
	if err != nil {
		internalError(w, err)
		return
	}
	if err := queries.InsertCredential(ctx, db.InsertCredentialParams{
		CredentialID: cert.CredentialID, KeyID: key.KeyID, CertificateID: cert.CertificateID,
	}); err != nil {
		internalError(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, err)
		return
	}
	reply(w, http.StatusCreated, cert)
}
