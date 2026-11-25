package keycert

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ziccardi/SignBird/key-certificate-service/internal/db"
)

var keyID = regexp.MustCompile("^[a-f0-9]{32}$")
var idempotencyKey = regexp.MustCompile("^[a-zA-Z0-9._-]{1,128}$")

type service struct {
	pool        *pgxpool.Pool
	queries     *db.Queries
	store       keystore
	ca          testCA
	consumeCode func(http.ResponseWriter, *http.Request) bool
}

type keyResponse struct {
	Alias        string                 `json:"alias,omitempty"`
	KeyID        string                 `json:"keyId"`
	KeystoreID   string                 `json:"keystoreId"`
	PublicKey    string                 `json:"publicKey"`
	Algorithm    string                 `json:"algorithm"`
	Status       string                 `json:"status"`
	CreatedAt    time.Time              `json:"createdAt"`
	Certificates *[]certificateResponse `json:"certificates,omitempty"`
}

func keyView(key db.Key) keyResponse {
	return keyResponse{
		KeyID: key.KeyID, KeystoreID: key.KeystoreID, PublicKey: key.PublicKey,
		Alias: key.Alias, Algorithm: key.Algorithm, Status: key.Status, CreatedAt: key.CreatedAt.Time.UTC(),
	}
}

func decodeRequest(w http.ResponseWriter, r *http.Request, into any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into) == nil && decoder.Decode(new(any)) == io.EOF
}

func requestID(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) == 0 {
		return newID(), true
	}
	if len(values) != 1 || !idempotencyKey.MatchString(values[0]) {
		fail(w, http.StatusBadRequest, "Invalid Idempotency-Key")
		return "", false
	}
	return values[0], true
}

func (s *service) createKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Alias      string `json:"alias"`
		KeystoreID string `json:"keystoreId"`
		Algorithm  string `json:"algorithm"`
	}
	if !decodeRequest(w, r, &request) || request.KeystoreID != "pkcs12-test" {
		fail(w, http.StatusBadRequest, "Expected a JSON object with keystoreId pkcs12-test")
		return
	}
	alias, ok := validateAlias(w, request.Alias)
	if !ok {
		return
	}
	if request.Algorithm == "" {
		request.Algorithm = rsa2048
	}
	if signingScheme(request.Algorithm) == "" {
		fail(w, http.StatusBadRequest, "Unsupported key algorithm")
		return
	}

	requestID, ok := requestID(w, r)
	if !ok || !s.authorizeChange(w, r) {
		return
	}
	ctx := r.Context()
	actor := ctx.Value(identityKey{}).(identity)
	ownerID, err := s.queries.EnsureUser(ctx, db.EnsureUserParams{Issuer: actor.issuer, Subject: actor.subject})
	if err != nil {
		internalError(w, err)
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	queries := s.queries.WithTx(tx)
	id := newID()
	id, err = queries.ReserveKey(ctx, db.ReserveKeyParams{
		KeyID: id, OwnerUserID: ownerID, ObjectRef: id + ".p12", RequestID: requestID, Algorithm: request.Algorithm, Alias: alias,
	})
	if err != nil {
		internalError(w, err)
		return
	}
	key, err := queries.LockOwnedKey(ctx, db.LockOwnedKeyParams{KeyID: id, OwnerUserID: ownerID})
	if err != nil {
		internalError(w, err)
		return
	}
	if key.Algorithm != request.Algorithm {
		fail(w, http.StatusConflict, "Idempotency key already used with a different algorithm")
		return
	}
	if key.Status == "PENDING" {
		container, err := queries.GetPKCS12(ctx, key.ObjectRef)
		if errors.Is(err, pgx.ErrNoRows) {
			container, err = s.store.generate(key.Algorithm)
			if err == nil {
				err = queries.InsertPKCS12(ctx, db.InsertPKCS12Params{ObjectRef: key.ObjectRef, Container: container})
			}
		}
		if err != nil {
			internalError(w, err)
			return
		}
		privateKey, err := s.store.decode(container)
		if err != nil {
			internalError(w, err)
			return
		}
		if keyAlgorithm(privateKey.Public()) != key.Algorithm {
			internalError(w, errors.New("PKCS#12 key algorithm differs from registered algorithm"))
			return
		}
		publicKey, err := publicKeyPEM(privateKey)
		if err != nil {
			internalError(w, err)
			return
		}
		key, err = queries.ActivateKey(ctx, db.ActivateKeyParams{KeyID: id, PublicKey: publicKey})
		if err != nil {
			internalError(w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, err)
		return
	}
	reply(w, http.StatusCreated, keyView(key))
}

func (s *service) listKeys(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(identityKey{}).(identity)
	keys, err := s.queries.ListOwnedKeys(r.Context(), db.ListOwnedKeysParams{Issuer: actor.issuer, Subject: actor.subject})
	if err != nil {
		internalError(w, err)
		return
	}
	result := make([]keyResponse, 0, len(keys))
	for _, key := range keys {
		result = append(result, keyView(key))
	}
	reply(w, http.StatusOK, result)
}

func (s *service) ownedKey(w http.ResponseWriter, r *http.Request, id string) (db.Key, bool) {
	if !keyID.MatchString(id) {
		fail(w, http.StatusNotFound, "Key not found")
		return db.Key{}, false
	}
	actor := r.Context().Value(identityKey{}).(identity)
	key, err := s.queries.GetOwnedKey(r.Context(), db.GetOwnedKeyParams{Issuer: actor.issuer, Subject: actor.subject, KeyID: id})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		fail(w, http.StatusNotFound, "Key not found")
	case err != nil:
		internalError(w, err)
	default:
		return key, true
	}
	return db.Key{}, false
}

func (s *service) getKey(w http.ResponseWriter, r *http.Request) {
	key, ok := s.ownedKey(w, r, r.PathValue("keyId"))
	if !ok {
		return
	}
	certs, err := s.queries.ListCertificates(r.Context(), key.KeyID)
	if err != nil {
		internalError(w, err)
		return
	}
	history := make([]certificateResponse, 0, len(certs))
	for _, cert := range certs {
		history = append(history, certificateResponse{
			Alias: cert.Alias, CertificateID: cert.CertificateID, CredentialID: cert.CredentialID,
			CertificatePEM: cert.CertificatePem, ChainPEM: cert.ChainPem,
			NotBefore: cert.NotBefore.Time.UTC(), NotAfter: cert.NotAfter.Time.UTC(),
		})
	}
	result := keyView(key)
	result.Certificates = &history
	reply(w, http.StatusOK, result)
}
