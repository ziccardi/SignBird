package keycert

import (
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ziccardi/SignBird/key-certificate-service/internal/db"
)

func validateAlias(w http.ResponseWriter, alias string) (string, bool) {
	if utf8.RuneCountInString(alias) > 80 || strings.ContainsFunc(alias, unicode.IsControl) {
		fail(w, http.StatusBadRequest, "Alias must contain at most 80 characters and no control characters")
		return "", false
	}
	return strings.TrimSpace(alias), true
}

func readAlias(w http.ResponseWriter, r *http.Request) (string, bool) {
	var request struct {
		Alias *string `json:"alias"`
	}
	if !decodeRequest(w, r, &request) || request.Alias == nil {
		fail(w, http.StatusBadRequest, "Expected a JSON object with alias")
		return "", false
	}
	return validateAlias(w, *request.Alias)
}

func (s *service) renameKey(w http.ResponseWriter, r *http.Request) {
	alias, ok := readAlias(w, r)
	if !ok {
		return
	}
	key, ok := s.ownedKey(w, r, r.PathValue("keyId"))
	if !ok || !s.authorizeChange(w, r) {
		return
	}
	count, err := s.queries.UpdateKeyAlias(r.Context(), db.UpdateKeyAliasParams{
		KeyID: key.KeyID, OwnerUserID: key.OwnerUserID, Alias: alias,
	})
	if err != nil {
		internalError(w, err)
		return
	}
	if count == 0 {
		fail(w, http.StatusNotFound, "Key not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) renameCertificate(w http.ResponseWriter, r *http.Request) {
	alias, ok := readAlias(w, r)
	if !ok {
		return
	}
	key, ok := s.ownedKey(w, r, r.PathValue("keyId"))
	if !ok {
		return
	}
	ctx := r.Context()
	id := r.PathValue("certificateId")
	found, err := s.queries.CertificateBelongsToKey(ctx, db.CertificateBelongsToKeyParams{KeyID: key.KeyID, CertificateID: id})
	if err != nil {
		internalError(w, err)
		return
	}
	if !found {
		fail(w, http.StatusNotFound, "Certificate not found")
		return
	}
	if !s.authorizeChange(w, r) {
		return
	}
	count, err := s.queries.UpdateCertificateAlias(ctx, db.UpdateCertificateAliasParams{
		KeyID: key.KeyID, CertificateID: id, OwnerUserID: key.OwnerUserID, Alias: alias,
	})
	if err != nil {
		internalError(w, err)
		return
	}
	if count == 0 {
		fail(w, http.StatusNotFound, "Certificate not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
