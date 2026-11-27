package api

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type apiService struct {
	upstream   http.Handler
	activation http.Handler
	documents  http.Handler
}

func keyServiceProxy(secret string) http.Handler {
	return internalProxy(secret, "127.0.0.1:8081", "Key and certificate service")
}

func internalProxy(secret, host, serviceName string) http.Handler {
	target := &url.URL{Scheme: "http", Host: host}
	return &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Header.Set("X-SignBird-Service-Token", secret)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("%s: %v", serviceName, err)
			writeJSON(w, http.StatusBadGateway, Error{Message: serviceName + " unavailable"})
		},
	}
}

func (s *apiService) Health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *apiService) CreateKey(w http.ResponseWriter, r *http.Request, _ CreateKeyParams) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) ListKeys(w http.ResponseWriter, r *http.Request) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) GetKey(w http.ResponseWriter, r *http.Request, _ string) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) IssueCertificate(w http.ResponseWriter, r *http.Request, _ IssueCertificateParams) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) GetTotpStatus(w http.ResponseWriter, r *http.Request) {
	s.forwardActivation(w, r)
}

func (s *apiService) StartTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	s.forwardActivation(w, r)
}

func (s *apiService) ConfirmTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	s.forwardActivation(w, r)
}

func (s *apiService) ListDigestSignatures(w http.ResponseWriter, r *http.Request) {
	s.forwardActivation(w, r)
}

func (s *apiService) CreateDigestSignature(w http.ResponseWriter, r *http.Request, _ CreateDigestSignatureParams) {
	s.forwardActivation(w, r)
}

func (s *apiService) GetDigestSignature(w http.ResponseWriter, r *http.Request, _ string) {
	s.forwardActivation(w, r)
}

func (s *apiService) ApproveDigestSignature(w http.ResponseWriter, r *http.Request, _ string) {
	s.forwardActivation(w, r)
}

func (s *apiService) forwardActivation(w http.ResponseWriter, r *http.Request) {
	if s.activation == nil {
		writeJSON(w, http.StatusServiceUnavailable, Error{Message: "Signature activation is unavailable"})
		return
	}
	s.activation.ServeHTTP(w, r)
}

func (s *apiService) GetKeyCapabilities(w http.ResponseWriter, r *http.Request) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) UploadP7m(w http.ResponseWriter, r *http.Request) { s.forwardDocuments(w, r) }
func (s *apiService) ListP7m(w http.ResponseWriter, r *http.Request)   { s.forwardDocuments(w, r) }
func (s *apiService) GetP7m(w http.ResponseWriter, r *http.Request, _ string) {
	s.forwardDocuments(w, r)
}
func (s *apiService) ApproveP7m(w http.ResponseWriter, r *http.Request, _ string) {
	s.forwardDocuments(w, r)
}
func (s *apiService) DownloadP7m(w http.ResponseWriter, r *http.Request, _ string) {
	s.forwardDocuments(w, r)
}

func (s *apiService) forwardDocuments(w http.ResponseWriter, r *http.Request) {
	if s.documents == nil {
		writeJSON(w, http.StatusServiceUnavailable, Error{Message: "Document signing is unavailable"})
		return
	}
	s.documents.ServeHTTP(w, r)
}

func (s *apiService) RenameKey(w http.ResponseWriter, r *http.Request, _ string, _ RenameKeyParams) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) RenameCertificate(w http.ResponseWriter, r *http.Request, _, _ string, _ RenameCertificateParams) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) CreateKeyCsr(w http.ResponseWriter, r *http.Request, _ string, _ CreateKeyCsrParams) {
	s.upstream.ServeHTTP(w, r)
}

func (s *apiService) ImportKeyCertificate(w http.ResponseWriter, r *http.Request, _ string, _ ImportKeyCertificateParams) {
	s.upstream.ServeHTTP(w, r)
}
