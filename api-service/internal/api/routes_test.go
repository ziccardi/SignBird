package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeyAndCertificateRoutes(t *testing.T) {
	service := &apiService{upstream: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") != "request-1" {
			t.Fatal("idempotency key was not forwarded")
		}
		if r.Header.Get("X-TOTP-Code") != "012345" {
			t.Fatal("TOTP code was not forwarded")
		}
		w.WriteHeader(http.StatusCreated)
	})}
	for _, path := range []string{"/v1/keys", "/v1/certificates"} {
		request := httptest.NewRequest("POST", path, nil)
		request.Header.Set("Idempotency-Key", "request-1")
		response := httptest.NewRecorder()
		Handler(service).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d without TOTP, want 400", path, response.Code)
		}
		request.Header.Set("X-TOTP-Code", "012345")
		response = httptest.NewRecorder()
		Handler(service).ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("%s: got %d, want 201", path, response.Code)
		}
	}
}

func TestMissingToken(t *testing.T) {
	handler := authenticate(nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached protected handler")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/v1/keys", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", response.Code)
	}
}

func TestSynchronousDigestRouteForwardsTOTP(t *testing.T) {
	service := &apiService{activation: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TOTP-Code") != "012345" {
			t.Fatal("TOTP code was not forwarded")
		}
		w.WriteHeader(http.StatusOK)
	})}
	handler := Handler(service)
	request := httptest.NewRequest(http.MethodPost, "/v1/signatures/digest", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("got %d without TOTP, want 400", response.Code)
	}

	request.Header.Set("X-TOTP-Code", "012345")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", response.Code)
	}
}
