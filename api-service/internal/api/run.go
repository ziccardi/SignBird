package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func Run() {
	issuer := requiredEnv("SIGNBIRD_OIDC_ISSUER")
	audience := requiredEnv("SIGNBIRD_OIDC_AUDIENCE")
	secret := requiredEnv("SIGNBIRD_INTERNAL_TOKEN")
	if len(secret) < 32 {
		log.Fatal("SIGNBIRD_INTERNAL_TOKEN must contain at least 32 characters")
	}
	service := &apiService{upstream: keyServiceProxy(secret)}
	if activationToken := os.Getenv("SIGNBIRD_ACTIVATION_API_TOKEN"); activationToken != "" {
		if len(activationToken) < 32 || activationToken == secret {
			log.Fatal("activation API token must be distinct and at least 32 characters")
		}
		service.activation = internalProxy(activationToken, "127.0.0.1:8082", "Signature activation service")
	}
	if documentToken := os.Getenv("SIGNBIRD_DOCUMENT_GATEWAY_TOKEN"); documentToken != "" {
		if len(documentToken) < 32 || documentToken == secret || documentToken == os.Getenv("SIGNBIRD_ACTIVATION_API_TOKEN") {
			log.Fatal("document gateway token must be distinct and at least 32 characters")
		}
		service.documents = internalProxy(documentToken, "127.0.0.1:8083", "Document signing service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	provider, err := oidc.NewProvider(ctx, issuer)
	cancel()
	if err != nil {
		log.Fatal(err)
	}

	handler := HandlerWithOptions(service, StdHTTPServerOptions{
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeJSON(w, http.StatusBadRequest, Error{Message: "Missing or invalid request parameter"})
		},
	})
	protected := authenticate(provider.VerifierContext(context.Background(), &oidc.Config{ClientID: audience}), handler)
	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
				handler.ServeHTTP(w, r)
				return
			}
			protected.ServeHTTP(w, r)
		}),
	}
	log.Printf("SignBird API listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func authenticate(verifier *oidc.IDTokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token, err := verifier.Verify(r.Context(), parts[1])
			if err == nil && token.Subject != "" {
				var claims struct {
					Type string `json:"typ"`
				}
				if token.Claims(&claims) == nil && claims.Type == "Bearer" {
					r.Header.Set("X-SignBird-Owner-Issuer", base64.RawURLEncoding.EncodeToString([]byte(token.Issuer)))
					r.Header.Set("X-SignBird-Owner-Subject", base64.RawURLEncoding.EncodeToString([]byte(token.Subject)))
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, Error{Message: "Invalid or missing access token"})
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}
