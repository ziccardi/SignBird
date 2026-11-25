package activation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

type actor struct {
	issuer, subject string
}

type actorKey struct{}

func Run() {
	apiToken := required("SIGNBIRD_ACTIVATION_API_TOKEN")
	signerToken := required("SIGNBIRD_ACTIVATION_SIGNER_TOKEN")
	if len(apiToken) < 32 || len(signerToken) < 32 || apiToken == signerToken {
		log.Fatal("activation service tokens must be distinct and at least 32 characters")
	}
	key, err := base64.StdEncoding.DecodeString(required("SIGNBIRD_TOTP_ENCRYPTION_KEY"))
	if err != nil || len(key) != 32 {
		log.Fatal("SIGNBIRD_TOTP_ENCRYPTION_KEY must contain 32 Base64-encoded bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	box, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, required("SIGNBIRD_ACTIVATION_DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, schema, pgx.QueryExecModeSimpleProtocol); err != nil {
		log.Fatal(err)
	}
	provider, err := oidc.NewProvider(ctx, required("SIGNBIRD_OIDC_ISSUER"))
	if err != nil {
		log.Fatal(err)
	}
	verifier := provider.VerifierContext(context.Background(), &oidc.Config{ClientID: required("SIGNBIRD_OIDC_AUDIENCE")})
	s := &service{pool: pool, box: box, signer: testSigner{
		token: signerToken,
		client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("POST /internal/activation/totp/consume", authenticate(signerToken, verifier, http.HandlerFunc(s.consume)))
	if documentToken := os.Getenv("SIGNBIRD_DOCUMENT_SERVICE_TOKEN"); documentToken != "" {
		if len(documentToken) < 32 || documentToken == apiToken || documentToken == signerToken {
			log.Fatal("document service token must be distinct and at least 32 characters")
		}
		s.documentRoutes(mux, documentToken, func(next http.Handler) http.Handler {
			return authenticate(documentToken, verifier, next)
		})
	}
	mux.Handle("/v1/", authenticate(apiToken, verifier, s.routes()))
	server := &http.Server{
		Addr: "127.0.0.1:8082", Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 25 * time.Second, IdleTimeout: time.Minute,
	}
	log.Printf("SignBird Signature Activation Service listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func authenticate(secret string, verifier *oidc.IDTokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SignBird-Service-Token")), []byte(secret)) == 1 &&
			len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token, err := verifier.Verify(r.Context(), parts[1])
			if err == nil && token.Subject != "" {
				var claims struct {
					Type string `json:"typ"`
				}
				if token.Claims(&claims) == nil && claims.Type == "Bearer" {
					ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
					defer cancel()
					next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, actorKey{}, actor{token.Issuer, token.Subject})))
					return
				}
			}
		}
		fail(w, http.StatusUnauthorized, "Invalid service or user credentials")
	})
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}

func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"message": message})
}

func unexpected(w http.ResponseWriter, err error) {
	log.Printf("activation operation: %v", err)
	fail(w, http.StatusInternalServerError, "Activation operation failed")
}
