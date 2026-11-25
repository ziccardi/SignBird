package keycert

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"signbird/key-certificate-service/internal/db"
)

type identity struct {
	issuer, subject string
}

type identityKey struct{}

func Run(args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, required("SIGNBIRD_DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if len(args) == 1 && args[0] == "migrate" {
		migrationCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := migrate(migrationCtx, pool, os.Getenv("SIGNBIRD_KEYSTORE_DIR"), os.Getenv("SIGNBIRD_PKCS12_PASSWORD")); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	secret := required("SIGNBIRD_INTERNAL_TOKEN")
	if len(secret) < 32 {
		log.Fatal("SIGNBIRD_INTERNAL_TOKEN must contain at least 32 characters")
	}
	provider, err := oidc.NewProvider(ctx, required("SIGNBIRD_OIDC_ISSUER"))
	if err != nil {
		log.Fatal(err)
	}
	verifier := provider.VerifierContext(context.Background(), &oidc.Config{ClientID: required("SIGNBIRD_OIDC_AUDIENCE")})
	ca, err := loadCA(required("SIGNBIRD_TEST_CA_CERT"), required("SIGNBIRD_TEST_CA_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	s := &service{
		pool: pool, queries: db.New(pool), ca: ca,
		store: keystore{password: required("SIGNBIRD_PKCS12_PASSWORD")},
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", authenticate(secret, verifier, s.routes()))
	if signerToken := os.Getenv("SIGNBIRD_ACTIVATION_SIGNER_TOKEN"); signerToken != "" {
		if len(signerToken) < 32 || signerToken == secret {
			log.Fatal("signer token must be distinct and at least 32 characters")
		}
		s.consumeCode = otpConsumer(signerToken)
		mux.Handle("/internal/signing-credentials/", authenticate(signerToken, verifier, s.testSigner()))
		mux.HandleFunc("POST /internal/queued-signing-credentials/{credentialId}", trustedQueuedSigner(signerToken, s.signDigest))
	}
	server := &http.Server{
		Addr: "127.0.0.1:8081", Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute,
	}
	log.Printf("SignBird Key & Certificate Service listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func (s *service) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys", s.createKey)
	mux.HandleFunc("GET /v1/keys", s.listKeys)
	mux.HandleFunc("GET /v1/keys/capabilities", s.capabilities)
	mux.HandleFunc("GET /v1/keys/{keyId}", s.getKey)
	mux.HandleFunc("PATCH /v1/keys/{keyId}", s.renameKey)
	mux.HandleFunc("PATCH /v1/keys/{keyId}/certificates/{certificateId}", s.renameCertificate)
	mux.HandleFunc("POST /v1/certificates", s.issueCertificate)
	return mux
}

func authenticate(secret string, verifier *oidc.IDTokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SignBird-Service-Token")), []byte(secret)) == 1 {
			parts := strings.Fields(r.Header.Get("Authorization"))
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				token, err := verifier.Verify(r.Context(), parts[1])
				if err == nil && token.Subject != "" {
					var claims struct {
						Type string `json:"typ"`
					}
					if token.Claims(&claims) == nil && claims.Type == "Bearer" {
						ctx := context.WithValue(r.Context(), identityKey{}, identity{token.Issuer, token.Subject})
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		fail(w, http.StatusUnauthorized, "Invalid service or user credentials")
	})
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}

func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"message": message})
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("key and certificate operation: %v", err)
	fail(w, http.StatusInternalServerError, "Key or certificate operation failed")
}
