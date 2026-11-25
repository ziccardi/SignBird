# SignBird Signature Activation Service

This Go service implements test-only digest signing with PKCS#12 and TOTP. It is part of the local stack started with `make dev` from the repository root.

## Portal workflow

1. Sign in to the [local portal](http://127.0.0.1:5173/). Open **Authenticator** to set up TOTP.
2. Start authenticator setup. Scan the QR code in Google Authenticator or another compatible application. To enroll manually, add the displayed setup key as a time-based entry. Confirm enrollment with a six-digit code.
3. Create a test key and issue a certificate if needed. Use a fresh code for each change.
4. Under **Digest signing**, select a signing credential, enter a hexadecimal digest for SHA-256 (64 characters) or SHA-512 (128 characters) and a fresh TOTP code, then submit. The portal converts the digest to Base64 and displays the resulting Base64 signature immediately.

To compute a hexadecimal digest locally, run:

```sh
openssl dgst -sha256 -binary document.pdf | xxd -p -c 32
openssl dgst -sha512 -binary document.pdf | xxd -p -c 64
```

## Public API

Use the [OpenAPI contract](../api-service/openapi.yaml) and a Keycloak access token.

| Method and path | Purpose |
|---|---|
| `GET /v1/activation/totp` | Read enrollment status |
| `POST /v1/activation/totp` | Start or resume pending enrollment and return the Base32 setup key |
| `POST /v1/activation/totp/confirm` | Enable TOTP with a code |
| `POST /v1/signatures/digest` | Sign a digest synchronously and return the Base64 signature |
| `GET /v1/signatures/digest` | List the latest 50 requests for the caller |
| `GET /v1/signatures/digest/{requestId}` | Read request status and signature |
| `POST /v1/signatures/digest/{requestId}/approve` | Approve a legacy pending request with a code |

Send a fresh six-digit TOTP in the `X-TOTP-Code` header. The signing body contains `credentialId`, `digest`, `hashAlgorithm` (`SHA-256` or `SHA-512`), and `signatureScheme`. The digest is standard Base64 for 32 or 64 prehashed bytes, respectively. Use `RSASSA-PKCS1-v1_5` for RSA keys and `ECDSA` for elliptic-curve keys. ECDSA signatures are encoded as an ASN.1 DER sequence before Base64 encoding. The response is `200 OK` with the Base64 signature in `signature`. Enrollment confirmation and legacy approval take a JSON object with a six-digit string `code`.

## Boundaries

Legacy pending requests retain their original expiration. The approval service verifies ownership, rate-limits failed codes per account, and persists the accepted TOTP counter together with the signature result. The Key & Certificate Service validates the active credential and signs the prehashed digest. It exposes its test signer only to the activation service through a dedicated internal token. The service returns the signature after the result and TOTP counter commit.

Enrollment secrets are encrypted in PostgreSQL. This development flow supports initial enrollment without recovery or replacement. The local stack uses shared development infrastructure and test credentials. Qualified signing remains a separate integration with a qualified trust service provider.

For standalone development, use `make run` and supply `SIGNBIRD_ACTIVATION_DATABASE_URL`, the Keycloak issuer and audience variables, `SIGNBIRD_ACTIVATION_API_TOKEN`, `SIGNBIRD_ACTIVATION_SIGNER_TOKEN`, and `SIGNBIRD_TOTP_ENCRYPTION_KEY` containing 32 Base64-encoded bytes. Configure the API Service with the API token and the Key & Certificate Service with the signer token. Keep the encryption key stable across restarts. The service initializes its PostgreSQL tables on startup.

Run `make check` to verify this module. Set `SIGNBIRD_TEST_DATABASE_URL` to a PostgreSQL test database and run `make test-integration` to verify ownership, expiration, rate limiting, and replay handling.
