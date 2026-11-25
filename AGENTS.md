# SignBird

SignBird is a remote signing system. These instructions apply throughout the repository. The service READMEs document local startup and configuration.

## Structure and responsibilities

- `api-service/` exposes the public REST API. The contract is in `openapi.yaml`, the executable entry point in `cmd/api-service`, and the application code in `internal/api`. The service validates Keycloak access tokens and forwards key and certificate requests.
- `key-certificate-service/` manages ownership, metadata, and the lifecycle of keys, certificates, and credentials. The executable entry point is in `cmd/key-certificate-service`, the service logic in `internal/keycert`, and PostgreSQL access in `internal/db`.
- `web-portal/` contains the React, TypeScript, and Vite portal. It uses the public API contract and the Keycloak adapter with Authorization Code and PKCE. The local demo is available in development mode.
- `signature-activation-service/` implements the test-only TOTP approval flow and calls the internal PKCS#12 signer. Its entry point is in `cmd/signature-activation-service` and its logic in `internal/activation`.
- Each Go service is a separate module. Run Go commands from the root of the relevant module. Keep entry points under `cmd/` and application packages under `internal/`. Define explicit contracts between services.
- `document-signing-service/` uses Java 21, Spring Boot, PostgreSQL, and DSS for queued CAdES/P7M signing. Keep document preparation and assembly there. Persist jobs in PostgreSQL and temporary files on the private volume. PAdES/PDF and qualified signature activation through a trust service provider are planned. Digest mode keeps the document on the client.

## Language

- Use English for source code, identifiers, comments, URLs, and all project documentation, including READMEs and agent instructions. Use English for URL paths, parameters, and fragments. Localized user-facing text follows the interface language.

## Go conventions and contracts

- Use the Go version declared by the module or a later compatible version. Format Go files with `gofmt`. Prefer the standard library and existing dependencies. Add packages and interfaces when they make a boundary explicit or simplify the code.
- Propagate request context to PostgreSQL and calls between services. Set consistent timeouts and release resources on error or cancellation. Keep diagnostic details in logs and return errors defined by the HTTP contract.
- For public API changes, update `api-service/openapi.yaml` first, then regenerate code and update handlers. Preserve compatibility under `/v1` unless a change is explicitly requested. Document inputs, responses, and errors.
- For data access changes, update the schema or queries in `key-certificate-service/internal/db/` and regenerate with `sqlc`. Update the generation sources and include the resulting generated code in the same change.
- Preserve idempotency and consistency across retries, concurrent requests, and interruptions. Register the PKCS#12 container and activate the key in the same transaction. Schema changes must support fresh installations and upgrades of existing databases. Use an explicit migration to alter an existing table.

## Identity, custody, and signing

- Verify the Keycloak access token signature, issuer, audience, and expiration. The project requires access tokens with the claim `typ=Bearer`. Derive owner identity from the verified `(iss, sub)` pair. Verify the calling service's identity on internal APIs.
- Populate the portal’s key and digest algorithm selectors from `GET /v1/keys/capabilities`. The Key & Certificate Service publishes the profiles supported by the test backend.
- Require a fresh TOTP code for test key creation, certificate issuance, renewal, and alias updates. Key & Certificate Service delegates verification to Signature Activation Service and shares its replay counter across mutations and signature approval. New digest signatures complete in one request using Base64 input and output. The portal accepts hexadecimal digests and converts them to Base64 before calling the API.
- Check ownership for every operation that accesses a key, certificate, or credential. Return the same `404` for a missing resource and a resource owned by someone else.
- Reserve the `pkcs12-test` backend and local CA for development and testing. Store encrypted containers in the `bytea` column `pkcs12_objects.container` and decode them in memory when needed. The filesystem is used to import legacy containers. PostgreSQL backups include the containers.
- Keep passwords, private keys, tokens, and approval material out of the repository, responses, and logs. Keep the container password outside the database. Use test credentials and synthetic data in tests and examples.
- In production, associate each key with its keystore instance through `keystoreId` and with its HSM object reference. The activation solution governs the use of non-exportable private keys. Keep requests bound to the approved key and backend even when that backend is unavailable.
- For signing and key destruction, verify the owner's approval for the specific operation in the activation service. For signing, bind approval to the key and the exact digest with a single-use challenge that expires. Require both application-level authentication and ownership checks and activation verification. For digest signing, specify the hash algorithm and signature scheme explicitly and verify that the input digest is used directly.

## Verifying changes

- GitHub Actions runs Go checks and PostgreSQL integration tests, Maven verification, and the portal build on pull requests and pushes to `main`. Keep `.github/workflows/ci.yml` aligned with the module Makefiles. Pull requests also validate each new commit against Conventional Commits. Use a header such as `feat(portal): add certificate filters`.

- Run `make check` from the repository root to verify all services with the local runtimes. The module Makefiles expose development commands for individual services. Use these targets in README examples.
- Run `make dev` from the root to start the local stack with Docker Compose and `make dev-down` to stop it. The realm credentials in `dev/` and the Compose settings are for development.
- Run `go test ./...` and `go vet ./...` in affected Go modules. Verify the build from the usual entry point when changing layout or startup.
- In the API Service, run `go generate ./...` after changing OpenAPI or the generation configuration.
- In the Document Signing Service, run `make check` to verify packaging and CAdES signatures. For workflow changes, also validate the downloaded CMS and its embedded file.
- In the Web Portal, run `npm run generate` after an OpenAPI change and `npm run build` to verify types and the bundle.
- In the Key & Certificate Service, run `sqlc generate` after changing the schema, queries, or `sqlc.yaml`.
- For integration tests, set `TEST_DATABASE_URL` to a dedicated PostgreSQL test database and run `SIGNBIRD_TEST_DATABASE_URL="$TEST_DATABASE_URL" go test -count=1 ./...` from the Key & Certificate Service root. The test uses a separate temporary schema. The PostgreSQL test runs only when the connection variable is set.
- When changing behavior, cover the most relevant regression at the appropriate level. Include denied-access cases for identity and ownership changes. Verify persistence and migrations on PostgreSQL. For changes that span services, verify the path through the public API when the environment allows it.
- Update the service README when startup, configuration, migration, or verification steps change. Report the checks you ran and those still outstanding.
