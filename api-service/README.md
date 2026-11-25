# SignBird API Service

The public API validates Keycloak access tokens and forwards key and certificate requests to the [Key & Certificate Service](../key-certificate-service/README.md). The [OpenAPI contract](openapi.yaml) drives generation of the `net/http` router and types through `oapi-codegen`.

The entry point is in `cmd/api-service`. The router, authentication, and proxy are in `internal/api`.

## Local startup

You need Go 1.24 or later, a Keycloak realm, and the Key & Certificate Service listening on `127.0.0.1:8081`. Use the same issuer, audience, and internal token for both processes. Run the commands below from the `api-service` directory.

```sh
export SIGNBIRD_OIDC_ISSUER='http://localhost:8180/realms/signbird'
export SIGNBIRD_OIDC_AUDIENCE='signbird-api'
export SIGNBIRD_INTERNAL_TOKEN='<Key & Certificate Service token>'
make run
```

For TOTP enrollment and signature routes, set `SIGNBIRD_ACTIVATION_API_TOKEN` to the value configured in the [Signature Activation Service](../signature-activation-service/README.md).

Use `GET /v1/keys/capabilities` to discover the supported key and digest signing profiles.

The API listens on `127.0.0.1:8080`. Set `SIGNBIRD_ACCESS_TOKEN` to a Keycloak JWT access token that includes the configured audience.

```sh
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/v1/keys \
  -H "Authorization: Bearer ${SIGNBIRD_ACCESS_TOKEN}" \
  -H "X-TOTP-Code: ${SIGNBIRD_TOTP_CODE}" \
  -H 'Idempotency-Key: create-key-1' \
  -H 'Content-Type: application/json' \
  -d '{"keystoreId":"pkcs12-test"}'
curl -i http://127.0.0.1:8080/v1/certificates \
  -H "Authorization: Bearer ${SIGNBIRD_ACCESS_TOKEN}" \
  -H "X-TOTP-Code: ${SIGNBIRD_NEXT_TOTP_CODE}" \
  -H 'Idempotency-Key: issue-certificate-1' \
  -H 'Content-Type: application/json' \
  -d '{"keyId":"<keyId returned by the create request>"}'
```

Key creation and certificate issuance require a fresh six-digit TOTP code per request. Use a fresh code with the same idempotency key to retry an operation. Use a new value for a new operation.

```sh
make generate
make test
```

## License

SignBird source code is licensed under [Apache License 2.0](../LICENSE).
