# SignBird Web Portal

The React, TypeScript, and Vite portal lets you generate and inspect test keys, issue certificates, and renew them. When connected to the SignBird services, you can download the public key, certificate, and certificate chain in PEM format. Set an optional alias when creating a key or issuing a certificate. Edit aliases from the key and certificate details. The signing selectors show aliases, with an abbreviated identifier as a fallback. The portal loads available key and digest algorithms from the public capabilities endpoint.

## Full local stack

With Docker and Docker Compose running, run `make dev` from the SignBird root.
Open the [portal](http://127.0.0.1:5173/) and sign in with `signbird-test` as both username and password.
Compose starts PostgreSQL, Keycloak, the three Go services, the Java Document Signing Service, and the portal. The bundled realm and credentials are for local development.
Use `make dev-logs` to follow logs and `make dev-down` to stop the stack. Volumes preserve data between runs.

Use the [Signature Activation Service guide](../signature-activation-service/README.md) to try digest signing with TOTP.

Use the [Document Signing Service guide](../document-signing-service/README.md) to upload and sign a file as P7M.

## Local preview

From the `web-portal` directory, run the following commands with Node.js 22.12 or later.

```sh
make install
make run
```

Open the [demo](http://127.0.0.1:5173/?demo=1) to try the portal without external services. It uses simulated data held in memory and resets on reload. The demo is available only through the Vite development server.

## Connecting to SignBird services

1. Start PostgreSQL, the [Key & Certificate Service](../key-certificate-service/README.md), and the [API Service](../api-service/README.md).
2. Configure a public Keycloak OpenID Connect client, such as `signbird-web`. Disable Client authentication, enable Standard flow, and set PKCE to `S256`. For development, set Valid Redirect URIs to `http://127.0.0.1:5173/` and Web Origins to `http://127.0.0.1:5173`. Use an audience mapper to add the audience configured on both services, such as `signbird-api`, to the client access token. Create a test user in the realm.
3. Copy `.env.example` to `.env.local` and set the Keycloak URL, realm, and client ID. Use values consistent with the issuer configured in the Go services.
4. Restart Vite and open the [portal](http://127.0.0.1:5173/). Sign in as the test user, generate a key, and issue a certificate from the key detail.

In development, Vite proxies `/v1` to the API Service. The Keycloak adapter uses Authorization Code with PKCE and keeps tokens in memory. Variables prefixed with `VITE_` are public and become part of the bundle.

## Build and API contract

```sh
make generate
make build
```

Regenerate the TypeScript types whenever `../api-service/openapi.yaml` changes. The build writes static files to `dist/`. For deployment, serve `dist/` and proxy `/v1` to the API Service on the same origin. Configure Keycloak with the deployed portal’s exact redirect URI and origin.

## License

SignBird source code is licensed under [Apache License 2.0](../LICENSE).
