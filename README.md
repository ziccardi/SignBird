# SignBird

SignBird is an open-source remote signing platform. It supports synchronous digest signing and queued CAdES/P7M signing with the original document embedded. The portal manages keys, certificates, and TOTP approvals.

The current stack is intended for development and testing. It uses a local certificate authority and encrypted PKCS#12 containers in PostgreSQL. Qualified signing, production HSM integration, and PAdES/PDF signing are planned.

## Quick start

Install Docker with the Compose plugin, then run from the repository root:

```sh
make dev
```

Open the [local portal](http://127.0.0.1:5173/) and sign in with `signbird-test` as both username and password. Set up your authenticator, generate a key, and issue a test certificate. Use a fresh code for each protected operation.

Use `make dev-logs` to follow the stack logs and `make dev-down` to stop the stack while retaining data in Docker volumes.

## Components

| Component | Responsibility |
| --- | --- |
| [Web Portal](web-portal/README.md) | React interface for identity, keys, certificates, and signing workflows |
| [API Service](api-service/README.md) | Public REST API, access token validation, and request routing |
| [Key & Certificate Service](key-certificate-service/README.md) | Key ownership, test certificate issuance and renewal, and PKCS#12 signing |
| [Signature Activation Service](signature-activation-service/README.md) | TOTP enrollment and operation-specific approval |
| [Document Signing Service](document-signing-service/README.md) | Persistent P7M queue, CAdES assembly with DSS, and expiring downloads |

The public contract is in [OpenAPI](api-service/openapi.yaml).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development checks and pull request conventions. Report security issues using [SECURITY.md](SECURITY.md).

## License

SignBird source code is licensed under [Apache License 2.0](LICENSE). Dependencies retain their own licenses. The Document Signing Service uses DSS under LGPL 2.1. See its [distribution notes](document-signing-service/README.md#third-party-licensing) before packaging DSS with a binary or container image.
