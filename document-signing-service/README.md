# SignBird Document Signing Service

The Java 21 service uses Spring Boot, PostgreSQL, and DSS to create CAdES Baseline B signatures with the original file embedded. The local flow uses active PKCS#12 test credentials, SHA-256, and either RSA PKCS#1 v1.5 or ECDSA.

## Try the workflow

Run `make dev` from the repository root. In the [portal](http://127.0.0.1:5173/#documents), open the P7M signing section. Select a key and valid certificate, upload a non-empty file of up to 10 MB, then wait for the preparation worker. Review the file and credential, approve with a fresh authenticator code, and download the P7M when the status is ready.

The [OpenAPI contract](../api-service/openapi.yaml) defines the multipart upload, job listing and status, approval, and binary download. Upload and approval return `202 Accepted`. Every operation is scoped to the authenticated owner through the API Service.

## Queue and storage

PostgreSQL stores job ownership, status, certificate information, the prepared digest, and expiration. The private Docker volume `document-storage` holds the original and signed file. The worker uses PostgreSQL row locks so interrupted jobs remain available after a restart. The activation service consumes the TOTP during approval and stores a job-specific grant for the approved key and digest. The worker uses that grant without storing the OTP or the user's access token.

The original is removed after the signed file is committed as ready, or when the job expires. Jobs can wait up to one hour for approval. After approval, signing has a 15-minute window. A failed processing step is retried up to twice. Signed files are available for repeated downloads for 24 hours by default, configurable with `SIGNBIRD_P7M_RETENTION_HOURS`. Cleanup runs while the service is active. The local volume belongs to a single host.

## Development

`make check` runs the Java build and tests. The tests assemble RSA and ECDSA CAdES documents, verify their CMS signatures independently, and check that the embedded file matches the original. `make run` starts the service with the PostgreSQL connection, gateway and activation tokens, and storage directory configured as shown in `compose.yaml`.

## Third-party licensing

The service uses unmodified [DSS 6.4](https://github.com/esig/dss/tree/6.4#licenses) as a Maven dependency under [LGPL 2.1](https://spdx.org/licenses/LGPL-2.1-only.html). The source repository declares the Maven coordinates and version in `pom.xml`.

Before publishing a JAR or OCI image that includes DSS, prepare a release package with a prominent DSS notice, the LGPL 2.1 license text and applicable copyright notices, and equivalent access from the release to the complete corresponding source for the DSS modules shipped, including any patches. Also provide the SignBird sources and build instructions for the exact release so recipients can rebuild the service against an interface-compatible modified DSS build. Verify that procedure by rebuilding and validating a P7M signature. Keep the distribution terms consistent with section 6, including modification for personal use and reverse engineering to debug such modifications.


## License

SignBird source code is licensed under [Apache License 2.0](../LICENSE).
