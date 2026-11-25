# Contributing to SignBird

Use the [root README](README.md#quick-start) to start the development stack. The module READMEs document standalone setup, configuration, and integration tests.

## Check your changes

Run `make check` from the root with the version of Go declared by the modules, Java 21 and Maven, and a supported Node.js version. On a fresh checkout, install the portal dependencies with `make -C web-portal install`.

- Run `make -C api-service generate` and `make -C web-portal generate` after an OpenAPI change.
- Run `make -C key-certificate-service generate` after a SQL schema, query, or generation configuration change.
- For changes involving PostgreSQL, set `SIGNBIRD_TEST_DATABASE_URL` to a dedicated test database and run the relevant module's `make test-integration`.
- For document signing changes, verify the resulting signature and confirm that the embedded file matches the original.

## Submit a pull request

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for every commit, for example `fix(portal): preserve the selected signing credential`. Describe the behavior change and the checks you ran. Keep code, comments, URLs, and project documentation in English. See [AGENTS.md](AGENTS.md) for architecture and implementation conventions.
