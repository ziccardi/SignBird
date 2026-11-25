CREATE TABLE IF NOT EXISTS users (
    user_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS keys (
    key_id text PRIMARY KEY CHECK (key_id ~ '^[a-f0-9]{32}$'),
    owner_user_id bigint NOT NULL REFERENCES users,
    keystore_id text NOT NULL CHECK (keystore_id = 'pkcs12-test'),
    object_ref text NOT NULL UNIQUE CHECK (object_ref = key_id || '.p12'),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE')),
    public_key text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    request_id text NOT NULL,
    UNIQUE (owner_user_id, request_id)
);

ALTER TABLE keys ADD COLUMN IF NOT EXISTS algorithm text NOT NULL DEFAULT 'RSA-2048'
    CHECK (algorithm IN ('RSA-2048', 'ECDSA-P256', 'ECDSA-P521'));

CREATE TABLE IF NOT EXISTS certificates (
    certificate_id text PRIMARY KEY,
    key_id text NOT NULL REFERENCES keys,
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    csr_pem text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    request_id text NOT NULL,
    UNIQUE (key_id, request_id),
    UNIQUE (key_id, certificate_id)
);

CREATE TABLE IF NOT EXISTS signing_credentials (
    credential_id text PRIMARY KEY,
    key_id text NOT NULL,
    certificate_id text NOT NULL UNIQUE,
    FOREIGN KEY (key_id, certificate_id) REFERENCES certificates (key_id, certificate_id)
);

CREATE TABLE IF NOT EXISTS pkcs12_objects (
    object_ref text PRIMARY KEY REFERENCES keys (object_ref),
    container bytea NOT NULL CHECK (octet_length(container) > 0)
);

ALTER TABLE keys ADD COLUMN IF NOT EXISTS alias text NOT NULL DEFAULT ''
    CHECK (char_length(alias) <= 80);
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS alias text NOT NULL DEFAULT ''
    CHECK (char_length(alias) <= 80);
