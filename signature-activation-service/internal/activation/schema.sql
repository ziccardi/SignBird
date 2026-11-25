CREATE TABLE IF NOT EXISTS activation_accounts (
    issuer text NOT NULL,
    subject text NOT NULL,
    encrypted_seed bytea NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    last_counter bigint NOT NULL DEFAULT -1,
    failure_window timestamptz NOT NULL DEFAULT now(),
    failures integer NOT NULL DEFAULT 0,
    PRIMARY KEY (issuer, subject)
);

CREATE TABLE IF NOT EXISTS signature_requests (
    request_id text PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    credential_id text NOT NULL,
    key_id text NOT NULL,
    digest text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    signature text NOT NULL DEFAULT '',
    FOREIGN KEY (issuer, subject) REFERENCES activation_accounts (issuer, subject)
);

CREATE INDEX IF NOT EXISTS signature_requests_owner_created
    ON signature_requests (issuer, subject, created_at DESC);

ALTER TABLE signature_requests ADD COLUMN IF NOT EXISTS hash_algorithm text NOT NULL DEFAULT 'SHA-256'
    CHECK (hash_algorithm IN ('SHA-256', 'SHA-512'));
ALTER TABLE signature_requests ADD COLUMN IF NOT EXISTS signature_scheme text NOT NULL DEFAULT 'RSASSA-PKCS1-v1_5'
    CHECK (signature_scheme IN ('RSASSA-PKCS1-v1_5', 'ECDSA'));

CREATE TABLE IF NOT EXISTS document_grants (
    job_id text PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    credential_id text NOT NULL,
    key_id text NOT NULL,
    digest text NOT NULL,
    scheme text NOT NULL,
    expires_at timestamptz NOT NULL,
    signature text NOT NULL DEFAULT ''
);
