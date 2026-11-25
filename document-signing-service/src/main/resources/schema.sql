CREATE TABLE IF NOT EXISTS p7m_jobs (
    job_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    key_id text NOT NULL,
    credential_id text NOT NULL,
    filename text NOT NULL,
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    scheme text NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED',
    digest text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour',
    ready_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS p7m_jobs_queue ON p7m_jobs (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS p7m_jobs_owner ON p7m_jobs (issuer, subject, created_at DESC);
