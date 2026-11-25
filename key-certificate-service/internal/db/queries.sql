-- name: EnsureUser :one
INSERT INTO users (issuer, subject) VALUES ($1, $2)
ON CONFLICT (issuer, subject) DO UPDATE SET subject = EXCLUDED.subject
RETURNING user_id;

-- name: ReserveKey :one
INSERT INTO keys (key_id, owner_user_id, keystore_id, object_ref, request_id, algorithm, alias)
VALUES ($1, $2, 'pkcs12-test', $3, $4, $5, $6)
ON CONFLICT (owner_user_id, request_id) DO UPDATE SET request_id = EXCLUDED.request_id
RETURNING key_id;

-- name: LockOwnedKey :one
SELECT * FROM keys WHERE key_id = $1 AND owner_user_id = $2 FOR UPDATE;

-- name: ActivateKey :one
UPDATE keys SET status = 'ACTIVE', public_key = $2 WHERE key_id = $1 RETURNING *;

-- name: ListOwnedKeys :many
SELECT keys.* FROM keys JOIN users ON user_id = owner_user_id
WHERE issuer = $1 AND subject = $2 AND status = 'ACTIVE'
ORDER BY created_at, key_id;

-- name: GetOwnedKey :one
SELECT keys.* FROM keys JOIN users ON user_id = owner_user_id
WHERE issuer = $1 AND subject = $2 AND key_id = $3 AND status = 'ACTIVE';

-- name: GetCredentialByRequest :one
SELECT c.*, sc.credential_id FROM certificates c JOIN signing_credentials sc USING (key_id, certificate_id)
WHERE c.key_id = $1 AND c.request_id = $2;

-- name: InsertCertificate :exec
INSERT INTO certificates (certificate_id, key_id, certificate_pem, chain_pem, csr_pem, not_before, not_after, request_id, alias)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: InsertCredential :exec
INSERT INTO signing_credentials (credential_id, key_id, certificate_id) VALUES ($1, $2, $3);

-- name: ListCertificates :many
SELECT c.*, sc.credential_id FROM certificates c JOIN signing_credentials sc USING (key_id, certificate_id)
WHERE c.key_id = $1 ORDER BY c.not_before DESC, c.certificate_id;

-- name: GetPKCS12 :one
SELECT container FROM pkcs12_objects WHERE object_ref = $1;

-- name: InsertPKCS12 :exec
INSERT INTO pkcs12_objects (object_ref, container) VALUES ($1, $2);

-- name: ListKeysMissingPKCS12 :many
SELECT key_id, object_ref, status, public_key FROM keys
WHERE NOT EXISTS (SELECT 1 FROM pkcs12_objects WHERE pkcs12_objects.object_ref = keys.object_ref)
ORDER BY key_id FOR UPDATE;

-- name: GetOwnedSigningCredential :one
SELECT k.key_id, k.object_ref, k.public_key, k.algorithm
FROM signing_credentials sc
JOIN keys k ON k.key_id = sc.key_id
JOIN users u ON u.user_id = k.owner_user_id
JOIN certificates c ON c.certificate_id = sc.certificate_id AND c.key_id = sc.key_id
WHERE u.issuer = $1 AND u.subject = $2 AND sc.credential_id = $3
  AND k.status = 'ACTIVE' AND k.keystore_id = 'pkcs12-test'
  AND c.not_before <= now() AND c.not_after > now();

-- name: UpdateKeyAlias :execrows
UPDATE keys SET alias = $3 WHERE key_id = $1 AND owner_user_id = $2 AND status = 'ACTIVE';

-- name: CertificateBelongsToKey :one
SELECT EXISTS (SELECT 1 FROM certificates WHERE key_id = $1 AND certificate_id = $2);

-- name: UpdateCertificateAlias :execrows
UPDATE certificates c SET alias = $4
FROM keys k WHERE c.key_id = k.key_id AND c.key_id = $1
    AND c.certificate_id = $2 AND k.owner_user_id = $3 AND k.status = 'ACTIVE';
