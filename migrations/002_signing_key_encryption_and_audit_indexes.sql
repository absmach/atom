ALTER TABLE signing_keys
    ALTER COLUMN private_key DROP NOT NULL;

ALTER TABLE signing_keys
    ADD COLUMN IF NOT EXISTS private_key_ciphertext BYTEA,
    ADD COLUMN IF NOT EXISTS private_key_nonce BYTEA,
    ADD COLUMN IF NOT EXISTS private_key_key_id TEXT,
    ADD COLUMN IF NOT EXISTS private_key_encryption_alg TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
    ON audit_logs(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_event_time
    ON audit_logs(event, created_at DESC);
