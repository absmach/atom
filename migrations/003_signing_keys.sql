-- =============================================================
-- SIGNING KEYS
--
-- Stores ES256 key pairs for JWT signing.
-- At most one key is 'primary' (signs new tokens) and one is
-- 'standby' (still validates tokens issued before last rotation).
-- Retired keys are kept for audit but never used for verification.
--
-- Private keys are stored as plain PKCS8 PEM. In production,
-- encrypt this column at rest or delegate to a KMS.
-- =============================================================
CREATE TABLE signing_keys (
    kid         TEXT        PRIMARY KEY,
    algorithm   TEXT        NOT NULL DEFAULT 'ES256',
    public_key  TEXT        NOT NULL,   -- SubjectPublicKeyInfo PEM
    private_key TEXT        NOT NULL,   -- PKCS8 PEM
    status      TEXT        NOT NULL DEFAULT 'primary'
                            CHECK (status IN ('primary', 'standby', 'retired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_signing_keys_status ON signing_keys(status);
