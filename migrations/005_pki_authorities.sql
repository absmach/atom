-- Atom-native multi-tenant PKI authority registry.
--
-- This migration is deliberately backward-compatible with the v1 file issuer:
-- existing certificate credentials keep issuer_id = NULL and remain unique in
-- the legacy global serial namespace. New tenant issuers receive a stable row
-- and certificates issued by them are unique by (issuer_id, serial_number).

CREATE TABLE pki_authorities (
    id                      UUID        PRIMARY KEY,
    tenant_id               UUID        REFERENCES tenants(id) ON DELETE RESTRICT,
    parent_id               UUID        REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    kind                    TEXT        NOT NULL
                                        CHECK (kind IN (
                                            'root',
                                            'platform_intermediate',
                                            'tenant_intermediate'
                                        )),
    version                 INTEGER     NOT NULL CHECK (version > 0),
    status                  TEXT        NOT NULL
                                        CHECK (status IN (
                                            'provisioning',
                                            'pending_signature',
                                            'active',
                                            'retiring',
                                            'retired',
                                            'revoked',
                                            'expired',
                                            'failed'
                                        )),
    -- This flag means "may issue leaf credentials". Platform intermediates may
    -- sign tenant-CA CSRs through a separate privileged operation, but are not
    -- leaf issuers and therefore never set this flag.
    issuance_enabled        BOOLEAN     NOT NULL DEFAULT false,

    subject                 TEXT        NOT NULL,
    serial_number           TEXT        NOT NULL
                                        CHECK (serial_number ~ '^[0-9a-f]+$'),
    fingerprint_sha256      TEXT        NOT NULL UNIQUE
                                        CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    subject_key_id          TEXT,
    authority_key_id        TEXT,
    certificate_pem         TEXT        NOT NULL,
    chain_pem               TEXT        NOT NULL,
    not_before              TIMESTAMPTZ NOT NULL,
    not_after               TIMESTAMPTZ NOT NULL,

    -- No OpenBao dependency. A CA key is either public-only (offline root),
    -- envelope-encrypted in Atom's database, or referenced through a signer
    -- backend. The key material and key reference forms are mutually exclusive.
    key_backend             TEXT        NOT NULL
                                        CHECK (key_backend IN (
                                            'public_only',
                                            'encrypted_database',
                                            'file',
                                            'pkcs11',
                                            'kms'
                                        )),
    key_reference           TEXT,
    encrypted_private_key   BYTEA,
    private_key_nonce       BYTEA,
    wrapped_dek             BYTEA,
    wrapped_dek_nonce       BYTEA,
    key_encryption_key_id   TEXT,
    encryption_algorithm    TEXT,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at            TIMESTAMPTZ,
    retiring_at             TIMESTAMPTZ,
    retired_at              TIMESTAMPTZ,

    CONSTRAINT chk_pki_authorities_nonzero_id
        CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT chk_pki_authorities_not_self_parent
        CHECK (parent_id IS NULL OR parent_id <> id),
    CONSTRAINT chk_pki_authorities_validity
        CHECK (not_after > not_before),
    CONSTRAINT chk_pki_authorities_scope
        CHECK (
            (kind = 'root' AND tenant_id IS NULL AND parent_id IS NULL)
            OR
            (kind = 'platform_intermediate' AND tenant_id IS NULL AND parent_id IS NOT NULL)
            OR
            (kind = 'tenant_intermediate' AND tenant_id IS NOT NULL AND parent_id IS NOT NULL)
        ),
    CONSTRAINT chk_pki_authorities_leaf_issuance
        CHECK (
            NOT issuance_enabled
            OR (
                kind = 'tenant_intermediate'
                AND status = 'active'
                AND key_backend <> 'public_only'
            )
        ),
    CONSTRAINT chk_pki_authorities_key_storage
        CHECK (
            (
                key_backend = 'public_only'
                AND key_reference IS NULL
                AND encrypted_private_key IS NULL
                AND private_key_nonce IS NULL
                AND wrapped_dek IS NULL
                AND wrapped_dek_nonce IS NULL
                AND key_encryption_key_id IS NULL
                AND encryption_algorithm IS NULL
            )
            OR
            (
                key_backend = 'encrypted_database'
                AND key_reference IS NULL
                AND encrypted_private_key IS NOT NULL
                AND private_key_nonce IS NOT NULL
                AND wrapped_dek IS NOT NULL
                AND wrapped_dek_nonce IS NOT NULL
                AND key_encryption_key_id IS NOT NULL
                AND encryption_algorithm IS NOT NULL
            )
            OR
            (
                key_backend IN ('file', 'pkcs11', 'kms')
                AND NULLIF(btrim(key_reference), '') IS NOT NULL
                AND encrypted_private_key IS NULL
                AND private_key_nonce IS NULL
                AND wrapped_dek IS NULL
                AND wrapped_dek_nonce IS NULL
                AND key_encryption_key_id IS NULL
                AND encryption_algorithm IS NULL
            )
        )
);

CREATE INDEX idx_pki_authorities_tenant ON pki_authorities(tenant_id);
CREATE INDEX idx_pki_authorities_parent ON pki_authorities(parent_id);
CREATE INDEX idx_pki_authorities_status ON pki_authorities(status);
CREATE INDEX idx_pki_authorities_expiry ON pki_authorities(not_after);

CREATE UNIQUE INDEX idx_pki_authorities_global_kind_version
    ON pki_authorities(kind, version)
    WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX idx_pki_authorities_tenant_kind_version
    ON pki_authorities(tenant_id, kind, version)
    WHERE tenant_id IS NOT NULL;

-- Exactly one tenant intermediate can receive new leaf issuance at a time.
-- Older versions remain addressable in retiring/retired state so their chains,
-- CRLs, OCSP responses, and historical credentials remain verifiable.
CREATE UNIQUE INDEX idx_pki_authorities_one_leaf_issuer_per_tenant
    ON pki_authorities(tenant_id)
    WHERE kind = 'tenant_intermediate' AND issuance_enabled = true;

ALTER TABLE credentials
    ADD COLUMN issuer_id UUID REFERENCES pki_authorities(id) ON DELETE RESTRICT;

ALTER TABLE credentials
    ADD CONSTRAINT chk_credentials_issuer_certificate_only
    CHECK (issuer_id IS NULL OR kind = 'certificate');

DROP INDEX IF EXISTS idx_credentials_certificate_serial;

-- NULL issuer_id is the legacy v1 file issuer. Coalescing it to a reserved UUID
-- preserves the existing global uniqueness rule while allowing the same serial
-- number to occur under two independent tenant issuers.
CREATE UNIQUE INDEX idx_credentials_certificate_issuer_serial
    ON credentials(
        COALESCE(issuer_id, '00000000-0000-0000-0000-000000000000'::uuid),
        identifier
    )
    WHERE kind = 'certificate' AND identifier IS NOT NULL;

CREATE INDEX idx_credentials_certificate_issuer
    ON credentials(issuer_id, status, expires_at)
    WHERE kind = 'certificate';

-- Fingerprint is the unambiguous runtime identity across issuers. Existing rows
-- without certificate metadata are intentionally excluded from this index.
CREATE UNIQUE INDEX idx_credentials_certificate_fingerprint
    ON credentials((metadata->>'fingerprint_sha256'))
    WHERE kind = 'certificate'
      AND NULLIF(metadata->>'fingerprint_sha256', '') IS NOT NULL;

-- v1 CRL state remains keyed by issuer fingerprint. issuer_id is nullable for
-- the legacy file issuer and will be populated by tenant-aware CRL generation.
ALTER TABLE certificate_crl_state
    ADD COLUMN issuer_id UUID REFERENCES pki_authorities(id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX idx_certificate_crl_state_issuer
    ON certificate_crl_state(issuer_id)
    WHERE issuer_id IS NOT NULL;
