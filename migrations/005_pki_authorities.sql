-- Atom-native multi-tenant PKI authority registry.
--
-- This migration is deliberately backward-compatible with the v1 file issuer:
-- existing certificate credentials keep issuer_id = NULL and retain the legacy
-- global serial-number uniqueness rule. Issuer-scoped duplicate serials are not
-- enabled until every live serial-only reader is migrated to issuer/fingerprint
-- identity in the resolver-v2 delivery PR.

CREATE TABLE pki_authorities (
    id                      UUID        PRIMARY KEY,
    -- A hard tenant purge removes its tenant-scoped authorities. Soft delete
    -- keeps them intact, so chains and revocation artifacts remain available
    -- throughout the configured retention period.
    tenant_id               UUID        REFERENCES tenants(id) ON DELETE CASCADE,
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
    ADD COLUMN issuer_id UUID REFERENCES pki_authorities(id) ON DELETE CASCADE;

ALTER TABLE credentials
    ADD CONSTRAINT chk_credentials_issuer_certificate_only
    CHECK (issuer_id IS NULL OR kind = 'certificate');

-- Keep idx_credentials_certificate_serial from migration 001. The current
-- GraphQL, renewal, revocation, OCSP, and gRPC paths still resolve by serial
-- alone. Allowing duplicate serials across issuers before those readers become
-- issuer-aware could select the wrong credential. This lookup index prepares the
-- next phase without weakening the live runtime contract.
CREATE INDEX idx_credentials_certificate_issuer_serial_lookup
    ON credentials(issuer_id, identifier)
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

-- A non-legacy certificate can only reference a tenant intermediate belonging
-- to the credential entity's own tenant. The trigger repeats the service-layer
-- invariant so imports, migrations, fixtures, and operator SQL cannot create a
-- cross-tenant or root/platform-issued leaf mapping.
CREATE OR REPLACE FUNCTION enforce_certificate_issuer_tenant() RETURNS trigger AS $$
DECLARE
    entity_tenant_id    UUID;
    authority_tenant_id UUID;
    authority_kind      TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.issuer_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT e.tenant_id, a.tenant_id, a.kind
      INTO entity_tenant_id, authority_tenant_id, authority_kind
      FROM entities e
      JOIN pki_authorities a ON a.id = NEW.issuer_id
     WHERE e.id = NEW.entity_id;

    -- Let the existing entity/authority foreign keys produce their normal error
    -- when either referenced row does not exist.
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF entity_tenant_id IS NULL
       OR authority_kind <> 'tenant_intermediate'
       OR authority_tenant_id IS DISTINCT FROM entity_tenant_id THEN
        RAISE EXCEPTION
            'certificate issuer must be a tenant intermediate for the credential entity tenant'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_credentials_certificate_issuer_tenant
    BEFORE INSERT OR UPDATE OF entity_id, kind, issuer_id ON credentials
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_issuer_tenant();

-- v1 CRL state remains keyed by issuer fingerprint. issuer_id is nullable for
-- the legacy file issuer and will be populated by tenant-aware CRL generation.
-- Hard-purging an authority removes its cached public artifact as well.
ALTER TABLE certificate_crl_state
    ADD COLUMN issuer_id UUID REFERENCES pki_authorities(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX idx_certificate_crl_state_issuer
    ON certificate_crl_state(issuer_id)
    WHERE issuer_id IS NOT NULL;
