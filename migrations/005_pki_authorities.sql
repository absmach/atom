-- Atom-native multi-tenant PKI authority registry.
--
-- Existing v1 file-issued certificates keep issuer_id = NULL and retain global
-- serial uniqueness until resolver v2 migrates every live serial-only reader.

CREATE TABLE pki_authorities (
    id                      UUID        PRIMARY KEY,
    tenant_id               UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    parent_id               UUID        REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    kind                    TEXT        NOT NULL
                                        CHECK (kind IN (
                                            'root',
                                            'platform_intermediate',
                                            'platform_leaf_issuer',
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

    -- The legacy v1 file issuer remains outside this registry as issuer_id=NULL.
    key_backend             TEXT        NOT NULL
                                        CHECK (key_backend IN (
                                            'public_only',
                                            'encrypted_database',
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
            (kind IN ('platform_intermediate', 'platform_leaf_issuer')
                AND tenant_id IS NULL AND parent_id IS NOT NULL)
            OR
            (kind = 'tenant_intermediate'
                AND tenant_id IS NOT NULL AND parent_id IS NOT NULL)
        ),
    CONSTRAINT chk_pki_authorities_leaf_issuance
        CHECK (
            NOT issuance_enabled
            OR (
                kind IN ('platform_leaf_issuer', 'tenant_intermediate')
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
                key_backend IN ('pkcs11', 'kms')
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

CREATE UNIQUE INDEX idx_pki_authorities_one_leaf_issuer_per_tenant
    ON pki_authorities(tenant_id)
    WHERE kind = 'tenant_intermediate' AND issuance_enabled = true;

CREATE UNIQUE INDEX idx_pki_authorities_one_platform_leaf_issuer
    ON pki_authorities((true))
    WHERE kind = 'platform_leaf_issuer' AND issuance_enabled = true;

-- Validate the parent kind and the child's validity window. Root may parent any
-- managed CA; platform intermediate may parent tenant intermediates only.
CREATE OR REPLACE FUNCTION enforce_pki_authority_parent() RETURNS trigger AS $$
DECLARE
    parent_kind       TEXT;
    parent_not_before TIMESTAMPTZ;
    parent_not_after  TIMESTAMPTZ;
BEGIN
    IF NEW.kind = 'root' THEN
        RETURN NEW;
    END IF;

    SELECT kind, not_before, not_after
      INTO parent_kind, parent_not_before, parent_not_after
      FROM pki_authorities
     WHERE id = NEW.parent_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF parent_kind <> 'root'
       AND NOT (parent_kind = 'platform_intermediate'
                AND NEW.kind = 'tenant_intermediate') THEN
        RAISE EXCEPTION 'invalid PKI authority parent kind'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.not_before < parent_not_before OR NEW.not_after > parent_not_after THEN
        RAISE EXCEPTION 'child authority validity must fit inside parent validity'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_pki_authorities_parent
    BEFORE INSERT OR UPDATE OF parent_id, kind, not_before, not_after
    ON pki_authorities
    FOR EACH ROW EXECUTE FUNCTION enforce_pki_authority_parent();

ALTER TABLE credentials
    ADD COLUMN issuer_id UUID REFERENCES pki_authorities(id) ON DELETE RESTRICT;

ALTER TABLE credentials
    ADD CONSTRAINT chk_credentials_issuer_certificate_only
    CHECK (issuer_id IS NULL OR kind = 'certificate');

-- Keep the v1 global serial unique index. PR-011 replaces it only after every
-- serial-only reader is issuer/fingerprint aware.
CREATE INDEX idx_credentials_certificate_issuer_serial_lookup
    ON credentials(issuer_id, identifier)
    WHERE kind = 'certificate' AND identifier IS NOT NULL;

CREATE INDEX idx_credentials_certificate_issuer
    ON credentials(issuer_id, status, expires_at)
    WHERE kind = 'certificate';

CREATE UNIQUE INDEX idx_credentials_certificate_fingerprint
    ON credentials((metadata->>'fingerprint_sha256'))
    WHERE kind = 'certificate'
      AND NULLIF(metadata->>'fingerprint_sha256', '') IS NOT NULL;

-- Tenant entities use their tenant intermediate. Global entities use the
-- platform leaf issuer. Imports and operator SQL cannot bypass this invariant.
CREATE OR REPLACE FUNCTION enforce_certificate_issuer_scope() RETURNS trigger AS $$
DECLARE
    entity_tenant_id    UUID;
    authority_tenant_id UUID;
    authority_kind      TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.issuer_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.entity_id IS NULL THEN
        RAISE EXCEPTION 'issuer-bound certificate requires an entity'
            USING ERRCODE = '23514';
    END IF;

    SELECT e.tenant_id, a.tenant_id, a.kind
      INTO entity_tenant_id, authority_tenant_id, authority_kind
      FROM entities e
      JOIN pki_authorities a ON a.id = NEW.issuer_id
     WHERE e.id = NEW.entity_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF entity_tenant_id IS NULL THEN
        IF authority_kind <> 'platform_leaf_issuer' OR authority_tenant_id IS NOT NULL THEN
            RAISE EXCEPTION 'global certificate requires platform leaf issuer'
                USING ERRCODE = '23514';
        END IF;
    ELSIF authority_kind <> 'tenant_intermediate'
          OR authority_tenant_id IS DISTINCT FROM entity_tenant_id THEN
        RAISE EXCEPTION 'tenant certificate requires its own tenant intermediate'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_credentials_certificate_issuer_scope
    BEFORE INSERT OR UPDATE OF entity_id, kind, issuer_id ON credentials
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_issuer_scope();

-- Moving an entity between tenant scopes would invalidate its issuer binding.
CREATE OR REPLACE FUNCTION prevent_issuer_bound_entity_tenant_change() RETURNS trigger AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       AND EXISTS (
           SELECT 1
             FROM credentials
            WHERE entity_id = OLD.id
              AND kind = 'certificate'
              AND issuer_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'entity tenant cannot change while issuer-bound certificates exist'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_entities_prevent_issuer_bound_tenant_change
    BEFORE UPDATE OF tenant_id ON entities
    FOR EACH ROW EXECUTE FUNCTION prevent_issuer_bound_entity_tenant_change();

-- CRL cache is regenerable, unlike certificate credentials.
ALTER TABLE certificate_crl_state
    ADD COLUMN issuer_id UUID REFERENCES pki_authorities(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX idx_certificate_crl_state_issuer
    ON certificate_crl_state(issuer_id)
    WHERE issuer_id IS NOT NULL;
