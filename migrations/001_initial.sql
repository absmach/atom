-- Atom initial schema.
--
-- This migration is intentionally squashed because Atom has not shipped a
-- released database contract yet. It creates the current schema directly and
-- seeds the platform data Atom requires to boot (admin identity, action
-- vocabulary, applicability, and assignment guardrails).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================
-- CORE CATALOG
-- =============================================================

CREATE TABLE tenants (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    alias       TEXT,
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'inactive', 'frozen', 'deleted')),
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_by  UUID,
    updated_by  UUID,
    deleted_by  UUID,
    deleted_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ,
    CONSTRAINT chk_tenants_alias_slug
        CHECK (alias IS NULL OR alias ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT chk_tenants_alias_not_uuid
        CHECK (
            alias IS NULL OR alias !~ (
                '^([0-9a-f]{32}|'
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
            )
        )
);

CREATE UNIQUE INDEX idx_tenants_name ON tenants(name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_tenants_alias
    ON tenants (lower(alias))
    WHERE alias IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_tenants_deleted_at ON tenants(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_tenants_attrs ON tenants USING GIN(attributes);
CREATE INDEX idx_tenants_tags ON tenants USING GIN(tags);

CREATE TABLE profiles (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID,
    object_kind  TEXT        NOT NULL CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'credential')),
    kind         TEXT        NOT NULL,
    key          TEXT        NOT NULL,
    display_name TEXT        NOT NULL,
    description  TEXT,
    status       TEXT        NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'deprecated', 'disabled')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ,
    CHECK (
        object_kind <> 'entity'
        OR kind IN ('human', 'device', 'service', 'workload', 'application')
    )
);

CREATE UNIQUE INDEX idx_profiles_global_unique
    ON profiles(object_kind, kind, key)
    WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX idx_profiles_tenant_unique
    ON profiles(tenant_id, object_kind, kind, key)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX idx_profiles_lookup
    ON profiles(object_kind, kind, key, tenant_id);

CREATE TABLE profile_versions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id  UUID        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    version     INTEGER     NOT NULL,
    json_schema JSONB       NOT NULL DEFAULT '{}',
    ui_schema   JSONB       NOT NULL DEFAULT '{}',
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('draft', 'active', 'deprecated', 'disabled')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(profile_id, version)
);

CREATE INDEX idx_profile_versions_profile ON profile_versions(profile_id);

CREATE TABLE entities (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind               TEXT        NOT NULL CHECK (kind IN ('human', 'device', 'service', 'workload', 'application')),
    name               TEXT        NOT NULL,
    tenant_id          UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    status             TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes         JSONB       NOT NULL DEFAULT '{}',
    profile_id         UUID        REFERENCES profiles(id),
    profile_version_id UUID        REFERENCES profile_versions(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ,
    deleted_at         TIMESTAMPTZ,
    deleted_by         UUID        REFERENCES entities(id) ON DELETE SET NULL,
    alias              TEXT,
    CONSTRAINT chk_entities_alias_slug
        CHECK (alias IS NULL OR alias ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT chk_entities_alias_not_uuid
        CHECK (
            alias IS NULL OR alias !~ (
                '^([0-9a-f]{32}|'
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
            )
        )
);

CREATE INDEX idx_entities_kind ON entities(kind);
CREATE INDEX idx_entities_tenant ON entities(tenant_id);
CREATE INDEX idx_entities_name ON entities(name);
CREATE INDEX idx_entities_attrs ON entities USING GIN(attributes);
CREATE INDEX idx_entities_profile ON entities(profile_id);
CREATE INDEX idx_entities_profile_version ON entities(profile_version_id);
CREATE UNIQUE INDEX idx_entities_name_tenant
    ON entities (
        name,
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_entities_alias
    ON entities (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(alias))
    WHERE alias IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_entities_deleted_at ON entities(deleted_at) WHERE deleted_at IS NOT NULL;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES entities(id) ON DELETE SET NULL;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_updated_by_fkey
    FOREIGN KEY (updated_by) REFERENCES entities(id) ON DELETE SET NULL;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_deleted_by_fkey
    FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL;

CREATE TABLE credentials (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind        TEXT        NOT NULL CHECK (kind IN ('password', 'access_token', 'certificate', 'shared_key')),
    identifier  TEXT,
    secret_hash TEXT,
    -- Access tokens with scoped = true carry a permission ceiling
    -- (credential_permission_limits) and fail closed if it is absent. scoped is
    -- independent of whether limit rows exist, so a deleted ceiling denies rather
    -- than silently granting full owner authority.
    scoped      BOOLEAN     NOT NULL DEFAULT false,
    -- Recoverable secrets (e.g. shared keys) are envelope-encrypted at rest; the
    -- plaintext is never stored. secret_hash remains the auth verifier, these
    -- columns are the reveal source. See src/crypto.rs and identity::service.
    secret_ciphertext BYTEA,
    secret_nonce      BYTEA,
    secret_key_id     TEXT,
    secret_enc_alg    TEXT,
    -- HMAC-SHA256 lookup digest for indexed shared-key authentication. The
    -- digest is keyed with ATOM_KEY_ENCRYPTION_KEY, so a DB-only leak does not
    -- enable cheap enumeration of arbitrary operator-supplied keys.
    secret_lookup_hash BYTEA,
    metadata    JSONB       NOT NULL DEFAULT '{}',
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_creds_entity ON credentials(entity_id);
CREATE INDEX idx_creds_kind ON credentials(kind);
CREATE INDEX idx_creds_identifier ON credentials(identifier);
CREATE UNIQUE INDEX idx_credentials_certificate_serial
    ON credentials(identifier)
    WHERE kind = 'certificate' AND identifier IS NOT NULL;
CREATE INDEX idx_credentials_certificate_status_expiry
    ON credentials(kind, status, expires_at)
    WHERE kind = 'certificate';
CREATE INDEX idx_credentials_shared_key_status
    ON credentials(entity_id, status, expires_at)
    WHERE kind = 'shared_key';
CREATE INDEX idx_credentials_shared_key_lookup
    ON credentials(entity_id, secret_lookup_hash, expires_at)
    WHERE kind = 'shared_key'
      AND status = 'active'
      AND secret_lookup_hash IS NOT NULL;

-- Shared keys are retrievable machine secrets: allowed for any machine entity,
-- forbidden for humans. The stable invariant enforced here is "shared_key =>
-- entity is non-human", which holds as new machine kinds are added.
CREATE OR REPLACE FUNCTION enforce_shared_key_non_human_credential() RETURNS trigger AS $$
DECLARE
    entity_kind TEXT;
BEGIN
    IF NEW.kind <> 'shared_key' THEN
        RETURN NEW;
    END IF;

    SELECT e.kind
      INTO entity_kind
      FROM entities e
     WHERE e.id = NEW.entity_id
     FOR UPDATE;

    IF entity_kind = 'human' THEN
        RAISE EXCEPTION 'shared_key credentials cannot belong to human entities'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_credentials_shared_key_non_human_only
    BEFORE INSERT OR UPDATE OF entity_id, kind ON credentials
    FOR EACH ROW EXECUTE FUNCTION enforce_shared_key_non_human_credential();

CREATE OR REPLACE FUNCTION prevent_human_entity_with_shared_key() RETURNS trigger AS $$
BEGIN
    IF NEW.kind = 'human'
       AND EXISTS (
           SELECT 1
             FROM credentials c
            WHERE c.entity_id = NEW.id
              AND c.kind = 'shared_key'
       ) THEN
        RAISE EXCEPTION 'entities with shared_key credentials cannot become human entities'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_entities_shared_key_non_human_only
    BEFORE UPDATE OF kind ON entities
    FOR EACH ROW
    WHEN (OLD.kind IS DISTINCT FROM NEW.kind)
    EXECUTE FUNCTION prevent_human_entity_with_shared_key();

CREATE TABLE certificate_crl_state (
    issuer_fingerprint_sha256 TEXT PRIMARY KEY,
    crl_number BIGINT NOT NULL DEFAULT 0,
    crl_der BYTEA,
    this_update TIMESTAMPTZ,
    next_update TIMESTAMPTZ,
    dirty BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_entity ON sessions(entity_id);
CREATE INDEX idx_sessions_active ON sessions(id) WHERE revoked_at IS NULL;

CREATE TABLE entity_emails (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE (entity_id)
);

-- Partial unique index so an email frees on soft delete (re-registration / OAuth
-- re-onboarding with the same address). Mirrors the name/alias partial indexes.
CREATE UNIQUE INDEX idx_entity_emails_email ON entity_emails(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_entity_emails_entity ON entity_emails(entity_id);
CREATE INDEX idx_entity_emails_verified ON entity_emails(verified_at);

CREATE TABLE email_verification_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    email_id    UUID        NOT NULL REFERENCES entity_emails(id) ON DELETE CASCADE,
    secret_hash TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_email_verification_tokens_entity ON email_verification_tokens(entity_id);
CREATE INDEX idx_email_verification_tokens_active
    ON email_verification_tokens(id)
    WHERE consumed_at IS NULL;

CREATE TABLE password_reset_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    email_id    UUID        NOT NULL REFERENCES entity_emails(id) ON DELETE CASCADE,
    secret_hash TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_reset_tokens_entity
    ON password_reset_tokens(entity_id, created_at DESC);

CREATE TABLE oauth_identities (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id      UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    provider       TEXT        NOT NULL,
    subject        TEXT        NOT NULL,
    email          TEXT        NOT NULL,
    email_verified BOOLEAN     NOT NULL DEFAULT false,
    profile        JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);

CREATE INDEX idx_oauth_identities_entity ON oauth_identities(entity_id);
CREATE INDEX idx_oauth_identities_email ON oauth_identities(email);

CREATE TABLE oauth_login_states (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider      TEXT        NOT NULL,
    state_hash    TEXT        NOT NULL,
    pkce_verifier TEXT        NOT NULL,
    nonce         TEXT        NOT NULL,
    return_to     TEXT,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_login_states_active
    ON oauth_login_states(id)
    WHERE consumed_at IS NULL;

CREATE TABLE auth_exchange_codes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    secret_hash TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_exchange_codes_active
    ON auth_exchange_codes(id)
    WHERE consumed_at IS NULL;

CREATE TABLE auth_login_attempts (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier  TEXT        NOT NULL,
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    success     BOOLEAN     NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_login_attempts_throttle
    ON auth_login_attempts(identifier, tenant_id, created_at DESC)
    WHERE success = FALSE;

CREATE INDEX idx_auth_login_attempts_created
    ON auth_login_attempts(created_at DESC);

CREATE TABLE signing_keys (
    kid                        TEXT        PRIMARY KEY,
    algorithm                  TEXT        NOT NULL DEFAULT 'ES256',
    public_key                 TEXT        NOT NULL,
    private_key                TEXT,
    status                     TEXT        NOT NULL DEFAULT 'primary'
                                           CHECK (status IN ('primary', 'standby', 'retired')),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    private_key_ciphertext     BYTEA,
    private_key_nonce          BYTEA,
    private_key_key_id         TEXT,
    private_key_encryption_alg TEXT
);

CREATE INDEX idx_signing_keys_status ON signing_keys(status);

CREATE TABLE principal_groups (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    description TEXT,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes  JSONB       NOT NULL DEFAULT '{}',
    deleted_at  TIMESTAMPTZ,
    deleted_by  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ
);

CREATE INDEX idx_principal_groups_tenant ON principal_groups(tenant_id);
CREATE INDEX idx_principal_groups_status ON principal_groups(status);
CREATE INDEX idx_principal_groups_attrs ON principal_groups USING GIN(attributes);
CREATE UNIQUE INDEX idx_principal_groups_name_tenant ON principal_groups(name, tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_principal_groups_deleted_at ON principal_groups(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE principal_group_members (
    group_id    UUID        NOT NULL REFERENCES principal_groups(id) ON DELETE CASCADE,
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, entity_id)
);

CREATE INDEX idx_principal_group_members_entity ON principal_group_members(entity_id);

CREATE TABLE principal_group_hierarchy (
    parent_id  UUID        NOT NULL REFERENCES principal_groups(id) ON DELETE CASCADE,
    child_id   UUID        NOT NULL REFERENCES principal_groups(id) ON DELETE CASCADE,
    tenant_id  UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (child_id),
    CHECK (parent_id <> child_id)
);

CREATE INDEX idx_principal_group_hierarchy_parent ON principal_group_hierarchy(parent_id);
CREATE INDEX idx_principal_group_hierarchy_tenant ON principal_group_hierarchy(tenant_id);

CREATE TABLE object_groups (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    description TEXT,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes  JSONB       NOT NULL DEFAULT '{}',
    deleted_at  TIMESTAMPTZ,
    deleted_by  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_object_groups_tenant ON object_groups(tenant_id);
CREATE INDEX idx_object_groups_status ON object_groups(status);
CREATE INDEX idx_object_groups_attrs ON object_groups USING GIN(attributes);
CREATE UNIQUE INDEX idx_object_groups_name_tenant ON object_groups(name, tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_object_groups_deleted_at ON object_groups(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE object_group_hierarchy (
    parent_id  UUID        NOT NULL REFERENCES object_groups(id) ON DELETE CASCADE,
    child_id   UUID        NOT NULL REFERENCES object_groups(id) ON DELETE CASCADE,
    tenant_id  UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (child_id),
    CHECK (parent_id <> child_id)
);

CREATE INDEX idx_object_group_hierarchy_parent ON object_group_hierarchy(parent_id);
CREATE INDEX idx_object_group_hierarchy_tenant ON object_group_hierarchy(tenant_id);

-- Compatibility read views for code paths that still use the generic "group"
-- shape. Physical storage is split into Principal Groups and Object Groups.
CREATE VIEW groups AS
SELECT id, name, tenant_id, 'object'::text AS group_type, description, status, attributes, deleted_at, deleted_by, created_at, updated_at
FROM object_groups
UNION ALL
SELECT id, name, tenant_id, 'principal'::text AS group_type, description, status, attributes, deleted_at, deleted_by, created_at, updated_at
FROM principal_groups;

CREATE VIEW group_members AS
SELECT group_id, entity_id, created_at
FROM principal_group_members;

CREATE VIEW group_hierarchy AS
SELECT parent_id, child_id, tenant_id, created_at, updated_at
FROM principal_group_hierarchy
UNION ALL
SELECT parent_id, child_id, tenant_id, created_at, updated_at
FROM object_group_hierarchy;

CREATE TABLE tenant_memberships (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'invited', 'suspended', 'left')),
    local_name  TEXT,
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity_id)
);

CREATE INDEX idx_tenant_memberships_entity ON tenant_memberships(entity_id);
CREATE INDEX idx_tenant_memberships_status ON tenant_memberships(status);

CREATE TABLE resources (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        TEXT        NOT NULL,
    name        TEXT,
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    owner_id    UUID        REFERENCES entities(id) ON DELETE SET NULL,
    attributes  JSONB       NOT NULL DEFAULT '{}',
    deleted_at  TIMESTAMPTZ,
    deleted_by  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ,
    alias       TEXT,
    CONSTRAINT chk_resources_alias_slug
        CHECK (alias IS NULL OR alias ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT chk_resources_alias_not_uuid
        CHECK (
            alias IS NULL OR alias !~ (
                '^([0-9a-f]{32}|'
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
            )
        )
);

CREATE INDEX idx_resources_kind ON resources(kind);
CREATE INDEX idx_resources_tenant ON resources(tenant_id);
CREATE INDEX idx_resources_owner ON resources(owner_id);
CREATE INDEX idx_resources_attrs ON resources USING GIN(attributes);
CREATE UNIQUE INDEX idx_resources_alias
    ON resources (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(alias))
    WHERE alias IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_resources_deleted_at ON resources(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE object_group_entities (
    group_id    UUID        NOT NULL REFERENCES object_groups(id) ON DELETE CASCADE,
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_id)
);

CREATE INDEX idx_object_group_entities_group ON object_group_entities(group_id);
CREATE INDEX idx_object_group_entities_tenant ON object_group_entities(tenant_id);

CREATE TABLE object_group_resources (
    group_id     UUID        NOT NULL REFERENCES object_groups(id) ON DELETE CASCADE,
    resource_id  UUID        NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_id)
);

CREATE INDEX idx_object_group_resources_group ON object_group_resources(group_id);
CREATE INDEX idx_object_group_resources_tenant ON object_group_resources(tenant_id);

CREATE VIEW group_entity_parents AS
SELECT group_id, entity_id, tenant_id, created_at, updated_at
FROM object_group_entities;

CREATE VIEW group_resource_parents AS
SELECT group_id, resource_id, tenant_id, created_at, updated_at
FROM object_group_resources;

CREATE TABLE ownerships (
    owner_id    UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    owned_id    UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation    TEXT        NOT NULL DEFAULT 'owner',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, owned_id)
);

CREATE INDEX idx_ownerships_owner ON ownerships(owner_id);
CREATE INDEX idx_ownerships_owned ON ownerships(owned_id);

CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    description TEXT,
    deleted_at  TIMESTAMPTZ,
    deleted_by  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_roles_name_tenant
    ON roles(name, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_deleted_at ON roles(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE actions (
    id              UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT    NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE TABLE action_applicability (
    action_id   UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    object_kind   TEXT NOT NULL CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy', 'credential', 'audit_log', 'signing_key')),
    object_type   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_action_applicability_unique
    ON action_applicability(action_id, object_kind, COALESCE(object_type, ''));
CREATE INDEX idx_action_applicability_object ON action_applicability(object_kind, object_type);

CREATE TABLE permission_blocks (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    scope_mode  TEXT        NOT NULL CHECK (scope_mode IN ('platform', 'tenant', 'object_kind', 'object_type', 'object', 'group', 'group_direct_objects', 'group_descendant_objects', 'group_child_groups', 'group_descendant_groups')),
    object_kind TEXT,
    object_type TEXT,
    object_id   UUID,
    group_id    UUID        REFERENCES object_groups(id) ON DELETE CASCADE,
    effect      TEXT        NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    conditions  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT permission_blocks_conditions_is_object
        CHECK (jsonb_typeof(conditions) = 'object'),
    CHECK (
        (scope_mode = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'tenant' AND tenant_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object_kind' AND tenant_id IS NOT NULL AND object_kind IS NOT NULL AND object_id IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object_type' AND tenant_id IS NOT NULL AND object_kind IS NOT NULL AND object_type IS NOT NULL AND object_id IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object' AND object_id IS NOT NULL AND group_id IS NULL)
        OR (scope_mode = 'group' AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode IN ('group_direct_objects', 'group_descendant_objects') AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_kind IN ('entity', 'resource') AND object_id IS NULL)
        OR (scope_mode IN ('group_child_groups', 'group_descendant_groups') AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
    )
);

CREATE INDEX idx_permission_blocks_tenant ON permission_blocks(tenant_id);
CREATE INDEX idx_permission_blocks_scope ON permission_blocks(scope_mode, object_kind, object_type);
CREATE INDEX idx_permission_blocks_object ON permission_blocks(object_id);
CREATE INDEX idx_permission_blocks_group ON permission_blocks(group_id);

CREATE TABLE permission_block_actions (
    permission_block_id UUID NOT NULL REFERENCES permission_blocks(id) ON DELETE CASCADE,
    action_id           UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_block_id, action_id)
);

CREATE INDEX idx_permission_block_actions_action ON permission_block_actions(action_id);

CREATE TABLE role_permission_blocks (
    id                  UUID GENERATED ALWAYS AS (permission_block_id) STORED,
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_block_id UUID NOT NULL REFERENCES permission_blocks(id) ON DELETE CASCADE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_block_id)
);

CREATE INDEX idx_role_permission_blocks_block ON role_permission_blocks(permission_block_id);

CREATE TABLE role_assignments (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    subject_kind TEXT        NOT NULL CHECK (subject_kind IN ('entity', 'group')),
    subject_id   UUID        NOT NULL,
    role_id      UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_role_assignments_tenant ON role_assignments(tenant_id);
CREATE INDEX idx_role_assignments_subject ON role_assignments(subject_kind, subject_id);
CREATE INDEX idx_role_assignments_role ON role_assignments(role_id);

CREATE TABLE direct_policies (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    subject_kind        TEXT        NOT NULL CHECK (subject_kind IN ('entity', 'group')),
    subject_id          UUID        NOT NULL,
    permission_block_id UUID        NOT NULL REFERENCES permission_blocks(id) ON DELETE CASCADE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_direct_policies_tenant ON direct_policies(tenant_id);
CREATE INDEX idx_direct_policies_subject ON direct_policies(subject_kind, subject_id);
CREATE INDEX idx_direct_policies_block ON direct_policies(permission_block_id);

-- Internal canonical access-edge helpers used by the PDP and authorization
-- listing queries. They are not public compatibility API.
CREATE FUNCTION effective_role_actions()
RETURNS TABLE(role_id UUID, capability_id UUID)
LANGUAGE sql
STABLE
AS $$
SELECT rpb.role_id, pba.action_id AS capability_id
FROM role_permission_blocks rpb
JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id;
$$;

CREATE FUNCTION effective_access_edges()
RETURNS TABLE(
    id UUID,
    tenant_id UUID,
    subject_kind TEXT,
    subject_id UUID,
    grant_kind TEXT,
    grant_id UUID,
    scope_kind TEXT,
    scope_ref TEXT,
    effect TEXT,
    conditions JSONB,
    created_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
AS $$
SELECT
    dp.id,
    dp.tenant_id,
    dp.subject_kind,
    dp.subject_id,
    'capability'::text AS grant_kind,
    pba.action_id AS grant_id,
    CASE
        WHEN pb.scope_mode = 'group_direct_objects' THEN 'group_object_type'
        WHEN pb.scope_mode = 'group_descendant_objects' THEN 'group_tree_object_type'
        WHEN pb.scope_mode = 'group_child_groups' THEN 'group_child_kind'
        WHEN pb.scope_mode = 'group_descendant_groups' THEN 'group_descendant_kind'
        ELSE pb.scope_mode
    END AS scope_kind,
    CASE
        WHEN pb.scope_mode = 'platform' THEN NULL
        WHEN pb.scope_mode = 'tenant' THEN pb.tenant_id::text
        WHEN pb.scope_mode = 'object_kind' THEN pb.object_kind
        WHEN pb.scope_mode = 'object_type' THEN pb.object_type
        WHEN pb.scope_mode = 'object' THEN pb.object_id::text
        WHEN pb.scope_mode = 'group' THEN pb.group_id::text || ':group'
        WHEN pb.scope_mode IN ('group_direct_objects', 'group_descendant_objects') THEN pb.group_id::text || ':' || pb.object_type
        WHEN pb.scope_mode IN ('group_child_groups', 'group_descendant_groups') THEN pb.group_id::text || ':group'
    END AS scope_ref,
    pb.effect,
    pb.conditions,
    dp.created_at
FROM direct_policies dp
JOIN permission_blocks pb ON pb.id = dp.permission_block_id
JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
UNION ALL
SELECT
    ra.id,
    ra.tenant_id,
    ra.subject_kind,
    ra.subject_id,
    'role'::text AS grant_kind,
    ra.role_id AS grant_id,
    CASE WHEN ra.tenant_id IS NULL THEN 'platform' ELSE 'tenant' END AS scope_kind,
    ra.tenant_id::text AS scope_ref,
    'allow'::text AS effect,
    '{}'::jsonb AS conditions,
    ra.created_at
FROM role_assignments ra
JOIN roles r ON r.id = ra.role_id AND r.deleted_at IS NULL;
$$;

-- ─── Canonical grant expansion ─────────────────────────────────────────────────
-- One source of truth for the runtime authorization path, shared by the PDP
-- (`engine::evaluate` via `repo::effective_grants_for_subject`) and every
-- authorized-listing reader. Keeps the scope mapping, the subject grant
-- expansion, and the scope predicate from drifting across readers.

-- Single scope mapping: a permission block's stored scope columns projected into
-- the canonical (scope_kind, scope_ref) pair the readers compare against.
CREATE VIEW permission_block_scopes AS
SELECT
    pb.id AS permission_block_id,
    CASE
        WHEN pb.scope_mode = 'group_direct_objects' THEN 'group_object_type'
        WHEN pb.scope_mode = 'group_descendant_objects' THEN 'group_tree_object_type'
        WHEN pb.scope_mode = 'group_child_groups' THEN 'group_child_kind'
        WHEN pb.scope_mode = 'group_descendant_groups' THEN 'group_descendant_kind'
        ELSE pb.scope_mode
    END AS scope_kind,
    CASE
        WHEN pb.scope_mode = 'platform' THEN NULL
        WHEN pb.scope_mode = 'tenant' THEN pb.tenant_id::text
        WHEN pb.scope_mode = 'object_kind' THEN pb.object_kind
        WHEN pb.scope_mode = 'object_type' THEN pb.object_type
        WHEN pb.scope_mode = 'object' THEN pb.object_id::text
        WHEN pb.scope_mode = 'group' THEN pb.group_id::text || ':group'
        WHEN pb.scope_mode IN ('group_direct_objects', 'group_descendant_objects') THEN pb.group_id::text || ':' || pb.object_type
        WHEN pb.scope_mode IN ('group_child_groups', 'group_descendant_groups') THEN pb.group_id::text || ':group'
    END AS scope_ref
FROM permission_blocks pb;

-- Permission ceiling for a scoped access token. Mirrors permission_blocks' scope
-- shape so the PDP/gate matchers can be reused unchanged. Effective access of a
-- scoped token = owner's live grants ∩ these allow-list limits (no deny in v1).
-- v1 supports the directly-matchable scope modes only; group-tree ceilings are a
-- future extension.
CREATE TABLE credential_permission_limits (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID        NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    scope_mode    TEXT        NOT NULL CHECK (scope_mode IN ('platform', 'tenant', 'object_kind', 'object_type', 'object')),
    tenant_id     UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    object_kind   TEXT,
    object_type   TEXT,
    object_id     UUID,
    conditions    JSONB       NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credential_permission_limits_conditions_is_object
        CHECK (jsonb_typeof(conditions) = 'object'),
    CHECK (
        (scope_mode = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode = 'tenant' AND tenant_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode = 'object_kind' AND object_kind IS NOT NULL AND object_id IS NULL AND object_type IS NULL)
        OR (scope_mode = 'object_type' AND object_kind IS NOT NULL AND object_type IS NOT NULL AND object_id IS NULL)
        OR (scope_mode = 'object' AND object_id IS NOT NULL)
    )
);
CREATE INDEX idx_credential_permission_limits_credential
    ON credential_permission_limits(credential_id);

CREATE TABLE credential_permission_limit_actions (
    limit_id  UUID NOT NULL REFERENCES credential_permission_limits(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    PRIMARY KEY (limit_id, action_id)
);
CREATE INDEX idx_credential_permission_limit_actions_action
    ON credential_permission_limit_actions(action_id);

-- Canonical (scope_kind, scope_ref) for a ceiling row, mirroring
-- permission_block_scopes so match_grant / scope_values_match treat a ceiling
-- entry exactly like a permission block.
CREATE VIEW credential_permission_limit_scopes AS
SELECT
    l.id AS limit_id,
    l.scope_mode AS scope_kind,
    CASE
        WHEN l.scope_mode = 'platform' THEN NULL
        WHEN l.scope_mode = 'tenant' THEN l.tenant_id::text
        WHEN l.scope_mode = 'object_kind' THEN l.object_kind
        -- object_type stores the full namespaced value (e.g. 'entity:device'),
        -- matching permission_block_scopes; passed through, not reconstructed.
        WHEN l.scope_mode = 'object_type' THEN l.object_type
        WHEN l.scope_mode = 'object' THEN l.object_id::text
    END AS scope_ref
FROM credential_permission_limits l;

-- Single subject grant expansion: direct policies, role-linked permission
-- blocks, and active tenant-membership tenant visibility for one subject,
-- principal-group membership resolved recursively. Each row is one fully
-- expanded grant carrying its block's own scope/effect/conditions and the
-- assignment-level tenant boundary.
CREATE FUNCTION subject_effective_grants(p_entity_id UUID)
RETURNS TABLE(
    assignment_id   UUID,
    block_id        UUID,
    role_id         UUID,
    role_name       TEXT,
    via             TEXT,
    tenant_boundary UUID,
    scope_kind      TEXT,
    scope_ref       TEXT,
    capability_id   UUID,
    effect          TEXT,
    conditions      JSONB
)
LANGUAGE sql
STABLE
AS $$
    WITH RECURSIVE subject_groups(group_id, path) AS (
        SELECT gm.group_id, g.name
        FROM group_members gm
        JOIN groups g ON g.id = gm.group_id AND g.status = 'active' AND g.deleted_at IS NULL
        WHERE gm.entity_id = p_entity_id
        UNION ALL
        SELECT gh.parent_id, parent.name || ' -> ' || sg.path
        FROM group_hierarchy gh
        JOIN subject_groups sg ON sg.group_id = gh.child_id
        JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active' AND parent.deleted_at IS NULL
    )
    SELECT dp.id AS assignment_id,
           pb.id AS block_id,
           NULL::uuid AS role_id,
           NULL::text AS role_name,
           CASE WHEN dp.subject_kind = 'entity' THEN 'direct' ELSE 'group:' || sg.path END AS via,
           dp.tenant_id AS tenant_boundary,
           pbs.scope_kind,
           pbs.scope_ref,
           pba.action_id AS capability_id,
           pb.effect,
           pb.conditions
    FROM direct_policies dp
    JOIN permission_blocks pb ON pb.id = dp.permission_block_id
    JOIN permission_block_scopes pbs ON pbs.permission_block_id = pb.id
    JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
    LEFT JOIN subject_groups sg ON dp.subject_kind = 'group' AND sg.group_id = dp.subject_id
    WHERE (dp.subject_kind = 'entity' AND dp.subject_id = p_entity_id)
       OR (dp.subject_kind = 'group' AND sg.group_id IS NOT NULL)
    UNION ALL
    SELECT ra.id AS assignment_id,
           pb.id AS block_id,
           ra.role_id AS role_id,
           r.name AS role_name,
           CASE WHEN ra.subject_kind = 'entity' THEN 'direct' ELSE 'group:' || sg.path END AS via,
           ra.tenant_id AS tenant_boundary,
           pbs.scope_kind,
           pbs.scope_ref,
           pba.action_id AS capability_id,
           pb.effect,
           pb.conditions
    FROM role_assignments ra
    JOIN roles r ON r.id = ra.role_id AND r.deleted_at IS NULL
    JOIN role_permission_blocks rpb ON rpb.role_id = ra.role_id
    JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
    JOIN permission_block_scopes pbs ON pbs.permission_block_id = pb.id
    JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
    LEFT JOIN subject_groups sg ON ra.subject_kind = 'group' AND sg.group_id = ra.subject_id
    WHERE (ra.subject_kind = 'entity' AND ra.subject_id = p_entity_id)
       OR (ra.subject_kind = 'group' AND sg.group_id IS NOT NULL)
    UNION ALL
    SELECT (
               substr(md5('tenant_membership_assignment:' || tm.tenant_id::text || ':' || tm.entity_id::text), 1, 8) || '-' ||
               substr(md5('tenant_membership_assignment:' || tm.tenant_id::text || ':' || tm.entity_id::text), 9, 4) || '-' ||
               substr(md5('tenant_membership_assignment:' || tm.tenant_id::text || ':' || tm.entity_id::text), 13, 4) || '-' ||
               substr(md5('tenant_membership_assignment:' || tm.tenant_id::text || ':' || tm.entity_id::text), 17, 4) || '-' ||
               substr(md5('tenant_membership_assignment:' || tm.tenant_id::text || ':' || tm.entity_id::text), 21, 12)
           )::uuid AS assignment_id,
           (
               substr(md5('tenant_membership_block:' || tm.tenant_id::text || ':' || tm.entity_id::text), 1, 8) || '-' ||
               substr(md5('tenant_membership_block:' || tm.tenant_id::text || ':' || tm.entity_id::text), 9, 4) || '-' ||
               substr(md5('tenant_membership_block:' || tm.tenant_id::text || ':' || tm.entity_id::text), 13, 4) || '-' ||
               substr(md5('tenant_membership_block:' || tm.tenant_id::text || ':' || tm.entity_id::text), 17, 4) || '-' ||
               substr(md5('tenant_membership_block:' || tm.tenant_id::text || ':' || tm.entity_id::text), 21, 12)
           )::uuid AS block_id,
           NULL::uuid AS role_id,
           NULL::text AS role_name,
           'tenant_membership' AS via,
           tm.tenant_id AS tenant_boundary,
           'object' AS scope_kind,
           tm.tenant_id::text AS scope_ref,
           a.id AS capability_id,
           'allow' AS effect,
           '{}'::jsonb AS conditions
    FROM tenant_memberships tm
    JOIN entities e ON e.id = tm.entity_id
    JOIN tenants t ON t.id = tm.tenant_id
    JOIN actions a ON a.name = 'read'
    WHERE tm.entity_id = p_entity_id
      AND tm.status = 'active'
      AND e.kind = 'human'
      AND e.status = 'active'
      AND e.deleted_at IS NULL
      AND t.status = 'active'
      AND t.deleted_at IS NULL
$$;

-- Single scope predicate: whether a grant's (scope_kind, scope_ref) covers a
-- candidate object. Set-based mirror of the Rust `scope_values_match` used by
-- the PDP; a parity test pins the two together. `p_ancestors` is the candidate's
-- recursive ancestor-group ids. Written without sublinks so PostgreSQL can
-- inline it into the listing queries (an `IN (SELECT unnest(...))` form would
-- block inlining and make this a per-candidate function call).
CREATE FUNCTION grant_scope_matches(
    p_scope_kind    TEXT,
    p_scope_ref     TEXT,
    p_coarse_kind   TEXT,
    p_sub_kind      TEXT,
    p_object_id     UUID,
    p_object_tenant UUID,
    p_parent_group  UUID,
    p_ancestors     UUID[]
)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE p_scope_kind
        WHEN 'platform' THEN TRUE
        WHEN 'tenant' THEN p_object_tenant IS NOT NULL AND p_scope_ref = p_object_tenant::text
        WHEN 'object_kind' THEN p_scope_ref = p_coarse_kind
        WHEN 'object_type' THEN p_scope_ref = p_coarse_kind || ':' || p_sub_kind
        WHEN 'object' THEN p_scope_ref = p_object_id::text
        WHEN 'group_object_type' THEN
            p_parent_group IS NOT NULL
            AND p_scope_ref = p_parent_group::text || ':' || p_coarse_kind || ':' || p_sub_kind
        WHEN 'group_tree_object_type' THEN
            substr(p_scope_ref, strpos(p_scope_ref, ':') + 1) = p_coarse_kind || ':' || p_sub_kind
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_ancestors)
        WHEN 'group_child_kind' THEN
            p_coarse_kind = 'group'
            AND p_parent_group IS NOT NULL
            AND p_scope_ref = p_parent_group::text || ':group'
        WHEN 'group_descendant_kind' THEN
            p_coarse_kind = 'group'
            AND (
                (p_parent_group IS NOT NULL AND p_scope_ref = p_parent_group::text || ':group')
                OR (split_part(p_scope_ref, ':', 2) = 'group'
                    AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_ancestors))
            )
        ELSE FALSE
    END
$$;

CREATE TABLE audit_logs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_entity_id UUID        REFERENCES entities(id) ON DELETE SET NULL,
    tenant_id       UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    target_kind     TEXT,
    target_id       UUID,
    event           TEXT        NOT NULL,
    outcome         TEXT        NOT NULL CHECK (outcome IN ('allow', 'deny', 'error')),
    details         JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_actor ON audit_logs(actor_entity_id);
CREATE INDEX idx_audit_target ON audit_logs(target_kind, target_id);
CREATE INDEX idx_audit_event ON audit_logs(event);
CREATE INDEX idx_audit_time ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_tenant_time
    ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_target_time
    ON audit_logs(target_kind, target_id, created_at DESC);
CREATE INDEX idx_audit_event_time
    ON audit_logs(event, created_at DESC);

CREATE TABLE action_assignment_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    entity_kind     TEXT        NOT NULL CHECK (entity_kind IN ('human', 'device', 'service', 'workload', 'application')),
    action_name     TEXT        NOT NULL,
    object_kind     TEXT        NOT NULL CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy', 'credential', 'audit_log', 'signing_key')),
    object_type     TEXT,
    decision        TEXT        NOT NULL CHECK (decision IN ('allow', 'deny', 'require_override')),
    is_absolute     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_aar_tenant ON action_assignment_rules(tenant_id);
CREATE INDEX idx_aar_lookup ON action_assignment_rules(entity_kind, action_name, object_kind);
CREATE UNIQUE INDEX idx_aar_unique_rule
    ON action_assignment_rules (
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
        entity_kind,
        action_name,
        object_kind,
        COALESCE(object_type, '')
    );

CREATE TABLE tenant_invitations (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invitee_user_id UUID        REFERENCES entities(id) ON DELETE CASCADE,
    invitee_email   TEXT,
    invited_by      UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    role_id         UUID        REFERENCES roles(id) ON DELETE SET NULL,
    secret_hash     TEXT,
    expires_at      TIMESTAMPTZ,
    accepted_by     UUID        REFERENCES entities(id) ON DELETE SET NULL,
    accepted_at     TIMESTAMPTZ,
    rejected_at     TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ
);

CREATE INDEX idx_tenant_invitations_tenant
    ON tenant_invitations(tenant_id, created_at DESC);

CREATE INDEX idx_tenant_invitations_invitee
    ON tenant_invitations(invitee_user_id, created_at DESC)
    WHERE invitee_user_id IS NOT NULL;

CREATE UNIQUE INDEX idx_tenant_invitations_tenant_invitee_user
    ON tenant_invitations(tenant_id, invitee_user_id)
    WHERE invitee_user_id IS NOT NULL;

CREATE UNIQUE INDEX idx_tenant_invitations_tenant_invitee_email
    ON tenant_invitations(tenant_id, lower(invitee_email))
    WHERE invitee_email IS NOT NULL;

CREATE INDEX idx_tenant_invitations_token_active
    ON tenant_invitations(id)
    WHERE secret_hash IS NOT NULL AND accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE api_endpoints (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    key                TEXT        NOT NULL,
    name               TEXT        NOT NULL,
    description        TEXT,
    method             TEXT        NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    path               TEXT        NOT NULL,
    operation_kind     TEXT        NOT NULL CHECK (operation_kind IN ('query', 'mutation')),
    graphql            TEXT        NOT NULL,
    auth_mode          TEXT        NOT NULL DEFAULT 'caller_context'
                                      CHECK (auth_mode IN ('caller_context', 'service_context')),
    service_entity_id  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    variables_mapping  JSONB       NOT NULL DEFAULT '{}',
    request_schema     JSONB       NOT NULL DEFAULT '{}',
    response_mapping   JSONB       NOT NULL DEFAULT '{}',
    status             TEXT        NOT NULL DEFAULT 'draft'
                                      CHECK (status IN ('draft', 'active', 'disabled')),
    created_by         UUID        REFERENCES entities(id) ON DELETE SET NULL,
    updated_by         UUID        REFERENCES entities(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_api_endpoints_global_key
    ON api_endpoints(key)
    WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX idx_api_endpoints_tenant_key
    ON api_endpoints(tenant_id, key)
    WHERE tenant_id IS NOT NULL;

CREATE UNIQUE INDEX idx_api_endpoints_active_method_path
    ON api_endpoints(method, path)
    WHERE status = 'active';

CREATE INDEX idx_api_endpoints_tenant ON api_endpoints(tenant_id);
CREATE INDEX idx_api_endpoints_status ON api_endpoints(status);

CREATE TABLE api_endpoint_executions (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id       UUID        REFERENCES api_endpoints(id) ON DELETE SET NULL,
    caller_entity_id  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    status            TEXT        NOT NULL CHECK (status IN ('success', 'error', 'denied')),
    request_summary   JSONB       NOT NULL DEFAULT '{}',
    response_summary  JSONB       NOT NULL DEFAULT '{}',
    error             TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_endpoint_executions_endpoint
    ON api_endpoint_executions(endpoint_id, created_at DESC);

CREATE INDEX idx_api_endpoint_executions_caller
    ON api_endpoint_executions(caller_entity_id, created_at DESC);

-- =============================================================
-- SEED DATA
-- =============================================================

WITH seeded_profiles AS (
    INSERT INTO profiles (object_kind, kind, key, display_name)
    VALUES
        ('entity', 'device',      'client',          'Client'),
        ('entity', 'device',      'gateway',         'Gateway'),
        ('entity', 'device',      'water_meter',     'Water Meter'),
        ('entity', 'human',       'user',            'User'),
        ('entity', 'service',     'service_account', 'Service Account'),
        ('entity', 'workload',    'workload',        'Workload'),
        ('entity', 'application', 'application',     'Application')
    RETURNING id
)
INSERT INTO profile_versions (profile_id, version, json_schema, ui_schema)
SELECT id, 1, '{}'::jsonb, '{}'::jsonb
FROM seeded_profiles;

INSERT INTO actions (name, description) VALUES
    ('read',                'Read / view an object'),
    ('create',              'Create an object'),
    ('write',               'Create or update an object'),
    ('delete',              'Delete an object'),
    ('revoke',              'Revoke an object or credential'),
    ('rotate',              'Rotate a key or secret material'),
    ('publish',             'Publish messages to a channel'),
    ('subscribe',           'Subscribe to channel messages'),
    ('execute',             'Execute a command or action'),
    ('manage',              'Full administrative control'),
    ('policy.manage',       'Manage assignments and policy records'),
    ('role.manage',         'Manage roles'),
    ('authz.check',         'Evaluate authorization checks for other subjects');

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, object_kind, object_type
FROM actions
CROSS JOIN LATERAL (
    VALUES
        ('entity', 'entity:human'),
        ('entity', 'entity:device'),
        ('entity', 'entity:service'),
        ('entity', 'entity:workload'),
        ('entity', 'entity:application'),
        ('resource', NULL),
        ('group', NULL)
) AS applicability(object_kind, object_type)
WHERE actions.name IN ('read', 'write', 'delete')
;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, object_kind, object_type
FROM actions
CROSS JOIN LATERAL (
    VALUES
        ('tenant', NULL),
        ('entity', NULL),
        ('resource', NULL),
        ('group', NULL)
) AS applicability(object_kind, object_type)
WHERE actions.name IN ('manage', 'role.manage', 'policy.manage');

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'role', NULL
FROM actions
WHERE actions.name = 'role.manage'
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'policy', NULL
FROM actions
WHERE actions.name = 'policy.manage'
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, object_kind, object_type
FROM actions
CROSS JOIN LATERAL (
    VALUES
        ('credential', NULL)
) AS applicability(object_kind, object_type)
WHERE actions.name IN ('read', 'manage', 'rotate', 'revoke')
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, object_kind, object_type
FROM actions
CROSS JOIN LATERAL (
    VALUES
        ('audit_log', NULL)
) AS applicability(object_kind, object_type)
WHERE actions.name = 'read'
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'tenant', NULL
FROM actions
WHERE actions.name IN ('read', 'create', 'manage')
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'signing_key', NULL
FROM actions
WHERE actions.name = 'rotate'
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'resource', 'resource:channel'
FROM actions
WHERE name IN ('publish', 'subscribe')
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'resource', 'resource:rule'
FROM actions
WHERE name = 'execute'
ON CONFLICT DO NOTHING;

INSERT INTO entities (id, kind, name, status, attributes)
VALUES
    (
        '00000000-0000-0000-0000-000000000001',
        'human',
        'admin',
        'active',
        '{"role": "admin", "system": true}'::jsonb
    ),
    (
        '00000000-0000-0000-0000-000000000003',
        'service',
        'example-service',
        'active',
        '{"system": true, "purpose": "example-service-integration"}'::jsonb
    );

INSERT INTO roles (id, name, description)
VALUES
    (
        '00000000-0000-0000-0000-000000000002',
        'atom-admin',
        'Full administrative access'
    ),
    (
        '00000000-0000-0000-0000-000000000004',
        'example-service',
        'Example service integration role'
    ),
    (
        '00000000-0000-0000-0000-000000000006',
        'domain-creator',
        'Allows authenticated users to create their own tenants/domains'
    );

INSERT INTO permission_blocks (id, scope_mode, effect, conditions)
VALUES
    ('00000000-0000-0000-0000-000000000007', 'platform', 'allow', '{}'::jsonb),
    ('00000000-0000-0000-0000-000000000008', 'platform', 'allow', '{}'::jsonb),
    ('00000000-0000-0000-0000-000000000009', 'platform', 'allow', '{}'::jsonb);

INSERT INTO permission_block_actions (permission_block_id, action_id)
SELECT '00000000-0000-0000-0000-000000000007', id
FROM actions;

INSERT INTO permission_block_actions (permission_block_id, action_id)
SELECT '00000000-0000-0000-0000-000000000008', id
FROM actions
WHERE name IN (
    'manage', 'read', 'write', 'delete', 'publish', 'subscribe',
    'execute', 'policy.manage', 'role.manage', 'authz.check'
);

INSERT INTO permission_block_actions (permission_block_id, action_id)
SELECT '00000000-0000-0000-0000-000000000009', id
FROM actions
WHERE name = 'create';

INSERT INTO role_permission_blocks (role_id, permission_block_id)
VALUES
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000007'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000008'),
    ('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000009');

INSERT INTO principal_groups (id, name, tenant_id, description, status, attributes)
VALUES (
    '00000000-0000-0000-0000-000000000005',
    'authenticated-users',
    NULL,
    'All authenticated human users',
    'active',
    '{"system": true, "purpose": "default-self-service-domain-creation"}'::jsonb
);

INSERT INTO principal_group_members (group_id, entity_id)
VALUES (
    '00000000-0000-0000-0000-000000000005',
    '00000000-0000-0000-0000-000000000001'
);

INSERT INTO role_assignments
    (id, tenant_id, subject_kind, subject_id, role_id)
VALUES
    (
        '00000000-0000-0000-0000-000000000001',
        NULL,
        'entity',
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000002'
    ),
    (
        gen_random_uuid(),
        NULL,
        'entity',
        '00000000-0000-0000-0000-000000000003',
        '00000000-0000-0000-0000-000000000004'
    ),
    (
        gen_random_uuid(),
        NULL,
        'group',
        '00000000-0000-0000-0000-000000000005',
        '00000000-0000-0000-0000-000000000006'
    );

INSERT INTO action_assignment_rules
    (entity_kind, action_name, object_kind, object_type, decision, is_absolute)
VALUES
    ('device', 'manage', 'resource', NULL, 'deny', TRUE),
    ('device', 'delete', 'resource', NULL, 'deny', TRUE),
    ('device', 'write', 'resource', NULL, 'deny', TRUE),
    ('human', 'manage', 'resource', NULL, 'allow', FALSE),
    ('human', 'manage', 'entity', NULL, 'allow', FALSE),
    ('human', 'manage', 'group', NULL, 'allow', FALSE),
    ('human', 'manage', 'credential', NULL, 'allow', FALSE),
    ('human', 'read', 'audit_log', NULL, 'allow', FALSE),
    ('human', 'policy.manage', 'policy', NULL, 'allow', FALSE),
    ('human', 'role.manage', 'role', NULL, 'allow', FALSE),
    ('service', 'manage', 'resource', NULL, 'allow', FALSE),
    ('service', 'manage', 'credential', NULL, 'allow', FALSE),
    ('service', 'policy.manage', 'policy', NULL, 'allow', FALSE),
    ('service', 'role.manage', 'role', NULL, 'allow', FALSE);

-- ─── Policy-object permission-block cleanup ──────────────────────────────────
-- Exact-object permission blocks can target a direct policy or role assignment
-- by id (object_kind = 'policy'), via the polymorphic permission_blocks.object_id
-- column, which has no foreign key. A policy/assignment row is removed by many
-- paths — direct delete, bulk delete, and FK cascade from tenants, roles, and
-- permission_blocks — and any block still pointing at a removed row would be left
-- dangling, granting access on a vanished object.
--
-- Enforce the cleanup as a DB-level invariant instead of at every call site: an
-- AFTER DELETE trigger removes the blocks targeting a policy row whenever that
-- row is deleted by ANY means (including referential-action cascades, for which
-- row-level triggers still fire). Deleting those blocks cascades to the policies
-- that reference them, re-firing the trigger; the recursion is monotonic (each
-- step removes rows) and terminates.

CREATE OR REPLACE FUNCTION purge_blocks_targeting_policy() RETURNS trigger AS $$
BEGIN
    DELETE FROM permission_blocks WHERE object_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_direct_policies_purge_object_blocks
    AFTER DELETE ON direct_policies
    FOR EACH ROW EXECUTE FUNCTION purge_blocks_targeting_policy();

CREATE TRIGGER trg_role_assignments_purge_object_blocks
    AFTER DELETE ON role_assignments
    FOR EACH ROW EXECUTE FUNCTION purge_blocks_targeting_policy();


-- Squashed from 002_platform_filtered_permission_scopes.sql; fresh-install baseline.

DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname
    INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'permission_blocks'::regclass
      AND contype = 'c'
      AND conname <> 'permission_blocks_conditions_is_object'
      AND pg_get_constraintdef(oid) LIKE '%object_kind%'
      AND pg_get_constraintdef(oid) LIKE '%tenant_id IS NOT NULL%'
      AND pg_get_constraintdef(oid) LIKE '%group_descendant_groups%'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE permission_blocks DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

ALTER TABLE permission_blocks
    DROP CONSTRAINT IF EXISTS permission_blocks_scope_shape;

ALTER TABLE permission_blocks
    ADD CONSTRAINT permission_blocks_scope_shape
    CHECK (
        (scope_mode = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'tenant' AND tenant_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object_kind' AND object_kind IS NOT NULL AND object_id IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object_type' AND object_kind IS NOT NULL AND object_type IS NOT NULL AND object_id IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object' AND object_id IS NOT NULL AND group_id IS NULL)
        OR (scope_mode = 'group' AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode IN ('group_direct_objects', 'group_descendant_objects') AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_kind IN ('entity', 'resource') AND object_id IS NULL)
        OR (scope_mode IN ('group_child_groups', 'group_descendant_groups') AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
    );


-- Squashed from 003_access_token_usage_and_ceiling_scope.sql; fresh-install baseline.

ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname
    INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'credential_permission_limits'::regclass
      AND contype = 'c'
      AND conname <> 'credential_permission_limits_conditions_is_object'
      AND pg_get_constraintdef(oid) LIKE '%scope_mode%'
      AND pg_get_constraintdef(oid) LIKE '%object_id IS NOT NULL%'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE credential_permission_limits DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

ALTER TABLE credential_permission_limits
    DROP CONSTRAINT IF EXISTS credential_permission_limits_scope_shape;

ALTER TABLE credential_permission_limits
    ADD CONSTRAINT credential_permission_limits_scope_shape
    CHECK (
        (scope_mode = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode = 'tenant' AND tenant_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode = 'object_kind' AND object_kind IS NOT NULL AND object_id IS NULL AND object_type IS NULL)
        OR (scope_mode = 'object_type' AND object_kind IS NOT NULL AND object_type IS NOT NULL AND object_id IS NULL)
        OR (scope_mode = 'object' AND object_id IS NOT NULL AND tenant_id IS NULL)
    );


-- Squashed from 004_event_outbox.sql; fresh-install baseline.

-- Generic domain-event publishing. Purely additive: one new table, no ALTER on
-- any existing table. Safe to apply on any deployment; the feature stays a
-- no-op until an operator sets ATOM_EVENTS_AMQP_URL.

CREATE TABLE event_outbox (
    id              UUID        PRIMARY KEY,
    event           TEXT        NOT NULL,
    -- Deliberately NOT foreign keys. The outbox is an append-only record of
    -- what happened, not of what currently exists, and constraining these
    -- columns to live rows lost events two ways:
    --
    --   1. Failure events. `audit::observe_error` publishes the attempt that
    --      failed, and a common reason for failing is that the tenant in the
    --      request does not exist. An FK rejected the outbox insert too, so
    --      exactly the events a consumer most needs to see — invalid-target
    --      failures — were the ones deterministically dropped.
    --
    --   2. `ON DELETE SET NULL` silently rewrote history: purging a tenant or
    --      entity blanked the actor/tenant on every past event it appeared in,
    --      including events already delivered to the broker with those ids
    --      populated. The payload JSONB kept the original values, so the row
    --      and its own payload disagreed.
    --
    -- Keeping them unconstrained (rather than nulling ids at the call site)
    -- keeps the columns truthful about what the event carried. Nothing joins
    -- them to `tenants`/`entities`; they exist for filtering and for the
    -- publisher, and the authoritative copy travels inside `payload`.
    actor_entity_id UUID        NULL,
    tenant_id       UUID        NULL,
    payload         JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ NULL,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT        NULL,
    -- Distinguishes a structurally-invalid row (payload no longer matches
    -- DomainEventPayload, e.g. left over from an older schema_version) from a
    -- row that has simply failed to publish so far. Only the former is safe to
    -- ever stop retrying: retrying a bad deserialize can never succeed, while a
    -- publish failure may just be a broker outage that recovers, and must stay
    -- retryable no matter how long that takes.
    unparseable     BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX idx_event_outbox_undelivered ON event_outbox(created_at) WHERE delivered_at IS NULL;

-- Optimizes outbox retention cleanup over delivered and exhausted rows.
CREATE INDEX idx_event_outbox_retention ON event_outbox(created_at) WHERE delivered_at IS NOT NULL OR (unparseable = true AND attempts >= 10);


-- Squashed from 005_managed_by.sql; fresh-install baseline.

-- Marks rows that were provisioned from a declarative bootstrap file (see
-- src/bootstrap.rs) so mutation endpoints can refuse to modify them out of
-- band. NULL = API-managed (default), 'config' = bootstrap-managed.
-- Config-managed rows can still be added to (e.g. extra applicability rows
-- attached to a config-managed capability), but they cannot be updated or
-- deleted via the API — the config file is the source of truth.

ALTER TABLE actions
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE action_applicability
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE action_assignment_rules
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');


-- Squashed from 006_managed_by_identity.sql; fresh-install baseline.

-- Extends the `managed_by` marker from 005 to identity tables. Entities and
-- credentials created from a bootstrap file (`src/bootstrap.rs`) are stamped
-- 'config' so the API refuses to update, delete, revoke, or rotate them.
-- Config-managed credentials are additionally hidden from list/read responses
-- — the API pretends they don't exist so operator-planted tokens can never
-- leak through introspection.

ALTER TABLE entities
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');


-- Squashed from 007_strip_product_specific_applicability.sql; fresh-install baseline.

-- Remove the two product-specific applicability rows migration 001 originally
-- seeded for magistrala (`publish`/`subscribe` on `resource:channel`,
-- `execute` on `resource:rule`). These are IoT-flavoured defaults that don't
-- belong in a generic authorization service — each product ships its own
-- vocabulary via the bootstrap config file (see src/bootstrap.rs
-- `capabilities` section, and the companion PR in magistrala).
--
-- Kept as a separate migration rather than editing 001 in place: modifying an
-- already-applied migration changes its checksum and makes sqlx refuse to
-- start against any existing deployment. This delta migration is safe both
-- for fresh installs (the rows are seeded by 001 and then removed here — a
-- few wasted inserts, no functional change) and for upgrades.

DELETE FROM action_applicability
WHERE (object_kind, object_type) IN (
    ('resource', 'resource:channel'),
    ('resource', 'resource:rule')
);


-- Squashed from 008_managed_by_rbac.sql; fresh-install baseline.

-- Extends the `managed_by` marker (introduced in 005/006) to the rest of the
-- tables the bootstrap YAML populates: tenants, resources, principal_groups,
-- object_groups, roles, permission_blocks, role_assignments, direct_policies.
-- Rows stamped 'config' are refused by update/delete/restore endpoints so the
-- deployment's declared graph can only be reshaped by editing the YAML and
-- restarting Atom.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE principal_groups
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE object_groups
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE permission_blocks
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE direct_policies
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

-- The `groups` view unifies principal_groups and object_groups; recreate it
-- with managed_by carried through from either underlying table.
DROP VIEW IF EXISTS groups;
CREATE VIEW groups AS
SELECT id, name, tenant_id, 'object'::text AS group_type, description, status,
       attributes, deleted_at, deleted_by, created_at, updated_at, managed_by
FROM object_groups
UNION ALL
SELECT id, name, tenant_id, 'principal'::text AS group_type, description, status,
       attributes, deleted_at, deleted_by, created_at, updated_at, managed_by
FROM principal_groups;


-- Squashed from 009_many_to_many_object_group_membership.sql; fresh-install baseline.

-- Object group membership becomes many-to-many.
--
-- `object_group_entities` / `object_group_resources` keyed membership by the
-- member alone, so an entity or resource could belong to at most one object
-- group — forbidding overlapping sets ("Customer A meters" and "Building 5
-- meters" intersecting without either containing the other). Both member
-- tables move together; they're read by the same queries and scope predicate.

-- Data-preserving: every existing row already has a distinct member id, so it
-- is trivially distinct under the wider key too.
ALTER TABLE object_group_entities
    DROP CONSTRAINT object_group_entities_pkey,
    ADD PRIMARY KEY (group_id, entity_id);

ALTER TABLE object_group_resources
    DROP CONSTRAINT object_group_resources_pkey,
    ADD PRIMARY KEY (group_id, resource_id);

-- The old member-keyed PK index served the member-side lookup ("which groups is
-- this entity in?"). The new PK leads with group_id, so that lookup needs its
-- own index; conversely the standalone group_id indexes are now redundant with
-- the PK's leading column.
DROP INDEX idx_object_group_entities_group;
DROP INDEX idx_object_group_resources_group;

CREATE INDEX idx_object_group_entities_entity ON object_group_entities(entity_id);
CREATE INDEX idx_object_group_resources_resource ON object_group_resources(resource_id);

-- `grant_scope_matches` is the scope predicate shared by every authorized
-- listing reader, mirroring the PDP's Rust `scope_values_match` (a parity
-- test pins them together). Its `p_parent_group UUID` argument assumed one
-- membership; it becomes `p_parent_groups UUID[]`, matching when a scope
-- names ANY of the object's groups. The group arms move to the same
-- split/`= ANY` form the tree arms already use — still sublink-free, so
-- Postgres can inline the function into the listing queries.
DROP FUNCTION grant_scope_matches(TEXT, TEXT, TEXT, TEXT, UUID, UUID, UUID, UUID[]);

CREATE FUNCTION grant_scope_matches(
    p_scope_kind    TEXT,
    p_scope_ref     TEXT,
    p_coarse_kind   TEXT,
    p_sub_kind      TEXT,
    p_object_id     UUID,
    p_object_tenant UUID,
    p_parent_groups UUID[],
    p_ancestors     UUID[]
)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE p_scope_kind
        WHEN 'platform' THEN TRUE
        WHEN 'tenant' THEN p_object_tenant IS NOT NULL AND p_scope_ref = p_object_tenant::text
        WHEN 'object_kind' THEN p_scope_ref = p_coarse_kind
        WHEN 'object_type' THEN p_scope_ref = p_coarse_kind || ':' || p_sub_kind
        WHEN 'object' THEN p_scope_ref = p_object_id::text
        WHEN 'group_object_type' THEN
            substr(p_scope_ref, strpos(p_scope_ref, ':') + 1) = p_coarse_kind || ':' || p_sub_kind
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_parent_groups)
        WHEN 'group_tree_object_type' THEN
            substr(p_scope_ref, strpos(p_scope_ref, ':') + 1) = p_coarse_kind || ':' || p_sub_kind
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_ancestors)
        WHEN 'group_child_kind' THEN
            p_coarse_kind = 'group'
            AND split_part(p_scope_ref, ':', 2) = 'group'
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_parent_groups)
        WHEN 'group_descendant_kind' THEN
            p_coarse_kind = 'group'
            AND split_part(p_scope_ref, ':', 2) = 'group'
            AND (
                split_part(p_scope_ref, ':', 1)::uuid = ANY(p_parent_groups)
                OR split_part(p_scope_ref, ':', 1)::uuid = ANY(p_ancestors)
            )
        ELSE FALSE
    END
$$;


-- Squashed from 010_entity_external_id.sql; fresh-install baseline.

-- `external_id` — an identifier assigned outside Atom (serial number, MAC
-- address, employee number, SKU). Purely additive: one nullable column plus
-- a partial unique index; existing rows get NULL.
--
-- Not `alias`: `alias` is a human-friendly slug Atom owns and constrains;
-- `external_id` is a foreign key into someone else's namespace and stays
-- opaque. The constraints below are sanity limits, not format validation.

ALTER TABLE entities ADD COLUMN external_id TEXT;

-- Case-sensitive: `ABC123` and `abc123` are different entities, unlike
-- `alias` (indexed on `lower(alias)`). Vendor schemes may distinguish case,
-- and folding is irreversible once two devices have merged under one value.
--
-- Whitespace is trimmed: `"ABC123 "` and `"ABC123"` are the same entity —
-- edge whitespace is a transport artifact, not data. Enforced both here and
-- in the application (`chk_entities_external_id_trimmed` below), so it holds
-- regardless of which client writes first. Interior whitespace is preserved.
--
-- Unique per tenant among live rows: NULLs and soft-deleted rows are excluded
-- (a retired serial is free for reuse; `restoreEntity` can then conflict if
-- it was reused during the retention window). `COALESCE(tenant_id, ...)`
-- mirrors `idx_entities_alias` so platform-level entities (`tenant_id IS
-- NULL`) get real uniqueness instead of every NULL comparing distinct. The
-- index leads with `external_id` rather than the tenant because lookups are
-- sometimes tenant-scoped and sometimes not (`entities(externalId:)` takes
-- an optional `tenantId`).
CREATE UNIQUE INDEX idx_entities_external_id
    ON entities (
        external_id,
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE external_id IS NOT NULL AND deleted_at IS NULL;

-- Sanity cap, not format validation — the value stays opaque (uppercase,
-- `/`, `.`, spaces, unicode all accepted). `length()` counts characters, to
-- match the application check.
ALTER TABLE entities ADD CONSTRAINT chk_entities_external_id_length
    CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 255);

ALTER TABLE entities ADD CONSTRAINT chk_entities_external_id_trimmed
    CHECK (external_id IS NULL OR external_id !~ '^\s|\s$');


-- Squashed from 011_pki_authorities.sql; fresh-install baseline.

-- Atom-native multi-tenant PKI authority registry.

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

-- Credentials issued before the authority registry have no trustworthy
-- authority row to reference.  Preserve them as explicitly unmanaged legacy
-- leaves: guessing an issuer would let Atom publish CRL/OCSP data under the
-- wrong CA.  New managed issuance always supplies issuer_id, so this marker is
-- only the forward-migration bridge for rows that existed before this column.
UPDATE credentials
   SET metadata = jsonb_set(
           metadata,
           '{issuer_migration}',
           '"legacy_unmanaged"'::jsonb,
           true
       )
 WHERE kind = 'certificate';

ALTER TABLE credentials
    ADD CONSTRAINT chk_credentials_issuer_certificate_only
    CHECK (
        (kind = 'certificate' AND issuer_id IS NOT NULL)
        OR (
            kind = 'certificate'
            AND issuer_id IS NULL
            AND metadata->>'issuer_migration' IS NOT DISTINCT FROM 'legacy_unmanaged'
        )
        OR (kind <> 'certificate' AND issuer_id IS NULL)
    );

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
    IF NEW.kind <> 'certificate' THEN
        RETURN NEW;
    END IF;

    -- The only issuer-less certificates permitted after this migration are
    -- rows that existed before issuer_id and were marked above.  Do not let a
    -- later import manufacture that compatibility marker to bypass managed
    -- issuer binding.
    IF NEW.issuer_id IS NULL THEN
        IF TG_OP = 'UPDATE'
           AND OLD.kind = 'certificate'
           AND OLD.issuer_id IS NULL
           AND OLD.metadata->>'issuer_migration' IS NOT DISTINCT FROM 'legacy_unmanaged'
           AND NEW.metadata->>'issuer_migration' IS NOT DISTINCT FROM 'legacy_unmanaged' THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'certificate requires a managed issuer authority'
            USING ERRCODE = '23514';
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


-- Squashed from 012_pki_ca_provisioning.sql; fresh-install baseline.

-- Controlled CA provisioning state for PR-003.
--
-- A managed CA does not have certificate material while its locally generated
-- key and CSR are waiting for an offline signature.  The foundation schema
-- intentionally modelled only completed authorities; make the material
-- state-aware without weakening the constraints on active authorities.

ALTER TABLE pki_authorities
    ALTER COLUMN serial_number DROP NOT NULL,
    ALTER COLUMN fingerprint_sha256 DROP NOT NULL,
    ALTER COLUMN certificate_pem DROP NOT NULL,
    ALTER COLUMN chain_pem DROP NOT NULL,
    ALTER COLUMN not_before DROP NOT NULL,
    ALTER COLUMN not_after DROP NOT NULL,
    ADD COLUMN provisioning_mode TEXT NOT NULL DEFAULT 'imported'
        CHECK (provisioning_mode IN ('imported', 'offline', 'automated')),
    ADD COLUMN csr_pem TEXT,
    ADD COLUMN failure_reason TEXT;

ALTER TABLE pki_authorities
    ADD CONSTRAINT chk_pki_authorities_completed_material
    CHECK (
        status IN ('provisioning', 'pending_signature', 'failed')
        OR (
            serial_number IS NOT NULL
            AND fingerprint_sha256 IS NOT NULL
            AND certificate_pem IS NOT NULL
            AND chain_pem IS NOT NULL
            AND not_before IS NOT NULL
            AND not_after IS NOT NULL
        )
    ),
    ADD CONSTRAINT chk_pki_authorities_pending_csr
    CHECK (
        status NOT IN ('provisioning', 'pending_signature')
        OR (
            kind <> 'root'
            AND key_backend <> 'public_only'
            AND NULLIF(btrim(csr_pem), '') IS NOT NULL
        )
    ),
    ADD CONSTRAINT chk_pki_authorities_failure_reason
    CHECK (
        (status = 'failed' AND NULLIF(btrim(failure_reason), '') IS NOT NULL)
        OR (status <> 'failed' AND failure_reason IS NULL)
    );

-- One unfinished request per scope makes repeated calls deterministic and
-- prevents concurrent replicas from generating abandoned CA keys for the same
-- tenant or global authority role.
CREATE UNIQUE INDEX idx_pki_authorities_one_pending_tenant
    ON pki_authorities(tenant_id)
    WHERE kind = 'tenant_intermediate'
      AND status IN ('provisioning', 'pending_signature');

CREATE UNIQUE INDEX idx_pki_authorities_one_pending_global_kind
    ON pki_authorities(kind)
    WHERE tenant_id IS NULL
      AND kind IN ('platform_intermediate', 'platform_leaf_issuer')
      AND status IN ('provisioning', 'pending_signature');

-- Only one platform intermediate is selected for automated CA signing.  Older
-- versions remain addressable in retiring/retired state for chain validation.
CREATE UNIQUE INDEX idx_pki_authorities_one_active_platform_intermediate
    ON pki_authorities((true))
    WHERE kind = 'platform_intermediate' AND status = 'active';

-- CA lifecycle administration is deliberately distinct from ordinary tenant
-- or credential management.  Automated CA signing is a second, stronger
-- capability so an operator can delegate offline-CSR handling without granting
-- use of the online platform-intermediate signer.
INSERT INTO actions (name, description) VALUES
    ('pki.provision', 'Manage PKI authority provisioning and lifecycle'),
    ('pki.provision_automated', 'Use the platform CA signer for automated authority provisioning')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permission_block_actions (permission_block_id, action_id)
SELECT '00000000-0000-0000-0000-000000000007', id
FROM actions
WHERE name IN ('pki.provision', 'pki.provision_automated')
ON CONFLICT DO NOTHING;


-- Squashed from 013_pki_certificate_profiles.sql; fresh-install baseline.

-- Stored certificate profiles and issuer artifact-discovery configuration.
--
-- Certificate shape is data.  The two global rows are conservative platform
-- ceilings; a tenant row references one of them and may only narrow it.

ALTER TABLE pki_authorities
    ADD COLUMN ocsp_url TEXT,
    ADD COLUMN ca_issuers_url TEXT,
    ADD COLUMN crl_distribution_point_url TEXT,
    ADD CONSTRAINT chk_pki_authorities_artifact_urls
    CHECK (
        (ocsp_url IS NULL
            AND ca_issuers_url IS NULL
            AND crl_distribution_point_url IS NULL)
        OR
        (ocsp_url ~ '^https?://[^[:space:]]+$'
            AND ca_issuers_url ~ '^https?://[^[:space:]]+$'
            AND crl_distribution_point_url ~ '^https?://[^[:space:]]+$')
    );

CREATE OR REPLACE FUNCTION pki_valid_san_policy(policy JSONB) RETURNS BOOLEAN AS $$
DECLARE
    san_type TEXT;
    rule JSONB;
    mode TEXT;
BEGIN
    IF jsonb_typeof(policy) <> 'object'
       OR NOT policy ?& ARRAY['dns', 'ip', 'email', 'uri']
       OR policy - ARRAY['dns', 'ip', 'email', 'uri'] <> '{}'::jsonb THEN
        RETURN false;
    END IF;

    FOREACH san_type IN ARRAY ARRAY['dns', 'ip', 'email', 'uri'] LOOP
        rule := policy -> san_type;
        mode := rule ->> 'mode';
        IF jsonb_typeof(rule) <> 'object'
           OR NOT rule ?& ARRAY['mode', 'values']
           OR rule - ARRAY['mode', 'values'] <> '{}'::jsonb
           OR jsonb_typeof(rule -> 'values') <> 'array' THEN
            RETURN false;
        END IF;

        IF san_type = 'dns' AND mode NOT IN ('deny', 'allowlist', 'entity_template') THEN
            RETURN false;
        ELSIF san_type IN ('ip', 'email') AND mode NOT IN ('deny', 'allowlist') THEN
            RETURN false;
        ELSIF san_type = 'uri' AND (mode <> 'identity' OR rule -> 'values' <> '[]'::jsonb) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION pki_san_rule_is_subset(child JSONB, ceiling JSONB)
RETURNS BOOLEAN AS $$
DECLARE
    child_mode TEXT := child ->> 'mode';
    ceiling_mode TEXT := ceiling ->> 'mode';
BEGIN
    IF ceiling_mode = 'deny' THEN
        RETURN child_mode = 'deny';
    ELSIF ceiling_mode = 'identity' THEN
        RETURN child_mode = 'identity';
    ELSIF ceiling_mode IN ('allowlist', 'entity_template') THEN
        RETURN child_mode = 'deny'
            OR (child_mode = ceiling_mode
                AND (ceiling -> 'values') @> (child -> 'values'));
    END IF;
    RETURN false;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE TABLE certificate_profiles (
    id                         UUID        PRIMARY KEY,
    tenant_id                  UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    base_profile_id            UUID        REFERENCES certificate_profiles(id) ON DELETE RESTRICT,
    name                       TEXT        NOT NULL
                                           CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$'),
    permitted_key_algorithms   JSONB       NOT NULL
                                           CHECK (jsonb_typeof(permitted_key_algorithms) = 'array'
                                               AND jsonb_array_length(permitted_key_algorithms) > 0),
    default_ttl_seconds        BIGINT      NOT NULL CHECK (default_ttl_seconds > 0),
    maximum_ttl_seconds        BIGINT      NOT NULL CHECK (maximum_ttl_seconds > 0),
    renewal_threshold_seconds  BIGINT      NOT NULL CHECK (renewal_threshold_seconds > 0),
    key_usages                 TEXT[]      NOT NULL,
    extended_key_usages        TEXT[]      NOT NULL,
    san_policy                 JSONB       NOT NULL CHECK (pki_valid_san_policy(san_policy)),
    identity_uri_template      TEXT        NOT NULL
                                           CHECK (identity_uri_template =
                                               'urn:atom:{scope}entity:{entity_id}'),
    basic_constraints          JSONB       NOT NULL
                                           CHECK (basic_constraints =
                                               '{"ca": false, "path_len": null}'::jsonb),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_certificate_profiles_nonzero_id
        CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT chk_certificate_profiles_scope
        CHECK ((tenant_id IS NULL AND base_profile_id IS NULL)
            OR (tenant_id IS NOT NULL AND base_profile_id IS NOT NULL)),
    CONSTRAINT chk_certificate_profiles_ttl
        CHECK (default_ttl_seconds <= maximum_ttl_seconds
            AND renewal_threshold_seconds <= maximum_ttl_seconds),
    CONSTRAINT chk_certificate_profiles_leaf_key_usages
        CHECK (key_usages <@ ARRAY[
            'digital_signature', 'content_commitment', 'key_encipherment',
            'data_encipherment', 'key_agreement'
        ]::TEXT[]),
    CONSTRAINT chk_certificate_profiles_extended_key_usages
        CHECK (extended_key_usages <@ ARRAY[
            'server_auth', 'client_auth', 'code_signing', 'email_protection',
            'time_stamping', 'ocsp_signing'
        ]::TEXT[])
);

CREATE UNIQUE INDEX idx_certificate_profiles_platform_name
    ON certificate_profiles(name) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX idx_certificate_profiles_tenant_name
    ON certificate_profiles(tenant_id, name) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_certificate_profiles_base ON certificate_profiles(base_profile_id);

CREATE OR REPLACE FUNCTION enforce_certificate_profile_ceiling() RETURNS trigger AS $$
DECLARE
    ceiling certificate_profiles%ROWTYPE;
    san_type TEXT;
BEGIN
    IF NEW.tenant_id IS NULL THEN
        IF EXISTS (
            SELECT 1
              FROM certificate_profiles child
             WHERE child.base_profile_id = NEW.id
               AND (
                    child.name <> NEW.name
                    OR child.default_ttl_seconds > NEW.default_ttl_seconds
                    OR child.maximum_ttl_seconds > NEW.maximum_ttl_seconds
                    OR child.renewal_threshold_seconds > NEW.renewal_threshold_seconds
                    OR child.permitted_key_algorithms <> NEW.permitted_key_algorithms
                    OR NOT child.key_usages <@ NEW.key_usages
                    OR NOT child.extended_key_usages <@ NEW.extended_key_usages
                    OR child.identity_uri_template <> NEW.identity_uri_template
                    OR child.basic_constraints <> NEW.basic_constraints
                    OR NOT pki_san_rule_is_subset(child.san_policy -> 'dns', NEW.san_policy -> 'dns')
                    OR NOT pki_san_rule_is_subset(child.san_policy -> 'ip', NEW.san_policy -> 'ip')
                    OR NOT pki_san_rule_is_subset(child.san_policy -> 'email', NEW.san_policy -> 'email')
                    OR NOT pki_san_rule_is_subset(child.san_policy -> 'uri', NEW.san_policy -> 'uri')
               )
        ) THEN
            RAISE EXCEPTION 'platform certificate profile update would exceed a tenant ceiling'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO ceiling
      FROM certificate_profiles
     WHERE id = NEW.base_profile_id AND tenant_id IS NULL
     FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant certificate profile requires a platform ceiling'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.name <> ceiling.name THEN
        RAISE EXCEPTION 'tenant certificate profile name must match its platform ceiling'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.default_ttl_seconds > ceiling.default_ttl_seconds
       OR NEW.maximum_ttl_seconds > ceiling.maximum_ttl_seconds
       OR NEW.renewal_threshold_seconds > ceiling.renewal_threshold_seconds THEN
        RAISE EXCEPTION 'tenant certificate profile cannot extend platform time limits'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.permitted_key_algorithms <> ceiling.permitted_key_algorithms
       OR NOT NEW.key_usages <@ ceiling.key_usages
       OR NOT NEW.extended_key_usages <@ ceiling.extended_key_usages
       OR NEW.identity_uri_template <> ceiling.identity_uri_template
       OR NEW.basic_constraints <> ceiling.basic_constraints THEN
        RAISE EXCEPTION 'tenant certificate profile exceeds platform certificate shape'
            USING ERRCODE = '23514';
    END IF;

    FOREACH san_type IN ARRAY ARRAY['dns', 'ip', 'email', 'uri'] LOOP
        IF NOT pki_san_rule_is_subset(
            NEW.san_policy -> san_type,
            ceiling.san_policy -> san_type
        ) THEN
            RAISE EXCEPTION 'tenant certificate profile widens platform SAN policy'
                USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_profiles_ceiling
    BEFORE INSERT OR UPDATE OF tenant_id, base_profile_id, name,
        permitted_key_algorithms, default_ttl_seconds, maximum_ttl_seconds,
        renewal_threshold_seconds, key_usages, extended_key_usages, san_policy,
        identity_uri_template, basic_constraints
    ON certificate_profiles
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_profile_ceiling();

INSERT INTO certificate_profiles (
    id, name, permitted_key_algorithms, default_ttl_seconds,
    maximum_ttl_seconds, renewal_threshold_seconds, key_usages,
    extended_key_usages, san_policy, identity_uri_template, basic_constraints
) VALUES
    (
        '00000000-0000-0000-0000-000000000401',
        'client',
        '[{"algorithm":"ecdsa","sizes":[256]}]'::jsonb,
        86400, 604800, 86400,
        ARRAY['digital_signature']::TEXT[],
        ARRAY['client_auth']::TEXT[],
        '{
            "dns":{"mode":"deny","values":[]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }'::jsonb,
        'urn:atom:{scope}entity:{entity_id}',
        '{"ca":false,"path_len":null}'::jsonb
    ),
    (
        '00000000-0000-0000-0000-000000000402',
        'server',
        '[{"algorithm":"ecdsa","sizes":[256]}]'::jsonb,
        86400, 604800, 86400,
        ARRAY['digital_signature']::TEXT[],
        ARRAY['server_auth']::TEXT[],
        '{
            "dns":{"mode":"deny","values":[]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }'::jsonb,
        'urn:atom:{scope}entity:{entity_id}',
        '{"ca":false,"path_len":null}'::jsonb
    )
ON CONFLICT (id) DO NOTHING;


-- Squashed from 014_pki_csr_issuance.sql; fresh-install baseline.

-- Idempotency ledger for managed, CSR-based leaf issuance.
--
-- The public idempotency token and CSR are never stored.  Only keyed request
-- identity and payload digests are retained, and the row commits atomically
-- with the issuer-bound certificate credential.

CREATE TABLE certificate_issuance_requests (
    id                          UUID        PRIMARY KEY,
    entity_id                   UUID        NOT NULL
                                             REFERENCES entities(id) ON DELETE CASCADE,
    request_key_hash            TEXT        NOT NULL
                                             CHECK (request_key_hash ~ '^[0-9a-f]{64}$'),
    request_fingerprint_sha256  TEXT        NOT NULL
                                             CHECK (request_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    credential_id               UUID        UNIQUE
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at                TIMESTAMPTZ,

    CONSTRAINT uq_certificate_issuance_request_key
        UNIQUE (entity_id, request_key_hash),
    CONSTRAINT chk_certificate_issuance_request_state
        CHECK ((credential_id IS NULL AND completed_at IS NULL)
            OR (credential_id IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE INDEX idx_certificate_issuance_requests_credential
    ON certificate_issuance_requests(credential_id)
    WHERE credential_id IS NOT NULL;

-- A retry ledger may only resolve to the managed certificate created for the
-- same entity.  This repeats the service invariant at the database boundary.
CREATE OR REPLACE FUNCTION enforce_certificate_issuance_request_credential()
RETURNS trigger AS $$
DECLARE
    credential_entity_id UUID;
    credential_kind      TEXT;
    credential_issuer_id UUID;
BEGIN
    IF NEW.credential_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT entity_id, kind, issuer_id
      INTO credential_entity_id, credential_kind, credential_issuer_id
      FROM credentials
     WHERE id = NEW.credential_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    IF credential_entity_id <> NEW.entity_id
       OR credential_kind <> 'certificate'
       OR credential_issuer_id IS NULL THEN
        RAISE EXCEPTION 'issuance request must reference its issuer-bound entity certificate'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_issuance_request_credential
    BEFORE INSERT OR UPDATE OF entity_id, credential_id
    ON certificate_issuance_requests
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_issuance_request_credential();


-- Squashed from 015_pki_certificate_renewal.sql; fresh-install baseline.

-- Exact-credential renewal history and idempotency ledger.
--
-- A certificate may have at most one replacement. The public idempotency
-- token and CSR are never stored; only domain-separated digests are retained.
-- The pending row, replacement credential, optional old-certificate
-- revocation, and completion link are committed in one transaction.

CREATE TABLE certificate_renewals (
    id                          UUID        PRIMARY KEY,
    previous_credential_id      UUID        NOT NULL UNIQUE
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    request_key_hash            TEXT        NOT NULL
                                             CHECK (request_key_hash ~ '^[0-9a-f]{64}$'),
    request_fingerprint_sha256  TEXT        NOT NULL
                                             CHECK (request_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    key_mode                    TEXT        NOT NULL CHECK (key_mode IN ('csr', 'generated')),
    replacement_credential_id   UUID        UNIQUE
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at                TIMESTAMPTZ,

    CONSTRAINT chk_certificate_renewal_state
        CHECK ((replacement_credential_id IS NULL AND completed_at IS NULL)
            OR (replacement_credential_id IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE INDEX idx_certificate_renewals_replacement
    ON certificate_renewals(replacement_credential_id)
    WHERE replacement_credential_id IS NOT NULL;

-- Keep the service's history invariants at the database boundary: both sides
-- are certificate credentials for one entity, the replacement is managed by
-- an explicit issuer, and its immutable metadata points back to the exact old
-- credential rather than an ambiguous serial.
CREATE OR REPLACE FUNCTION enforce_certificate_renewal_link()
RETURNS trigger AS $$
DECLARE
    previous_entity_id UUID;
    previous_kind      TEXT;
    replacement_entity_id UUID;
    replacement_kind      TEXT;
    replacement_issuer_id UUID;
    replacement_previous_id TEXT;
BEGIN
    SELECT entity_id, kind
      INTO previous_entity_id, previous_kind
      FROM credentials
     WHERE id = NEW.previous_credential_id;

    IF NOT FOUND OR previous_kind <> 'certificate' THEN
        RAISE EXCEPTION 'renewal source must be a certificate credential'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.replacement_credential_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.replacement_credential_id = NEW.previous_credential_id THEN
        RAISE EXCEPTION 'renewal replacement must differ from its source'
            USING ERRCODE = '23514';
    END IF;

    SELECT entity_id, kind, issuer_id,
           metadata->>'renewed_from_credential_id'
      INTO replacement_entity_id, replacement_kind,
           replacement_issuer_id, replacement_previous_id
      FROM credentials
     WHERE id = NEW.replacement_credential_id;

    IF NOT FOUND
       OR replacement_kind <> 'certificate'
       OR replacement_issuer_id IS NULL
       OR replacement_entity_id <> previous_entity_id
       OR replacement_previous_id IS DISTINCT FROM NEW.previous_credential_id::text THEN
        RAISE EXCEPTION 'renewal replacement must be an issuer-bound certificate for the same entity'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_renewal_link
    BEFORE INSERT OR UPDATE OF previous_credential_id, replacement_credential_id
    ON certificate_renewals
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_renewal_link();


-- Squashed from 016_pki_certificate_revocation.sql; fresh-install baseline.

-- Issuer-aware, immediately authoritative certificate revocation state.
--
-- credentials.status remains the hot-path decision. This immutable companion
-- row records who revoked the exact credential, why, when, and which issuer's
-- publication artifacts must be refreshed. The trigger covers every lifecycle
-- path that transitions a certificate to revoked, including entity/tenant
-- deletion.

CREATE TABLE certificate_revocations (
    credential_id              UUID        PRIMARY KEY
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    -- issuer_id may become NULL only via the authority-purge FK cascade set
    -- up in migration 023. The record trigger enforces NOT NULL at INSERT.
    issuer_id                  UUID        REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    issuer_fingerprint_sha256  TEXT        NOT NULL
                                             CHECK (issuer_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    serial_number              TEXT        NOT NULL CHECK (serial_number ~ '^[0-9a-f]+$'),
    reason                     TEXT        NOT NULL CHECK (
                                             length(btrim(reason)) BETWEEN 1 AND 128
                                           ),
    -- Deliberately not an FK: revocation evidence must retain the actor UUID
    -- after that actor is purged, and an ON DELETE action would conflict with
    -- this table's immutability trigger.
    actor_entity_id            UUID,
    revoked_at                 TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_certificate_revocations_issuer
    ON certificate_revocations(issuer_id, revoked_at DESC)
    WHERE issuer_id IS NOT NULL;

CREATE INDEX idx_certificate_revocations_issuer_fingerprint
    ON certificate_revocations(issuer_fingerprint_sha256, revoked_at DESC);

-- Preserve already-revoked data during rollout. Old rows did not have a
-- normalized actor column; that nullable field stays explicitly unknown
-- rather than being invented.  Migration 011 marks pre-registry leaves as
-- `issuer_migration = legacy_unmanaged`: those records have no trustworthy
-- authority to publish against and must not be fabricated into this ledger.
-- Every other revoked certificate must map to a managed pki_authorities row.
-- Check that invariant before the insert: an INNER JOIN alone would silently
-- omit an orphaned managed certificate.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM credentials c
          LEFT JOIN pki_authorities a ON a.id = c.issuer_id
         WHERE c.kind = 'certificate'
           AND c.status = 'revoked'
           AND (
               (c.issuer_id IS NOT NULL AND a.id IS NULL)
               OR (
                   c.issuer_id IS NULL
                   AND c.metadata->>'issuer_migration' IS DISTINCT FROM 'legacy_unmanaged'
               )
           )
    ) THEN
        RAISE EXCEPTION 'revoked certificate is missing a managed issuer authority'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

INSERT INTO certificate_revocations (
    credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
    reason, actor_entity_id, revoked_at
)
SELECT c.id,
       c.issuer_id,
       a.fingerprint_sha256,
       c.identifier,
       left(COALESCE(NULLIF(btrim(c.metadata->>'revocation_reason'), ''), 'unspecified'), 128),
       CASE
           WHEN c.metadata->>'revoked_by_entity_id'
                ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
           THEN (c.metadata->>'revoked_by_entity_id')::uuid
       END,
       CASE
           WHEN c.metadata->>'revoked_at' ~ '^\d{4}-\d{2}-\d{2}[T ]'
           THEN (c.metadata->>'revoked_at')::timestamptz
           ELSE c.created_at
       END
  FROM credentials c
  JOIN pki_authorities a ON a.id = c.issuer_id
 WHERE c.kind = 'certificate'
   AND c.status = 'revoked'
   AND c.identifier IS NOT NULL
ON CONFLICT (credential_id) DO NOTHING;

-- Any existing per-issuer cache represented by a revoked credential is stale.
INSERT INTO certificate_crl_state (
    issuer_fingerprint_sha256, issuer_id, crl_number, dirty
)
SELECT DISTINCT ON (r.issuer_fingerprint_sha256)
       r.issuer_fingerprint_sha256, r.issuer_id, 0, TRUE
  FROM certificate_revocations r
 ORDER BY r.issuer_fingerprint_sha256, r.revoked_at DESC
ON CONFLICT (issuer_fingerprint_sha256) DO UPDATE
    SET dirty = TRUE,
        issuer_id = COALESCE(certificate_crl_state.issuer_id, EXCLUDED.issuer_id),
        updated_at = now();

CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time         TIMESTAMPTZ;
    event_reason       TEXT;
    event_actor        UUID;
    issuer_fingerprint TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    -- Pre-registry credentials remain locally revocable through
    -- credentials.status, but have no authority under which Atom can publish
    -- CRL/OCSP evidence.  Migration 011 marked this exact bounded exception.
    IF NEW.issuer_id IS NULL
       AND NEW.metadata->>'issuer_migration' = 'legacy_unmanaged' THEN
        RETURN NEW;
    END IF;

    SELECT a.fingerprint_sha256
      INTO issuer_fingerprint
      FROM pki_authorities a
     WHERE a.id = NEW.issuer_id;
    IF issuer_fingerprint IS NULL THEN
        RAISE EXCEPTION 'revoked certificate % missing pki_authorities row for issuer_id %',
            NEW.id, NEW.issuer_id USING ERRCODE = '23514';
    END IF;

    event_time := COALESCE((NEW.metadata->>'revoked_at')::timestamptz, now());
    event_reason := left(
        COALESCE(NULLIF(btrim(NEW.metadata->>'revocation_reason'), ''), 'unspecified'),
        128
    );
    event_actor := NULLIF(NEW.metadata->>'revoked_by_entity_id', '')::uuid;

    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at
    ) VALUES (
        NEW.id, NEW.issuer_id, issuer_fingerprint, NEW.identifier,
        event_reason, event_actor, event_time
    )
    ON CONFLICT (credential_id) DO NOTHING;

    -- CRL/OCSP generation is deliberately outside this PR. Mark only the
    -- exact issuer cache stale; never fan out to unrelated tenants/issuers.
    INSERT INTO certificate_crl_state (
        issuer_fingerprint_sha256, issuer_id, crl_number, dirty
    ) VALUES (issuer_fingerprint, NEW.issuer_id, 0, TRUE)
    ON CONFLICT (issuer_fingerprint_sha256) DO UPDATE
        SET dirty = TRUE,
            issuer_id = COALESCE(
                certificate_crl_state.issuer_id,
                EXCLUDED.issuer_id
            ),
            updated_at = now();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_credentials_record_certificate_revocation
    AFTER INSERT OR UPDATE OF status ON credentials
    FOR EACH ROW EXECUTE FUNCTION record_certificate_revocation();

-- The ledger is immutable evidence. Credential deletion cascades it; all
-- other mutation attempts are rejected.
CREATE OR REPLACE FUNCTION prevent_certificate_revocation_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'certificate revocation records are immutable'
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_revocations_immutable
    BEFORE UPDATE ON certificate_revocations
    FOR EACH ROW EXECUTE FUNCTION prevent_certificate_revocation_mutation();


-- Squashed from 017_pki_issuer_crls.sql; fresh-install baseline.

-- Issuer-keyed CRL publication state.
--
-- Every certificate_crl_state row corresponds to a managed pki_authorities
-- row via issuer_id. Any row whose fingerprint does not match a live
-- authority is orphaned by design and must be dropped before the tightening.

UPDATE certificate_crl_state s
   SET issuer_id = a.id
  FROM pki_authorities a
 WHERE s.issuer_id IS NULL
   AND a.fingerprint_sha256 = s.issuer_fingerprint_sha256;

DELETE FROM certificate_crl_state
 WHERE issuer_id IS NULL;

ALTER TABLE certificate_crl_state
    ADD COLUMN crl_sha256 TEXT;

UPDATE certificate_crl_state
   SET crl_sha256 = CASE
           WHEN crl_der IS NULL THEN NULL
           ELSE encode(digest(crl_der, 'sha256'), 'hex')
       END;

ALTER TABLE certificate_crl_state
    ALTER COLUMN issuer_id SET NOT NULL,
    DROP CONSTRAINT certificate_crl_state_pkey,
    ADD CONSTRAINT certificate_crl_state_pkey PRIMARY KEY (issuer_id),
    ADD CONSTRAINT chk_certificate_crl_state_hash CHECK (
        (crl_der IS NULL AND crl_sha256 IS NULL)
        OR (
            crl_der IS NOT NULL
            AND crl_sha256 ~ '^[0-9a-f]{64}$'
            AND crl_sha256 = encode(digest(crl_der, 'sha256'), 'hex')
        )
    );

DROP INDEX idx_certificate_crl_state_issuer;

CREATE UNIQUE INDEX idx_certificate_crl_state_fingerprint
    ON certificate_crl_state(issuer_fingerprint_sha256);

-- PR-008 owns authoritative revocation. Replacing its trigger here changes
-- only the artifact-state representation: publication is keyed by
-- pki_authorities.id, and the fingerprint stays as historical evidence.
CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time         TIMESTAMPTZ;
    event_reason       TEXT;
    event_actor        UUID;
    issuer_fingerprint TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    -- Migration 011 explicitly marks pre-registry leaves. They retain local
    -- status revocation but cannot produce artifacts for an unknown issuer.
    IF NEW.issuer_id IS NULL
       AND NEW.metadata->>'issuer_migration' = 'legacy_unmanaged' THEN
        RETURN NEW;
    END IF;

    SELECT a.fingerprint_sha256
      INTO issuer_fingerprint
      FROM pki_authorities a
     WHERE a.id = NEW.issuer_id;
    IF issuer_fingerprint IS NULL THEN
        RAISE EXCEPTION 'revoked certificate % missing pki_authorities row for issuer_id %',
            NEW.id, NEW.issuer_id USING ERRCODE = '23514';
    END IF;

    event_time := COALESCE((NEW.metadata->>'revoked_at')::timestamptz, now());
    event_reason := left(
        COALESCE(NULLIF(btrim(NEW.metadata->>'revocation_reason'), ''), 'unspecified'),
        128
    );
    event_actor := NULLIF(NEW.metadata->>'revoked_by_entity_id', '')::uuid;

    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at
    ) VALUES (
        NEW.id, NEW.issuer_id, issuer_fingerprint, NEW.identifier,
        event_reason, event_actor, event_time
    )
    ON CONFLICT (credential_id) DO NOTHING;

    INSERT INTO certificate_crl_state (
        issuer_id, issuer_fingerprint_sha256, crl_number, dirty
    ) VALUES (
        NEW.issuer_id, issuer_fingerprint, 0, TRUE
    )
    ON CONFLICT (issuer_id) DO UPDATE
        SET dirty = TRUE, updated_at = now();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Squashed from 018_pki_runtime_resolver_v2.sql; fresh-install baseline.

-- Unambiguous certificate runtime identity and issuer-scoped serials.
--
-- Application readers resolve managed credentials by fingerprint or by
-- issuer identity plus serial. Build the replacement unique index before
-- removing the old global one so the migration never exposes an
-- unconstrained serial window.

ALTER TABLE credentials
    DROP CONSTRAINT credentials_status_check;

ALTER TABLE credentials
    ADD CONSTRAINT credentials_status_check
    CHECK (
        status IN ('active', 'revoked')
        OR (kind = 'certificate' AND status = 'revocation_pending')
    );

CREATE UNIQUE INDEX idx_credentials_certificate_issuer_serial
    ON credentials(issuer_id, identifier)
    WHERE kind = 'certificate'
      AND identifier IS NOT NULL;

DROP INDEX idx_credentials_certificate_serial;
DROP INDEX idx_credentials_certificate_issuer_serial_lookup;


-- Squashed from 019_pki_enrollment.sql; fresh-install baseline.

-- PR-014: durable enrollment abuse-control windows. Keeping counters in
-- PostgreSQL makes limits atomic across Atom replicas and process restarts.
CREATE TABLE pki_enrollment_rate_windows (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('entity', 'tenant')),
    scope_id UUID NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, scope_id, window_start)
);

CREATE INDEX idx_pki_enrollment_rate_windows_updated
    ON pki_enrollment_rate_windows (updated_at);

COMMENT ON TABLE pki_enrollment_rate_windows IS
    'Fixed-window counters for PR-014 per-entity and per-tenant enrollment limits';


-- Squashed from 020_pki_lifecycle_automation.sql; fresh-install baseline.

-- PR-015: durable, replica-safe lifecycle notification ledger.
--
-- The marker and its event_outbox row are written in the same transaction.
-- A unique window identity makes retries, restarts, and concurrent replicas
-- converge on one notification without relying on process memory.
CREATE TABLE pki_lifecycle_notifications (
    subject_kind   TEXT        NOT NULL
                               CHECK (subject_kind IN ('credential', 'authority')),
    subject_id     UUID        NOT NULL
                               CHECK (subject_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    window_kind    TEXT        NOT NULL
                               CHECK (window_kind IN (
                                   'renewal',
                                   'expiry',
                                   'authority_expiry'
                               )),
    window_at      TIMESTAMPTZ NOT NULL,
    emitted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_kind, subject_id, window_kind)
);

CREATE INDEX idx_pki_lifecycle_notifications_emitted
    ON pki_lifecycle_notifications (emitted_at);

-- Supports stable expiry-window pagination independent of credential creation
-- order. Existing issuer/status indexes continue to serve the other filters.
CREATE INDEX idx_credentials_certificate_expiry_listing
    ON credentials (expires_at, id)
    WHERE kind = 'certificate' AND expires_at IS NOT NULL;

COMMENT ON TABLE pki_lifecycle_notifications IS
    'Exactly-once-per-window notification ledger for PR-015 lifecycle sweeps';


-- Squashed from 021_pki_profile_usage_invariants.sql; fresh-install baseline.

-- An empty KeyUsage or ExtendedKeyUsage extension is not a restriction. When
-- rcgen receives an empty list it omits the extension, and relying parties can
-- interpret the certificate as valid for unrestricted purposes. Every stored
-- leaf profile must therefore name at least one usage in both categories.

ALTER TABLE certificate_profiles
    ADD CONSTRAINT chk_certificate_profiles_nonempty_key_usages
        CHECK (cardinality(key_usages) > 0),
    ADD CONSTRAINT chk_certificate_profiles_nonempty_extended_key_usages
        CHECK (cardinality(extended_key_usages) > 0);


-- Squashed from 022_pki_durable_revocation_evidence.sql; fresh-install baseline.

-- Revocation publication evidence must outlive the credential and identity
-- rows that produced it. A still-valid revoked certificate remains revoked
-- after an explicit entity/tenant purge, and its issuer keeps publishing that
-- state until the certificate expires.

DROP TRIGGER trg_certificate_revocations_immutable ON certificate_revocations;

ALTER TABLE certificate_revocations
    ADD COLUMN expires_at TIMESTAMPTZ;

UPDATE certificate_revocations r
   SET expires_at = COALESCE(c.expires_at, 'infinity'::timestamptz)
  FROM credentials c
 WHERE c.id = r.credential_id;

UPDATE certificate_revocations
   SET expires_at = 'infinity'::timestamptz
 WHERE expires_at IS NULL;

ALTER TABLE certificate_revocations
    ALTER COLUMN expires_at SET NOT NULL,
    DROP CONSTRAINT certificate_revocations_credential_id_fkey;

CREATE UNIQUE INDEX idx_certificate_revocations_issuer_serial
    ON certificate_revocations(issuer_id, serial_number)
    WHERE issuer_id IS NOT NULL;

-- PR-009's issuer-keyed state function is retained here with one additional
-- immutable value: the credential expiry copied at the revocation boundary.
CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time         TIMESTAMPTZ;
    event_reason       TEXT;
    event_actor        UUID;
    issuer_fingerprint TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    -- Migration 011 explicitly marks pre-registry leaves. They retain local
    -- status revocation but cannot produce artifacts for an unknown issuer.
    IF NEW.issuer_id IS NULL
       AND NEW.metadata->>'issuer_migration' = 'legacy_unmanaged' THEN
        RETURN NEW;
    END IF;

    SELECT a.fingerprint_sha256
      INTO issuer_fingerprint
      FROM pki_authorities a
     WHERE a.id = NEW.issuer_id;
    IF issuer_fingerprint IS NULL THEN
        RAISE EXCEPTION 'revoked certificate % missing pki_authorities row for issuer_id %',
            NEW.id, NEW.issuer_id USING ERRCODE = '23514';
    END IF;

    event_time := COALESCE((NEW.metadata->>'revoked_at')::timestamptz, now());
    event_reason := left(
        COALESCE(NULLIF(btrim(NEW.metadata->>'revocation_reason'), ''), 'unspecified'),
        128
    );
    event_actor := NULLIF(NEW.metadata->>'revoked_by_entity_id', '')::uuid;

    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at, expires_at
    ) VALUES (
        NEW.id, NEW.issuer_id, issuer_fingerprint, NEW.identifier,
        event_reason, event_actor, event_time,
        COALESCE(NEW.expires_at, 'infinity'::timestamptz)
    )
    ON CONFLICT (credential_id) DO NOTHING;

    INSERT INTO certificate_crl_state (
        issuer_id, issuer_fingerprint_sha256, crl_number, dirty
    ) VALUES (
        NEW.issuer_id, issuer_fingerprint, 0, TRUE
    )
    ON CONFLICT (issuer_id) DO UPDATE
        SET dirty = TRUE, updated_at = now();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- The ledger no longer relies on a credential-delete cascade. Reject direct
-- updates and deletes so revocation cannot disappear before expiry.
CREATE TRIGGER trg_certificate_revocations_immutable
    BEFORE UPDATE OR DELETE ON certificate_revocations
    FOR EACH ROW EXECUTE FUNCTION prevent_certificate_revocation_mutation();


-- Squashed from 023_pki_purgeable_authorities.sql; fresh-install baseline.

-- Tenant and authority purge must succeed even after the authority has issued
-- revocations. Migration 016 pointed certificate_revocations.issuer_id at
-- pki_authorities with ON DELETE RESTRICT, so a purge that reaches the
-- authority row is blocked and rolled back for any tenant that has ever
-- revoked a managed certificate. Migration 022 gave the ledger its own
-- durable lifetime (own expires_at, no more credential-delete cascade) so
-- revocation evidence outlives the identity rows that produced it.
--
-- Switch the FK to ON DELETE SET NULL so authority purge succeeds. Once
-- issuer_id is cleared, the row stops feeding CRL/OCSP publication (which
-- keys off issuer_id) but the fingerprint, serial, and credential_id remain
-- as immutable audit evidence. The immutability trigger is extended to allow
-- exactly one column mutation — the FK cascade clearing issuer_id — while
-- continuing to reject every other UPDATE and every DELETE.

ALTER TABLE certificate_revocations
    DROP CONSTRAINT certificate_revocations_issuer_id_fkey;

ALTER TABLE certificate_revocations
    ADD CONSTRAINT certificate_revocations_issuer_id_fkey
        FOREIGN KEY (issuer_id)
        REFERENCES pki_authorities(id)
        ON DELETE SET NULL;

CREATE OR REPLACE FUNCTION prevent_certificate_revocation_mutation()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.issuer_id IS NOT NULL
           AND NEW.issuer_id IS NULL
           AND NEW.credential_id             IS NOT DISTINCT FROM OLD.credential_id
           AND NEW.issuer_fingerprint_sha256 IS NOT DISTINCT FROM OLD.issuer_fingerprint_sha256
           AND NEW.serial_number             IS NOT DISTINCT FROM OLD.serial_number
           AND NEW.reason                    IS NOT DISTINCT FROM OLD.reason
           AND NEW.actor_entity_id           IS NOT DISTINCT FROM OLD.actor_entity_id
           AND NEW.revoked_at                IS NOT DISTINCT FROM OLD.revoked_at
           AND NEW.expires_at                IS NOT DISTINCT FROM OLD.expires_at
           AND NEW.created_at                IS NOT DISTINCT FROM OLD.created_at
        THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION 'certificate revocation records are immutable'
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;


-- Squashed from 024_pki_config_bootstrap_provisioning_mode.sql; fresh-install baseline.

-- Config-driven bootstrap of the platform intermediate authority uses a new
-- provisioning_mode value 'config_bootstrap' distinct from the other
-- interactive flows (imported/offline/automated).

ALTER TABLE pki_authorities
    DROP CONSTRAINT IF EXISTS pki_authorities_provisioning_mode_check;

ALTER TABLE pki_authorities
    ADD CONSTRAINT pki_authorities_provisioning_mode_check
        CHECK (provisioning_mode IN ('imported', 'offline', 'automated', 'config_bootstrap'));


-- Squashed from 025_case_insensitive_entity_email_unique.sql; fresh-install baseline.

-- Email identity is global and case-insensitive. All login and invitation
-- lookups already compare normalized/lower-case email addresses, so the backing
-- uniqueness invariant must use the same key.

DROP INDEX IF EXISTS idx_entity_emails_email;

-- Older admin-created human entities predate the canonical email table. Bring
-- valid email attributes into that table before enforcing the new invariant.
INSERT INTO entity_emails (entity_id, email, deleted_at)
SELECT e.id,
       lower(trim(e.attributes->>'email')),
       e.deleted_at
FROM entities e
LEFT JOIN entity_emails ee ON ee.entity_id = e.id
WHERE e.kind = 'human'
  AND ee.id IS NULL
  AND e.attributes->>'email' IS NOT NULL
  AND trim(e.attributes->>'email') ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$';

-- Keep the oldest verified canonical row for duplicate legacy addresses and
-- release the others before creating the case-insensitive unique index.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY lower(email)
               ORDER BY verified_at DESC NULLS LAST, created_at, id
           ) AS row_number
    FROM entity_emails
    WHERE deleted_at IS NULL
)
UPDATE entity_emails ee
SET deleted_at = now(), updated_at = now()
FROM ranked
WHERE ee.id = ranked.id
  AND ranked.row_number > 1;

CREATE UNIQUE INDEX idx_entity_emails_email
    ON entity_emails (lower(email))
    WHERE deleted_at IS NULL;


-- Squashed from 026_global_protected_object_registry.sql; fresh-install baseline.

-- Exact object scopes carry only a UUID.  Reserve that UUID globally across
-- every physical table that backs a first-class protected object so one scope
-- can never name two different objects.

-- The launch baseline creates every table before application traffic begins, so
-- no concurrent writers exist to serialize. The upgrade-only table lock is intentionally
-- omitted: PostgreSQL permits LOCK TABLE only inside an explicit transaction
-- when this file is applied as plain SQL.

-- Migration 001 used ...0001 for both the seeded admin entity and that
-- entity's seeded role assignment. Resolve this one known legacy collision to
-- a permanently reserved assignment UUID before enforcing the global
-- namespace. Exact-object blocks and access-token ceilings declare their
-- target kind, so only policy references move with the assignment; an
-- unclassified/invalid legacy reference must be repaired by the operator
-- instead of being guessed here.
DO $seed_assignment_remap$
DECLARE
    occupied text;
    invalid_scopes text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM role_assignments
        WHERE id = '00000000-0000-0000-0000-000000000001'
          AND tenant_id IS NULL
          AND subject_kind = 'entity'
          AND subject_id = '00000000-0000-0000-0000-000000000001'
          AND role_id = '00000000-0000-0000-0000-000000000002'
    ) THEN
        SELECT string_agg(source_table, ', ' ORDER BY source_table)
        INTO occupied
        FROM (
            SELECT 'tenants' AS source_table FROM tenants
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'entities' FROM entities
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'resources' FROM resources
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'principal_groups' FROM principal_groups
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'object_groups' FROM object_groups
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'roles' FROM roles
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'credentials' FROM credentials
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'direct_policies' FROM direct_policies
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'role_assignments' FROM role_assignments
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'api_endpoints' FROM api_endpoints
            WHERE id = '00000000-0000-0000-0000-00000000000a'
        ) occupied_sources;

        IF occupied IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE = 'reserved v1 admin role-assignment UUID 00000000-0000-0000-0000-00000000000a is already used by: ' || occupied,
                HINT = 'Remap the reported custom row before rerunning migration 026.';
        END IF;

        SELECT string_agg(
                   format('%s[%s, object_kind=%s]', source_table, id,
                          COALESCE(object_kind, 'NULL')),
                   '; ' ORDER BY source_table, id
               )
        INTO invalid_scopes
        FROM (
            SELECT 'permission_blocks'::text AS source_table, id, object_kind
            FROM permission_blocks
            WHERE scope_mode = 'object'
              AND object_id = '00000000-0000-0000-0000-000000000001'
              AND (object_kind IS NULL OR object_kind NOT IN ('entity', 'policy'))

            UNION ALL

            SELECT 'credential_permission_limits', id, object_kind
            FROM credential_permission_limits
            WHERE scope_mode = 'object'
              AND object_id = '00000000-0000-0000-0000-000000000001'
              AND (object_kind IS NULL OR object_kind NOT IN ('entity', 'policy'))
        ) invalid;

        IF invalid_scopes IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'unclassified exact-object reference targets legacy UUID 00000000-0000-0000-0000-000000000001: ' || invalid_scopes,
                HINT = 'Set each reported permission_blocks.object_kind or credential_permission_limits.object_kind to entity or policy before rerunning migration 026.';
        END IF;

        UPDATE permission_blocks
        SET object_id = '00000000-0000-0000-0000-00000000000a'
        WHERE scope_mode = 'object'
          AND object_kind = 'policy'
          AND object_id = '00000000-0000-0000-0000-000000000001';

        UPDATE credential_permission_limits
        SET object_id = '00000000-0000-0000-0000-00000000000a'
        WHERE scope_mode = 'object'
          AND object_kind = 'policy'
          AND object_id = '00000000-0000-0000-0000-000000000001';

        UPDATE role_assignments
        SET id = '00000000-0000-0000-0000-00000000000a'
        WHERE id = '00000000-0000-0000-0000-000000000001'
          AND tenant_id IS NULL
          AND subject_kind = 'entity'
          AND subject_id = '00000000-0000-0000-0000-000000000001'
          AND role_id = '00000000-0000-0000-0000-000000000002';
    END IF;
END
$seed_assignment_remap$;

DO $preflight$
DECLARE
    collisions text;
BEGIN
    WITH protected_rows(id, source_table, object_kind) AS (
        SELECT id, 'tenants', 'tenant' FROM tenants
        UNION ALL SELECT id, 'entities', 'entity' FROM entities
        UNION ALL SELECT id, 'resources', 'resource' FROM resources
        UNION ALL SELECT id, 'principal_groups', 'group' FROM principal_groups
        UNION ALL SELECT id, 'object_groups', 'group' FROM object_groups
        UNION ALL SELECT id, 'roles', 'role' FROM roles
        UNION ALL SELECT id, 'credentials', 'credential' FROM credentials
        UNION ALL SELECT id, 'direct_policies', 'policy' FROM direct_policies
        UNION ALL SELECT id, 'role_assignments', 'policy' FROM role_assignments
        UNION ALL SELECT id, 'api_endpoints', 'api_endpoint' FROM api_endpoints
    ), duplicates AS (
        SELECT id,
               string_agg(source_table || ':' || object_kind, ', ' ORDER BY source_table) AS sources
        FROM protected_rows
        GROUP BY id
        HAVING count(*) > 1
    )
    SELECT string_agg(id::text || ' => ' || sources, '; ' ORDER BY id)
    INTO collisions
    FROM duplicates;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'global protected-object UUID collisions: ' || collisions,
            HINT = 'Assign a distinct UUID to every reported row before rerunning migration 026.';
    END IF;
END
$preflight$;

CREATE TABLE protected_object_ids (
    id           UUID        PRIMARY KEY,
    object_kind  TEXT        NOT NULL,
    source_table TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT protected_object_ids_source_kind_check CHECK (
        (source_table = 'tenants'          AND object_kind = 'tenant')
        OR (source_table = 'entities'          AND object_kind = 'entity')
        OR (source_table = 'resources'         AND object_kind = 'resource')
        OR (source_table = 'principal_groups'  AND object_kind = 'group')
        OR (source_table = 'object_groups'     AND object_kind = 'group')
        OR (source_table = 'roles'             AND object_kind = 'role')
        OR (source_table = 'credentials'       AND object_kind = 'credential')
        OR (source_table = 'direct_policies'   AND object_kind = 'policy')
        OR (source_table = 'role_assignments'  AND object_kind = 'policy')
        OR (source_table = 'api_endpoints'      AND object_kind = 'api_endpoint')
    )
);

INSERT INTO protected_object_ids (id, source_table, object_kind)
SELECT id, 'tenants', 'tenant' FROM tenants
UNION ALL SELECT id, 'entities', 'entity' FROM entities
UNION ALL SELECT id, 'resources', 'resource' FROM resources
UNION ALL SELECT id, 'principal_groups', 'group' FROM principal_groups
UNION ALL SELECT id, 'object_groups', 'group' FROM object_groups
UNION ALL SELECT id, 'roles', 'role' FROM roles
UNION ALL SELECT id, 'credentials', 'credential' FROM credentials
UNION ALL SELECT id, 'direct_policies', 'policy' FROM direct_policies
UNION ALL SELECT id, 'role_assignments', 'policy' FROM role_assignments
UNION ALL SELECT id, 'api_endpoints', 'api_endpoint' FROM api_endpoints;

CREATE FUNCTION register_protected_object_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    kind text;
BEGIN
    kind := CASE TG_TABLE_NAME
        WHEN 'tenants' THEN 'tenant'
        WHEN 'entities' THEN 'entity'
        WHEN 'resources' THEN 'resource'
        WHEN 'principal_groups' THEN 'group'
        WHEN 'object_groups' THEN 'group'
        WHEN 'roles' THEN 'role'
        WHEN 'credentials' THEN 'credential'
        WHEN 'direct_policies' THEN 'policy'
        WHEN 'role_assignments' THEN 'policy'
        WHEN 'api_endpoints' THEN 'api_endpoint'
        ELSE NULL
    END;
    IF kind IS NULL THEN
        RAISE EXCEPTION 'unsupported protected-object source table %', TG_TABLE_NAME;
    END IF;
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, kind, TG_TABLE_NAME);
    RETURN NEW;
END
$$;

CREATE FUNCTION unregister_protected_object_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = TG_TABLE_NAME;
    RETURN OLD;
END
$$;

CREATE FUNCTION reject_protected_object_id_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = format('%s.id is immutable once registered', TG_TABLE_NAME);
END
$$;

CREATE FUNCTION reject_protected_object_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = format('TRUNCATE is not supported for protected-object table %s; use DELETE', TG_TABLE_NAME);
END
$$;

DO $triggers$
DECLARE
    source text;
BEGIN
    FOREACH source IN ARRAY ARRAY[
        'tenants', 'entities', 'resources', 'principal_groups', 'object_groups',
        'roles', 'credentials', 'direct_policies', 'role_assignments', 'api_endpoints'
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER register_protected_object_id AFTER INSERT ON %I FOR EACH ROW EXECUTE FUNCTION register_protected_object_id()',
            source
        );
        EXECUTE format(
            'CREATE TRIGGER unregister_protected_object_id AFTER DELETE ON %I FOR EACH ROW EXECUTE FUNCTION unregister_protected_object_id()',
            source
        );
        EXECUTE format(
            'CREATE TRIGGER reject_protected_object_id_update BEFORE UPDATE OF id ON %I FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id) EXECUTE FUNCTION reject_protected_object_id_update()',
            source
        );
        EXECUTE format(
            'CREATE TRIGGER reject_protected_object_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION reject_protected_object_truncate()',
            source
        );
    END LOOP;
END
$triggers$;

ALTER TABLE action_applicability
    DROP CONSTRAINT action_applicability_object_kind_check;
ALTER TABLE action_applicability
    ADD CONSTRAINT action_applicability_object_kind_check
    CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy',
                           'credential', 'audit_log', 'signing_key', 'api_endpoint'));

ALTER TABLE action_assignment_rules
    DROP CONSTRAINT action_assignment_rules_object_kind_check;
ALTER TABLE action_assignment_rules
    ADD CONSTRAINT action_assignment_rules_object_kind_check
    CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy',
                           'credential', 'audit_log', 'signing_key', 'api_endpoint'));

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, object_kind, NULL
FROM actions
CROSS JOIN LATERAL (
    VALUES
        ('read', 'role'),
        ('read', 'policy'),
        ('manage', 'policy'),
        ('read', 'api_endpoint'),
        ('manage', 'api_endpoint'),
        ('execute', 'api_endpoint')
) AS additions(action_name, object_kind)
WHERE actions.name = additions.action_name
ON CONFLICT DO NOTHING;


-- Squashed from 027_tenant_admin_defaults.sql; fresh-install baseline.

-- Persist deployment-defined tenant-admin defaults so tenant creation can
-- apply them after startup, and safely identify Atom-owned tenant-admin RBAC.

ALTER TABLE roles DROP CONSTRAINT roles_managed_by_check;
ALTER TABLE roles ADD CONSTRAINT roles_managed_by_check
    CHECK (managed_by IS NULL OR managed_by IN ('config', 'system:tenant-admin'));

ALTER TABLE permission_blocks DROP CONSTRAINT permission_blocks_managed_by_check;
ALTER TABLE permission_blocks ADD CONSTRAINT permission_blocks_managed_by_check
    CHECK (managed_by IS NULL OR managed_by IN ('config', 'system:tenant-admin'));

CREATE TABLE tenant_admin_default_actions (
    action_id UUID PRIMARY KEY REFERENCES actions(id) ON DELETE CASCADE
);

-- Adopt only the exact RBAC shape created by bootstrap_tenant_admin for the
-- tenant creator. A user role that merely shares the name is not adopted.
WITH generated AS (
    SELECT r.id AS role_id, pb.id AS permission_block_id
    FROM roles r
    JOIN tenants t ON t.id = r.tenant_id
    JOIN role_assignments ra
      ON ra.role_id = r.id
     AND ra.tenant_id = r.tenant_id
     AND ra.subject_kind = 'entity'
     AND ra.subject_id = t.created_by
    JOIN role_permission_blocks rpb ON rpb.role_id = r.id
    JOIN permission_blocks pb
      ON pb.id = rpb.permission_block_id
     AND pb.tenant_id = r.tenant_id
    WHERE r.name = 'tenant-admin'
      AND r.description = 'Default tenant administration role'
      AND r.deleted_at IS NULL
      AND r.managed_by IS NULL
      AND pb.scope_mode = 'tenant'
      AND pb.effect = 'allow'
      AND pb.conditions = '{}'::jsonb
      AND pb.managed_by IS NULL
      AND (SELECT count(*) FROM role_permission_blocks links WHERE links.role_id = r.id) = 1
)
UPDATE roles r
SET managed_by = 'system:tenant-admin'
FROM generated g
WHERE r.id = g.role_id;

UPDATE permission_blocks pb
SET managed_by = 'system:tenant-admin'
FROM role_permission_blocks rpb
JOIN roles r ON r.id = rpb.role_id
WHERE pb.id = rpb.permission_block_id
  AND r.managed_by = 'system:tenant-admin';
