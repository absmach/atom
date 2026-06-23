-- Atom initial schema.
--
-- This migration is intentionally squashed because Atom has not shipped a
-- released database contract yet. It creates the current schema directly and
-- seeds the platform data required by Atom and Magistrala.

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

CREATE UNIQUE INDEX idx_tenants_name ON tenants(name);
CREATE UNIQUE INDEX idx_tenants_alias
    ON tenants (lower(alias))
    WHERE alias IS NOT NULL;
CREATE INDEX idx_tenants_status ON tenants(status);
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
    );
CREATE UNIQUE INDEX idx_entities_alias
    ON entities (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(alias))
    WHERE alias IS NOT NULL;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES entities(id) ON DELETE SET NULL;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_updated_by_fkey
    FOREIGN KEY (updated_by) REFERENCES entities(id) ON DELETE SET NULL;

CREATE TABLE credentials (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind        TEXT        NOT NULL CHECK (kind IN ('password', 'api_key', 'certificate')),
    identifier  TEXT,
    secret_hash TEXT,
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
    email       TEXT        NOT NULL UNIQUE,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entity_id)
);

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
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    description TEXT,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ
);

CREATE INDEX idx_principal_groups_tenant ON principal_groups(tenant_id);
CREATE INDEX idx_principal_groups_status ON principal_groups(status);
CREATE INDEX idx_principal_groups_attrs ON principal_groups USING GIN(attributes);
CREATE UNIQUE INDEX idx_principal_groups_name_tenant ON principal_groups(name, tenant_id);

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
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    description TEXT,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_object_groups_tenant ON object_groups(tenant_id);
CREATE INDEX idx_object_groups_status ON object_groups(status);
CREATE INDEX idx_object_groups_attrs ON object_groups USING GIN(attributes);
CREATE UNIQUE INDEX idx_object_groups_name_tenant ON object_groups(name, tenant_id);

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
SELECT id, name, tenant_id, 'object'::text AS group_type, description, status, attributes, created_at, updated_at
FROM object_groups
UNION ALL
SELECT id, name, tenant_id, 'principal'::text AS group_type, description, status, attributes, created_at, updated_at
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
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    owner_id    UUID        REFERENCES entities(id) ON DELETE SET NULL,
    attributes  JSONB       NOT NULL DEFAULT '{}',
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
    WHERE alias IS NOT NULL;

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
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_roles_name_tenant
    ON roles(name, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

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
FROM role_assignments ra;
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

-- Single subject grant expansion: direct policies and role-linked permission
-- blocks for one subject, principal-group membership resolved recursively. Each
-- row is one fully expanded grant carrying its block's own scope/effect/
-- conditions and the assignment-level tenant boundary.
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
        JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
        WHERE gm.entity_id = p_entity_id
        UNION ALL
        SELECT gh.parent_id, parent.name || ' -> ' || sg.path
        FROM group_hierarchy gh
        JOIN subject_groups sg ON sg.group_id = gh.child_id
        JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active'
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
    JOIN roles r ON r.id = ra.role_id
    JOIN role_permission_blocks rpb ON rpb.role_id = ra.role_id
    JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
    JOIN permission_block_scopes pbs ON pbs.permission_block_id = pb.id
    JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
    LEFT JOIN subject_groups sg ON ra.subject_kind = 'group' AND sg.group_id = ra.subject_id
    WHERE (ra.subject_kind = 'entity' AND ra.subject_id = p_entity_id)
       OR (ra.subject_kind = 'group' AND sg.group_id IS NOT NULL)
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
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    entity_id   UUID        REFERENCES entities(id) ON DELETE SET NULL,
    event       TEXT        NOT NULL,
    outcome     TEXT        NOT NULL CHECK (outcome IN ('allow', 'deny', 'error')),
    details     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_entity ON audit_logs(entity_id);
CREATE INDEX idx_audit_event ON audit_logs(event);
CREATE INDEX idx_audit_time ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_tenant_time
    ON audit_logs(tenant_id, created_at DESC);
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
        'mg-service',
        'active',
        '{"system": true, "purpose": "magistrala-service-integration"}'::jsonb
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
        'mg-service',
        'Magistrala service integration role'
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
