-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================
-- ENTITIES
-- Every principal in the system (human, device, service, etc.)
-- =============================================================
CREATE TABLE entities (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        TEXT        NOT NULL CHECK (kind IN ('human', 'device', 'service', 'workload', 'application')),
    name        TEXT        NOT NULL,
    tenant_id   UUID,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_entities_kind      ON entities(kind);
CREATE INDEX idx_entities_tenant    ON entities(tenant_id);
CREATE INDEX idx_entities_name      ON entities(name);
CREATE INDEX idx_entities_attrs     ON entities USING GIN(attributes);
CREATE UNIQUE INDEX idx_entities_name_tenant ON entities(name, tenant_id);

-- =============================================================
-- CREDENTIALS
-- Multiple credentials per entity; supports password, api_key, cert
-- =============================================================
CREATE TABLE credentials (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind        TEXT        NOT NULL CHECK (kind IN ('password', 'api_key', 'certificate')),
    -- lookup identifier: username/email for passwords, key-prefix for api_keys
    identifier  TEXT,
    secret_hash TEXT,
    metadata    JSONB       NOT NULL DEFAULT '{}',
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_creds_entity     ON credentials(entity_id);
CREATE INDEX idx_creds_kind       ON credentials(kind);
CREATE INDEX idx_creds_identifier ON credentials(identifier);

-- =============================================================
-- SESSIONS
-- Tracks active auth sessions; JWT references a session row
-- =============================================================
CREATE TABLE sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_entity ON sessions(entity_id);
-- Partial index for active sessions (most lookups are for active ones)
CREATE INDEX idx_sessions_active ON sessions(id) WHERE revoked_at IS NULL;

-- =============================================================
-- GROUPS
-- Named collections of entities; scoped per tenant
-- =============================================================
CREATE TABLE groups (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    tenant_id   UUID,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_groups_tenant ON groups(tenant_id);
CREATE UNIQUE INDEX idx_groups_name_tenant ON groups(name, tenant_id);

-- =============================================================
-- GROUP MEMBERS
-- =============================================================
CREATE TABLE group_members (
    group_id    UUID        NOT NULL REFERENCES groups(id)   ON DELETE CASCADE,
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, entity_id)
);

CREATE INDEX idx_group_members_entity ON group_members(entity_id);

-- =============================================================
-- OWNERSHIPS
-- Parent-child relationship between entities
-- =============================================================
CREATE TABLE ownerships (
    owner_id    UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    owned_id    UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation    TEXT        NOT NULL DEFAULT 'owner',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, owned_id)
);

CREATE INDEX idx_ownerships_owner ON ownerships(owner_id);
CREATE INDEX idx_ownerships_owned ON ownerships(owned_id);

-- =============================================================
-- RESOURCES
-- Anything that can be protected by authorization
-- =============================================================
CREATE TABLE resources (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        TEXT        NOT NULL,
    name        TEXT,
    tenant_id   UUID,
    owner_id    UUID        REFERENCES entities(id) ON DELETE SET NULL,
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_resources_kind   ON resources(kind);
CREATE INDEX idx_resources_tenant ON resources(tenant_id);
CREATE INDEX idx_resources_owner  ON resources(owner_id);
CREATE INDEX idx_resources_attrs  ON resources USING GIN(attributes);

-- =============================================================
-- ROLES
-- Named bundles of capabilities
-- =============================================================
CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    tenant_id   UUID,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_roles_name_tenant ON roles(name, tenant_id);

-- =============================================================
-- CAPABILITIES
-- Atomic permissions; optionally scoped to a resource kind
-- =============================================================
CREATE TABLE capabilities (
    id              UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT    NOT NULL,
    resource_kind   TEXT,   -- NULL means applies to all resource kinds
    description     TEXT,
    UNIQUE (name, resource_kind)
);

-- =============================================================
-- ROLE CAPABILITIES
-- Many-to-many: roles bundle capabilities
-- =============================================================
CREATE TABLE role_capabilities (
    role_id         UUID    NOT NULL REFERENCES roles(id)         ON DELETE CASCADE,
    capability_id   UUID    NOT NULL REFERENCES capabilities(id)  ON DELETE CASCADE,
    PRIMARY KEY (role_id, capability_id)
);

-- =============================================================
-- POLICY BINDINGS
-- Grants a capability or role to a subject over a resource scope
-- =============================================================
CREATE TABLE policy_bindings (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- who: entity or group
    subject_kind        TEXT        NOT NULL CHECK (subject_kind IN ('entity', 'group')),
    subject_id          UUID        NOT NULL,
    -- what: capability or role
    grant_kind          TEXT        NOT NULL CHECK (grant_kind IN ('capability', 'role')),
    grant_id            UUID        NOT NULL,
    -- over what: specific resource, all of a kind, or everything
    scope_kind          TEXT        NOT NULL CHECK (scope_kind IN ('all', 'resource_kind', 'resource')),
    scope_ref           TEXT,       -- resource kind name OR resource UUID (as text)
    -- allow or deny
    effect              TEXT        NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    -- ABAC conditions: dot-path conditions evaluated against eval context
    conditions          JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pb_subject ON policy_bindings(subject_kind, subject_id);
CREATE INDEX idx_pb_grant   ON policy_bindings(grant_kind, grant_id);
CREATE INDEX idx_pb_scope   ON policy_bindings(scope_kind, scope_ref);

-- =============================================================
-- AUDIT LOG
-- Immutable record of authorization decisions and identity events
-- =============================================================
CREATE TABLE audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID        REFERENCES entities(id) ON DELETE SET NULL,
    event       TEXT        NOT NULL,
    outcome     TEXT        NOT NULL CHECK (outcome IN ('allow', 'deny', 'error')),
    details     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_entity ON audit_logs(entity_id);
CREATE INDEX idx_audit_event  ON audit_logs(event);
CREATE INDEX idx_audit_time   ON audit_logs(created_at DESC);

-- =============================================================
-- SEED: standard capabilities (no resource_kind = applies to all)
-- =============================================================
INSERT INTO capabilities (name, resource_kind, description) VALUES
    ('read',        NULL, 'Read / view a resource'),
    ('write',       NULL, 'Create or update a resource'),
    ('delete',      NULL, 'Delete a resource'),
    ('publish',     NULL, 'Publish messages to a resource'),
    ('subscribe',   NULL, 'Subscribe to messages from a resource'),
    ('execute',     NULL, 'Execute a command or action'),
    ('manage',      NULL, 'Full administrative control');
