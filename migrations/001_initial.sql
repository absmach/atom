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
    route       TEXT,
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'inactive', 'frozen', 'deleted')),
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_by  UUID,
    updated_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_tenants_name ON tenants(name);
CREATE UNIQUE INDEX idx_tenants_route ON tenants(route) WHERE route IS NOT NULL;
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
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
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
    tenant_id          UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    status             TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes         JSONB       NOT NULL DEFAULT '{}',
    profile_id         UUID        REFERENCES profiles(id),
    profile_version_id UUID        REFERENCES profile_versions(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_entities_kind ON entities(kind);
CREATE INDEX idx_entities_tenant ON entities(tenant_id);
CREATE INDEX idx_entities_name ON entities(name);
CREATE INDEX idx_entities_attrs ON entities USING GIN(attributes);
CREATE INDEX idx_entities_profile ON entities(profile_id);
CREATE INDEX idx_entities_profile_version ON entities(profile_version_id);
CREATE UNIQUE INDEX idx_entities_name_tenant ON entities(name, tenant_id);

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
    kid         TEXT        PRIMARY KEY,
    algorithm   TEXT        NOT NULL DEFAULT 'ES256',
    public_key  TEXT        NOT NULL,
    private_key TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'primary'
                            CHECK (status IN ('primary', 'standby', 'retired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_signing_keys_status ON signing_keys(status);

CREATE TABLE groups (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    tenant_id   UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    description TEXT,
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_groups_tenant ON groups(tenant_id);
CREATE INDEX idx_groups_status ON groups(status);
CREATE INDEX idx_groups_attrs ON groups USING GIN(attributes);
CREATE UNIQUE INDEX idx_groups_name_tenant ON groups(name, tenant_id);

CREATE TABLE group_members (
    group_id    UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    entity_id   UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, entity_id)
);

CREATE INDEX idx_group_members_entity ON group_members(entity_id);

CREATE TABLE group_hierarchy (
    parent_id  UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    child_id   UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    tenant_id  UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (child_id),
    CHECK (parent_id <> child_id)
);

CREATE INDEX idx_group_hierarchy_parent ON group_hierarchy(parent_id);
CREATE INDEX idx_group_hierarchy_tenant ON group_hierarchy(tenant_id);

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
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_resources_kind ON resources(kind);
CREATE INDEX idx_resources_tenant ON resources(tenant_id);
CREATE INDEX idx_resources_owner ON resources(owner_id);
CREATE INDEX idx_resources_attrs ON resources USING GIN(attributes);

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
    scope_kind  TEXT        NOT NULL CHECK (scope_kind IN ('platform', 'tenant', 'object_kind', 'object_type', 'object')),
    scope_ref   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_roles_name_tenant_scope
    ON roles(name, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), scope_kind, COALESCE(scope_ref, ''));

CREATE INDEX idx_roles_scope ON roles(scope_kind, scope_ref);

CREATE TABLE capabilities (
    id              UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT    NOT NULL,
    resource_kind   TEXT,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, resource_kind)
);

CREATE TABLE role_capabilities (
    role_id         UUID    NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    capability_id   UUID    NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, capability_id)
);

CREATE TABLE policy_bindings (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    subject_kind        TEXT        NOT NULL CHECK (subject_kind IN ('entity', 'group')),
    subject_id          UUID        NOT NULL,
    grant_kind          TEXT        NOT NULL CHECK (grant_kind IN ('capability', 'role')),
    grant_id            UUID        NOT NULL,
    scope_kind          TEXT        NOT NULL CHECK (scope_kind IN ('platform', 'tenant', 'object_kind', 'object_type', 'object')),
    scope_ref           TEXT,
    effect              TEXT        NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    conditions          JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pb_tenant ON policy_bindings(tenant_id);
CREATE INDEX idx_pb_subject ON policy_bindings(subject_kind, subject_id);
CREATE INDEX idx_pb_grant ON policy_bindings(grant_kind, grant_id);
CREATE INDEX idx_pb_scope ON policy_bindings(scope_kind, scope_ref);

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

CREATE TABLE capability_assignment_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    entity_kind     TEXT        NOT NULL CHECK (entity_kind IN ('human', 'device', 'service', 'workload', 'application')),
    capability_name TEXT        NOT NULL,
    object_kind     TEXT        NOT NULL CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy', 'credential', 'audit_log')),
    object_type     TEXT,
    decision        TEXT        NOT NULL CHECK (decision IN ('allow', 'deny', 'require_override')),
    is_absolute     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_car_tenant ON capability_assignment_rules(tenant_id);
CREATE INDEX idx_car_lookup ON capability_assignment_rules(entity_kind, capability_name, object_kind);

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
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
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
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
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

INSERT INTO capabilities (name, resource_kind, description) VALUES
    ('read',                NULL, 'Read / view a resource'),
    ('write',               NULL, 'Create or update a resource'),
    ('delete',              NULL, 'Delete a resource'),
    ('publish',             NULL, 'Publish messages to a resource'),
    ('subscribe',           NULL, 'Subscribe to messages from a resource'),
    ('execute',             NULL, 'Execute a command or action'),
    ('manage',              NULL, 'Full administrative control'),
    ('list',                NULL, 'List resources'),
    ('credential.manage',   NULL, 'Manage credentials'),
    ('credential.revoke',   NULL, 'Revoke credentials'),
    ('signing_key.rotate',  NULL, 'Rotate JWT signing keys'),
    ('audit.read',          NULL, 'Read audit logs'),
    ('policy.manage',       NULL, 'Manage policies'),
    ('role.manage',         NULL, 'Manage roles'),
    ('tenant.manage',       NULL, 'Manage tenants (lifecycle and metadata)'),
    ('authz.check',         NULL, 'Evaluate authorization checks for other subjects'),
    ('tenant.create',       NULL, 'Create tenants/domains'),
    ('list',                'channel', 'List channels'),
    ('read',                'channel', 'Read channel metadata'),
    ('write',               'channel', 'Create or update channels'),
    ('delete',              'channel', 'Delete channels'),
    ('manage',              'channel', 'Manage channel policies and metadata'),
    ('publish',             'channel', 'Publish messages to channels'),
    ('subscribe',           'channel', 'Subscribe to channel messages'),
    ('list',                'rule', 'List rules'),
    ('read',                'rule', 'Read rule metadata'),
    ('write',               'rule', 'Create or update rules'),
    ('delete',              'rule', 'Delete rules'),
    ('manage',              'rule', 'Manage rule policies and metadata'),
    ('execute',             'rule', 'Execute rule actions'),
    ('list',                'alarm', 'List alarms'),
    ('read',                'alarm', 'Read alarm metadata'),
    ('write',               'alarm', 'Create or update alarms'),
    ('delete',              'alarm', 'Delete alarms'),
    ('manage',              'alarm', 'Manage alarm policies and metadata'),
    ('list',                'report', 'List reports'),
    ('read',                'report', 'Read report metadata'),
    ('write',               'report', 'Create or update reports'),
    ('delete',              'report', 'Delete reports'),
    ('manage',              'report', 'Manage report policies and metadata'),
    ('execute',             'report', 'Generate or send reports');

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

INSERT INTO roles (id, name, description, scope_kind, scope_ref)
VALUES
    (
        '00000000-0000-0000-0000-000000000002',
        'atom-admin',
        'Full administrative access',
        'platform',
        NULL
    ),
    (
        '00000000-0000-0000-0000-000000000004',
        'mg-service',
        'Magistrala service integration role',
        'platform',
        NULL
    ),
    (
        '00000000-0000-0000-0000-000000000006',
        'domain-creator',
        'Allows authenticated users to create their own tenants/domains',
        'platform',
        NULL
    );

INSERT INTO role_capabilities (role_id, capability_id)
SELECT '00000000-0000-0000-0000-000000000002', id
FROM capabilities;

INSERT INTO role_capabilities (role_id, capability_id)
SELECT '00000000-0000-0000-0000-000000000004', id
FROM capabilities
WHERE name IN (
    'manage', 'list', 'read', 'write', 'delete', 'publish', 'subscribe',
    'execute', 'policy.manage', 'role.manage', 'authz.check', 'credential.manage'
);

INSERT INTO role_capabilities (role_id, capability_id)
SELECT '00000000-0000-0000-0000-000000000006', id
FROM capabilities
WHERE name = 'tenant.create' AND resource_kind IS NULL;

INSERT INTO groups (id, name, tenant_id, description, status, attributes)
VALUES (
    '00000000-0000-0000-0000-000000000005',
    'authenticated-users',
    NULL,
    'All authenticated human users',
    'active',
    '{"system": true, "purpose": "default-self-service-domain-creation"}'::jsonb
);

INSERT INTO group_members (group_id, entity_id)
VALUES (
    '00000000-0000-0000-0000-000000000005',
    '00000000-0000-0000-0000-000000000001'
);

INSERT INTO policy_bindings
    (id, tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions)
VALUES
    (
        '00000000-0000-0000-0000-000000000001',
        NULL,
        'entity',
        '00000000-0000-0000-0000-000000000001',
        'role',
        '00000000-0000-0000-0000-000000000002',
        'platform',
        NULL,
        'allow',
        '{}'::jsonb
    ),
    (
        gen_random_uuid(),
        NULL,
        'entity',
        '00000000-0000-0000-0000-000000000003',
        'role',
        '00000000-0000-0000-0000-000000000004',
        'platform',
        NULL,
        'allow',
        '{}'::jsonb
    ),
    (
        gen_random_uuid(),
        NULL,
        'group',
        '00000000-0000-0000-0000-000000000005',
        'role',
        '00000000-0000-0000-0000-000000000006',
        'platform',
        NULL,
        'allow',
        '{}'::jsonb
    );

INSERT INTO capability_assignment_rules
    (entity_kind, capability_name, object_kind, object_type, decision, is_absolute)
VALUES
    ('device', 'manage', 'resource', NULL, 'deny', TRUE),
    ('device', 'delete', 'resource', NULL, 'deny', TRUE),
    ('device', 'write', 'resource', NULL, 'deny', TRUE),
    ('device', 'publish', 'resource', 'resource:channel', 'allow', FALSE),
    ('device', 'subscribe', 'resource', 'resource:channel', 'allow', FALSE),
    ('human', 'manage', 'resource', NULL, 'allow', FALSE),
    ('human', 'manage', 'entity', NULL, 'allow', FALSE),
    ('human', 'manage', 'group', NULL, 'allow', FALSE),
    ('human', 'policy.manage', 'policy', NULL, 'allow', FALSE),
    ('human', 'role.manage', 'role', NULL, 'allow', FALSE),
    ('service', 'manage', 'resource', NULL, 'allow', FALSE),
    ('service', 'policy.manage', 'policy', NULL, 'allow', FALSE),
    ('service', 'role.manage', 'role', NULL, 'allow', FALSE);
