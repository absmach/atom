-- Atom SQLite baseline schema.
--
-- Semantic mirror of migrations/001_initial.sql (the PostgreSQL baseline).
-- Encodings: UUID = 16-byte BLOB, timestamps = fixed-width RFC 3339 text with
-- microseconds and a Z suffix, JSON = TEXT guarded by json_valid, arrays = JSON
-- text, booleans = INTEGER 0/1. Table definitions, CHECK constraints, views and
-- indexes use only SQLite built-ins, so any SQLite tool can open, copy
-- (VACUUM INTO) and read the database. The invariant triggers call a few atom_*
-- functions that the application registers on every connection (see
-- src/db/sqlite_functions.rs); writes from another client would need them.

PRAGMA defer_foreign_keys = ON;

-- Tables

CREATE TABLE action_applicability (
    action_id BLOB NOT NULL,
    object_kind TEXT NOT NULL,
    object_type TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT action_applicability_action_id_fkey FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    CONSTRAINT action_applicability_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT action_applicability_object_kind_check CHECK ((object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy', 'credential', 'audit_log', 'signing_key', 'api_endpoint')))
);

CREATE TABLE action_assignment_rules (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB,
    entity_kind TEXT NOT NULL,
    action_name TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    object_type TEXT,
    decision TEXT NOT NULL,
    is_absolute INTEGER NOT NULL DEFAULT 0 CHECK (is_absolute IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT action_assignment_rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT action_assignment_rules_decision_check CHECK ((decision IN ('allow', 'deny', 'require_override'))),
    CONSTRAINT action_assignment_rules_entity_kind_check CHECK ((entity_kind IN ('human', 'device', 'service', 'workload', 'application'))),
    CONSTRAINT action_assignment_rules_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT action_assignment_rules_object_kind_check CHECK ((object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy', 'credential', 'audit_log', 'signing_key', 'api_endpoint')))
);

CREATE TABLE actions (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT actions_name_key UNIQUE (name),
    CONSTRAINT actions_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config')))
);

CREATE TABLE api_endpoint_executions (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    endpoint_id BLOB,
    caller_entity_id BLOB,
    status TEXT NOT NULL,
    request_summary TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(request_summary)),
    response_summary TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(response_summary)),
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT api_endpoint_executions_caller_entity_id_fkey FOREIGN KEY (caller_entity_id) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT api_endpoint_executions_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES api_endpoints(id) ON DELETE SET NULL,
    CONSTRAINT api_endpoint_executions_status_check CHECK ((status IN ('success', 'error', 'denied')))
);

CREATE TABLE api_endpoints (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    operation_kind TEXT NOT NULL,
    graphql TEXT NOT NULL,
    auth_mode TEXT NOT NULL DEFAULT 'caller_context',
    service_entity_id BLOB,
    variables_mapping TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(variables_mapping)),
    request_schema TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(request_schema)),
    response_mapping TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(response_mapping)),
    status TEXT NOT NULL DEFAULT 'draft',
    created_by BLOB,
    updated_by BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    CONSTRAINT api_endpoints_created_by_fkey FOREIGN KEY (created_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT api_endpoints_service_entity_id_fkey FOREIGN KEY (service_entity_id) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT api_endpoints_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT api_endpoints_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT api_endpoints_auth_mode_check CHECK ((auth_mode IN ('caller_context', 'service_context'))),
    CONSTRAINT api_endpoints_method_check CHECK ((method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'))),
    CONSTRAINT api_endpoints_operation_kind_check CHECK ((operation_kind IN ('query', 'mutation'))),
    CONSTRAINT api_endpoints_status_check CHECK ((status IN ('draft', 'active', 'disabled')))
);

CREATE TABLE audit_logs (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    actor_entity_id BLOB,
    tenant_id BLOB,
    target_kind TEXT,
    target_id BLOB,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT audit_logs_actor_entity_id_fkey FOREIGN KEY (actor_entity_id) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT audit_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
    CONSTRAINT audit_logs_outcome_check CHECK ((outcome IN ('allow', 'deny', 'error')))
);

CREATE TABLE auth_exchange_codes (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT auth_exchange_codes_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE auth_login_attempts (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    identifier TEXT NOT NULL,
    tenant_id BLOB,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT auth_login_attempts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE certificate_crl_state (
    issuer_fingerprint_sha256 TEXT NOT NULL,
    crl_number INTEGER NOT NULL DEFAULT 0,
    crl_der BLOB,
    this_update TEXT,
    next_update TEXT,
    dirty INTEGER NOT NULL DEFAULT 1 CHECK (dirty IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    issuer_id BLOB PRIMARY KEY NOT NULL,
    crl_sha256 TEXT,
    CONSTRAINT certificate_crl_state_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES pki_authorities(id) ON DELETE CASCADE,
    CONSTRAINT chk_certificate_crl_state_hash CHECK ((((crl_der IS NULL) AND (crl_sha256 IS NULL)) OR ((crl_der IS NOT NULL) AND (length(crl_sha256) = 64 AND crl_sha256 NOT GLOB '*[^0-9a-f]*'))))
);

CREATE TABLE certificate_issuance_requests (
    id BLOB PRIMARY KEY NOT NULL,
    entity_id BLOB NOT NULL,
    request_key_hash TEXT NOT NULL,
    request_fingerprint_sha256 TEXT NOT NULL,
    credential_id BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    completed_at TEXT,
    CONSTRAINT certificate_issuance_requests_credential_id_key UNIQUE (credential_id),
    CONSTRAINT uq_certificate_issuance_request_key UNIQUE (entity_id, request_key_hash),
    CONSTRAINT certificate_issuance_requests_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE,
    CONSTRAINT certificate_issuance_requests_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT certificate_issuance_requests_request_fingerprint_sha256_check CHECK ((length(request_fingerprint_sha256) = 64 AND request_fingerprint_sha256 NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT certificate_issuance_requests_request_key_hash_check CHECK ((length(request_key_hash) = 64 AND request_key_hash NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT chk_certificate_issuance_request_state CHECK ((((credential_id IS NULL) AND (completed_at IS NULL)) OR ((credential_id IS NOT NULL) AND (completed_at IS NOT NULL))))
);

CREATE TABLE certificate_profiles (
    id BLOB PRIMARY KEY NOT NULL,
    tenant_id BLOB,
    base_profile_id BLOB,
    name TEXT NOT NULL,
    permitted_key_algorithms TEXT NOT NULL CHECK (json_valid(permitted_key_algorithms)),
    default_ttl_seconds INTEGER NOT NULL,
    maximum_ttl_seconds INTEGER NOT NULL,
    renewal_threshold_seconds INTEGER NOT NULL,
    key_usages TEXT NOT NULL CHECK (json_valid(key_usages) AND json_type(key_usages) = 'array'),
    extended_key_usages TEXT NOT NULL CHECK (json_valid(extended_key_usages) AND json_type(extended_key_usages) = 'array'),
    san_policy TEXT NOT NULL CHECK (json_valid(san_policy)),
    identity_uri_template TEXT NOT NULL,
    basic_constraints TEXT NOT NULL CHECK (json_valid(basic_constraints)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT certificate_profiles_base_profile_id_fkey FOREIGN KEY (base_profile_id) REFERENCES certificate_profiles(id) ON DELETE RESTRICT,
    CONSTRAINT certificate_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT certificate_profiles_basic_constraints_check CHECK ((json_type(basic_constraints, '$.ca') = 'false' AND json_type(basic_constraints, '$.path_len') = 'null' AND json_remove(basic_constraints, '$.ca', '$.path_len') = '{}')),
    CONSTRAINT certificate_profiles_default_ttl_seconds_check CHECK ((default_ttl_seconds > 0)),
    CONSTRAINT certificate_profiles_identity_uri_template_check CHECK ((identity_uri_template = 'urn:atom:{scope}entity:{entity_id}')),
    CONSTRAINT certificate_profiles_maximum_ttl_seconds_check CHECK ((maximum_ttl_seconds > 0)),
    CONSTRAINT certificate_profiles_name_check CHECK ((length(name) BETWEEN 1 AND 63 AND name GLOB '[a-z]*' AND name NOT GLOB '*[^a-z0-9_-]*')),
    CONSTRAINT certificate_profiles_permitted_key_algorithms_check CHECK (((json_type(permitted_key_algorithms) = 'array') AND (json_array_length(permitted_key_algorithms) > 0))),
    CONSTRAINT certificate_profiles_renewal_threshold_seconds_check CHECK ((renewal_threshold_seconds > 0)),
    CONSTRAINT certificate_profiles_san_policy_check CHECK ((json_valid(san_policy) AND json_type(san_policy) = 'object' AND json_remove(san_policy, '$.dns', '$.ip', '$.email', '$.uri') = '{}' AND json_type(san_policy, '$.dns') = 'object' AND json_type(san_policy, '$.dns.mode') = 'text' AND json_type(san_policy, '$.dns.values') = 'array' AND json_remove(json_extract(san_policy, '$.dns'), '$.mode', '$.values') = '{}' AND json_type(san_policy, '$.ip') = 'object' AND json_type(san_policy, '$.ip.mode') = 'text' AND json_type(san_policy, '$.ip.values') = 'array' AND json_remove(json_extract(san_policy, '$.ip'), '$.mode', '$.values') = '{}' AND json_type(san_policy, '$.email') = 'object' AND json_type(san_policy, '$.email.mode') = 'text' AND json_type(san_policy, '$.email.values') = 'array' AND json_remove(json_extract(san_policy, '$.email'), '$.mode', '$.values') = '{}' AND json_type(san_policy, '$.uri') = 'object' AND json_type(san_policy, '$.uri.mode') = 'text' AND json_type(san_policy, '$.uri.values') = 'array' AND json_remove(json_extract(san_policy, '$.uri'), '$.mode', '$.values') = '{}' AND json_extract(san_policy, '$.dns.mode') IN ('deny', 'allowlist', 'entity_template') AND json_extract(san_policy, '$.ip.mode') IN ('deny', 'allowlist') AND json_extract(san_policy, '$.email.mode') IN ('deny', 'allowlist') AND json_extract(san_policy, '$.uri.mode') = 'identity' AND json_array_length(san_policy, '$.uri.values') = 0)),
    CONSTRAINT chk_certificate_profiles_extended_key_usages CHECK (((json_valid(extended_key_usages) AND replace(replace(replace(replace(replace(replace(json(extended_key_usages), '"server_auth"', ''), '"client_auth"', ''), '"code_signing"', ''), '"email_protection"', ''), '"time_stamping"', ''), '"ocsp_signing"', '') NOT GLOB '*[^],[]*'))),
    CONSTRAINT chk_certificate_profiles_leaf_key_usages CHECK (((json_valid(key_usages) AND replace(replace(replace(replace(replace(json(key_usages), '"digital_signature"', ''), '"content_commitment"', ''), '"key_encipherment"', ''), '"data_encipherment"', ''), '"key_agreement"', '') NOT GLOB '*[^],[]*'))),
    CONSTRAINT chk_certificate_profiles_nonempty_extended_key_usages CHECK ((json_array_length(extended_key_usages) > 0)),
    CONSTRAINT chk_certificate_profiles_nonempty_key_usages CHECK ((json_array_length(key_usages) > 0)),
    CONSTRAINT chk_certificate_profiles_nonzero_id CHECK ((id <> x'00000000000000000000000000000000')),
    CONSTRAINT chk_certificate_profiles_scope CHECK ((((tenant_id IS NULL) AND (base_profile_id IS NULL)) OR ((tenant_id IS NOT NULL) AND (base_profile_id IS NOT NULL)))),
    CONSTRAINT chk_certificate_profiles_ttl CHECK (((default_ttl_seconds <= maximum_ttl_seconds) AND (renewal_threshold_seconds <= maximum_ttl_seconds)))
);

CREATE TABLE certificate_renewals (
    id BLOB PRIMARY KEY NOT NULL,
    previous_credential_id BLOB NOT NULL,
    request_key_hash TEXT NOT NULL,
    request_fingerprint_sha256 TEXT NOT NULL,
    key_mode TEXT NOT NULL,
    replacement_credential_id BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    completed_at TEXT,
    CONSTRAINT certificate_renewals_previous_credential_id_key UNIQUE (previous_credential_id),
    CONSTRAINT certificate_renewals_replacement_credential_id_key UNIQUE (replacement_credential_id),
    CONSTRAINT certificate_renewals_previous_credential_id_fkey FOREIGN KEY (previous_credential_id) REFERENCES credentials(id) ON DELETE CASCADE,
    CONSTRAINT certificate_renewals_replacement_credential_id_fkey FOREIGN KEY (replacement_credential_id) REFERENCES credentials(id) ON DELETE CASCADE,
    CONSTRAINT certificate_renewals_key_mode_check CHECK ((key_mode IN ('csr', 'generated'))),
    CONSTRAINT certificate_renewals_request_fingerprint_sha256_check CHECK ((length(request_fingerprint_sha256) = 64 AND request_fingerprint_sha256 NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT certificate_renewals_request_key_hash_check CHECK ((length(request_key_hash) = 64 AND request_key_hash NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT chk_certificate_renewal_state CHECK ((((replacement_credential_id IS NULL) AND (completed_at IS NULL)) OR ((replacement_credential_id IS NOT NULL) AND (completed_at IS NOT NULL))))
);

CREATE TABLE certificate_revocations (
    credential_id BLOB PRIMARY KEY NOT NULL,
    issuer_id BLOB,
    issuer_fingerprint_sha256 TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_entity_id BLOB,
    revoked_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    expires_at TEXT NOT NULL,
    CONSTRAINT certificate_revocations_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES pki_authorities(id) ON DELETE SET NULL,
    CONSTRAINT certificate_revocations_issuer_fingerprint_sha256_check CHECK ((length(issuer_fingerprint_sha256) = 64 AND issuer_fingerprint_sha256 NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT certificate_revocations_reason_check CHECK (((length(trim(reason)) >= 1) AND (length(trim(reason)) <= 128))),
    CONSTRAINT certificate_revocations_serial_number_check CHECK ((length(serial_number) >= 1 AND serial_number NOT GLOB '*[^0-9a-f]*'))
);

CREATE TABLE credential_permission_limit_actions (
    limit_id BLOB NOT NULL,
    action_id BLOB NOT NULL,
    PRIMARY KEY (limit_id, action_id),
    CONSTRAINT credential_permission_limit_actions_action_id_fkey FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    CONSTRAINT credential_permission_limit_actions_limit_id_fkey FOREIGN KEY (limit_id) REFERENCES credential_permission_limits(id) ON DELETE CASCADE
);

CREATE TABLE credential_permission_limits (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    credential_id BLOB NOT NULL,
    scope_mode TEXT NOT NULL,
    tenant_id BLOB,
    object_kind TEXT,
    object_type TEXT,
    object_id BLOB,
    conditions TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(conditions)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT credential_permission_limits_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE,
    CONSTRAINT credential_permission_limits_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT credential_permission_limits_conditions_is_object CHECK ((json_type(conditions) = 'object')),
    CONSTRAINT credential_permission_limits_scope_mode_check CHECK ((scope_mode IN ('platform', 'tenant', 'object_kind', 'object_type', 'object'))),
    CONSTRAINT credential_permission_limits_scope_shape CHECK ((((scope_mode = 'platform') AND (tenant_id IS NULL) AND (object_id IS NULL) AND (object_kind IS NULL) AND (object_type IS NULL)) OR ((scope_mode = 'tenant') AND (tenant_id IS NOT NULL) AND (object_id IS NULL) AND (object_kind IS NULL) AND (object_type IS NULL)) OR ((scope_mode = 'object_kind') AND (object_kind IS NOT NULL) AND (object_id IS NULL) AND (object_type IS NULL)) OR ((scope_mode = 'object_type') AND (object_kind IS NOT NULL) AND (object_type IS NOT NULL) AND (object_id IS NULL)) OR ((scope_mode = 'object') AND (object_id IS NOT NULL) AND (tenant_id IS NULL))))
);

CREATE TABLE credentials (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    kind TEXT NOT NULL,
    identifier TEXT,
    secret_hash TEXT,
    scoped INTEGER NOT NULL DEFAULT 0 CHECK (scoped IN (0, 1)),
    secret_ciphertext BLOB,
    secret_nonce BLOB,
    secret_key_id TEXT,
    secret_enc_alg TEXT,
    secret_lookup_hash BLOB,
    metadata TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata)),
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    last_used_at TEXT,
    managed_by TEXT,
    issuer_id BLOB,
    CONSTRAINT credentials_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT credentials_issuer_id_fkey FOREIGN KEY (issuer_id) REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    CONSTRAINT chk_credentials_issuer_certificate_only CHECK ((((kind = 'certificate') AND (issuer_id IS NOT NULL)) OR ((kind = 'certificate') AND (issuer_id IS NULL) AND (NOT ((metadata ->> 'issuer_migration') IS DISTINCT FROM 'legacy_unmanaged'))) OR ((kind <> 'certificate') AND (issuer_id IS NULL)))),
    CONSTRAINT credentials_kind_check CHECK ((kind IN ('password', 'access_token', 'certificate', 'shared_key'))),
    CONSTRAINT credentials_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT credentials_status_check CHECK (((status IN ('active', 'revoked')) OR ((kind = 'certificate') AND (status = 'revocation_pending'))))
);

CREATE TABLE direct_policies (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB,
    subject_kind TEXT NOT NULL,
    subject_id BLOB NOT NULL,
    permission_block_id BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT direct_policies_permission_block_id_fkey FOREIGN KEY (permission_block_id) REFERENCES permission_blocks(id) ON DELETE CASCADE,
    CONSTRAINT direct_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT direct_policies_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT direct_policies_subject_kind_check CHECK ((subject_kind IN ('entity', 'group')))
);

CREATE TABLE email_verification_tokens (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    email_id BLOB NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT email_verification_tokens_email_id_fkey FOREIGN KEY (email_id) REFERENCES entity_emails(id) ON DELETE CASCADE,
    CONSTRAINT email_verification_tokens_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE entities (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    tenant_id BLOB,
    status TEXT NOT NULL DEFAULT 'active',
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    profile_id BLOB,
    profile_version_id BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    deleted_at TEXT,
    deleted_by BLOB,
    alias TEXT,
    managed_by TEXT,
    external_id TEXT,
    CONSTRAINT entities_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT entities_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id),
    CONSTRAINT entities_profile_version_id_fkey FOREIGN KEY (profile_version_id) REFERENCES profile_versions(id),
    CONSTRAINT entities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_entities_alias_not_uuid CHECK (((alias IS NULL) OR (NOT ((length(alias) = 32 AND alias NOT GLOB '*[^0-9a-f]*') OR alias GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')))),
    CONSTRAINT chk_entities_alias_slug CHECK (((alias IS NULL) OR (length(alias) BETWEEN 1 AND 63 AND alias NOT GLOB '*[^a-z0-9-]*' AND alias NOT GLOB '-*' AND alias NOT GLOB '*-'))),
    CONSTRAINT chk_entities_external_id_length CHECK (((external_id IS NULL) OR ((length(external_id) >= 1) AND (length(external_id) <= 255)))),
    CONSTRAINT chk_entities_external_id_trimmed CHECK (((external_id IS NULL) OR (substr(external_id, 1, 1) NOT IN (' ', char(9), char(10), char(11), char(12), char(13)) AND substr(external_id, -1, 1) NOT IN (' ', char(9), char(10), char(11), char(12), char(13))))),
    CONSTRAINT entities_kind_check CHECK ((kind IN ('human', 'device', 'service', 'workload', 'application'))),
    CONSTRAINT entities_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT entities_status_check CHECK ((status IN ('active', 'inactive', 'suspended')))
);

CREATE TABLE entity_emails (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    email TEXT NOT NULL,
    verified_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    deleted_at TEXT,
    CONSTRAINT entity_emails_entity_id_key UNIQUE (entity_id),
    CONSTRAINT entity_emails_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE event_outbox (
    id BLOB PRIMARY KEY NOT NULL,
    event TEXT NOT NULL,
    actor_entity_id BLOB,
    tenant_id BLOB,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    delivered_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    unparseable INTEGER NOT NULL DEFAULT 0 CHECK (unparseable IN (0, 1))
);

CREATE TABLE object_group_entities (
    group_id BLOB NOT NULL,
    entity_id BLOB NOT NULL,
    tenant_id BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (group_id, entity_id),
    CONSTRAINT object_group_entities_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT object_group_entities_group_id_fkey FOREIGN KEY (group_id) REFERENCES object_groups(id) ON DELETE CASCADE,
    CONSTRAINT object_group_entities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE object_group_hierarchy (
    parent_id BLOB NOT NULL,
    child_id BLOB PRIMARY KEY NOT NULL,
    tenant_id BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT object_group_hierarchy_child_id_fkey FOREIGN KEY (child_id) REFERENCES object_groups(id) ON DELETE CASCADE,
    CONSTRAINT object_group_hierarchy_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES object_groups(id) ON DELETE CASCADE,
    CONSTRAINT object_group_hierarchy_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT object_group_hierarchy_check CHECK ((parent_id <> child_id))
);

CREATE TABLE principal_group_hierarchy (
    parent_id BLOB NOT NULL,
    child_id BLOB PRIMARY KEY NOT NULL,
    tenant_id BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT principal_group_hierarchy_child_id_fkey FOREIGN KEY (child_id) REFERENCES principal_groups(id) ON DELETE CASCADE,
    CONSTRAINT principal_group_hierarchy_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES principal_groups(id) ON DELETE CASCADE,
    CONSTRAINT principal_group_hierarchy_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT principal_group_hierarchy_check CHECK ((parent_id <> child_id))
);

CREATE TABLE principal_group_members (
    group_id BLOB NOT NULL,
    entity_id BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (group_id, entity_id),
    CONSTRAINT principal_group_members_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT principal_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES principal_groups(id) ON DELETE CASCADE
);

CREATE TABLE object_group_resources (
    group_id BLOB NOT NULL,
    resource_id BLOB NOT NULL,
    tenant_id BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (group_id, resource_id),
    CONSTRAINT object_group_resources_group_id_fkey FOREIGN KEY (group_id) REFERENCES object_groups(id) ON DELETE CASCADE,
    CONSTRAINT object_group_resources_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    CONSTRAINT object_group_resources_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE object_groups (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    name TEXT NOT NULL,
    tenant_id BLOB,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    deleted_at TEXT,
    deleted_by BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT object_groups_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT object_groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT object_groups_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT object_groups_status_check CHECK ((status IN ('active', 'inactive', 'suspended')))
);

CREATE TABLE principal_groups (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    name TEXT NOT NULL,
    tenant_id BLOB,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    deleted_at TEXT,
    deleted_by BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    managed_by TEXT,
    CONSTRAINT principal_groups_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT principal_groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT principal_groups_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT principal_groups_status_check CHECK ((status IN ('active', 'inactive', 'suspended')))
);

CREATE TABLE oauth_identities (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    profile TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(profile)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT oauth_identities_provider_subject_key UNIQUE (provider, subject),
    CONSTRAINT oauth_identities_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE oauth_login_states (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    provider TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    return_to TEXT,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')
);

CREATE TABLE ownerships (
    owner_id BLOB NOT NULL,
    owned_id BLOB NOT NULL,
    relation TEXT NOT NULL DEFAULT 'owner',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (owner_id, owned_id),
    CONSTRAINT ownerships_owned_id_fkey FOREIGN KEY (owned_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT ownerships_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE password_reset_tokens (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    email_id BLOB NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT password_reset_tokens_email_id_fkey FOREIGN KEY (email_id) REFERENCES entity_emails(id) ON DELETE CASCADE,
    CONSTRAINT password_reset_tokens_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE permission_block_actions (
    permission_block_id BLOB NOT NULL,
    action_id BLOB NOT NULL,
    PRIMARY KEY (permission_block_id, action_id),
    CONSTRAINT permission_block_actions_action_id_fkey FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    CONSTRAINT permission_block_actions_permission_block_id_fkey FOREIGN KEY (permission_block_id) REFERENCES permission_blocks(id) ON DELETE CASCADE
);

CREATE TABLE permission_blocks (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB,
    scope_mode TEXT NOT NULL,
    object_kind TEXT,
    object_type TEXT,
    object_id BLOB,
    group_id BLOB,
    effect TEXT NOT NULL DEFAULT 'allow',
    conditions TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(conditions)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT permission_blocks_group_id_fkey FOREIGN KEY (group_id) REFERENCES object_groups(id) ON DELETE CASCADE,
    CONSTRAINT permission_blocks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT permission_blocks_conditions_is_object CHECK ((json_type(conditions) = 'object')),
    CONSTRAINT permission_blocks_effect_check CHECK ((effect IN ('allow', 'deny'))),
    CONSTRAINT permission_blocks_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by IN ('config', 'system:tenant-admin')))),
    CONSTRAINT permission_blocks_scope_mode_check CHECK ((scope_mode IN ('platform', 'tenant', 'object_kind', 'object_type', 'object', 'group', 'group_direct_objects', 'group_descendant_objects', 'group_child_groups', 'group_descendant_groups'))),
    CONSTRAINT permission_blocks_scope_shape CHECK ((((scope_mode = 'platform') AND (tenant_id IS NULL) AND (object_id IS NULL) AND (object_kind IS NULL) AND (object_type IS NULL) AND (group_id IS NULL)) OR ((scope_mode = 'tenant') AND (tenant_id IS NOT NULL) AND (object_id IS NULL) AND (object_kind IS NULL) AND (object_type IS NULL) AND (group_id IS NULL)) OR ((scope_mode = 'object_kind') AND (object_kind IS NOT NULL) AND (object_id IS NULL) AND (object_type IS NULL) AND (group_id IS NULL)) OR ((scope_mode = 'object_type') AND (object_kind IS NOT NULL) AND (object_type IS NOT NULL) AND (object_id IS NULL) AND (group_id IS NULL)) OR ((scope_mode = 'object') AND (object_id IS NOT NULL) AND (group_id IS NULL)) OR ((scope_mode = 'group') AND (tenant_id IS NOT NULL) AND (group_id IS NOT NULL) AND (object_id IS NULL) AND (object_kind IS NULL) AND (object_type IS NULL)) OR ((scope_mode IN ('group_direct_objects', 'group_descendant_objects')) AND (tenant_id IS NOT NULL) AND (group_id IS NOT NULL) AND (object_kind IN ('entity', 'resource')) AND (object_id IS NULL)) OR ((scope_mode IN ('group_child_groups', 'group_descendant_groups')) AND (tenant_id IS NOT NULL) AND (group_id IS NOT NULL) AND (object_id IS NULL) AND (object_kind IS NULL) AND (object_type IS NULL))))
);

CREATE TABLE pki_authorities (
    id BLOB PRIMARY KEY NOT NULL,
    tenant_id BLOB,
    parent_id BLOB,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    issuance_enabled INTEGER NOT NULL DEFAULT 0 CHECK (issuance_enabled IN (0, 1)),
    subject TEXT NOT NULL,
    serial_number TEXT,
    fingerprint_sha256 TEXT,
    subject_key_id TEXT,
    authority_key_id TEXT,
    certificate_pem TEXT,
    chain_pem TEXT,
    not_before TEXT,
    not_after TEXT,
    key_backend TEXT NOT NULL,
    key_reference TEXT,
    encrypted_private_key BLOB,
    private_key_nonce BLOB,
    wrapped_dek BLOB,
    wrapped_dek_nonce BLOB,
    key_encryption_key_id TEXT,
    encryption_algorithm TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    activated_at TEXT,
    retiring_at TEXT,
    retired_at TEXT,
    provisioning_mode TEXT NOT NULL DEFAULT 'imported',
    csr_pem TEXT,
    failure_reason TEXT,
    ocsp_url TEXT,
    ca_issuers_url TEXT,
    crl_distribution_point_url TEXT,
    CONSTRAINT pki_authorities_fingerprint_sha256_key UNIQUE (fingerprint_sha256),
    CONSTRAINT pki_authorities_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    CONSTRAINT pki_authorities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_pki_authorities_artifact_urls CHECK ((((ocsp_url IS NULL) AND (ca_issuers_url IS NULL) AND (crl_distribution_point_url IS NULL)) OR (((ocsp_url GLOB 'http://?*' OR ocsp_url GLOB 'https://?*') AND instr(ocsp_url, ' ') = 0 AND instr(ocsp_url, char(9)) = 0 AND instr(ocsp_url, char(10)) = 0 AND instr(ocsp_url, char(13)) = 0) AND ((ca_issuers_url GLOB 'http://?*' OR ca_issuers_url GLOB 'https://?*') AND instr(ca_issuers_url, ' ') = 0 AND instr(ca_issuers_url, char(9)) = 0 AND instr(ca_issuers_url, char(10)) = 0 AND instr(ca_issuers_url, char(13)) = 0) AND ((crl_distribution_point_url GLOB 'http://?*' OR crl_distribution_point_url GLOB 'https://?*') AND instr(crl_distribution_point_url, ' ') = 0 AND instr(crl_distribution_point_url, char(9)) = 0 AND instr(crl_distribution_point_url, char(10)) = 0 AND instr(crl_distribution_point_url, char(13)) = 0)))),
    CONSTRAINT chk_pki_authorities_completed_material CHECK (((status IN ('provisioning', 'pending_signature', 'failed')) OR ((serial_number IS NOT NULL) AND (fingerprint_sha256 IS NOT NULL) AND (certificate_pem IS NOT NULL) AND (chain_pem IS NOT NULL) AND (not_before IS NOT NULL) AND (not_after IS NOT NULL)))),
    CONSTRAINT chk_pki_authorities_failure_reason CHECK ((((status = 'failed') AND (NULLIF(trim(failure_reason), '') IS NOT NULL)) OR ((status <> 'failed') AND (failure_reason IS NULL)))),
    CONSTRAINT chk_pki_authorities_key_storage CHECK ((((key_backend = 'public_only') AND (key_reference IS NULL) AND (encrypted_private_key IS NULL) AND (private_key_nonce IS NULL) AND (wrapped_dek IS NULL) AND (wrapped_dek_nonce IS NULL) AND (key_encryption_key_id IS NULL) AND (encryption_algorithm IS NULL)) OR ((key_backend = 'encrypted_database') AND (key_reference IS NULL) AND (encrypted_private_key IS NOT NULL) AND (private_key_nonce IS NOT NULL) AND (wrapped_dek IS NOT NULL) AND (wrapped_dek_nonce IS NOT NULL) AND (key_encryption_key_id IS NOT NULL) AND (encryption_algorithm IS NOT NULL)) OR ((key_backend IN ('pkcs11', 'kms')) AND (NULLIF(trim(key_reference), '') IS NOT NULL) AND (encrypted_private_key IS NULL) AND (private_key_nonce IS NULL) AND (wrapped_dek IS NULL) AND (wrapped_dek_nonce IS NULL) AND (key_encryption_key_id IS NULL) AND (encryption_algorithm IS NULL)))),
    CONSTRAINT chk_pki_authorities_leaf_issuance CHECK (((NOT issuance_enabled) OR ((kind IN ('platform_leaf_issuer', 'tenant_intermediate')) AND (status = 'active') AND (key_backend <> 'public_only')))),
    CONSTRAINT chk_pki_authorities_nonzero_id CHECK ((id <> x'00000000000000000000000000000000')),
    CONSTRAINT chk_pki_authorities_not_self_parent CHECK (((parent_id IS NULL) OR (parent_id <> id))),
    CONSTRAINT chk_pki_authorities_pending_csr CHECK (((status NOT IN ('provisioning', 'pending_signature')) OR ((kind <> 'root') AND (key_backend <> 'public_only') AND (NULLIF(trim(csr_pem), '') IS NOT NULL)))),
    CONSTRAINT chk_pki_authorities_scope CHECK ((((kind = 'root') AND (tenant_id IS NULL) AND (parent_id IS NULL)) OR ((kind IN ('platform_intermediate', 'platform_leaf_issuer')) AND (tenant_id IS NULL) AND (parent_id IS NOT NULL)) OR ((kind = 'tenant_intermediate') AND (tenant_id IS NOT NULL) AND (parent_id IS NOT NULL)))),
    CONSTRAINT chk_pki_authorities_validity CHECK ((not_after > not_before)),
    CONSTRAINT pki_authorities_fingerprint_sha256_check CHECK ((length(fingerprint_sha256) = 64 AND fingerprint_sha256 NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT pki_authorities_key_backend_check CHECK ((key_backend IN ('public_only', 'encrypted_database', 'pkcs11', 'kms'))),
    CONSTRAINT pki_authorities_kind_check CHECK ((kind IN ('root', 'platform_intermediate', 'platform_leaf_issuer', 'tenant_intermediate'))),
    CONSTRAINT pki_authorities_provisioning_mode_check CHECK ((provisioning_mode IN ('imported', 'offline', 'automated', 'config_bootstrap'))),
    CONSTRAINT pki_authorities_serial_number_check CHECK ((length(serial_number) >= 1 AND serial_number NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT pki_authorities_status_check CHECK ((status IN ('provisioning', 'pending_signature', 'active', 'retiring', 'retired', 'revoked', 'expired', 'failed'))),
    CONSTRAINT pki_authorities_version_check CHECK ((version > 0))
);

CREATE TABLE pki_enrollment_rate_windows (
    scope_kind TEXT NOT NULL,
    scope_id BLOB NOT NULL,
    window_start TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (scope_kind, scope_id, window_start),
    CONSTRAINT pki_enrollment_rate_windows_request_count_check CHECK ((request_count > 0)),
    CONSTRAINT pki_enrollment_rate_windows_scope_kind_check CHECK ((scope_kind IN ('entity', 'tenant')))
);

CREATE TABLE pki_lifecycle_notifications (
    subject_kind TEXT NOT NULL,
    subject_id BLOB NOT NULL,
    window_kind TEXT NOT NULL,
    window_at TEXT NOT NULL,
    emitted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (subject_kind, subject_id, window_kind),
    CONSTRAINT pki_lifecycle_notifications_subject_id_check CHECK ((subject_id <> x'00000000000000000000000000000000')),
    CONSTRAINT pki_lifecycle_notifications_subject_kind_check CHECK ((subject_kind IN ('credential', 'authority'))),
    CONSTRAINT pki_lifecycle_notifications_window_kind_check CHECK ((window_kind IN ('renewal', 'expiry', 'authority_expiry')))
);

CREATE TABLE profile_versions (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    profile_id BLOB NOT NULL,
    version INTEGER NOT NULL,
    json_schema TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(json_schema)),
    ui_schema TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(ui_schema)),
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT profile_versions_profile_id_version_key UNIQUE (profile_id, version),
    CONSTRAINT profile_versions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT profile_versions_status_check CHECK ((status IN ('draft', 'active', 'deprecated', 'disabled')))
);

CREATE TABLE profiles (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB,
    object_kind TEXT NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    CONSTRAINT profiles_check CHECK (((object_kind <> 'entity') OR (kind IN ('human', 'device', 'service', 'workload', 'application')))),
    CONSTRAINT profiles_object_kind_check CHECK ((object_kind IN ('entity', 'resource', 'group', 'tenant', 'credential'))),
    CONSTRAINT profiles_status_check CHECK ((status IN ('active', 'deprecated', 'disabled')))
);

CREATE TABLE protected_object_ids (
    id BLOB PRIMARY KEY NOT NULL,
    object_kind TEXT NOT NULL,
    source_table TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT protected_object_ids_source_kind_check CHECK ((((source_table = 'tenants') AND (object_kind = 'tenant')) OR ((source_table = 'entities') AND (object_kind = 'entity')) OR ((source_table = 'resources') AND (object_kind = 'resource')) OR ((source_table = 'principal_groups') AND (object_kind = 'group')) OR ((source_table = 'object_groups') AND (object_kind = 'group')) OR ((source_table = 'roles') AND (object_kind = 'role')) OR ((source_table = 'credentials') AND (object_kind = 'credential')) OR ((source_table = 'direct_policies') AND (object_kind = 'policy')) OR ((source_table = 'role_assignments') AND (object_kind = 'policy')) OR ((source_table = 'api_endpoints') AND (object_kind = 'api_endpoint'))))
);

CREATE TABLE resources (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    kind TEXT NOT NULL,
    name TEXT,
    tenant_id BLOB,
    owner_id BLOB,
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    deleted_at TEXT,
    deleted_by BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    alias TEXT,
    managed_by TEXT,
    CONSTRAINT resources_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT resources_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT resources_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_resources_alias_not_uuid CHECK (((alias IS NULL) OR (NOT ((length(alias) = 32 AND alias NOT GLOB '*[^0-9a-f]*') OR alias GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')))),
    CONSTRAINT chk_resources_alias_slug CHECK (((alias IS NULL) OR (length(alias) BETWEEN 1 AND 63 AND alias NOT GLOB '*[^a-z0-9-]*' AND alias NOT GLOB '-*' AND alias NOT GLOB '*-'))),
    CONSTRAINT resources_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config')))
);

CREATE TABLE role_assignments (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB,
    subject_kind TEXT NOT NULL,
    subject_id BLOB NOT NULL,
    role_id BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    managed_by TEXT,
    CONSTRAINT role_assignments_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT role_assignments_subject_kind_check CHECK ((subject_kind IN ('entity', 'group')))
);

CREATE TABLE role_permission_blocks (
    id BLOB GENERATED ALWAYS AS (permission_block_id) STORED,
    role_id BLOB NOT NULL,
    permission_block_id BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (role_id, permission_block_id),
    CONSTRAINT role_permission_blocks_permission_block_id_fkey FOREIGN KEY (permission_block_id) REFERENCES permission_blocks(id) ON DELETE CASCADE,
    CONSTRAINT role_permission_blocks_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE roles (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    name TEXT NOT NULL,
    tenant_id BLOB,
    description TEXT,
    deleted_at TEXT,
    deleted_by BLOB,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    managed_by TEXT,
    CONSTRAINT roles_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT roles_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by IN ('config', 'system:tenant-admin'))))
);

CREATE TABLE sessions (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    entity_id BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CONSTRAINT sessions_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'ES256',
    public_key TEXT NOT NULL,
    private_key TEXT,
    status TEXT NOT NULL DEFAULT 'primary',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    private_key_ciphertext BLOB,
    private_key_nonce BLOB,
    private_key_key_id TEXT,
    private_key_encryption_alg TEXT,
    CONSTRAINT signing_keys_status_check CHECK ((status IN ('primary', 'standby', 'retired')))
);

CREATE TABLE tenant_admin_default_actions (
    action_id BLOB PRIMARY KEY NOT NULL,
    CONSTRAINT tenant_admin_default_actions_action_id_fkey FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
);

CREATE TABLE tenant_invitations (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    tenant_id BLOB NOT NULL,
    invitee_user_id BLOB,
    invitee_email TEXT,
    invited_by BLOB NOT NULL,
    role_id BLOB,
    secret_hash TEXT,
    expires_at TEXT,
    accepted_by BLOB,
    accepted_at TEXT,
    rejected_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    CONSTRAINT tenant_invitations_accepted_by_fkey FOREIGN KEY (accepted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT tenant_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT tenant_invitations_invitee_user_id_fkey FOREIGN KEY (invitee_user_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT tenant_invitations_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL,
    CONSTRAINT tenant_invitations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE tenant_memberships (
    tenant_id BLOB NOT NULL,
    entity_id BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    local_name TEXT,
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (tenant_id, entity_id),
    CONSTRAINT tenant_memberships_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    CONSTRAINT tenant_memberships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT tenant_memberships_status_check CHECK ((status IN ('active', 'invited', 'suspended', 'left')))
);

CREATE TABLE tenants (
    id BLOB PRIMARY KEY NOT NULL DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    name TEXT NOT NULL,
    alias TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    tags TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags) AND json_type(tags) = 'array'),
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    created_by BLOB,
    updated_by BLOB,
    deleted_by BLOB,
    deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at TEXT,
    managed_by TEXT,
    CONSTRAINT tenants_created_by_fkey FOREIGN KEY (created_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT tenants_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT tenants_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES entities(id) ON DELETE SET NULL,
    CONSTRAINT chk_tenants_alias_not_uuid CHECK (((alias IS NULL) OR (NOT ((length(alias) = 32 AND alias NOT GLOB '*[^0-9a-f]*') OR alias GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')))),
    CONSTRAINT chk_tenants_alias_slug CHECK (((alias IS NULL) OR (length(alias) BETWEEN 1 AND 63 AND alias NOT GLOB '*[^a-z0-9-]*' AND alias NOT GLOB '-*' AND alias NOT GLOB '*-'))),
    CONSTRAINT tenants_managed_by_check CHECK (((managed_by IS NULL) OR (managed_by = 'config'))),
    CONSTRAINT tenants_status_check CHECK ((status IN ('active', 'inactive', 'frozen', 'deleted')))
);

-- Views

CREATE VIEW credential_permission_limit_scopes AS
SELECT id AS limit_id,
       scope_mode AS scope_kind,
       CASE
           WHEN scope_mode = 'platform' THEN NULL
           WHEN scope_mode = 'tenant' THEN CASE WHEN tenant_id IS NULL THEN NULL ELSE substr(lower(hex(tenant_id)), 1, 8) || '-' || substr(lower(hex(tenant_id)), 9, 4) || '-' || substr(lower(hex(tenant_id)), 13, 4) || '-' || substr(lower(hex(tenant_id)), 17, 4) || '-' || substr(lower(hex(tenant_id)), 21, 12) END
           WHEN scope_mode = 'object_kind' THEN object_kind
           WHEN scope_mode = 'object_type' THEN object_type
           WHEN scope_mode = 'object' THEN CASE WHEN object_id IS NULL THEN NULL ELSE substr(lower(hex(object_id)), 1, 8) || '-' || substr(lower(hex(object_id)), 9, 4) || '-' || substr(lower(hex(object_id)), 13, 4) || '-' || substr(lower(hex(object_id)), 17, 4) || '-' || substr(lower(hex(object_id)), 21, 12) END
           ELSE NULL
       END AS scope_ref
FROM credential_permission_limits;

CREATE VIEW permission_block_scopes AS
SELECT id AS permission_block_id,
       CASE
        WHEN scope_mode = 'group_direct_objects' THEN 'group_object_type'
        WHEN scope_mode = 'group_descendant_objects' THEN 'group_tree_object_type'
        WHEN scope_mode = 'group_child_groups' THEN 'group_child_kind'
        WHEN scope_mode = 'group_descendant_groups' THEN 'group_descendant_kind'
        ELSE scope_mode
    END AS scope_kind,
       CASE
        WHEN scope_mode = 'platform' THEN NULL
        WHEN scope_mode = 'tenant' THEN CASE WHEN tenant_id IS NULL THEN NULL ELSE substr(lower(hex(tenant_id)), 1, 8) || '-' || substr(lower(hex(tenant_id)), 9, 4) || '-' || substr(lower(hex(tenant_id)), 13, 4) || '-' || substr(lower(hex(tenant_id)), 17, 4) || '-' || substr(lower(hex(tenant_id)), 21, 12) END
        WHEN scope_mode = 'object_kind' THEN object_kind
        WHEN scope_mode = 'object_type' THEN object_type
        WHEN scope_mode = 'object' THEN CASE WHEN object_id IS NULL THEN NULL ELSE substr(lower(hex(object_id)), 1, 8) || '-' || substr(lower(hex(object_id)), 9, 4) || '-' || substr(lower(hex(object_id)), 13, 4) || '-' || substr(lower(hex(object_id)), 17, 4) || '-' || substr(lower(hex(object_id)), 21, 12) END
        WHEN scope_mode = 'group' THEN CASE WHEN group_id IS NULL THEN NULL ELSE substr(lower(hex(group_id)), 1, 8) || '-' || substr(lower(hex(group_id)), 9, 4) || '-' || substr(lower(hex(group_id)), 13, 4) || '-' || substr(lower(hex(group_id)), 17, 4) || '-' || substr(lower(hex(group_id)), 21, 12) END || ':group'
        WHEN scope_mode IN ('group_direct_objects', 'group_descendant_objects') THEN CASE WHEN group_id IS NULL THEN NULL ELSE substr(lower(hex(group_id)), 1, 8) || '-' || substr(lower(hex(group_id)), 9, 4) || '-' || substr(lower(hex(group_id)), 13, 4) || '-' || substr(lower(hex(group_id)), 17, 4) || '-' || substr(lower(hex(group_id)), 21, 12) END || ':' || object_type
        WHEN scope_mode IN ('group_child_groups', 'group_descendant_groups') THEN CASE WHEN group_id IS NULL THEN NULL ELSE substr(lower(hex(group_id)), 1, 8) || '-' || substr(lower(hex(group_id)), 9, 4) || '-' || substr(lower(hex(group_id)), 13, 4) || '-' || substr(lower(hex(group_id)), 17, 4) || '-' || substr(lower(hex(group_id)), 21, 12) END || ':group'
        ELSE NULL
    END AS scope_ref
FROM permission_blocks;

CREATE VIEW group_entity_parents AS
SELECT group_id, entity_id, tenant_id, created_at, updated_at
FROM object_group_entities;

CREATE VIEW group_resource_parents AS
SELECT group_id, resource_id, tenant_id, created_at, updated_at
FROM object_group_resources;

CREATE VIEW group_members AS
SELECT group_id, entity_id, created_at
FROM principal_group_members;

CREATE VIEW group_hierarchy AS
SELECT parent_id, child_id, tenant_id, created_at, updated_at
FROM principal_group_hierarchy
UNION ALL
SELECT parent_id, child_id, tenant_id, created_at, updated_at
FROM object_group_hierarchy;

CREATE VIEW groups AS
SELECT id, name, tenant_id, 'object' AS group_type, description, status, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by
FROM object_groups
UNION ALL
SELECT id, name, tenant_id, 'principal' AS group_type, description, status, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by
FROM principal_groups;

CREATE VIEW effective_access_edges AS
SELECT dp.id AS id,
       dp.tenant_id AS tenant_id,
       dp.subject_kind AS subject_kind,
       dp.subject_id AS subject_id,
       'capability' AS grant_kind,
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
        WHEN pb.scope_mode = 'tenant' THEN CASE WHEN pb.tenant_id IS NULL THEN NULL ELSE substr(lower(hex(pb.tenant_id)), 1, 8) || '-' || substr(lower(hex(pb.tenant_id)), 9, 4) || '-' || substr(lower(hex(pb.tenant_id)), 13, 4) || '-' || substr(lower(hex(pb.tenant_id)), 17, 4) || '-' || substr(lower(hex(pb.tenant_id)), 21, 12) END
        WHEN pb.scope_mode = 'object_kind' THEN pb.object_kind
        WHEN pb.scope_mode = 'object_type' THEN pb.object_type
        WHEN pb.scope_mode = 'object' THEN CASE WHEN pb.object_id IS NULL THEN NULL ELSE substr(lower(hex(pb.object_id)), 1, 8) || '-' || substr(lower(hex(pb.object_id)), 9, 4) || '-' || substr(lower(hex(pb.object_id)), 13, 4) || '-' || substr(lower(hex(pb.object_id)), 17, 4) || '-' || substr(lower(hex(pb.object_id)), 21, 12) END
        WHEN pb.scope_mode = 'group' THEN CASE WHEN pb.group_id IS NULL THEN NULL ELSE substr(lower(hex(pb.group_id)), 1, 8) || '-' || substr(lower(hex(pb.group_id)), 9, 4) || '-' || substr(lower(hex(pb.group_id)), 13, 4) || '-' || substr(lower(hex(pb.group_id)), 17, 4) || '-' || substr(lower(hex(pb.group_id)), 21, 12) END || ':group'
        WHEN pb.scope_mode IN ('group_direct_objects', 'group_descendant_objects') THEN CASE WHEN pb.group_id IS NULL THEN NULL ELSE substr(lower(hex(pb.group_id)), 1, 8) || '-' || substr(lower(hex(pb.group_id)), 9, 4) || '-' || substr(lower(hex(pb.group_id)), 13, 4) || '-' || substr(lower(hex(pb.group_id)), 17, 4) || '-' || substr(lower(hex(pb.group_id)), 21, 12) END || ':' || pb.object_type
        WHEN pb.scope_mode IN ('group_child_groups', 'group_descendant_groups') THEN CASE WHEN pb.group_id IS NULL THEN NULL ELSE substr(lower(hex(pb.group_id)), 1, 8) || '-' || substr(lower(hex(pb.group_id)), 9, 4) || '-' || substr(lower(hex(pb.group_id)), 13, 4) || '-' || substr(lower(hex(pb.group_id)), 17, 4) || '-' || substr(lower(hex(pb.group_id)), 21, 12) END || ':group'
        ELSE NULL
    END AS scope_ref,
       pb.effect AS effect,
       pb.conditions AS conditions,
       dp.created_at AS created_at
FROM direct_policies dp
JOIN permission_blocks pb ON pb.id = dp.permission_block_id
JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
UNION ALL
SELECT ra.id,
       ra.tenant_id,
       ra.subject_kind,
       ra.subject_id,
       'role',
       ra.role_id,
       CASE WHEN ra.tenant_id IS NULL THEN 'platform' ELSE 'tenant' END,
       CASE WHEN ra.tenant_id IS NULL THEN NULL ELSE substr(lower(hex(ra.tenant_id)), 1, 8) || '-' || substr(lower(hex(ra.tenant_id)), 9, 4) || '-' || substr(lower(hex(ra.tenant_id)), 13, 4) || '-' || substr(lower(hex(ra.tenant_id)), 17, 4) || '-' || substr(lower(hex(ra.tenant_id)), 21, 12) END,
       'allow',
       '{}',
       ra.created_at
FROM role_assignments ra
JOIN roles r ON r.id = ra.role_id AND r.deleted_at IS NULL;

CREATE VIEW effective_role_actions AS
SELECT rpb.role_id AS role_id, pba.action_id AS capability_id
FROM role_permission_blocks rpb
JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id;


-- Indexes

CREATE INDEX idx_aar_lookup ON action_assignment_rules (entity_kind, action_name, object_kind);
CREATE INDEX idx_aar_tenant ON action_assignment_rules (tenant_id);
CREATE UNIQUE INDEX idx_aar_unique_rule ON action_assignment_rules (COALESCE(tenant_id, x'00000000000000000000000000000000'), entity_kind, action_name, object_kind, COALESCE(object_type, ''));
CREATE INDEX idx_action_applicability_object ON action_applicability (object_kind, object_type);
CREATE UNIQUE INDEX idx_action_applicability_unique ON action_applicability (action_id, object_kind, COALESCE(object_type, ''));
CREATE INDEX idx_api_endpoint_executions_caller ON api_endpoint_executions (caller_entity_id, created_at DESC);
CREATE INDEX idx_api_endpoint_executions_endpoint ON api_endpoint_executions (endpoint_id, created_at DESC);
CREATE UNIQUE INDEX idx_api_endpoints_active_method_path ON api_endpoints (method, path) WHERE (status = 'active');
CREATE UNIQUE INDEX idx_api_endpoints_global_key ON api_endpoints (key) WHERE (tenant_id IS NULL);
CREATE INDEX idx_api_endpoints_status ON api_endpoints (status);
CREATE INDEX idx_api_endpoints_tenant ON api_endpoints (tenant_id);
CREATE UNIQUE INDEX idx_api_endpoints_tenant_key ON api_endpoints (tenant_id, key) WHERE (tenant_id IS NOT NULL);
CREATE INDEX idx_audit_actor ON audit_logs (actor_entity_id);
CREATE INDEX idx_audit_event ON audit_logs (event);
CREATE INDEX idx_audit_event_time ON audit_logs (event, created_at DESC);
CREATE INDEX idx_audit_target ON audit_logs (target_kind, target_id);
CREATE INDEX idx_audit_target_time ON audit_logs (target_kind, target_id, created_at DESC);
CREATE INDEX idx_audit_tenant ON audit_logs (tenant_id);
CREATE INDEX idx_audit_tenant_time ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX idx_audit_time ON audit_logs (created_at DESC);
CREATE INDEX idx_auth_exchange_codes_active ON auth_exchange_codes (id) WHERE (consumed_at IS NULL);
CREATE INDEX idx_auth_login_attempts_created ON auth_login_attempts (created_at DESC);
CREATE INDEX idx_auth_login_attempts_throttle ON auth_login_attempts (identifier, tenant_id, created_at DESC) WHERE (success = false);
CREATE UNIQUE INDEX idx_certificate_crl_state_fingerprint ON certificate_crl_state (issuer_fingerprint_sha256);
CREATE INDEX idx_certificate_issuance_requests_credential ON certificate_issuance_requests (credential_id) WHERE (credential_id IS NOT NULL);
CREATE INDEX idx_certificate_profiles_base ON certificate_profiles (base_profile_id);
CREATE UNIQUE INDEX idx_certificate_profiles_platform_name ON certificate_profiles (name) WHERE (tenant_id IS NULL);
CREATE UNIQUE INDEX idx_certificate_profiles_tenant_name ON certificate_profiles (tenant_id, name) WHERE (tenant_id IS NOT NULL);
CREATE INDEX idx_certificate_renewals_replacement ON certificate_renewals (replacement_credential_id) WHERE (replacement_credential_id IS NOT NULL);
CREATE INDEX idx_certificate_revocations_issuer ON certificate_revocations (issuer_id, revoked_at DESC) WHERE (issuer_id IS NOT NULL);
CREATE INDEX idx_certificate_revocations_issuer_fingerprint ON certificate_revocations (issuer_fingerprint_sha256, revoked_at DESC);
CREATE UNIQUE INDEX idx_certificate_revocations_issuer_serial ON certificate_revocations (issuer_id, serial_number) WHERE (issuer_id IS NOT NULL);
CREATE INDEX idx_credential_permission_limit_actions_action ON credential_permission_limit_actions (action_id);
CREATE INDEX idx_credential_permission_limits_credential ON credential_permission_limits (credential_id);
CREATE INDEX idx_credentials_certificate_expiry_listing ON credentials (expires_at, id) WHERE ((kind = 'certificate') AND (expires_at IS NOT NULL));
CREATE UNIQUE INDEX idx_credentials_certificate_fingerprint ON credentials (((metadata ->> 'fingerprint_sha256'))) WHERE ((kind = 'certificate') AND (NULLIF((metadata ->> 'fingerprint_sha256'), '') IS NOT NULL));
CREATE INDEX idx_credentials_certificate_issuer ON credentials (issuer_id, status, expires_at) WHERE (kind = 'certificate');
CREATE UNIQUE INDEX idx_credentials_certificate_issuer_serial ON credentials (issuer_id, identifier) WHERE ((kind = 'certificate') AND (identifier IS NOT NULL));
CREATE INDEX idx_credentials_certificate_status_expiry ON credentials (kind, status, expires_at) WHERE (kind = 'certificate');
CREATE INDEX idx_credentials_shared_key_lookup ON credentials (entity_id, secret_lookup_hash, expires_at) WHERE ((kind = 'shared_key') AND (status = 'active') AND (secret_lookup_hash IS NOT NULL));
CREATE INDEX idx_credentials_shared_key_status ON credentials (entity_id, status, expires_at) WHERE (kind = 'shared_key');
CREATE INDEX idx_creds_entity ON credentials (entity_id);
CREATE INDEX idx_creds_identifier ON credentials (identifier);
CREATE INDEX idx_creds_kind ON credentials (kind);
CREATE INDEX idx_direct_policies_block ON direct_policies (permission_block_id);
CREATE INDEX idx_direct_policies_subject ON direct_policies (subject_kind, subject_id);
CREATE INDEX idx_direct_policies_tenant ON direct_policies (tenant_id);
CREATE INDEX idx_email_verification_tokens_active ON email_verification_tokens (id) WHERE (consumed_at IS NULL);
CREATE INDEX idx_email_verification_tokens_entity ON email_verification_tokens (entity_id);
CREATE UNIQUE INDEX idx_entities_alias ON entities (COALESCE(tenant_id, x'00000000000000000000000000000000'), lower(alias)) WHERE ((alias IS NOT NULL) AND (deleted_at IS NULL));
CREATE INDEX idx_entities_deleted_at ON entities (deleted_at) WHERE (deleted_at IS NOT NULL);
CREATE UNIQUE INDEX idx_entities_external_id ON entities (external_id, COALESCE(tenant_id, x'00000000000000000000000000000000')) WHERE ((external_id IS NOT NULL) AND (deleted_at IS NULL));
CREATE INDEX idx_entities_kind ON entities (kind);
CREATE INDEX idx_entities_name ON entities (name);
CREATE UNIQUE INDEX idx_entities_name_tenant ON entities (name, COALESCE(tenant_id, x'00000000000000000000000000000000')) WHERE (deleted_at IS NULL);
CREATE INDEX idx_entities_profile ON entities (profile_id);
CREATE INDEX idx_entities_profile_version ON entities (profile_version_id);
CREATE INDEX idx_entities_tenant ON entities (tenant_id);
CREATE UNIQUE INDEX idx_entity_emails_email ON entity_emails (lower(email)) WHERE (deleted_at IS NULL);
CREATE INDEX idx_entity_emails_entity ON entity_emails (entity_id);
CREATE INDEX idx_entity_emails_verified ON entity_emails (verified_at);
CREATE INDEX idx_event_outbox_retention ON event_outbox (created_at) WHERE ((delivered_at IS NOT NULL) OR ((unparseable = true) AND (attempts >= 10)));
CREATE INDEX idx_event_outbox_undelivered ON event_outbox (created_at) WHERE (delivered_at IS NULL);
CREATE INDEX idx_oauth_identities_email ON oauth_identities (email);
CREATE INDEX idx_oauth_identities_entity ON oauth_identities (entity_id);
CREATE INDEX idx_oauth_login_states_active ON oauth_login_states (id) WHERE (consumed_at IS NULL);
CREATE INDEX idx_object_group_entities_entity ON object_group_entities (entity_id);
CREATE INDEX idx_object_group_entities_tenant ON object_group_entities (tenant_id);
CREATE INDEX idx_object_group_hierarchy_parent ON object_group_hierarchy (parent_id);
CREATE INDEX idx_object_group_hierarchy_tenant ON object_group_hierarchy (tenant_id);
CREATE INDEX idx_object_group_resources_resource ON object_group_resources (resource_id);
CREATE INDEX idx_object_group_resources_tenant ON object_group_resources (tenant_id);
CREATE INDEX idx_object_groups_deleted_at ON object_groups (deleted_at) WHERE (deleted_at IS NOT NULL);
CREATE UNIQUE INDEX idx_object_groups_name_tenant ON object_groups (name, tenant_id) WHERE (deleted_at IS NULL);
CREATE INDEX idx_object_groups_status ON object_groups (status);
CREATE INDEX idx_object_groups_tenant ON object_groups (tenant_id);
CREATE INDEX idx_ownerships_owned ON ownerships (owned_id);
CREATE INDEX idx_ownerships_owner ON ownerships (owner_id);
CREATE INDEX idx_password_reset_tokens_entity ON password_reset_tokens (entity_id, created_at DESC);
CREATE INDEX idx_permission_block_actions_action ON permission_block_actions (action_id);
CREATE INDEX idx_permission_blocks_group ON permission_blocks (group_id);
CREATE INDEX idx_permission_blocks_object ON permission_blocks (object_id);
CREATE INDEX idx_permission_blocks_scope ON permission_blocks (scope_mode, object_kind, object_type);
CREATE INDEX idx_permission_blocks_tenant ON permission_blocks (tenant_id);
CREATE INDEX idx_pki_authorities_expiry ON pki_authorities (not_after);
CREATE UNIQUE INDEX idx_pki_authorities_global_kind_version ON pki_authorities (kind, version) WHERE (tenant_id IS NULL);
CREATE UNIQUE INDEX idx_pki_authorities_one_active_platform_intermediate ON pki_authorities ((true)) WHERE ((kind = 'platform_intermediate') AND (status = 'active'));
CREATE UNIQUE INDEX idx_pki_authorities_one_leaf_issuer_per_tenant ON pki_authorities (tenant_id) WHERE ((kind = 'tenant_intermediate') AND (issuance_enabled = true));
CREATE UNIQUE INDEX idx_pki_authorities_one_pending_global_kind ON pki_authorities (kind) WHERE ((tenant_id IS NULL) AND (kind IN ('platform_intermediate', 'platform_leaf_issuer')) AND (status IN ('provisioning', 'pending_signature')));
CREATE UNIQUE INDEX idx_pki_authorities_one_pending_tenant ON pki_authorities (tenant_id) WHERE ((kind = 'tenant_intermediate') AND (status IN ('provisioning', 'pending_signature')));
CREATE UNIQUE INDEX idx_pki_authorities_one_platform_leaf_issuer ON pki_authorities ((true)) WHERE ((kind = 'platform_leaf_issuer') AND (issuance_enabled = true));
CREATE INDEX idx_pki_authorities_parent ON pki_authorities (parent_id);
CREATE INDEX idx_pki_authorities_status ON pki_authorities (status);
CREATE INDEX idx_pki_authorities_tenant ON pki_authorities (tenant_id);
CREATE UNIQUE INDEX idx_pki_authorities_tenant_kind_version ON pki_authorities (tenant_id, kind, version) WHERE (tenant_id IS NOT NULL);
CREATE INDEX idx_pki_enrollment_rate_windows_updated ON pki_enrollment_rate_windows (updated_at);
CREATE INDEX idx_pki_lifecycle_notifications_emitted ON pki_lifecycle_notifications (emitted_at);
CREATE INDEX idx_principal_group_hierarchy_parent ON principal_group_hierarchy (parent_id);
CREATE INDEX idx_principal_group_hierarchy_tenant ON principal_group_hierarchy (tenant_id);
CREATE INDEX idx_principal_group_members_entity ON principal_group_members (entity_id);
CREATE INDEX idx_principal_groups_deleted_at ON principal_groups (deleted_at) WHERE (deleted_at IS NOT NULL);
CREATE UNIQUE INDEX idx_principal_groups_name_tenant ON principal_groups (name, tenant_id) WHERE (deleted_at IS NULL);
CREATE INDEX idx_principal_groups_status ON principal_groups (status);
CREATE INDEX idx_principal_groups_tenant ON principal_groups (tenant_id);
CREATE INDEX idx_profile_versions_profile ON profile_versions (profile_id);
CREATE UNIQUE INDEX idx_profiles_global_unique ON profiles (object_kind, kind, key) WHERE (tenant_id IS NULL);
CREATE INDEX idx_profiles_lookup ON profiles (object_kind, kind, key, tenant_id);
CREATE UNIQUE INDEX idx_profiles_tenant_unique ON profiles (tenant_id, object_kind, kind, key) WHERE (tenant_id IS NOT NULL);
CREATE UNIQUE INDEX idx_resources_alias ON resources (COALESCE(tenant_id, x'00000000000000000000000000000000'), lower(alias)) WHERE ((alias IS NOT NULL) AND (deleted_at IS NULL));
CREATE INDEX idx_resources_deleted_at ON resources (deleted_at) WHERE (deleted_at IS NOT NULL);
CREATE INDEX idx_resources_kind ON resources (kind);
CREATE INDEX idx_resources_owner ON resources (owner_id);
CREATE INDEX idx_resources_tenant ON resources (tenant_id);
CREATE INDEX idx_role_assignments_role ON role_assignments (role_id);
CREATE INDEX idx_role_assignments_subject ON role_assignments (subject_kind, subject_id);
CREATE INDEX idx_role_assignments_tenant ON role_assignments (tenant_id);
CREATE INDEX idx_role_permission_blocks_block ON role_permission_blocks (permission_block_id);
CREATE INDEX idx_roles_deleted_at ON roles (deleted_at) WHERE (deleted_at IS NOT NULL);
CREATE UNIQUE INDEX idx_roles_name_tenant ON roles (name, COALESCE(tenant_id, x'00000000000000000000000000000000')) WHERE (deleted_at IS NULL);
CREATE INDEX idx_sessions_active ON sessions (id) WHERE (revoked_at IS NULL);
CREATE INDEX idx_sessions_entity ON sessions (entity_id);
CREATE INDEX idx_signing_keys_status ON signing_keys (status);
CREATE INDEX idx_tenant_invitations_invitee ON tenant_invitations (invitee_user_id, created_at DESC) WHERE (invitee_user_id IS NOT NULL);
CREATE INDEX idx_tenant_invitations_tenant ON tenant_invitations (tenant_id, created_at DESC);
CREATE UNIQUE INDEX idx_tenant_invitations_tenant_invitee_email ON tenant_invitations (tenant_id, lower(invitee_email)) WHERE (invitee_email IS NOT NULL);
CREATE UNIQUE INDEX idx_tenant_invitations_tenant_invitee_user ON tenant_invitations (tenant_id, invitee_user_id) WHERE (invitee_user_id IS NOT NULL);
CREATE INDEX idx_tenant_invitations_token_active ON tenant_invitations (id) WHERE ((secret_hash IS NOT NULL) AND (accepted_at IS NULL) AND (revoked_at IS NULL));
CREATE INDEX idx_tenant_memberships_entity ON tenant_memberships (entity_id);
CREATE INDEX idx_tenant_memberships_status ON tenant_memberships (status);
CREATE UNIQUE INDEX idx_tenants_alias ON tenants (lower(alias)) WHERE ((alias IS NOT NULL) AND (deleted_at IS NULL));
CREATE INDEX idx_tenants_deleted_at ON tenants (deleted_at) WHERE (deleted_at IS NOT NULL);
CREATE UNIQUE INDEX idx_tenants_name ON tenants (name) WHERE (deleted_at IS NULL);
CREATE INDEX idx_tenants_status ON tenants (status);

-- Seed data

INSERT INTO actions (id, name, description, created_at, updated_at, managed_by) VALUES
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'read', 'Read / view an object', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4a946e4fd9284a928e1ca41b2e43719f', 'create', 'Create an object', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'write', 'Create or update an object', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'delete', 'Delete an object', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'3128fec0f70b439d99cad391c6acf213', 'revoke', 'Revoke an object or credential', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'1503e6935d704361a756af437dd0b60e', 'rotate', 'Rotate a key or secret material', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'cf485b74537149b0b6b9bde721a3a775', 'publish', 'Publish messages to a channel', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'5ffc337833e940a1ac846f95906871da', 'subscribe', 'Subscribe to channel messages', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'eb1810a5be8b40499078df20d87cee96', 'execute', 'Execute a command or action', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'manage', 'Full administrative control', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'887c5d5edb504c1da3df81e21d0d8ca3', 'policy.manage', 'Manage assignments and policy records', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd8c8da7a94814ddb89e739f1368641b6', 'role.manage', 'Manage roles', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'186bc3d4da2b4e529fa1ae74737f5eb8', 'authz.check', 'Evaluate authorization checks for other subjects', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'cb157e08ada44a688477c935ec7c7d56', 'pki.provision', 'Manage PKI authority provisioning and lifecycle', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'421a48d476f04dc0af2a0fcf257a6787', 'pki.provision_automated', 'Use the platform CA signer for automated authority provisioning', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL);

INSERT INTO action_applicability (action_id, object_kind, object_type, created_at, managed_by) VALUES
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'entity', 'entity:human', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'entity', 'entity:human', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'entity', 'entity:human', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'entity', 'entity:device', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'entity', 'entity:device', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'entity', 'entity:device', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'entity', 'entity:service', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'entity', 'entity:service', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'entity', 'entity:service', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'entity', 'entity:workload', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'entity', 'entity:workload', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'entity', 'entity:workload', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'entity', 'entity:application', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'entity', 'entity:application', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'entity', 'entity:application', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'resource', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'resource', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'resource', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'group', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'adb9460791e14623800c9050a82b61b8', 'group', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f238c03249b14ff9abb32cd351bb9933', 'group', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'tenant', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'887c5d5edb504c1da3df81e21d0d8ca3', 'tenant', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd8c8da7a94814ddb89e739f1368641b6', 'tenant', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'entity', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'887c5d5edb504c1da3df81e21d0d8ca3', 'entity', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd8c8da7a94814ddb89e739f1368641b6', 'entity', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'resource', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'887c5d5edb504c1da3df81e21d0d8ca3', 'resource', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd8c8da7a94814ddb89e739f1368641b6', 'resource', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'group', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'887c5d5edb504c1da3df81e21d0d8ca3', 'group', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd8c8da7a94814ddb89e739f1368641b6', 'group', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd8c8da7a94814ddb89e739f1368641b6', 'role', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'887c5d5edb504c1da3df81e21d0d8ca3', 'policy', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'credential', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'3128fec0f70b439d99cad391c6acf213', 'credential', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'1503e6935d704361a756af437dd0b60e', 'credential', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'credential', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'audit_log', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'tenant', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4a946e4fd9284a928e1ca41b2e43719f', 'tenant', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'1503e6935d704361a756af437dd0b60e', 'signing_key', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'api_endpoint', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'policy', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4c3cfa6f8b9f48679c676ccd26f58250', 'role', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'eb1810a5be8b40499078df20d87cee96', 'api_endpoint', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'api_endpoint', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8d0203fe66d54a9a9b1796761654dff8', 'policy', NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL);

INSERT INTO action_assignment_rules (id, tenant_id, entity_kind, action_name, object_kind, object_type, decision, is_absolute, created_at, managed_by) VALUES
    (x'de4cee5d9d024fe5bbdf58727330bb61', NULL, 'device', 'manage', 'resource', NULL, 'deny', 1, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f9e4f97d6a2a495eb167bc333a338809', NULL, 'device', 'delete', 'resource', NULL, 'deny', 1, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'4a10f5940c1e4959b9e8212d967d1a67', NULL, 'device', 'write', 'resource', NULL, 'deny', 1, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'2323c8b05fbd49c996d7ded1770f8cb5', NULL, 'human', 'manage', 'resource', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'e24e6cf87d714641a0416155f4bd0c36', NULL, 'human', 'manage', 'entity', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'a7e14ba7580f46d1ba690fce7df08175', NULL, 'human', 'manage', 'group', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'd9676412b8ce498382f652f6f29fe4bc', NULL, 'human', 'manage', 'credential', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'84258a3d8ad74f2c8ca1020d02abce51', NULL, 'human', 'read', 'audit_log', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'f213323ea7fd4f81a19513fbd303a148', NULL, 'human', 'policy.manage', 'policy', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'337c8d6afbf847018e93b2373797ad9c', NULL, 'human', 'role.manage', 'role', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'0d479823f9044b7cb5f5acfceeba2d73', NULL, 'service', 'manage', 'resource', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'44c21b7d04474160a2d96b12da3cd304', NULL, 'service', 'manage', 'credential', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'2b0d59ae7f4e42139d662449abcb8830', NULL, 'service', 'policy.manage', 'policy', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'cd119ea6f14b46adaa9473127f966363', NULL, 'service', 'role.manage', 'role', NULL, 'allow', 0, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL);

INSERT INTO profiles (id, tenant_id, object_kind, kind, key, display_name, description, status, created_at, updated_at) VALUES
    (x'8b29401618a749be920df23591095c8a', NULL, 'entity', 'device', 'client', 'Client', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'8f6715e8db3d47b58c93df8996b85759', NULL, 'entity', 'device', 'gateway', 'Gateway', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'7dc2c44bfd46451cbee65a901e64790c', NULL, 'entity', 'device', 'water_meter', 'Water Meter', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'ceb41565a7364a35aa437dfd79044312', NULL, 'entity', 'human', 'user', 'User', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'6fe1ee73787c4f04a334d0999e456ebd', NULL, 'entity', 'service', 'service_account', 'Service Account', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'c977555b92434f84b85cb1bb1c0e81cf', NULL, 'entity', 'workload', 'workload', 'Workload', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'a1b7df39ac8f42d69fdc2a2339f50364', NULL, 'entity', 'application', 'application', 'Application', NULL, 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL);

INSERT INTO profile_versions (id, profile_id, version, json_schema, ui_schema, status, created_at) VALUES
    (x'987318499e574b449c50c7cd8b76e323', x'8b29401618a749be920df23591095c8a', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'9556a6a7e13b4ba78c7d3c82bfac1cfc', x'8f6715e8db3d47b58c93df8996b85759', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'e578c934d57044aeb756c090443405df', x'7dc2c44bfd46451cbee65a901e64790c', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'306293ae830e43a695ad99a67f31283b', x'ceb41565a7364a35aa437dfd79044312', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'a862f81f360f4f0da8e255506693daa0', x'6fe1ee73787c4f04a334d0999e456ebd', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'1ed0268969d040a99479e3c1e13875c3', x'c977555b92434f84b85cb1bb1c0e81cf', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'18452b95351e4d1eaa0c87ebee423c4e', x'a1b7df39ac8f42d69fdc2a2339f50364', 1, '{}', '{}', 'active', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'));

INSERT INTO entities (id, kind, name, tenant_id, status, attributes, profile_id, profile_version_id, created_at, updated_at, deleted_at, deleted_by, alias, managed_by, external_id) VALUES
    (x'00000000000000000000000000000001', 'human', 'admin', NULL, 'active', '{"role":"admin","system":true}', NULL, NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL, NULL, NULL, NULL, NULL, NULL),
    (x'00000000000000000000000000000003', 'service', 'example-service', NULL, 'active', '{"purpose":"example-service-integration","system":true}', NULL, NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL, NULL, NULL, NULL, NULL, NULL);

INSERT INTO certificate_profiles (id, tenant_id, base_profile_id, name, permitted_key_algorithms, default_ttl_seconds, maximum_ttl_seconds, renewal_threshold_seconds, key_usages, extended_key_usages, san_policy, identity_uri_template, basic_constraints, created_at, updated_at) VALUES
    (x'00000000000000000000000000000401', NULL, NULL, 'client', '[{"algorithm":"ecdsa","sizes":[256]}]', 86400, 604800, 86400, '["digital_signature"]', '["client_auth"]', '{"dns":{"mode":"deny","values":[]},"email":{"mode":"deny","values":[]},"ip":{"mode":"deny","values":[]},"uri":{"mode":"identity","values":[]}}', 'urn:atom:{scope}entity:{entity_id}', '{"ca":false,"path_len":null}', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000402', NULL, NULL, 'server', '[{"algorithm":"ecdsa","sizes":[256]}]', 86400, 604800, 86400, '["digital_signature"]', '["server_auth"]', '{"dns":{"mode":"deny","values":[]},"email":{"mode":"deny","values":[]},"ip":{"mode":"deny","values":[]},"uri":{"mode":"identity","values":[]}}', 'urn:atom:{scope}entity:{entity_id}', '{"ca":false,"path_len":null}', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'));

INSERT INTO roles (id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at, managed_by) VALUES
    (x'00000000000000000000000000000002', 'atom-admin', NULL, 'Full administrative access', NULL, NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL, NULL),
    (x'00000000000000000000000000000004', 'example-service', NULL, 'Example service integration role', NULL, NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL, NULL),
    (x'00000000000000000000000000000006', 'domain-creator', NULL, 'Allows authenticated users to create their own tenants/domains', NULL, NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL, NULL);

INSERT INTO permission_blocks (id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions, created_at, updated_at, managed_by) VALUES
    (x'00000000000000000000000000000007', NULL, 'platform', NULL, NULL, NULL, NULL, 'allow', '{}', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'00000000000000000000000000000008', NULL, 'platform', NULL, NULL, NULL, NULL, 'allow', '{}', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'00000000000000000000000000000009', NULL, 'platform', NULL, NULL, NULL, NULL, 'allow', '{}', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL);

INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES
    (x'00000000000000000000000000000007', x'4c3cfa6f8b9f48679c676ccd26f58250'),
    (x'00000000000000000000000000000007', x'4a946e4fd9284a928e1ca41b2e43719f'),
    (x'00000000000000000000000000000007', x'adb9460791e14623800c9050a82b61b8'),
    (x'00000000000000000000000000000007', x'f238c03249b14ff9abb32cd351bb9933'),
    (x'00000000000000000000000000000007', x'3128fec0f70b439d99cad391c6acf213'),
    (x'00000000000000000000000000000007', x'1503e6935d704361a756af437dd0b60e'),
    (x'00000000000000000000000000000007', x'cf485b74537149b0b6b9bde721a3a775'),
    (x'00000000000000000000000000000007', x'5ffc337833e940a1ac846f95906871da'),
    (x'00000000000000000000000000000007', x'eb1810a5be8b40499078df20d87cee96'),
    (x'00000000000000000000000000000007', x'8d0203fe66d54a9a9b1796761654dff8'),
    (x'00000000000000000000000000000007', x'887c5d5edb504c1da3df81e21d0d8ca3'),
    (x'00000000000000000000000000000007', x'd8c8da7a94814ddb89e739f1368641b6'),
    (x'00000000000000000000000000000007', x'186bc3d4da2b4e529fa1ae74737f5eb8'),
    (x'00000000000000000000000000000008', x'4c3cfa6f8b9f48679c676ccd26f58250'),
    (x'00000000000000000000000000000008', x'adb9460791e14623800c9050a82b61b8'),
    (x'00000000000000000000000000000008', x'f238c03249b14ff9abb32cd351bb9933'),
    (x'00000000000000000000000000000008', x'cf485b74537149b0b6b9bde721a3a775'),
    (x'00000000000000000000000000000008', x'5ffc337833e940a1ac846f95906871da'),
    (x'00000000000000000000000000000008', x'eb1810a5be8b40499078df20d87cee96'),
    (x'00000000000000000000000000000008', x'8d0203fe66d54a9a9b1796761654dff8'),
    (x'00000000000000000000000000000008', x'887c5d5edb504c1da3df81e21d0d8ca3'),
    (x'00000000000000000000000000000008', x'd8c8da7a94814ddb89e739f1368641b6'),
    (x'00000000000000000000000000000008', x'186bc3d4da2b4e529fa1ae74737f5eb8'),
    (x'00000000000000000000000000000009', x'4a946e4fd9284a928e1ca41b2e43719f'),
    (x'00000000000000000000000000000007', x'cb157e08ada44a688477c935ec7c7d56'),
    (x'00000000000000000000000000000007', x'421a48d476f04dc0af2a0fcf257a6787');

INSERT INTO role_permission_blocks (role_id, permission_block_id, created_at) VALUES
    (x'00000000000000000000000000000002', x'00000000000000000000000000000007', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000004', x'00000000000000000000000000000008', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000006', x'00000000000000000000000000000009', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'));

INSERT INTO principal_groups (id, name, tenant_id, description, status, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by) VALUES
    (x'00000000000000000000000000000005', 'authenticated-users', NULL, 'All authenticated human users', 'active', '{"purpose":"default-self-service-domain-creation","system":true}', NULL, NULL, (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL, NULL);

INSERT INTO principal_group_members (group_id, entity_id, created_at) VALUES
    (x'00000000000000000000000000000005', x'00000000000000000000000000000001', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'));

INSERT INTO role_assignments (id, tenant_id, subject_kind, subject_id, role_id, created_at, managed_by) VALUES
    (x'b32782ca4b5f4a6a8c4ee577a49d890b', NULL, 'entity', x'00000000000000000000000000000003', x'00000000000000000000000000000004', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'6501b7958c6744b390b592455db79448', NULL, 'group', x'00000000000000000000000000000005', x'00000000000000000000000000000006', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL),
    (x'0000000000000000000000000000000a', NULL, 'entity', x'00000000000000000000000000000001', x'00000000000000000000000000000002', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'), NULL);

INSERT INTO protected_object_ids (id, object_kind, source_table, created_at) VALUES
    (x'00000000000000000000000000000001', 'entity', 'entities', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000003', 'entity', 'entities', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000005', 'group', 'principal_groups', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000002', 'role', 'roles', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000004', 'role', 'roles', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'00000000000000000000000000000006', 'role', 'roles', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'b32782ca4b5f4a6a8c4ee577a49d890b', 'policy', 'role_assignments', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'6501b7958c6744b390b592455db79448', 'policy', 'role_assignments', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')),
    (x'0000000000000000000000000000000a', 'policy', 'role_assignments', (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'));


-- Triggers

CREATE TRIGGER register_protected_object_id_api_endpoints AFTER INSERT ON api_endpoints FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'api_endpoint', 'api_endpoints');
END;

CREATE TRIGGER reject_protected_object_id_update_api_endpoints BEFORE UPDATE OF id ON api_endpoints FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'api_endpoints.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_api_endpoints AFTER DELETE ON api_endpoints FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'api_endpoints';
END;

CREATE TRIGGER register_protected_object_id_credentials AFTER INSERT ON credentials FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'credential', 'credentials');
END;

CREATE TRIGGER reject_protected_object_id_update_credentials BEFORE UPDATE OF id ON credentials FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'credentials.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_credentials AFTER DELETE ON credentials FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'credentials';
END;

CREATE TRIGGER register_protected_object_id_direct_policies AFTER INSERT ON direct_policies FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'policy', 'direct_policies');
END;

CREATE TRIGGER reject_protected_object_id_update_direct_policies BEFORE UPDATE OF id ON direct_policies FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'direct_policies.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_direct_policies AFTER DELETE ON direct_policies FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'direct_policies';
END;

CREATE TRIGGER register_protected_object_id_entities AFTER INSERT ON entities FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'entity', 'entities');
END;

CREATE TRIGGER reject_protected_object_id_update_entities BEFORE UPDATE OF id ON entities FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'entities.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_entities AFTER DELETE ON entities FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'entities';
END;

CREATE TRIGGER register_protected_object_id_object_groups AFTER INSERT ON object_groups FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'group', 'object_groups');
END;

CREATE TRIGGER reject_protected_object_id_update_object_groups BEFORE UPDATE OF id ON object_groups FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'object_groups.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_object_groups AFTER DELETE ON object_groups FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'object_groups';
END;

CREATE TRIGGER register_protected_object_id_principal_groups AFTER INSERT ON principal_groups FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'group', 'principal_groups');
END;

CREATE TRIGGER reject_protected_object_id_update_principal_groups BEFORE UPDATE OF id ON principal_groups FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'principal_groups.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_principal_groups AFTER DELETE ON principal_groups FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'principal_groups';
END;

CREATE TRIGGER register_protected_object_id_resources AFTER INSERT ON resources FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'resource', 'resources');
END;

CREATE TRIGGER reject_protected_object_id_update_resources BEFORE UPDATE OF id ON resources FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'resources.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_resources AFTER DELETE ON resources FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'resources';
END;

CREATE TRIGGER register_protected_object_id_role_assignments AFTER INSERT ON role_assignments FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'policy', 'role_assignments');
END;

CREATE TRIGGER reject_protected_object_id_update_role_assignments BEFORE UPDATE OF id ON role_assignments FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'role_assignments.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_role_assignments AFTER DELETE ON role_assignments FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'role_assignments';
END;

CREATE TRIGGER register_protected_object_id_roles AFTER INSERT ON roles FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'role', 'roles');
END;

CREATE TRIGGER reject_protected_object_id_update_roles BEFORE UPDATE OF id ON roles FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'roles.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_roles AFTER DELETE ON roles FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'roles';
END;

CREATE TRIGGER register_protected_object_id_tenants AFTER INSERT ON tenants FOR EACH ROW
BEGIN
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, 'tenant', 'tenants');
END;

CREATE TRIGGER reject_protected_object_id_update_tenants BEFORE UPDATE OF id ON tenants FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
BEGIN
    SELECT RAISE(ABORT, 'tenants.id is immutable once registered');
END;

CREATE TRIGGER unregister_protected_object_id_tenants AFTER DELETE ON tenants FOR EACH ROW
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = 'tenants';
END;

CREATE TRIGGER trg_certificate_issuance_request_credential_ins BEFORE INSERT ON certificate_issuance_requests FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'issuance request must reference its issuer-bound entity certificate')
    WHERE NEW.credential_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM credentials c
        WHERE c.id = NEW.credential_id
          AND (c.entity_id <> NEW.entity_id OR c.kind <> 'certificate' OR c.issuer_id IS NULL));
END;

CREATE TRIGGER trg_certificate_issuance_request_credential_upd BEFORE UPDATE OF entity_id, credential_id ON certificate_issuance_requests FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'issuance request must reference its issuer-bound entity certificate')
    WHERE NEW.credential_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM credentials c
        WHERE c.id = NEW.credential_id
          AND (c.entity_id <> NEW.entity_id OR c.kind <> 'certificate' OR c.issuer_id IS NULL));
END;

CREATE TRIGGER trg_certificate_profiles_ceiling_platform_ins BEFORE INSERT ON certificate_profiles FOR EACH ROW
WHEN NEW.tenant_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'platform certificate profile update would exceed a tenant ceiling')
    WHERE EXISTS (
        SELECT 1 FROM certificate_profiles child
        WHERE child.base_profile_id = NEW.id
          AND (
               child.name <> NEW.name
            OR child.default_ttl_seconds > NEW.default_ttl_seconds
            OR child.maximum_ttl_seconds > NEW.maximum_ttl_seconds
            OR child.renewal_threshold_seconds > NEW.renewal_threshold_seconds
            OR NOT atom_json_eq(child.permitted_key_algorithms, NEW.permitted_key_algorithms)
            OR NOT atom_json_subset(child.key_usages, NEW.key_usages)
            OR NOT atom_json_subset(child.extended_key_usages, NEW.extended_key_usages)
            OR child.identity_uri_template <> NEW.identity_uri_template
            OR NOT atom_json_eq(child.basic_constraints, NEW.basic_constraints)
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.dns', NEW.san_policy -> '$.dns')
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.ip', NEW.san_policy -> '$.ip')
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.email', NEW.san_policy -> '$.email')
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.uri', NEW.san_policy -> '$.uri')));
END;

CREATE TRIGGER trg_certificate_profiles_ceiling_tenant_ins BEFORE INSERT ON certificate_profiles FOR EACH ROW
WHEN NEW.tenant_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'tenant certificate profile requires a platform ceiling')
    WHERE NOT EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL);
    SELECT RAISE(ABORT, 'tenant certificate profile name must match its platform ceiling')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL AND NEW.name <> c.name);
    SELECT RAISE(ABORT, 'tenant certificate profile cannot extend platform time limits')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL
        AND (NEW.default_ttl_seconds > c.default_ttl_seconds OR NEW.maximum_ttl_seconds > c.maximum_ttl_seconds
             OR NEW.renewal_threshold_seconds > c.renewal_threshold_seconds));
    SELECT RAISE(ABORT, 'tenant certificate profile exceeds platform certificate shape')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL
        AND (NOT atom_json_eq(NEW.permitted_key_algorithms, c.permitted_key_algorithms)
             OR NOT atom_json_subset(NEW.key_usages, c.key_usages)
             OR NOT atom_json_subset(NEW.extended_key_usages, c.extended_key_usages)
             OR NEW.identity_uri_template <> c.identity_uri_template
             OR NOT atom_json_eq(NEW.basic_constraints, c.basic_constraints)));
    SELECT RAISE(ABORT, 'tenant certificate profile widens platform SAN policy')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL
        AND (NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.dns', c.san_policy -> '$.dns') OR NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.ip', c.san_policy -> '$.ip') OR NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.email', c.san_policy -> '$.email') OR NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.uri', c.san_policy -> '$.uri')));
END;

CREATE TRIGGER trg_certificate_profiles_ceiling_platform_upd BEFORE UPDATE OF tenant_id, base_profile_id, name, permitted_key_algorithms, default_ttl_seconds, maximum_ttl_seconds, renewal_threshold_seconds, key_usages, extended_key_usages, san_policy, identity_uri_template, basic_constraints ON certificate_profiles FOR EACH ROW
WHEN NEW.tenant_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'platform certificate profile update would exceed a tenant ceiling')
    WHERE EXISTS (
        SELECT 1 FROM certificate_profiles child
        WHERE child.base_profile_id = NEW.id
          AND (
               child.name <> NEW.name
            OR child.default_ttl_seconds > NEW.default_ttl_seconds
            OR child.maximum_ttl_seconds > NEW.maximum_ttl_seconds
            OR child.renewal_threshold_seconds > NEW.renewal_threshold_seconds
            OR NOT atom_json_eq(child.permitted_key_algorithms, NEW.permitted_key_algorithms)
            OR NOT atom_json_subset(child.key_usages, NEW.key_usages)
            OR NOT atom_json_subset(child.extended_key_usages, NEW.extended_key_usages)
            OR child.identity_uri_template <> NEW.identity_uri_template
            OR NOT atom_json_eq(child.basic_constraints, NEW.basic_constraints)
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.dns', NEW.san_policy -> '$.dns')
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.ip', NEW.san_policy -> '$.ip')
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.email', NEW.san_policy -> '$.email')
            OR NOT atom_pki_san_rule_is_subset(child.san_policy -> '$.uri', NEW.san_policy -> '$.uri')));
END;

CREATE TRIGGER trg_certificate_profiles_ceiling_tenant_upd BEFORE UPDATE OF tenant_id, base_profile_id, name, permitted_key_algorithms, default_ttl_seconds, maximum_ttl_seconds, renewal_threshold_seconds, key_usages, extended_key_usages, san_policy, identity_uri_template, basic_constraints ON certificate_profiles FOR EACH ROW
WHEN NEW.tenant_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'tenant certificate profile requires a platform ceiling')
    WHERE NOT EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL);
    SELECT RAISE(ABORT, 'tenant certificate profile name must match its platform ceiling')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL AND NEW.name <> c.name);
    SELECT RAISE(ABORT, 'tenant certificate profile cannot extend platform time limits')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL
        AND (NEW.default_ttl_seconds > c.default_ttl_seconds OR NEW.maximum_ttl_seconds > c.maximum_ttl_seconds
             OR NEW.renewal_threshold_seconds > c.renewal_threshold_seconds));
    SELECT RAISE(ABORT, 'tenant certificate profile exceeds platform certificate shape')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL
        AND (NOT atom_json_eq(NEW.permitted_key_algorithms, c.permitted_key_algorithms)
             OR NOT atom_json_subset(NEW.key_usages, c.key_usages)
             OR NOT atom_json_subset(NEW.extended_key_usages, c.extended_key_usages)
             OR NEW.identity_uri_template <> c.identity_uri_template
             OR NOT atom_json_eq(NEW.basic_constraints, c.basic_constraints)));
    SELECT RAISE(ABORT, 'tenant certificate profile widens platform SAN policy')
    WHERE EXISTS (SELECT 1 FROM certificate_profiles c WHERE c.id = NEW.base_profile_id AND c.tenant_id IS NULL
        AND (NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.dns', c.san_policy -> '$.dns') OR NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.ip', c.san_policy -> '$.ip') OR NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.email', c.san_policy -> '$.email') OR NOT atom_pki_san_rule_is_subset(NEW.san_policy -> '$.uri', c.san_policy -> '$.uri')));
END;

CREATE TRIGGER trg_certificate_renewal_link_ins BEFORE INSERT ON certificate_renewals FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'renewal source must be a certificate credential')
    WHERE NOT EXISTS (SELECT 1 FROM credentials WHERE id = NEW.previous_credential_id AND kind = 'certificate');
    SELECT RAISE(ABORT, 'renewal replacement must differ from its source')
    WHERE NEW.replacement_credential_id IS NOT NULL AND NEW.replacement_credential_id = NEW.previous_credential_id;
    SELECT RAISE(ABORT, 'renewal replacement must be an issuer-bound certificate for the same entity')
    WHERE NEW.replacement_credential_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM credentials r JOIN credentials p ON p.id = NEW.previous_credential_id
        WHERE r.id = NEW.replacement_credential_id
          AND r.kind = 'certificate'
          AND r.issuer_id IS NOT NULL
          AND r.entity_id = p.entity_id
          AND (r.metadata ->> '$.renewed_from_credential_id') IS (CASE WHEN NEW.previous_credential_id IS NULL THEN NULL ELSE substr(lower(hex(NEW.previous_credential_id)), 1, 8) || '-' || substr(lower(hex(NEW.previous_credential_id)), 9, 4) || '-' || substr(lower(hex(NEW.previous_credential_id)), 13, 4) || '-' || substr(lower(hex(NEW.previous_credential_id)), 17, 4) || '-' || substr(lower(hex(NEW.previous_credential_id)), 21, 12) END));
END;

CREATE TRIGGER trg_certificate_renewal_link_upd BEFORE UPDATE OF previous_credential_id, replacement_credential_id ON certificate_renewals FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'renewal source must be a certificate credential')
    WHERE NOT EXISTS (SELECT 1 FROM credentials WHERE id = NEW.previous_credential_id AND kind = 'certificate');
    SELECT RAISE(ABORT, 'renewal replacement must differ from its source')
    WHERE NEW.replacement_credential_id IS NOT NULL AND NEW.replacement_credential_id = NEW.previous_credential_id;
    SELECT RAISE(ABORT, 'renewal replacement must be an issuer-bound certificate for the same entity')
    WHERE NEW.replacement_credential_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM credentials r JOIN credentials p ON p.id = NEW.previous_credential_id
        WHERE r.id = NEW.replacement_credential_id
          AND r.kind = 'certificate'
          AND r.issuer_id IS NOT NULL
          AND r.entity_id = p.entity_id
          AND (r.metadata ->> '$.renewed_from_credential_id') IS (CASE WHEN NEW.previous_credential_id IS NULL THEN NULL ELSE substr(lower(hex(NEW.previous_credential_id)), 1, 8) || '-' || substr(lower(hex(NEW.previous_credential_id)), 9, 4) || '-' || substr(lower(hex(NEW.previous_credential_id)), 13, 4) || '-' || substr(lower(hex(NEW.previous_credential_id)), 17, 4) || '-' || substr(lower(hex(NEW.previous_credential_id)), 21, 12) END));
END;

CREATE TRIGGER trg_certificate_revocations_immutable_del BEFORE DELETE ON certificate_revocations FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'certificate revocation records are immutable');
END;

CREATE TRIGGER trg_certificate_revocations_immutable_upd BEFORE UPDATE ON certificate_revocations FOR EACH ROW
WHEN NOT (OLD.issuer_id IS NOT NULL AND NEW.issuer_id IS NULL
         AND NEW.credential_id IS OLD.credential_id
         AND NEW.issuer_fingerprint_sha256 IS OLD.issuer_fingerprint_sha256
         AND NEW.serial_number IS OLD.serial_number
         AND NEW.reason IS OLD.reason
         AND NEW.actor_entity_id IS OLD.actor_entity_id
         AND NEW.revoked_at IS OLD.revoked_at
         AND NEW.expires_at IS OLD.expires_at
         AND NEW.created_at IS OLD.created_at)
BEGIN
    SELECT RAISE(ABORT, 'certificate revocation records are immutable');
END;

CREATE TRIGGER trg_credentials_certificate_issuer_scope_ins BEFORE INSERT ON credentials FOR EACH ROW
WHEN NEW.kind = 'certificate'
BEGIN
    SELECT RAISE(ABORT, 'certificate requires a managed issuer authority')
    WHERE NEW.issuer_id IS NULL;
    SELECT RAISE(ABORT, 'issuer-bound certificate requires an entity')
    WHERE NEW.issuer_id IS NOT NULL AND NEW.entity_id IS NULL;
    SELECT RAISE(ABORT, 'global certificate requires platform leaf issuer')
    WHERE NEW.issuer_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM entities e JOIN pki_authorities a ON a.id = NEW.issuer_id
        WHERE e.id = NEW.entity_id AND e.tenant_id IS NULL
          AND (a.kind <> 'platform_leaf_issuer' OR a.tenant_id IS NOT NULL));
    SELECT RAISE(ABORT, 'tenant certificate requires its own tenant intermediate')
    WHERE NEW.issuer_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM entities e JOIN pki_authorities a ON a.id = NEW.issuer_id
        WHERE e.id = NEW.entity_id AND e.tenant_id IS NOT NULL
          AND (a.kind <> 'tenant_intermediate' OR a.tenant_id IS NOT e.tenant_id));
END;

CREATE TRIGGER trg_credentials_certificate_issuer_scope_upd BEFORE UPDATE OF entity_id, kind, issuer_id ON credentials FOR EACH ROW
WHEN NEW.kind = 'certificate'
BEGIN
    SELECT RAISE(ABORT, 'certificate requires a managed issuer authority')
    WHERE NEW.issuer_id IS NULL AND NOT (
        OLD.kind = 'certificate' AND OLD.issuer_id IS NULL
        AND (OLD.metadata ->> '$.issuer_migration') IS 'legacy_unmanaged'
        AND (NEW.metadata ->> '$.issuer_migration') IS 'legacy_unmanaged');
    SELECT RAISE(ABORT, 'issuer-bound certificate requires an entity')
    WHERE NEW.issuer_id IS NOT NULL AND NEW.entity_id IS NULL;
    SELECT RAISE(ABORT, 'global certificate requires platform leaf issuer')
    WHERE NEW.issuer_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM entities e JOIN pki_authorities a ON a.id = NEW.issuer_id
        WHERE e.id = NEW.entity_id AND e.tenant_id IS NULL
          AND (a.kind <> 'platform_leaf_issuer' OR a.tenant_id IS NOT NULL));
    SELECT RAISE(ABORT, 'tenant certificate requires its own tenant intermediate')
    WHERE NEW.issuer_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM entities e JOIN pki_authorities a ON a.id = NEW.issuer_id
        WHERE e.id = NEW.entity_id AND e.tenant_id IS NOT NULL
          AND (a.kind <> 'tenant_intermediate' OR a.tenant_id IS NOT e.tenant_id));
END;

CREATE TRIGGER trg_credentials_record_certificate_revocation_ins AFTER INSERT ON credentials FOR EACH ROW
WHEN NEW.kind = 'certificate' AND NEW.status = 'revoked'
  AND NOT (NEW.issuer_id IS NULL AND (NEW.metadata ->> '$.issuer_migration') = 'legacy_unmanaged')
BEGIN
    SELECT RAISE(ABORT, 'revoked certificate is missing its pki_authorities row')
    WHERE (SELECT a.fingerprint_sha256 FROM pki_authorities a WHERE a.id = NEW.issuer_id) IS NULL;
    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at, expires_at
    ) VALUES (
        NEW.id, NEW.issuer_id, (SELECT a.fingerprint_sha256 FROM pki_authorities a WHERE a.id = NEW.issuer_id), NEW.identifier,
        substr(COALESCE(NULLIF(trim(NEW.metadata ->> '$.revocation_reason'), ''), 'unspecified'), 1, 128),
        unhex(replace(NULLIF(NEW.metadata ->> '$.revoked_by_entity_id', ''), '-', '')),
        COALESCE(atom_timestamp(NEW.metadata ->> '$.revoked_at'), strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
        COALESCE(NEW.expires_at, '9999-12-31T23:59:59.999999Z')
    )
    ON CONFLICT (credential_id) DO NOTHING;

    INSERT INTO certificate_crl_state (issuer_id, issuer_fingerprint_sha256, crl_number, dirty)
    VALUES (NEW.issuer_id, (SELECT a.fingerprint_sha256 FROM pki_authorities a WHERE a.id = NEW.issuer_id), 0, 1)
    ON CONFLICT (issuer_id) DO UPDATE
        SET dirty = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z';
END;

CREATE TRIGGER trg_credentials_record_certificate_revocation_upd AFTER UPDATE OF status ON credentials FOR EACH ROW
WHEN NEW.kind = 'certificate' AND NEW.status = 'revoked'
  AND NOT (NEW.issuer_id IS NULL AND (NEW.metadata ->> '$.issuer_migration') = 'legacy_unmanaged')
  AND OLD.status <> 'revoked'
BEGIN
    SELECT RAISE(ABORT, 'revoked certificate is missing its pki_authorities row')
    WHERE (SELECT a.fingerprint_sha256 FROM pki_authorities a WHERE a.id = NEW.issuer_id) IS NULL;
    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at, expires_at
    ) VALUES (
        NEW.id, NEW.issuer_id, (SELECT a.fingerprint_sha256 FROM pki_authorities a WHERE a.id = NEW.issuer_id), NEW.identifier,
        substr(COALESCE(NULLIF(trim(NEW.metadata ->> '$.revocation_reason'), ''), 'unspecified'), 1, 128),
        unhex(replace(NULLIF(NEW.metadata ->> '$.revoked_by_entity_id', ''), '-', '')),
        COALESCE(atom_timestamp(NEW.metadata ->> '$.revoked_at'), strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
        COALESCE(NEW.expires_at, '9999-12-31T23:59:59.999999Z')
    )
    ON CONFLICT (credential_id) DO NOTHING;

    INSERT INTO certificate_crl_state (issuer_id, issuer_fingerprint_sha256, crl_number, dirty)
    VALUES (NEW.issuer_id, (SELECT a.fingerprint_sha256 FROM pki_authorities a WHERE a.id = NEW.issuer_id), 0, 1)
    ON CONFLICT (issuer_id) DO UPDATE
        SET dirty = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z';
END;

CREATE TRIGGER trg_credentials_shared_key_non_human_only_ins BEFORE INSERT ON credentials FOR EACH ROW
WHEN NEW.kind = 'shared_key'
BEGIN
    SELECT RAISE(ABORT, 'shared_key credentials cannot belong to human entities')
    WHERE EXISTS (SELECT 1 FROM entities e WHERE e.id = NEW.entity_id AND e.kind = 'human');
END;

CREATE TRIGGER trg_credentials_shared_key_non_human_only_upd BEFORE UPDATE OF entity_id, kind ON credentials FOR EACH ROW
WHEN NEW.kind = 'shared_key'
BEGIN
    SELECT RAISE(ABORT, 'shared_key credentials cannot belong to human entities')
    WHERE EXISTS (SELECT 1 FROM entities e WHERE e.id = NEW.entity_id AND e.kind = 'human');
END;

CREATE TRIGGER trg_entities_shared_key_non_human_only BEFORE UPDATE OF kind ON entities FOR EACH ROW
WHEN OLD.kind IS NOT NEW.kind
BEGIN
    SELECT RAISE(ABORT, 'entities with shared_key credentials cannot become human entities')
    WHERE NEW.kind = 'human' AND EXISTS (SELECT 1 FROM credentials c WHERE c.entity_id = NEW.id AND c.kind = 'shared_key');
END;

CREATE TRIGGER trg_entities_prevent_issuer_bound_tenant_change BEFORE UPDATE OF tenant_id ON entities FOR EACH ROW
WHEN NEW.tenant_id IS NOT OLD.tenant_id
BEGIN
    SELECT RAISE(ABORT, 'entity tenant cannot change while issuer-bound certificates exist')
    WHERE EXISTS (SELECT 1 FROM credentials WHERE entity_id = OLD.id AND kind = 'certificate' AND issuer_id IS NOT NULL);
END;

CREATE TRIGGER trg_direct_policies_purge_object_blocks AFTER DELETE ON direct_policies FOR EACH ROW
BEGIN
    DELETE FROM permission_blocks WHERE object_id = OLD.id;
END;

CREATE TRIGGER trg_role_assignments_purge_object_blocks AFTER DELETE ON role_assignments FOR EACH ROW
BEGIN
    DELETE FROM permission_blocks WHERE object_id = OLD.id;
END;

CREATE TRIGGER trg_pki_authorities_parent_ins BEFORE INSERT ON pki_authorities FOR EACH ROW
WHEN NEW.kind <> 'root'
BEGIN
    SELECT RAISE(ABORT, 'invalid PKI authority parent kind')
    WHERE EXISTS (SELECT 1 FROM pki_authorities p WHERE p.id = NEW.parent_id AND p.kind <> 'root'
        AND NOT (p.kind = 'platform_intermediate' AND NEW.kind = 'tenant_intermediate'));
    SELECT RAISE(ABORT, 'child authority validity must fit inside parent validity')
    WHERE EXISTS (SELECT 1 FROM pki_authorities p WHERE p.id = NEW.parent_id
        AND (NEW.not_before < p.not_before OR NEW.not_after > p.not_after));
END;

CREATE TRIGGER trg_pki_authorities_parent_upd BEFORE UPDATE OF parent_id, kind, not_before, not_after ON pki_authorities FOR EACH ROW
WHEN NEW.kind <> 'root'
BEGIN
    SELECT RAISE(ABORT, 'invalid PKI authority parent kind')
    WHERE EXISTS (SELECT 1 FROM pki_authorities p WHERE p.id = NEW.parent_id AND p.kind <> 'root'
        AND NOT (p.kind = 'platform_intermediate' AND NEW.kind = 'tenant_intermediate'));
    SELECT RAISE(ABORT, 'child authority validity must fit inside parent validity')
    WHERE EXISTS (SELECT 1 FROM pki_authorities p WHERE p.id = NEW.parent_id
        AND (NEW.not_before < p.not_before OR NEW.not_after > p.not_after));
END;

