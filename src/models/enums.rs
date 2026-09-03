use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntityKind {
    Human,
    Device,
    Service,
    Workload,
    Application,
}

impl EntityKind {
    /// Machine identities authenticate with machine secrets (shared keys, API keys,
    /// certificates) rather than human passwords. Every kind except `Human` is a machine.
    pub fn is_machine(&self) -> bool {
        !matches!(self, EntityKind::Human)
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntityStatus {
    #[default]
    Active,
    Inactive,
    Suspended,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    /// Bearer token credential (`atom_...`). Serves both provisioned "API key" use
    /// (unscoped) and self-service personal tokens (scoped via a permission ceiling).
    AccessToken,
    Certificate,
    SharedKey,
}

impl CredentialKind {
    /// Single authority for which credential kinds an entity kind may hold.
    /// `SharedKey` is a retrievable machine secret and is forbidden for humans;
    /// all other kinds are unrestricted at this layer.
    pub fn allowed_for(&self, entity: &EntityKind) -> bool {
        match self {
            CredentialKind::SharedKey => entity.is_machine(),
            CredentialKind::Password
            | CredentialKind::AccessToken
            | CredentialKind::Certificate => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    RevocationPending,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SubjectKind {
    Entity,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GrantKind {
    Capability,
    Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Top of the scope hierarchy. Matches every protected object and inherits
    /// into every tenant for the same capability (full inheritance lands in M4).
    Platform,
    /// Inheritance into objects whose `tenant_id` matches `scope_ref`. The PDP
    /// stub treats this as no-match until M3/M4 ship.
    Tenant,
    /// Matches every object whose coarse object kind equals `scope_ref`.
    ObjectKind,
    /// Matches every object whose namespaced sub-kind equals `scope_ref` (e.g.
    /// `resource:channel` or `entity:device`).
    ObjectType,
    /// Matches a single object whose UUID (as text) equals `scope_ref`.
    Object,
    /// Matches objects of a namespaced type whose direct parent group equals
    /// the UUID embedded in `scope_ref`.
    GroupObjectType,
    /// Matches objects of a namespaced type whose direct parent group is the
    /// UUID embedded in `scope_ref`, or any descendant of that group.
    GroupTreeObjectType,
    /// Matches direct child groups of the group UUID embedded in `scope_ref`.
    GroupChildKind,
    /// Matches descendant groups of the group UUID embedded in `scope_ref`.
    GroupDescendantKind,
}

/// Canonical set of protected object kinds. Used for `object_kind` columns in
/// policy scopes, guardrail rules, and authorization checks.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Entity,
    Resource,
    Group,
    Tenant,
    Role,
    Policy,
    Credential,
    ApiEndpoint,
    AuditLog,
    SigningKey,
}

impl ObjectKind {
    /// Canonical string form (matches the DB CHECK constraint and the API
    /// contract). `AuditLog` serialises as `audit_log`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectKind::Entity => "entity",
            ObjectKind::Resource => "resource",
            ObjectKind::Group => "group",
            ObjectKind::Tenant => "tenant",
            ObjectKind::Role => "role",
            ObjectKind::Policy => "policy",
            ObjectKind::Credential => "credential",
            ObjectKind::ApiEndpoint => "api_endpoint",
            ObjectKind::AuditLog => "audit_log",
            ObjectKind::SigningKey => "signing_key",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ActionAssignmentDecision {
    Allow,
    Deny,
    RequireOverride,
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Allow,
    Deny,
    Error,
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, sqlx::Type,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    #[default]
    Active,
    Inactive,
    Frozen,
    Deleted,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DeletedFilter {
    #[default]
    Live,
    Deleted,
    All,
}

/// Filters a tenant invitation list by outcome. Absent (`None`) means no
/// filtering — every invitation regardless of state, matching prior behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationState {
    Pending,
    Accepted,
    Rejected,
    Revoked,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SortDir {
    Asc,
    #[default]
    Desc,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EntityOrderField {
    #[default]
    CreatedAt,
    UpdatedAt,
    Name,
    Username,
    FirstName,
    LastName,
    Email,
    Kind,
    Status,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceOrderField {
    #[default]
    CreatedAt,
    UpdatedAt,
    Name,
    Kind,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GroupOrderField {
    #[default]
    CreatedAt,
    UpdatedAt,
    Name,
    Status,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TenantOrderField {
    #[default]
    CreatedAt,
    UpdatedAt,
    Name,
    Alias,
    Status,
}

impl DeletedFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            DeletedFilter::Live => "live",
            DeletedFilter::Deleted => "deleted",
            DeletedFilter::All => "all",
        }
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    fn contract() -> serde_json::Value {
        serde_json::from_str(include_str!("../../api/v1/persisted-semantics.json"))
            .expect("persisted-semantics contract")
    }

    fn contract_strings(value: &serde_json::Value) -> Vec<String> {
        value
            .as_array()
            .expect("string array")
            .iter()
            .map(|value| value.as_str().expect("string value").to_string())
            .collect()
    }

    fn schema_strings<T: schemars::JsonSchema>() -> Vec<String> {
        let schema = serde_json::to_value(schemars::schema_for!(T)).expect("enum JSON Schema");
        fn collect(schema: &serde_json::Value, root: &serde_json::Value, out: &mut Vec<String>) {
            if let Some(values) = schema.get("enum").and_then(serde_json::Value::as_array) {
                out.extend(
                    values
                        .iter()
                        .map(|value| value.as_str().expect("string enum value").to_string()),
                );
                return;
            }
            if let Some(value) = schema.get("const").and_then(serde_json::Value::as_str) {
                out.push(value.to_string());
                return;
            }
            for combinator in ["oneOf", "anyOf"] {
                if let Some(branches) = schema.get(combinator).and_then(serde_json::Value::as_array)
                {
                    for branch in branches {
                        collect(branch, root, out);
                    }
                    return;
                }
            }
            if let Some(reference) = schema.get("$ref").and_then(serde_json::Value::as_str) {
                let pointer = reference
                    .strip_prefix('#')
                    .expect("local enum-schema reference");
                collect(
                    root.pointer(pointer).expect("enum-schema reference target"),
                    root,
                    out,
                );
            }
        }

        let mut values = Vec::new();
        collect(&schema, &schema, &mut values);
        assert!(!values.is_empty(), "enum schema has no values");
        values
    }

    fn serialized<T: Serialize>(values: &[T]) -> Vec<String> {
        values
            .iter()
            .map(|value| {
                serde_json::to_value(value)
                    .expect("serialize enum")
                    .as_str()
                    .expect("enum serializes as a string")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn persisted_v1_enum_spellings_match_runtime() {
        let contract = contract();
        let enums = contract["enums"].as_object().expect("enum contract map");
        let expected = |name: &str| {
            enums[name]
                .as_array()
                .unwrap_or_else(|| panic!("missing enum contract {name}"))
                .iter()
                .map(|value| value.as_str().expect("enum string").to_string())
                .collect::<Vec<_>>()
        };

        assert_eq!(
            serialized(&[
                ActionAssignmentDecision::Allow,
                ActionAssignmentDecision::Deny,
                ActionAssignmentDecision::RequireOverride,
            ]),
            expected("actionAssignmentDecision")
        );
        assert_eq!(
            serialized(&[AuditOutcome::Allow, AuditOutcome::Deny, AuditOutcome::Error]),
            expected("auditOutcome")
        );
        assert_eq!(
            serialized(&[
                CredentialKind::Password,
                CredentialKind::AccessToken,
                CredentialKind::Certificate,
                CredentialKind::SharedKey,
            ]),
            expected("credentialKind")
        );
        assert_eq!(
            serialized(&[
                CredentialStatus::Active,
                CredentialStatus::RevocationPending,
                CredentialStatus::Revoked,
            ]),
            expected("credentialStatus")
        );
        assert_eq!(
            serialized(&[
                DeletedFilter::Live,
                DeletedFilter::Deleted,
                DeletedFilter::All
            ]),
            expected("deletedFilter")
        );
        assert_eq!(
            serialized(&[Effect::Allow, Effect::Deny]),
            expected("effect")
        );
        assert_eq!(
            serialized(&[
                EntityKind::Human,
                EntityKind::Device,
                EntityKind::Service,
                EntityKind::Workload,
                EntityKind::Application,
            ]),
            expected("entityKind")
        );
        assert_eq!(
            serialized(&[
                EntityOrderField::CreatedAt,
                EntityOrderField::UpdatedAt,
                EntityOrderField::Name,
                EntityOrderField::Username,
                EntityOrderField::FirstName,
                EntityOrderField::LastName,
                EntityOrderField::Email,
                EntityOrderField::Kind,
                EntityOrderField::Status,
            ]),
            expected("entityOrderField")
        );
        assert_eq!(
            serialized(&[
                EntityStatus::Active,
                EntityStatus::Inactive,
                EntityStatus::Suspended,
            ]),
            expected("entityStatus")
        );
        assert_eq!(
            serialized(&[GrantKind::Capability, GrantKind::Role]),
            expected("grantKind")
        );
        assert_eq!(
            serialized(&[
                GroupOrderField::CreatedAt,
                GroupOrderField::UpdatedAt,
                GroupOrderField::Name,
                GroupOrderField::Status,
            ]),
            expected("groupOrderField")
        );
        assert_eq!(
            serialized(&[
                ObjectKind::Entity,
                ObjectKind::Resource,
                ObjectKind::Group,
                ObjectKind::Tenant,
                ObjectKind::Role,
                ObjectKind::Policy,
                ObjectKind::Credential,
                ObjectKind::ApiEndpoint,
                ObjectKind::AuditLog,
                ObjectKind::SigningKey,
            ]),
            expected("objectKind")
        );
        assert_eq!(
            serialized(&[
                ResourceOrderField::CreatedAt,
                ResourceOrderField::UpdatedAt,
                ResourceOrderField::Name,
                ResourceOrderField::Kind,
            ]),
            expected("resourceOrderField")
        );
        assert_eq!(
            serialized(&[
                ScopeKind::Platform,
                ScopeKind::Tenant,
                ScopeKind::ObjectKind,
                ScopeKind::ObjectType,
                ScopeKind::Object,
                ScopeKind::GroupObjectType,
                ScopeKind::GroupTreeObjectType,
                ScopeKind::GroupChildKind,
                ScopeKind::GroupDescendantKind,
            ]),
            expected("scopeKind")
        );
        assert_eq!(
            serialized(&[SortDir::Asc, SortDir::Desc]),
            expected("sortDir")
        );
        assert_eq!(
            serialized(&[SubjectKind::Entity, SubjectKind::Group]),
            expected("subjectKind")
        );
        assert_eq!(
            serialized(&[
                TenantOrderField::CreatedAt,
                TenantOrderField::UpdatedAt,
                TenantOrderField::Name,
                TenantOrderField::Alias,
                TenantOrderField::Status,
            ]),
            expected("tenantOrderField")
        );
        assert_eq!(
            serialized(&[
                TenantStatus::Active,
                TenantStatus::Inactive,
                TenantStatus::Frozen,
                TenantStatus::Deleted,
            ]),
            expected("tenantStatus")
        );

        macro_rules! schema_matches {
            ($ty:ty, $name:literal) => {
                let mut schema_values = schema_strings::<$ty>();
                let mut contract_values = expected($name);
                schema_values.sort();
                contract_values.sort();
                assert_eq!(schema_values, contract_values);
            };
        }
        schema_matches!(ActionAssignmentDecision, "actionAssignmentDecision");
        schema_matches!(AuditOutcome, "auditOutcome");
        schema_matches!(CredentialKind, "credentialKind");
        schema_matches!(CredentialStatus, "credentialStatus");
        schema_matches!(DeletedFilter, "deletedFilter");
        schema_matches!(Effect, "effect");
        schema_matches!(EntityKind, "entityKind");
        schema_matches!(EntityOrderField, "entityOrderField");
        schema_matches!(EntityStatus, "entityStatus");
        schema_matches!(GrantKind, "grantKind");
        schema_matches!(GroupOrderField, "groupOrderField");
        schema_matches!(ObjectKind, "objectKind");
        schema_matches!(ResourceOrderField, "resourceOrderField");
        schema_matches!(ScopeKind, "scopeKind");
        schema_matches!(SortDir, "sortDir");
        schema_matches!(SubjectKind, "subjectKind");
        schema_matches!(TenantOrderField, "tenantOrderField");
        schema_matches!(TenantStatus, "tenantStatus");
    }

    #[test]
    fn seeded_actions_and_database_string_domains_match_the_v1_contract() {
        fn seeded_actions(sql: &str) -> Vec<String> {
            let marker = "INSERT INTO actions (name, description) VALUES";
            sql.split(marker)
                .skip(1)
                .flat_map(|tail| tail.split(';').next().into_iter())
                .flat_map(str::lines)
                .filter_map(|line| {
                    let rest = line.trim().strip_prefix("('")?;
                    let end = rest.find("',")?;
                    Some(rest[..end].to_string())
                })
                .collect()
        }

        let contract = contract();
        let mut runtime_actions = seeded_actions(include_str!("../../migrations/001_initial.sql"));
        runtime_actions.extend(seeded_actions(include_str!(
            "../../migrations/012_pki_ca_provisioning.sql"
        )));
        assert_eq!(
            runtime_actions,
            contract_strings(&contract["seededActions"])
        );

        let endpoint_authorization = &contract["authorizationTargets"]["api_endpoint"];
        assert_eq!(
            contract_strings(&endpoint_authorization["mutationActions"]),
            ["manage"]
        );
        assert_eq!(endpoint_authorization["mutationScope"], "platform");

        let tenant_admin = &contract["bootstrapReconciliation"]["tenantAdminDefaults"];
        assert_eq!(tenant_admin["field"], "tenant_defaults.admin_capabilities");
        assert_eq!(
            tenant_admin["baseCapabilities"],
            serde_json::json!(crate::tenants::repo::TENANT_ADMIN_BASE_CAPABILITIES)
        );
        assert_eq!(
            tenant_admin["effectiveCapabilities"],
            "base_union_configured"
        );
        assert_eq!(
            tenant_admin["targets"],
            "existing_and_future_system_tenant_admin_roles"
        );
        assert_eq!(tenant_admin["unknownCapability"], "startup_rejected");

        let managed_by = &contract["managedBy"];
        assert!(managed_by["apiManaged"].is_null());
        assert_eq!(managed_by["configOwned"], "config");
        assert_eq!(managed_by["systemTenantAdmin"], "system:tenant-admin");
        assert_eq!(
            managed_by["systemTenantAdminTables"],
            serde_json::json!(["roles", "permission_blocks"])
        );
        assert_eq!(
            managed_by["apiMutationRejectedMarkers"],
            serde_json::json!(["config"])
        );
        assert_eq!(
            managed_by["bootstrapReconciledMarkers"],
            serde_json::json!(["system:tenant-admin"])
        );
        let tenant_repo = include_str!("../tenants/repo.rs");
        let bootstrap = include_str!("../bootstrap.rs");
        let managed_by_guard = include_str!("../managed_by.rs");
        let tenant_admin_migration = include_str!("../../migrations/027_tenant_admin_defaults.sql");
        assert!(tenant_repo.contains("'system:tenant-admin'"));
        assert!(bootstrap.contains("managed_by = 'system:tenant-admin'"));
        assert!(managed_by_guard.contains("value == \"config\""));
        assert!(tenant_admin_migration.contains("'config', 'system:tenant-admin'"));

        let persisted = &contract["persistedStrings"];
        assert_eq!(
            contract_strings(&persisted["profileObjectKind"]),
            ["entity", "resource", "group", "tenant", "credential"]
        );
        assert_eq!(
            contract_strings(&persisted["profileEntityKind"]),
            ["human", "device", "service", "workload", "application"]
        );
        assert_eq!(persisted["profileNonEntityKindConstraint"], "non_null_text");
        assert_eq!(
            contract_strings(&persisted["profileStatus"]),
            ["active", "deprecated", "disabled"]
        );
        assert_eq!(
            contract_strings(&persisted["profileVersionStatus"]),
            ["draft", "active", "deprecated", "disabled"]
        );
        assert_eq!(
            contract_strings(&persisted["tenantMembershipStatus"]),
            ["active", "invited", "suspended", "left"]
        );
        assert_eq!(
            contract_strings(&persisted["groupType"]),
            ["object", "principal"]
        );
        assert_eq!(
            contract_strings(&persisted["signingKeyAlgorithm"]),
            ["ES256"]
        );
        assert_eq!(
            contract_strings(&persisted["signingKeyStatus"]),
            ["primary", "standby", "retired"]
        );
        assert_eq!(
            contract_strings(&persisted["permissionBlockScopeMode"]),
            [
                "platform",
                "tenant",
                "object_kind",
                "object_type",
                "object",
                "group",
                "group_direct_objects",
                "group_descendant_objects",
                "group_child_groups",
                "group_descendant_groups",
            ]
        );
        assert_eq!(
            contract_strings(&persisted["accessTokenCeilingScopeMode"]),
            ["platform", "tenant", "object_kind", "object_type", "object"]
        );

        let initial = include_str!("../../migrations/001_initial.sql");
        for exact_constraint in [
            "CHECK (status IN ('active', 'inactive', 'frozen', 'deleted'))",
            "CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'credential'))",
            "OR kind IN ('human', 'device', 'service', 'workload', 'application')",
            "CHECK (status IN ('active', 'deprecated', 'disabled'))",
            "CHECK (status IN ('draft', 'active', 'deprecated', 'disabled'))",
            "CHECK (kind IN ('human', 'device', 'service', 'workload', 'application'))",
            "CHECK (status IN ('active', 'inactive', 'suspended'))",
            "CHECK (kind IN ('password', 'access_token', 'certificate', 'shared_key'))",
            "CHECK (status IN ('primary', 'standby', 'retired'))",
            "CHECK (status IN ('active', 'invited', 'suspended', 'left'))",
            "CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy', 'credential', 'audit_log', 'signing_key'))",
            "CHECK (scope_mode IN ('platform', 'tenant', 'object_kind', 'object_type', 'object', 'group', 'group_direct_objects', 'group_descendant_objects', 'group_child_groups', 'group_descendant_groups'))",
            "CHECK (effect IN ('allow', 'deny'))",
            "CHECK (subject_kind IN ('entity', 'group'))",
            "CHECK (scope_mode IN ('platform', 'tenant', 'object_kind', 'object_type', 'object'))",
            "CHECK (outcome IN ('allow', 'deny', 'error'))",
            "CHECK (decision IN ('allow', 'deny', 'require_override'))",
            "CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'))",
            "CHECK (operation_kind IN ('query', 'mutation'))",
            "CHECK (auth_mode IN ('caller_context', 'service_context'))",
            "CHECK (status IN ('draft', 'active', 'disabled'))",
            "CHECK (status IN ('success', 'error', 'denied'))",
        ] {
            assert!(
                initial.contains(exact_constraint),
                "missing persisted constraint {exact_constraint}"
            );
        }
        assert!(initial.contains("kind         TEXT        NOT NULL,"));
        assert!(initial.contains("algorithm                  TEXT        NOT NULL DEFAULT 'ES256'"));
        assert!(initial.contains("'object'::text AS group_type"));
        assert!(initial.contains("'principal'::text AS group_type"));

        let profile_resolver = include_str!("../graphql/profiles.rs");
        assert!(
            profile_resolver.contains("Some(\"active\" | \"deprecated\" | \"disabled\") | None")
        );
        assert!(profile_resolver
            .contains("Some(\"draft\" | \"active\" | \"deprecated\" | \"disabled\") | None"));
        assert!(
            include_str!("../../migrations/018_pki_runtime_resolver_v2.sql")
                .contains("status IN ('active', 'revoked')")
        );
        assert!(
            include_str!("../../migrations/018_pki_runtime_resolver_v2.sql")
                .contains("kind = 'certificate' AND status = 'revocation_pending'")
        );
    }

    #[test]
    fn pki_persisted_strings_match_runtime_and_database_constraints() {
        use crate::certs::{
            authority::{AuthorityKeyBackend, AuthorityKind, AuthorityStatus},
            enrollment::repo::RateLimitScope,
            profile::{KeyAlgorithm, SanRuleMode},
            service::RenewalKeySource,
        };

        fn authority_kind(value: AuthorityKind) -> AuthorityKind {
            match value {
                AuthorityKind::Root
                | AuthorityKind::PlatformIntermediate
                | AuthorityKind::PlatformLeafIssuer
                | AuthorityKind::TenantIntermediate => value,
            }
        }
        fn authority_status(value: AuthorityStatus) -> AuthorityStatus {
            match value {
                AuthorityStatus::Provisioning
                | AuthorityStatus::PendingSignature
                | AuthorityStatus::Active
                | AuthorityStatus::Retiring
                | AuthorityStatus::Retired
                | AuthorityStatus::Revoked
                | AuthorityStatus::Expired
                | AuthorityStatus::Failed => value,
            }
        }
        fn authority_backend(value: AuthorityKeyBackend) -> AuthorityKeyBackend {
            match value {
                AuthorityKeyBackend::PublicOnly
                | AuthorityKeyBackend::EncryptedDatabase
                | AuthorityKeyBackend::Pkcs11
                | AuthorityKeyBackend::Kms => value,
            }
        }
        fn key_algorithm(value: KeyAlgorithm) -> KeyAlgorithm {
            match value {
                KeyAlgorithm::Ecdsa | KeyAlgorithm::Rsa | KeyAlgorithm::Ed25519 => value,
            }
        }
        fn san_rule_mode(value: SanRuleMode) -> SanRuleMode {
            match value {
                SanRuleMode::Deny
                | SanRuleMode::Allowlist
                | SanRuleMode::EntityTemplate
                | SanRuleMode::Identity => value,
            }
        }
        fn renewal_mode(value: &RenewalKeySource) -> &'static str {
            match value {
                RenewalKeySource::Csr(_) | RenewalKeySource::Generated => value.mode(),
            }
        }
        fn enrollment_scope(value: RateLimitScope) -> &'static str {
            match value {
                RateLimitScope::Entity | RateLimitScope::Tenant => value.as_str(),
            }
        }

        let contract = contract();
        let pki = &contract["pki"];
        assert_eq!(
            serialized(
                &[
                    AuthorityKind::Root,
                    AuthorityKind::PlatformIntermediate,
                    AuthorityKind::PlatformLeafIssuer,
                    AuthorityKind::TenantIntermediate,
                ]
                .map(authority_kind)
            ),
            contract_strings(&pki["authorityKind"])
        );
        assert_eq!(
            serialized(
                &[
                    AuthorityStatus::Provisioning,
                    AuthorityStatus::PendingSignature,
                    AuthorityStatus::Active,
                    AuthorityStatus::Retiring,
                    AuthorityStatus::Retired,
                    AuthorityStatus::Revoked,
                    AuthorityStatus::Expired,
                    AuthorityStatus::Failed,
                ]
                .map(authority_status)
            ),
            contract_strings(&pki["authorityStatus"])
        );
        assert_eq!(
            serialized(
                &[
                    AuthorityKeyBackend::PublicOnly,
                    AuthorityKeyBackend::EncryptedDatabase,
                    AuthorityKeyBackend::Pkcs11,
                    AuthorityKeyBackend::Kms,
                ]
                .map(authority_backend)
            ),
            contract_strings(&pki["authorityKeyBackend"])
        );
        assert_eq!(
            serialized(
                &[
                    KeyAlgorithm::Ecdsa,
                    KeyAlgorithm::Rsa,
                    KeyAlgorithm::Ed25519
                ]
                .map(key_algorithm)
            ),
            contract_strings(&pki["certificateProfile"]["keyAlgorithm"])
        );
        assert_eq!(
            serialized(
                &[
                    SanRuleMode::Deny,
                    SanRuleMode::Allowlist,
                    SanRuleMode::EntityTemplate,
                    SanRuleMode::Identity,
                ]
                .map(san_rule_mode)
            ),
            ["deny", "allowlist", "entity_template", "identity"]
        );

        let renewal_modes = [
            renewal_mode(&RenewalKeySource::Csr(String::new())),
            renewal_mode(&RenewalKeySource::Generated),
        ];
        assert_eq!(renewal_modes.as_slice(), ["csr", "generated"]);
        assert_eq!(
            renewal_modes,
            contract_strings(&pki["certificateRenewalKeyMode"])
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
        );
        assert_eq!(
            [
                enrollment_scope(RateLimitScope::Entity),
                enrollment_scope(RateLimitScope::Tenant),
            ],
            ["entity", "tenant"]
        );
        assert_eq!(
            [
                enrollment_scope(RateLimitScope::Entity),
                enrollment_scope(RateLimitScope::Tenant),
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
            contract_strings(&pki["enrollmentRateScopeKind"])
        );

        assert_eq!(
            contract_strings(&pki["authorityProvisioningMode"]),
            ["imported", "offline", "automated", "config_bootstrap"]
        );
        assert_eq!(
            contract_strings(&pki["lifecycleSubjectKind"]),
            ["credential", "authority"]
        );
        assert_eq!(
            contract_strings(&pki["lifecycleWindowKind"]),
            ["renewal", "expiry", "authority_expiry"]
        );

        let profile = &pki["certificateProfile"];
        assert_eq!(
            contract_strings(&profile["keyUsage"]),
            [
                "digital_signature",
                "content_commitment",
                "key_encipherment",
                "data_encipherment",
                "key_agreement",
            ]
        );
        assert_eq!(
            contract_strings(&profile["extendedKeyUsage"]),
            [
                "server_auth",
                "client_auth",
                "code_signing",
                "email_protection",
                "time_stamping",
                "ocsp_signing",
            ]
        );
        assert_eq!(
            profile["identityUriTemplate"],
            "urn:atom:{scope}entity:{entity_id}"
        );
        assert_eq!(
            profile["basicConstraints"],
            serde_json::json!({"ca": false, "path_len": null})
        );
        assert_eq!(
            profile["keySizePolicy"]["ecdsa"],
            serde_json::json!([256, 384])
        );
        assert_eq!(
            profile["keySizePolicy"]["rsa"],
            "integer_gte_2048_divisible_by_256"
        );
        assert_eq!(
            profile["keySizePolicy"]["ed25519"],
            serde_json::json!([255])
        );
        assert_eq!(
            contract_strings(&profile["sanRuleMode"]["dns"]),
            ["deny", "allowlist", "entity_template"]
        );
        assert_eq!(
            contract_strings(&profile["sanRuleMode"]["ip"]),
            ["deny", "allowlist"]
        );
        assert_eq!(
            contract_strings(&profile["sanRuleMode"]["email"]),
            ["deny", "allowlist"]
        );
        assert_eq!(
            contract_strings(&profile["sanRuleMode"]["uri"]),
            ["identity"]
        );

        let authority_sql = include_str!("../../migrations/011_pki_authorities.sql");
        for value in contract_strings(&pki["authorityKind"])
            .into_iter()
            .chain(contract_strings(&pki["authorityStatus"]))
            .chain(contract_strings(&pki["authorityKeyBackend"]))
        {
            assert!(authority_sql.contains(&format!("'{value}'")));
        }
        assert!(include_str!("../../migrations/024_pki_config_bootstrap_provisioning_mode.sql")
            .contains("CHECK (provisioning_mode IN ('imported', 'offline', 'automated', 'config_bootstrap'))"));
        assert!(
            include_str!("../../migrations/015_pki_certificate_renewal.sql")
                .contains("CHECK (key_mode IN ('csr', 'generated'))")
        );
        assert!(include_str!("../../migrations/019_pki_enrollment.sql")
            .contains("CHECK (scope_kind IN ('entity', 'tenant'))"));
        let lifecycle = include_str!("../../migrations/020_pki_lifecycle_automation.sql");
        assert!(lifecycle.contains("CHECK (subject_kind IN ('credential', 'authority'))"));
        for value in contract_strings(&pki["lifecycleWindowKind"]) {
            assert!(lifecycle.contains(&format!("'{value}'")));
        }

        let legacy_issuer = &pki["legacyIssuerMigration"];
        assert_eq!(legacy_issuer["metadataKey"], "issuer_migration");
        assert_eq!(legacy_issuer["sentinel"], "legacy_unmanaged");
        assert_eq!(legacy_issuer["appliesToCredentialKind"], "certificate");
        assert!(legacy_issuer["issuerId"].is_null());
        assert_eq!(
            legacy_issuer["revocationArtifactPolicy"],
            "local_status_only_no_crl_or_ocsp"
        );
        let authority_migration = include_str!("../../migrations/011_pki_authorities.sql");
        assert!(authority_migration.contains("'{issuer_migration}'"));
        assert!(authority_migration.contains("'\"legacy_unmanaged\"'::jsonb"));
        assert!(authority_migration
            .contains("metadata->>'issuer_migration' IS NOT DISTINCT FROM 'legacy_unmanaged'"));
        for migration in [
            include_str!("../../migrations/016_pki_certificate_revocation.sql"),
            include_str!("../../migrations/017_pki_issuer_crls.sql"),
            include_str!("../../migrations/022_pki_durable_revocation_evidence.sql"),
        ] {
            assert!(migration.contains("metadata->>'issuer_migration' = 'legacy_unmanaged'"));
        }

        let profile_sql = include_str!("../../migrations/013_pki_certificate_profiles.sql");
        for value in contract_strings(&profile["keyUsage"])
            .into_iter()
            .chain(contract_strings(&profile["extendedKeyUsage"]))
        {
            assert!(profile_sql.contains(&format!("'{value}'")));
        }
        let profile_runtime = include_str!("../certs/profile.rs");
        for value in contract_strings(&profile["keyUsage"])
            .into_iter()
            .chain(contract_strings(&profile["extendedKeyUsage"]))
        {
            assert!(profile_runtime.contains(&format!("\"{value}\" => Ok(Self::")));
        }
        for exact_runtime_rule in [
            "KeyAlgorithm::Ecdsa => !matches!(*size, 256 | 384)",
            "KeyAlgorithm::Rsa => *size < 2048 || *size % 256 != 0",
            "KeyAlgorithm::Ed25519 => *size != 255",
            "row.identity_uri_template != \"urn:atom:{scope}entity:{entity_id}\"",
            "if basic_constraints.ca || basic_constraints.path_len.is_some()",
        ] {
            assert!(profile_runtime.contains(exact_runtime_rule));
        }

        let metadata_contract = &pki["certificateMetadata"];
        let now = chrono::Utc::now();
        let metadata = crate::certs::service::CertificateMetadata {
            certificate_pem: "certificate".to_string(),
            chain_pem: None,
            subject: serde_json::json!({}),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            issuer_kind: "tenant_intermediate".to_string(),
            issuer_subject: "issuer".to_string(),
            issuer_serial_number: "01".to_string(),
            issuer_fingerprint_sha256: "a".repeat(64),
            fingerprint_sha256: "b".repeat(64),
            profile_id: None,
            profile_name: None,
            identity_uri: None,
            renewed_from_credential_id: None,
            renewal_threshold_seconds: None,
            renewal_due_at: None,
            not_before: now,
            not_after: now,
            issued_from_csr: false,
            revoked_at: None,
            revocation_reason: None,
        };
        let metadata_keys = serde_json::to_value(metadata)
            .expect("certificate metadata JSON")
            .as_object()
            .expect("certificate metadata object")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            metadata_keys,
            contract_strings(&metadata_contract["serializedKeys"])
                .into_iter()
                .collect()
        );

        let cert_runtime = include_str!("../certs/service.rs");
        for key in contract_strings(&metadata_contract["revocationKeys"]) {
            assert!(cert_runtime.contains(&format!("metadata[\"{key}\"]")));
        }
        assert!(
            cert_runtime.contains("value.unwrap_or(\"unspecified\").trim().to_ascii_lowercase()")
        );
        assert!(cert_runtime.contains("reason.len() > 64"));
        assert!(cert_runtime.contains("matches!(ch, '_' | '-' | '.')"));
        assert!(cert_runtime.contains("reason.as_deref().or(Some(\"entity_revoked\"))"));
        assert!(cert_runtime.contains("\"superseded\","));
        assert_eq!(metadata_contract["defaultReason"], "unspecified");
        assert_eq!(
            metadata_contract["entityWideDefaultReason"],
            "entity_revoked"
        );
        assert_eq!(metadata_contract["renewalReplacementReason"], "superseded");
        for reason in metadata_contract["rfcReasonMappings"]
            .as_object()
            .expect("RFC revocation reason map")
            .keys()
        {
            assert!(
                cert_runtime.matches(&format!("\"{reason}\" =>")).count() >= 2,
                "reason must map in both CRL and OCSP paths: {reason}"
            );
        }
        assert!(
            cert_runtime
                .matches("_ => X509CrlReason::Unspecified")
                .count()
                == 1
        );
        assert!(
            cert_runtime
                .matches("_ => RevocationReason::Unspecified")
                .count()
                == 1
        );

        let provenance =
            contract_strings(&contract["persistedStrings"]["credentialRevocationProvenance"]);
        assert_eq!(provenance, ["tenant_deleted", "entity_deleted", "manual"]);
        let credential_metadata = &contract["credentialMetadata"];
        assert_eq!(
            contract_strings(&credential_metadata["accessTokenKeys"]),
            ["name", "description"]
        );
        assert_eq!(
            contract_strings(&credential_metadata["accessTokenNameReadFallback"]),
            ["metadata.name", "identifier", "Access token"]
        );
        assert!(credential_metadata["accessTokenEmptyDescriptionReadsAs"].is_null());
        assert_eq!(
            contract_strings(&credential_metadata["sharedKeyKeys"]),
            ["description"]
        );
        assert_eq!(
            contract_strings(&credential_metadata["revocationKeys"]),
            ["revoked_at", "revocation_reason", "revoked_by_entity_id"]
        );
        assert_eq!(
            contract_strings(&credential_metadata["tenantRestoreClears"]),
            ["revoked_at", "revocation_reason"]
        );
        assert_eq!(
            contract_strings(&credential_metadata["revocationReasonValues"]),
            provenance
        );
        assert_eq!(
            credential_metadata["manualRevocationOverwritesPriorProvenance"],
            true
        );

        let access_tokens = include_str!("../identity/access_tokens.rs");
        assert!(access_tokens
            .contains("serde_json::json!({ \"name\": &name, \"description\": &description })"));
        assert!(access_tokens.contains("metadata->>'name'"));
        assert!(access_tokens.contains("metadata->>'description'"));
        let bootstrap = include_str!("../bootstrap.rs");
        assert!(bootstrap
            .contains("serde_json::json!({ \"name\": name, \"description\": description })"));
        assert!(bootstrap.contains("serde_json::json!({ \"description\": description })"));
        let identity_service = include_str!("../identity/service.rs");
        assert!(
            identity_service.contains("serde_json::json!({ \"description\": req.description })")
        );

        let tenant_repo = include_str!("../tenants/repo.rs");
        let identity_repo = include_str!("../identity/repo.rs");
        assert!(tenant_repo.contains("'revocation_reason', 'tenant_deleted'"));
        assert!(identity_repo.contains("'revocation_reason', 'entity_deleted'"));
        assert!(identity_service.contains("'revocation_reason', 'manual'"));
        assert!(access_tokens.contains("'revocation_reason', 'manual'"));
        for source in [tenant_repo, identity_repo] {
            assert!(source.contains("'revoked_at', now()"));
            assert!(source.contains("'revoked_by_entity_id'"));
        }
        assert!(tenant_repo.contains("metadata = c.metadata - 'revoked_at' - 'revocation_reason'"));
        for source in [identity_service, access_tokens] {
            assert!(source.contains("metadata = metadata - 'revoked_at' - 'revocation_reason'"));
        }
    }

    #[test]
    fn callout_string_semantics_match_runtime_configuration() {
        use crate::{
            auth::AuthContext,
            callout::{
                config::{CalloutsFile, HttpMethod, SurfaceKind},
                envelope::{Actor, Decision, DENYLIST_KEYS},
                Surface, TransportConfig,
            },
        };

        let contract = contract();
        let callouts = &contract["callouts"];
        fn on_error(value: crate::callout::OnError) -> &'static str {
            match value {
                crate::callout::OnError::Deny | crate::callout::OnError::Allow => value.as_str(),
            }
        }
        fn http_method(value: HttpMethod) -> &'static str {
            match value {
                HttpMethod::Post | HttpMethod::Get => value.as_str(),
            }
        }
        fn decision(value: Decision) -> Decision {
            match value {
                Decision::Allow | Decision::Deny => value,
            }
        }
        let yaml = r#"
callouts:
  endpoints:
    - id: http-policy
      transport: http
      url: https://policy.example/check
    - id: grpc-policy
      transport: grpc
      address: https://policy.example:9443
  operations:
    - name: createEntity
      surface: graphql
      endpoints: [http-policy]
    - name: /atom.v1.AuthzService/Check
      surface: grpc
      endpoints: [grpc-policy]
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).expect("callout v1 config");
        let endpoints = &file.callouts.endpoints;
        let transports = endpoints
            .iter()
            .map(|endpoint| match &endpoint.transport {
                TransportConfig::Http(_) => "http",
                TransportConfig::Grpc(_) => "grpc",
            })
            .collect::<Vec<_>>();
        assert_eq!(transports, contract_strings(&callouts["transport"]));
        assert!(matches!(
            endpoints[0].on_error,
            crate::callout::OnError::Deny
        ));
        assert_eq!(endpoints[0].on_error.as_str(), callouts["defaultOnError"]);
        assert_eq!(
            Some(endpoints[0].timeout_ms),
            callouts["defaultTimeoutMilliseconds"].as_u64()
        );
        match &endpoints[0].transport {
            TransportConfig::Http(http) => {
                assert!(matches!(http.method, HttpMethod::Post));
                assert_eq!(http.method.as_str(), callouts["defaultHttpMethod"]);
            }
            TransportConfig::Grpc(_) => panic!("expected HTTP endpoint"),
        }

        let surfaces = file
            .callouts
            .operations
            .iter()
            .map(|operation| match operation.surface {
                SurfaceKind::Graphql => Surface::GraphQL.as_str(),
                SurfaceKind::Grpc => Surface::Grpc.as_str(),
            })
            .collect::<Vec<_>>();
        assert_eq!(surfaces, contract_strings(&callouts["surface"]));
        assert_eq!(
            serialized(&[Decision::Allow, Decision::Deny].map(decision)),
            contract_strings(&callouts["decision"])
        );
        assert_eq!(
            [
                on_error(crate::callout::OnError::Deny),
                on_error(crate::callout::OnError::Allow),
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
            contract_strings(&callouts["onError"])
        );
        assert_eq!(
            [http_method(HttpMethod::Post), http_method(HttpMethod::Get)]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            contract_strings(&callouts["httpMethod"])
        );

        let empty = Actor::from_auth(&AuthContext::default()).scope;
        let session = Actor::from_auth(&AuthContext {
            session_id: Some(uuid::Uuid::nil()),
            ..Default::default()
        })
        .scope;
        let access_token = Actor::from_auth(&AuthContext {
            credential_id: Some(uuid::Uuid::nil()),
            ..Default::default()
        })
        .scope;
        assert_eq!(
            [empty, session, access_token]
                .into_iter()
                .collect::<Vec<_>>(),
            contract_strings(&callouts["actorScope"])
        );
        assert_eq!(
            DENYLIST_KEYS,
            contract_strings(&callouts["redactedFieldNamesCaseInsensitive"])
        );
        assert_eq!(
            callouts["chainEvaluation"],
            "ordered_all_must_allow_fail_fast"
        );
    }

    #[test]
    fn deployment_environment_surface_matches_v1_contract() {
        use std::collections::BTreeSet;

        fn production_prefix(source: &str) -> &str {
            source.split("#[cfg(test)]").next().unwrap_or(source)
        }

        fn quoted_strings(source: &str) -> Vec<String> {
            let mut strings = Vec::new();
            let mut current = String::new();
            let mut quoted = false;
            let mut escaped = false;
            for character in source.chars() {
                if !quoted {
                    if character == '"' {
                        quoted = true;
                        current.clear();
                    }
                    continue;
                }
                if escaped {
                    current.push(character);
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    strings.push(current.clone());
                    quoted = false;
                } else {
                    current.push(character);
                }
            }
            strings
        }

        fn is_static_env_name(value: &str) -> bool {
            let fixed = [
                "ADMIN_ENTITY_ID",
                "ADMIN_SECRET",
                "DATABASE_URL",
                "GRPC_ADDR",
                "JWT_EXPIRY_SECS",
                "LISTEN_ADDR",
                "RUST_LOG",
            ];
            fixed.contains(&value)
                || (value.starts_with("ATOM_")
                    && value.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                    && !matches!(
                        value,
                        "ATOM_VERSION" | "ATOM_REVISION" | "ATOM_TEST_REDIS_URL"
                    ))
        }

        let artifact: serde_json::Value =
            serde_json::from_str(include_str!("../../api/v1/deployment-config.json"))
                .expect("deployment-config v1 contract");
        let artifact_names = contract_strings(&artifact["staticEnvironmentVariables"])
            .into_iter()
            .collect::<BTreeSet<_>>();
        let default_names = artifact["effectiveDefaults"]
            .as_object()
            .expect("effective-default map")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            artifact_names, default_names,
            "every static env has one default"
        );
        assert_eq!(
            artifact_names.len(),
            162,
            "review any deployment API addition"
        );

        let sources = [
            include_str!("../config.rs"),
            include_str!("../callout/config.rs"),
            include_str!("../identity/service.rs"),
            include_str!("../cache/mod.rs"),
            include_str!("../grpc.rs"),
            include_str!("../mail.rs"),
            include_str!("../tenants/repo.rs"),
            include_str!("../authz/engine.rs"),
        ];
        let runtime_names = sources
            .iter()
            .flat_map(|source| quoted_strings(production_prefix(source)))
            .filter(|value| is_static_env_name(value))
            .collect::<BTreeSet<_>>();
        assert_eq!(runtime_names, artifact_names);

        let config_source = production_prefix(include_str!("../config.rs"));
        let callout_source = production_prefix(include_str!("../callout/config.rs"));

        let default = |name: &str| &artifact["effectiveDefaults"][name];
        assert_eq!(
            default("ADMIN_ENTITY_ID").as_str(),
            Some("00000000-0000-0000-0000-000000000001")
        );
        assert_eq!(
            default("ATOM_SERVICE_ENTITY_ID").as_str(),
            Some("00000000-0000-0000-0000-000000000003")
        );
        assert_eq!(
            crate::config::ADMIN_ENTITY_ID.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            crate::config::SERVICE_ENTITY_ID.to_string(),
            "00000000-0000-0000-0000-000000000003"
        );
        assert_eq!(default("JWT_EXPIRY_SECS"), 3_600);
        assert_eq!(default("ATOM_EMAIL_VERIFICATION_EXPIRY_SECS"), 86_400);
        assert_eq!(default("ATOM_INVITATION_EXPIRY_SECS"), 604_800);
        assert_eq!(default("ATOM_OAUTH_STATE_EXPIRY_SECS"), 600);
        assert_eq!(default("ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS"), 300);

        let parsing = &artifact["parsing"];
        assert_eq!(
            contract_strings(&parsing["booleanTruthyValues"]),
            ["1", "true", "yes", "on"].map(str::to_string)
        );
        assert_eq!(
            contract_strings(&parsing["booleanFalseValues"]),
            ["0", "false", "no", "off"].map(str::to_string)
        );
        assert!(parsing["booleanRule"]
            .as_str()
            .expect("boolean parsing rule")
            .contains("including blank, fails startup"));
        assert_eq!(
            contract_strings(&parsing["uuidOverrides"]["variables"]),
            ["ADMIN_ENTITY_ID", "ATOM_SERVICE_ENTITY_ID"].map(str::to_string)
        );
        assert_eq!(
            contract_strings(&parsing["positiveAuthLifetimeSeconds"]["variables"]),
            [
                "JWT_EXPIRY_SECS",
                "ATOM_EMAIL_VERIFICATION_EXPIRY_SECS",
                "ATOM_INVITATION_EXPIRY_SECS",
                "ATOM_OAUTH_STATE_EXPIRY_SECS",
                "ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS",
            ]
            .map(str::to_string)
        );
        assert!(config_source.contains("\"1\" | \"true\" | \"yes\" | \"on\" => Ok(true)"));
        assert!(config_source.contains("\"0\" | \"false\" | \"no\" | \"off\" => Ok(false)"));
        assert!(config_source.contains("env_parse(\"ADMIN_ENTITY_ID\", ADMIN_ENTITY_ID)?"));
        assert!(config_source.contains("env_parse(\"ATOM_SERVICE_ENTITY_ID\", SERVICE_ENTITY_ID)?"));
        assert!(config_source.contains("env_positive_lifetime_secs(\"JWT_EXPIRY_SECS\", 3_600)?"));
        assert!(callout_source.contains("env_bool_default(\"ATOM_CALLOUTS_ENABLED\", true)?"));

        let db = crate::config::DbPoolConfig::default();
        assert_eq!(default("ATOM_DB_MAX_CONNECTIONS"), db.max_connections);
        assert_eq!(default("ATOM_DB_MIN_CONNECTIONS"), db.min_connections);
        assert_eq!(
            default("ATOM_DB_ACQUIRE_TIMEOUT_SECS"),
            db.acquire_timeout_secs
        );
        assert_eq!(
            default("ATOM_DB_CONNECT_TIMEOUT_SECS"),
            db.connect_timeout_secs
        );
        assert_eq!(default("ATOM_DB_IDLE_TIMEOUT_SECS"), db.idle_timeout_secs);
        assert_eq!(default("ATOM_DB_MAX_LIFETIME_SECS"), db.max_lifetime_secs);

        let http = crate::config::HttpServerConfig::default();
        assert_eq!(default("ATOM_HTTP_MAX_CONNECTIONS"), http.max_connections);
        assert_eq!(
            default("ATOM_HTTP_MAX_CONNECTIONS_PER_IP"),
            http.max_connections_per_ip
        );
        assert_eq!(
            default("ATOM_HTTP_HEADER_TIMEOUT_SECS"),
            http.http_header_timeout_secs
        );
        assert_eq!(
            default("ATOM_HTTP_REQUEST_TIMEOUT_SECS"),
            http.request_timeout_secs
        );
        assert_eq!(
            default("ATOM_HTTP_CONNECTION_TIMEOUT_SECS"),
            http.connection_timeout_secs
        );
        assert_eq!(
            default("ATOM_HTTP_SHUTDOWN_DRAIN_TIMEOUT_SECS"),
            http.shutdown_drain_timeout_secs
        );

        let cache = crate::config::CacheConfig::default();
        assert_eq!(default("ATOM_CACHE_POOL_MAX_SIZE"), cache.pool_max_size);
        assert_eq!(
            default("ATOM_CACHE_CONNECT_TIMEOUT_MS"),
            cache.connect_timeout_ms
        );
        assert_eq!(default("ATOM_CACHE_OP_TIMEOUT_MS"), cache.op_timeout_ms);
        assert_eq!(
            default("ATOM_CACHE_FAIL_FAST_ON_STARTUP"),
            cache.fail_fast_on_startup
        );
        assert_eq!(
            default("ATOM_CACHE_TTL_SESSION_SECS"),
            cache.ttl.session_secs
        );
        assert_eq!(
            default("ATOM_CACHE_TTL_ENTITY_STATUS_SECS"),
            cache.ttl.entity_status_secs
        );
        assert_eq!(
            default("ATOM_CACHE_TTL_TENANT_STATUS_SECS"),
            cache.ttl.tenant_status_secs
        );
        assert_eq!(
            default("ATOM_CACHE_TTL_CREDENTIAL_SECS"),
            cache.ttl.credential_secs
        );
        assert_eq!(
            default("ATOM_CACHE_TTL_CREDENTIAL_CEILING_SECS"),
            cache.ttl.credential_ceiling_secs
        );
        assert_eq!(default("ATOM_CACHE_TTL_GRANTS_SECS"), cache.ttl.grants_secs);

        let enrollment = crate::config::EnrollmentConfig::default();
        assert_eq!(default("ATOM_PKI_ENROLLMENT_ENABLED"), enrollment.enabled);
        assert_eq!(
            default("ATOM_PKI_ENROLLMENT_LISTEN_ADDR").as_str(),
            Some(enrollment.listen_addr.as_str())
        );
        assert_eq!(
            default("ATOM_PKI_ENROLLMENT_MAX_CSR_BYTES"),
            enrollment.max_csr_bytes
        );
        assert_eq!(
            default("ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS"),
            enrollment.max_connections
        );
        assert_eq!(
            default("ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS_PER_IP"),
            enrollment.max_connections_per_ip
        );

        let events = crate::config::EventsConfig::default();
        assert!(default("ATOM_EVENTS_AMQP_URL").is_null());
        assert_eq!(
            default("ATOM_EVENTS_AMQP_ROUTING_KEY").as_str(),
            Some(events.amqp_routing_key.as_str())
        );
        assert_eq!(
            default("ATOM_EVENTS_OUTBOX_BATCH_SIZE"),
            events.outbox_batch_size
        );
        assert_eq!(
            default("ATOM_EVENTS_OUTBOX_MAX_ATTEMPTS"),
            events.outbox_max_attempts
        );
        assert_eq!(
            default("ATOM_EVENTS_PUBLISH_TIMEOUT_SECS"),
            events.publish_timeout_secs
        );

        let graphql = crate::config::GraphqlLimitConfig::default();
        assert_eq!(default("ATOM_GRAPHQL_MAX_DEPTH"), graphql.max_depth);
        assert_eq!(
            default("ATOM_GRAPHQL_MAX_COMPLEXITY"),
            graphql.max_complexity
        );
        assert_eq!(
            default("ATOM_GRAPHQL_INTROSPECTION_ENABLED"),
            graphql.introspection_enabled
        );

        let audit_policy = crate::config::AuditPolicyConfig::default();
        assert_eq!(
            default("ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED"),
            audit_policy.hot_path_allow_db_enabled
        );
        let audit = crate::config::AuditRetentionConfig::default();
        assert_eq!(default("ATOM_AUDIT_RETENTION_ENABLED"), audit.enabled);
        assert_eq!(default("ATOM_AUDIT_RETENTION_DAYS"), audit.days);
        assert_eq!(
            default("ATOM_AUDIT_CLEANUP_INTERVAL_SECS"),
            audit.cleanup_interval_secs
        );
        assert_eq!(
            default("ATOM_AUDIT_CLEANUP_BATCH_SIZE"),
            audit.cleanup_batch_size
        );

        let purge = crate::config::PurgeConfig::default();
        assert_eq!(default("ATOM_PURGE_ENABLED"), purge.enabled);
        assert_eq!(default("ATOM_PURGE_RETENTION_DAYS"), purge.retention_days);
        assert_eq!(default("ATOM_PURGE_INTERVAL_SECS"), purge.interval_secs);
        assert_eq!(default("ATOM_PURGE_BATCH_SIZE"), purge.batch_size);

        let rate = crate::config::RateLimitConfig::default();
        assert_eq!(default("ATOM_RATE_LIMIT_ENABLED"), rate.enabled);
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_AUTH_ROUTES"),
            rate.auth_routes.max_requests
        );
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_PUBLIC_ROUTES"),
            rate.public_routes.max_requests
        );
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_ENROLLMENT"),
            rate.enrollment.max_requests
        );
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_GRAPHQL"),
            rate.graphql.max_requests
        );
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS"),
            rate.custom_endpoints.max_requests
        );
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_ADMIN_ROUTES"),
            rate.admin_routes.max_requests
        );
        assert_eq!(
            default("ATOM_HTTP_RATE_LIMIT_IPV6_PREFIX_LEN"),
            rate.ipv6_prefix_len
        );

        let body = crate::config::BodyLimitConfig::default();
        assert_eq!(default("ATOM_AUTH_BODY_LIMIT_BYTES"), body.auth_bytes);
        assert_eq!(default("ATOM_GRAPHQL_BODY_LIMIT_BYTES"), body.graphql_bytes);
        assert_eq!(
            default("ATOM_CUSTOM_ENDPOINT_BODY_LIMIT_BYTES"),
            body.custom_endpoint_bytes
        );

        let lifecycle = crate::config::PkiLifecycleConfig::default();
        assert_eq!(default("ATOM_PKI_LIFECYCLE_ENABLED"), lifecycle.enabled);
        assert_eq!(
            default("ATOM_PKI_LIFECYCLE_INTERVAL_SECS"),
            lifecycle.interval_secs
        );
        assert_eq!(
            default("ATOM_PKI_LIFECYCLE_BATCH_SIZE"),
            lifecycle.batch_size
        );
        assert_eq!(
            default("ATOM_PKI_EXPIRY_WARNING_SECS"),
            lifecycle.expiry_warning_secs
        );
        assert_eq!(
            default("ATOM_PKI_AUTHORITY_WARNING_SECS"),
            lifecycle.authority_warning_secs
        );

        let signing = crate::config::SigningKeyConfig::default();
        assert_eq!(
            default("ATOM_KEY_ENCRYPTION_KEY_ID").as_str(),
            Some(signing.key_encryption_key_id.as_str())
        );
        assert_eq!(
            default("ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS"),
            signing.allow_plaintext_signing_keys
        );
        let ca = crate::config::PkiCaKeyConfig::default();
        assert_eq!(
            default("ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID").as_str(),
            Some(ca.key_encryption_key_id.as_str())
        );
        assert_eq!(
            default("ATOM_PKI_CA_KEY_BACKEND"),
            ca.provisioning_backend.as_str()
        );

        let logging = crate::config::LoggingConfig::default();
        assert_eq!(
            default("ATOM_LOG_LEVEL").as_str(),
            Some(logging.level.as_str())
        );
        assert_eq!(default("ATOM_LOG_FORMAT"), logging.format.as_str());
        let metrics = crate::config::MetricsConfig::default();
        assert_eq!(default("ATOM_METRICS_ENABLED"), metrics.enabled);
        let broker = crate::config::BrokerAuthConfig::default();
        assert_eq!(default("ATOM_BROKER_AUTH_ENABLED"), broker.enabled);

        assert!(config_source.contains("non_empty_env(\"ATOM_LOG_LEVEL\")"));
        assert!(config_source.contains(".or_else(|| non_empty_env(\"RUST_LOG\"))"));
        assert!(config_source.contains("(CacheMode::Enabled, true)"));
        assert!(config_source.contains("(CacheMode::Disabled, false)"));
        assert!(
            config_source.contains("ATOM_CACHE_MODE conflicts with deprecated ATOM_CACHE_ENABLED")
        );
        assert!(config_source.contains("ATOM_EVENTS_AMQP_TLS_CLIENT_CERT_PATH and ATOM_EVENTS_AMQP_TLS_CLIENT_KEY_PATH must both be set"));
        assert!(config_source
            .contains("gRPC TLS requires both ATOM_GRPC_TLS_CERT_PATH and ATOM_GRPC_TLS_KEY_PATH"));
        assert!(config_source.contains("ATOM_PKI_ENROLLMENT_REQUEST_BODY_TIMEOUT_SECS was renamed to ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS"));
        assert!(config_source.contains("ATOM_BROKER_AUTH_ENABLED=true requires gRPC mTLS"));

        let password_source = include_str!("../identity/service.rs");
        assert!(password_source.contains("const DEFAULT_MIN_PASSWORD_CHARS: usize = 12;"));
        assert!(password_source.contains("std::env::var(\"ATOM_MIN_PASSWORD_CHARS\")"));
        assert_eq!(artifact["effectiveDefaults"]["ATOM_MIN_PASSWORD_CHARS"], 12);

        assert!(callout_source.contains("format!(\"ATOM_CALLOUT_{sanitized}_\")"));
        assert!(callout_source.contains("format!(\"{prefix}TIMEOUT_MS\")"));
        assert!(callout_source.contains("format!(\"{prefix}URL\")"));
        assert!(callout_source.contains("format!(\"{prefix}ADDRESS\")"));
    }

    #[test]
    fn graphql_root_auth_registry_matches_sdl_and_focused_runtime_gates() {
        use std::collections::BTreeSet;

        fn root_fields(sdl: &str, root: &str) -> BTreeSet<String> {
            let body = sdl
                .split_once(&format!("type {root} {{"))
                .unwrap_or_else(|| panic!("missing GraphQL root {root}"))
                .1
                .split_once("\n}")
                .expect("GraphQL root terminator")
                .0;
            body.lines()
                .filter_map(|line| {
                    let line = line.trim_start();
                    let end = line.find(|character: char| {
                        !(character.is_ascii_alphanumeric() || character == '_')
                    })?;
                    let name = &line[..end];
                    matches!(line.as_bytes().get(end), Some(b'(' | b':')).then(|| name.to_string())
                })
                .collect()
        }

        fn function_section<'a>(source: &'a str, name: &str) -> &'a str {
            let marker = format!("async fn {name}");
            let tail = source
                .split_once(&marker)
                .unwrap_or_else(|| panic!("missing resolver {name}"))
                .1;
            tail.split("\n    async fn ").next().unwrap_or(tail)
        }

        fn top_level_async_function_section<'a>(source: &'a str, name: &str) -> &'a str {
            let markers = [
                format!("pub async fn {name}"),
                format!("pub(crate) async fn {name}"),
                format!("async fn {name}"),
            ];
            let tail = markers
                .iter()
                .find_map(|marker| source.split_once(marker).map(|(_, tail)| tail))
                .unwrap_or_else(|| panic!("missing top-level function {name}"));
            ["\npub async fn ", "\npub(crate) async fn ", "\nasync fn "]
                .into_iter()
                .filter_map(|marker| tail.find(marker))
                .min()
                .map(|end| &tail[..end])
                .unwrap_or(tail)
        }

        let artifact: serde_json::Value =
            serde_json::from_str(include_str!("../../api/v1/graphql-auth-matrix.json"))
                .expect("GraphQL auth registry");
        let sdl = include_str!("../../apidocs/graphql-schema.graphql");
        let queries = root_fields(sdl, "QueryRoot");
        let mutations = root_fields(sdl, "MutationRoot");
        assert_eq!(
            queries,
            contract_strings(&artifact["rootOperations"]["query"])
                .into_iter()
                .collect()
        );
        assert_eq!(
            mutations,
            contract_strings(&artifact["rootOperations"]["mutation"])
                .into_iter()
                .collect()
        );
        let all = queries.union(&mutations).cloned().collect::<BTreeSet<_>>();
        let assignments = artifact["profileAssignments"]
            .as_object()
            .expect("authorization profile assignments")
            .values()
            .flat_map(contract_strings)
            .collect::<Vec<_>>();
        assert_eq!(
            assignments.len(),
            assignments.iter().collect::<BTreeSet<_>>().len(),
            "a GraphQL operation cannot have two authorization profiles"
        );
        assert_eq!(all, assignments.into_iter().collect());
        assert_eq!(
            contract_strings(&artifact["authentication"]["public"]),
            ["health", "login", "signup"].map(str::to_string)
        );

        let auth_source = include_str!("../graphql/auth.rs");
        for public in ["health", "login", "signup"] {
            assert!(
                !function_section(auth_source, public).contains("require_auth(ctx)"),
                "public resolver {public} acquired authentication"
            );
        }
        assert!(function_section(auth_source, "logout").contains("require_auth(ctx)?"));
        let refresh = function_section(auth_source, "refresh_session");
        assert!(refresh.contains("require_auth(ctx)?"));
        assert!(refresh.contains("auth.session_id.ok_or_else"));

        for (source, names) in [
            (
                include_str!("../graphql/tenants.rs"),
                &["restore_tenant", "purge_tenant"][..],
            ),
            (
                include_str!("../graphql/entities.rs"),
                &["restore_entity", "purge_entity"][..],
            ),
            (
                include_str!("../graphql/resources.rs"),
                &["restore_resource", "purge_resource"][..],
            ),
            (
                include_str!("../graphql/groups.rs"),
                &["restore_group", "purge_group"][..],
            ),
            (
                include_str!("../graphql/policies.rs"),
                &["restore_role", "purge_role"][..],
            ),
            (
                include_str!("../graphql/api_endpoints.rs"),
                &[
                    "create_api_endpoint",
                    "update_api_endpoint",
                    "enable_api_endpoint",
                    "disable_api_endpoint",
                ][..],
            ),
        ] {
            for name in names {
                let resolver = function_section(source, name);
                assert!(resolver.contains("require_auth(ctx)?"));
                assert!(resolver.contains("\"manage\", Scope::Platform"));
            }
        }

        let operations = include_str!("../graphql/operations.rs");
        assert!(
            function_section(operations, "system_status").contains("\"manage\", Scope::Platform")
        );
        assert!(function_section(operations, "signing_keys").contains("\"read\", Scope::Platform"));
        assert!(function_section(operations, "rotate_signing_keys")
            .contains("\"rotate\", Scope::Platform"));

        let access = include_str!("../authz/access.rs");
        assert!(access.contains("if auth.entity_id == subject_id"));
        assert!(access.contains("(\"authz.check\", scope)"));
        assert!(access.contains("(\"authz.check\", Scope::Platform)"));
        assert!(!access.contains("(\"policy.manage\", scope)"));
        assert!(!access.contains("(\"manage\", scope)"));
        assert_eq!(
            contract_strings(&artifact["delegatedAuthzInvocation"]["operations"]),
            ["authorizedObjectIds", "authzCheck", "authzBulkCheck"].map(str::to_string)
        );

        let entity_authorization = &artifact["entityMutationAuthorization"];
        assert_eq!(
            entity_authorization,
            &serde_json::json!({
                "operations": ["updateEntity", "deleteEntity"],
                "selfTargetBypass": false,
                "updateSourceAnyOf": [
                    {"action": "manage", "scope": "target_object"},
                    {"action": "manage", "scope": "source_tenant_or_platform"},
                    {"action": "write", "scope": "source_tenant_or_platform"}
                ],
                "deleteSourceAnyOf": [
                    {"action": "manage", "scope": "target_object"},
                    {"action": "manage", "scope": "source_tenant_or_platform"}
                ],
                "tenantMoveDestinationAnyOf": [
                    {"action": "manage", "scope": "destination_tenant"},
                    {"action": "write", "scope": "destination_tenant"}
                ],
                "scopedCredentialCeiling": "enforced",
                "authorizationSnapshotMustMatchMutation": true
            })
        );

        let entity_resolvers = include_str!("../graphql/entities.rs");
        let update_resolver = function_section(entity_resolvers, "update_entity");
        assert!(update_resolver.contains("identity_service::update_entity_authorized"));
        assert!(!update_resolver.contains("auth.entity_id == id"));
        assert!(!update_resolver.contains("auth.entity_id != id"));
        let delete_resolver = function_section(entity_resolvers, "delete_entity");
        assert!(delete_resolver.contains("identity_service::delete_entity_authorized"));
        assert!(!delete_resolver.contains("auth.entity_id == id"));
        assert!(!delete_resolver.contains("auth.entity_id != id"));

        let identity_service = include_str!("../identity/service.rs");
        let update_service =
            top_level_async_function_section(identity_service, "update_entity_authorized");
        for gate in [
            "(\"manage\", AuthScope::Object(id))",
            "(\"manage\", scope_for_tenant(existing.tenant_id))",
            "(\"write\", scope_for_tenant(existing.tenant_id))",
            "(\"manage\", destination_scope)",
            "(\"write\", destination_scope)",
        ] {
            assert!(update_service.contains(gate), "missing update gate {gate}");
        }
        assert!(update_service.contains("update_entity_with_expected_tenant_and_audit"));
        assert!(update_service.contains("existing.tenant_id"));
        assert!(!update_service.contains("auth.entity_id == id"));
        assert!(!update_service.contains("auth.entity_id != id"));

        let delete_service =
            top_level_async_function_section(identity_service, "delete_entity_authorized");
        for gate in [
            "(\"manage\", AuthScope::Object(id))",
            "(\"manage\", scope_for_tenant(existing.tenant_id))",
        ] {
            assert!(delete_service.contains(gate), "missing delete gate {gate}");
        }
        assert!(delete_service.contains("Some(existing.tenant_id)"));
        assert!(!delete_service.contains("auth.entity_id == id"));
        assert!(!delete_service.contains("auth.entity_id != id"));

        let identity_repo = include_str!("../identity/repo.rs");
        assert!(identity_repo.contains("expected_tenant_id.is_some_and"));
        assert!(identity_repo.contains("entity tenant changed after authorization"));
    }
}
