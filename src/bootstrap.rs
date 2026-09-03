//! Declarative startup bootstrap from a YAML configuration file.
//!
//! Standing up a fresh Atom deployment previously meant either setting a handful
//! of `*_SECRET` env vars or driving the API by hand to create the initial
//! tenants, entities, roles and policies. Neither is friendly for repeatable,
//! reviewable platform management.
//!
//! This module lets an operator describe the desired baseline in a single YAML
//! file (pointed to by `ATOM_BOOTSTRAP_FILE`). The file is loaded once at
//! startup, right after migrations, and applied **idempotently**: every record
//! is keyed on a stable identity, and an existing record is accepted only when
//! its normalized persisted semantics match the declaration exactly. Drift
//! fails startup rather than clobbering runtime data or attaching config links
//! to a different object. It runs *alongside* the env-var bootstrap, not instead
//! of it.
//!
//! It provisions the full RBAC graph, applied in dependency order:
//! tenants → entities (+ credentials) → resources → principal groups
//! (+ members) → object groups (+ members, hierarchy) → capabilities
//! (+ applicability) → assignment guardrails → permission blocks (+ actions)
//! → roles (+ block links) → role assignments → direct policies.
//! Records may reference rows that already exist in the database (for example
//! the pre-seeded `admin` entity or `atom-admin` role); foreign-key violations
//! for genuinely missing references abort startup.
//!
//! ## Example
//!
//! ```yaml
//! tenants:
//!   - id: 33333333-3333-3333-3333-333333333333
//!     name: factory
//!     alias: factory
//!
//! entities:
//!   - id: 22222222-2222-2222-2222-222222222222
//!     kind: device
//!     name: gateway-01
//!     tenant_id: 33333333-3333-3333-3333-333333333333
//!     credentials:
//!       - kind: shared_key
//!         key: a-strong-device-secret
//!
//! permission_blocks:
//!   - id: 44444444-4444-4444-4444-444444444444
//!     scope:
//!       mode: object_type
//!       tenant_id: 33333333-3333-3333-3333-333333333333
//!       object_kind: resource
//!       object_type: resource:channel
//!     actions: [publish, subscribe]
//!     effect: allow
//!
//! roles:
//!   - id: 55555555-5555-5555-5555-555555555555
//!     name: publisher
//!     tenant_id: 33333333-3333-3333-3333-333333333333
//!     permission_blocks: [44444444-4444-4444-4444-444444444444]
//!
//! role_assignments:
//!   - id: 66666666-6666-6666-6666-666666666666
//!     tenant_id: 33333333-3333-3333-3333-333333333333
//!     subject: { kind: entity, id: 22222222-2222-2222-2222-222222222222 }
//!     role_id: 55555555-5555-5555-5555-555555555555
//! ```

use std::collections::HashSet;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::config::SigningKeyConfig;
use crate::identity;
use crate::models::action_assignment_rule::CreateActionAssignmentRule;
use crate::models::alias::validate_alias_opt;
use crate::models::enums::{
    ActionAssignmentDecision, CredentialKind, CredentialStatus, Effect, EntityKind, EntityStatus,
    ObjectKind, SubjectKind, TenantStatus,
};
use crate::models::policy::{CreateDirectPolicy, CreatePermissionBlock, CreateRoleAssignment};
use crate::models::token::CreateSharedKey;

/// Sentinel written to `managed_by` columns for rows provisioned from a
/// bootstrap file. Mutation endpoints refuse to touch rows carrying this tag.
pub const MANAGED_BY_CONFIG: &str = "config";

/// Root of the bootstrap document. Every section is optional.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Defaults applied whenever Atom creates tenant-owned system RBAC.
    #[serde(default)]
    pub tenant_defaults: BootstrapTenantDefaults,
    #[serde(default)]
    pub tenants: Vec<BootstrapTenant>,
    #[serde(default)]
    pub entities: Vec<BootstrapEntity>,
    #[serde(default)]
    pub resources: Vec<BootstrapResource>,
    #[serde(default)]
    pub groups: Vec<BootstrapGroup>,
    #[serde(default)]
    pub object_groups: Vec<BootstrapObjectGroup>,
    #[serde(default)]
    pub permission_blocks: Vec<BootstrapPermissionBlock>,
    #[serde(default)]
    pub roles: Vec<BootstrapRole>,
    #[serde(default)]
    pub role_assignments: Vec<BootstrapRoleAssignment>,
    #[serde(default)]
    pub direct_policies: Vec<BootstrapDirectPolicy>,
    /// Additional action names (capabilities) beyond the built-in vocabulary,
    /// e.g. product-specific verbs like `publish` or `alarm.acknowledge`. Each
    /// entry may also declare the object kinds/types it applies to.
    #[serde(default)]
    pub capabilities: Vec<BootstrapCapability>,
    /// Guardrail rules constraining which entity kinds may perform which
    /// actions on which object kinds — the platform-wide "device cannot manage
    /// resources" style rails.
    #[serde(default)]
    pub action_assignment_rules: Vec<BootstrapActionAssignmentRule>,
}

/// Defaults for RBAC objects Atom creates for every tenant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTenantDefaults {
    /// Additional capabilities granted to the system-created `tenant-admin`
    /// role. Capabilities must exist in Atom's built-in or declared vocabulary.
    #[serde(default)]
    pub admin_capabilities: Vec<String>,
}

/// A tenant (domain). `None` `tenant_id` on other records means platform scope.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTenant {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attributes: Option<Value>,
    #[serde(default)]
    pub status: TenantStatus,
}

/// An entity, together with its credentials.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapEntity {
    /// Stable UUID — the key we upsert on. Use the well-known seed UUIDs to
    /// attach credentials to the pre-seeded `admin`/`example-service` entities.
    pub id: Uuid,
    pub kind: EntityKind,
    pub name: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub status: EntityStatus,
    #[serde(default)]
    pub attributes: Option<Value>,
    /// Owning tenant. `None` places the entity at platform scope.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub credentials: Vec<BootstrapCredential>,
}

/// A credential to ensure exists for an entity. The secret material is declared
/// inline, exactly like the existing `ADMIN_SECRET` env var — protect the file
/// accordingly (mount it as a secret, keep it out of version control).
// `deny_unknown_fields` is intentionally omitted: serde does not support it on
// internally tagged enums (it would reject the `kind` discriminant itself).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootstrapCredential {
    /// A password credential. Validated against the configured strength policy.
    Password { secret: String },
    /// A retrievable machine shared key. Only valid for non-human entities. The
    /// key must be supplied explicitly so bootstrap stays deterministic (an
    /// auto-generated key would be lost, never surfaced to the operator).
    SharedKey {
        key: String,
        #[serde(default)]
        description: Option<String>,
    },
    /// A pre-provisioned unscoped access token (`atom_<id_hex>_<secret_hex>`).
    /// The operator generates the token once (e.g. from `openssl rand`) and
    /// splices the same value into both this YAML *and* the env file consumed
    /// by downstream services — so `docker compose up` needs no round-trip
    /// between an atom-bootstrap init container and services waiting on it.
    /// The credential row is stamped `managed_by='config'`, so the API refuses
    /// to mutate or revoke it. List/read responses still expose its non-secret
    /// metadata and the managed marker so clients can present it as read-only.
    AccessToken {
        /// Full `atom_<id_hex>_<secret_hex>` token string.
        token: String,
        /// Human label for the token, surfaced in audit logs.
        name: String,
        #[serde(default)]
        description: Option<String>,
    },
}

/// A protected resource object (e.g. a `channel`). `kind` is a free-form label.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapResource {
    pub id: Uuid,
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    /// Owning tenant. `None` places the resource at platform scope.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    /// Optional owning entity.
    #[serde(default)]
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: Option<Value>,
}

/// A principal (subject) group and its entity members.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapGroup {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: Option<Value>,
    /// Entity IDs that belong to this group.
    #[serde(default)]
    pub members: Vec<Uuid>,
}

/// An object group: groups entities and/or resources so a single permission
/// block can scope to all of them (and, via `parent`, to descendant groups).
/// Membership is many-to-many: an entity or resource may belong to several
/// object groups. Membership rows require a tenant, so a group with members
/// must declare `tenant_id`.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapObjectGroup {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: Option<Value>,
    /// Parent object group (this group becomes its child in the hierarchy).
    #[serde(default)]
    pub parent: Option<Uuid>,
    /// Entity IDs that belong to this group.
    #[serde(default)]
    pub entities: Vec<Uuid>,
    /// Resource IDs that belong to this group.
    #[serde(default)]
    pub resources: Vec<Uuid>,
}

/// A permission block: scope + actions + effect + conditions. Shared — link it
/// to roles (`roles[].permission_blocks`) and/or grant it directly to subjects
/// (`direct_policies[].permission_block_id`).
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPermissionBlock {
    pub id: Uuid,
    pub scope: BootstrapScope,
    /// Action names (e.g. `read`, `publish`). Resolved to seeded action IDs.
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub effect: Effect,
    #[serde(default)]
    pub conditions: Option<Value>,
}

/// Permission-block scope modes. The `group_*` modes scope a block to the
/// members (or descendant groups) of an object group, referenced by
/// `scope.group_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    Platform,
    Tenant,
    ObjectKind,
    ObjectType,
    Object,
    /// A namespaced object type among the direct entity/resource members of the
    /// object group (needs `object_kind` + `object_type`).
    GroupDirectObjects,
    /// Like `group_direct_objects`, extended to descendant groups.
    GroupDescendantObjects,
    /// Direct child groups of the object group.
    GroupChildGroups,
    /// Descendant groups of the object group.
    GroupDescendantGroups,
}

impl ScopeMode {
    fn as_str(self) -> &'static str {
        match self {
            ScopeMode::Platform => "platform",
            ScopeMode::Tenant => "tenant",
            ScopeMode::ObjectKind => "object_kind",
            ScopeMode::ObjectType => "object_type",
            ScopeMode::Object => "object",
            ScopeMode::GroupDirectObjects => "group_direct_objects",
            ScopeMode::GroupDescendantObjects => "group_descendant_objects",
            ScopeMode::GroupChildGroups => "group_child_groups",
            ScopeMode::GroupDescendantGroups => "group_descendant_groups",
        }
    }

    fn is_group(self) -> bool {
        matches!(
            self,
            ScopeMode::GroupDirectObjects
                | ScopeMode::GroupDescendantObjects
                | ScopeMode::GroupChildGroups
                | ScopeMode::GroupDescendantGroups
        )
    }
}

/// Scope of a permission block. Which fields are required depends on `mode`;
/// [`BootstrapScope::validate`] mirrors the database CHECK constraint so a bad
/// combination is rejected before insert.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapScope {
    pub mode: ScopeMode,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub object_kind: Option<String>,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub object_id: Option<Uuid>,
    /// Object group the block scopes to (required by the `group_*` modes).
    #[serde(default)]
    pub group_id: Option<Uuid>,
}

impl BootstrapScope {
    fn validate(&self, block_id: Uuid) -> Result<()> {
        let has_kind = self.object_kind.is_some();
        let has_type = self.object_type.is_some();
        let has_object = self.object_id.is_some();
        let has_tenant = self.tenant_id.is_some();
        let has_group = self.group_id.is_some();
        let require = |cond: bool, msg: &str| -> Result<()> {
            if cond {
                Ok(())
            } else {
                Err(anyhow!("permission block {block_id}: {msg}"))
            }
        };
        // group_id belongs only to the group_* modes.
        if !self.mode.is_group() {
            require(!has_group, "only group_* scopes take a group_id")?;
        }
        match self.mode {
            ScopeMode::Platform => {
                require(
                    !has_tenant && !has_kind && !has_type && !has_object,
                    "platform scope takes no tenant_id/object_kind/object_type/object_id",
                )?;
            }
            ScopeMode::Tenant => {
                require(has_tenant, "tenant scope requires tenant_id")?;
                require(
                    !has_kind && !has_type && !has_object,
                    "tenant scope takes no object_kind/object_type/object_id",
                )?;
            }
            ScopeMode::ObjectKind => {
                require(
                    has_tenant && has_kind,
                    "object_kind scope requires tenant_id and object_kind",
                )?;
                require(
                    !has_type && !has_object,
                    "object_kind scope takes no object_type/object_id",
                )?;
            }
            ScopeMode::ObjectType => {
                require(
                    has_tenant && has_kind && has_type,
                    "object_type scope requires tenant_id, object_kind and object_type",
                )?;
                require(!has_object, "object_type scope takes no object_id")?;
            }
            ScopeMode::Object => {
                require(has_object, "object scope requires object_id")?;
                require(
                    !has_kind && !has_type,
                    "object scope takes no object_kind/object_type",
                )?;
            }
            ScopeMode::GroupChildGroups | ScopeMode::GroupDescendantGroups => {
                require(
                    has_tenant && has_group,
                    "group scopes require tenant_id and group_id",
                )?;
                require(
                    !has_kind && !has_type && !has_object,
                    "this group scope takes no object_kind/object_type/object_id",
                )?;
            }
            ScopeMode::GroupDirectObjects | ScopeMode::GroupDescendantObjects => {
                require(
                    has_tenant && has_group,
                    "group object scopes require tenant_id and group_id",
                )?;
                let kind_ok = matches!(
                    self.object_kind.as_deref(),
                    Some("entity") | Some("resource")
                );
                require(
                    kind_ok,
                    "group object scopes require object_kind of 'entity' or 'resource'",
                )?;
                // The scope_ref is `<group>:<object_type>` (e.g.
                // `resource:channel`); without object_type the scope never
                // matches, so require it rather than ship a dead grant.
                require(
                    has_type,
                    "group object scopes require object_type (e.g. 'resource:channel')",
                )?;
                require(!has_object, "group object scopes take no object_id")?;
            }
        }
        Ok(())
    }
}

/// A role, optionally linked to permission blocks defined above.
#[derive(Debug, Clone, PartialEq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRole {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub description: Option<String>,
    /// IDs of permission blocks to attach to this role.
    #[serde(default)]
    pub permission_blocks: Vec<Uuid>,
}

/// The subject of an assignment or direct policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSubject {
    pub kind: SubjectKind,
    pub id: Uuid,
}

/// Grants a role to a subject.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRoleAssignment {
    pub id: Uuid,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub subject: BootstrapSubject,
    pub role_id: Uuid,
}

/// Grants a permission block directly to a subject.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapDirectPolicy {
    pub id: Uuid,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub subject: BootstrapSubject,
    pub permission_block_id: Uuid,
}

/// A capability (action) to ensure exists. Keyed on `name` (the unique column
/// on `actions`), so re-running the bootstrap file is a no-op. The optional
/// `applicability` block lists object kinds/types this action can target;
/// its declared set must exactly match any persisted applicability rows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapCapability {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub applicability: Vec<BootstrapCapabilityApplicability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapCapabilityApplicability {
    pub object_kind: ObjectKind,
    #[serde(default)]
    pub object_type: Option<String>,
}

/// A guardrail rule. Same shape as the `action_assignment_rules` row, minus
/// the auto-generated id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapActionAssignmentRule {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub entity_kind: EntityKind,
    pub action_name: String,
    pub object_kind: ObjectKind,
    #[serde(default)]
    pub object_type: Option<String>,
    pub decision: ActionAssignmentDecision,
    #[serde(default)]
    pub is_absolute: bool,
}

impl BootstrapConfig {
    /// Structural validation performed before touching the database, so a
    /// malformed file aborts startup with a clear message instead of a partial,
    /// half-applied bootstrap.
    pub fn validate(&self) -> Result<()> {
        unique_ids(self.tenants.iter().map(|t| t.id), "tenant")?;
        unique_ids(self.entities.iter().map(|e| e.id), "entity")?;
        unique_ids(self.resources.iter().map(|r| r.id), "resource")?;
        unique_ids(self.groups.iter().map(|g| g.id), "group")?;
        unique_ids(self.object_groups.iter().map(|g| g.id), "object group")?;
        unique_ids(
            self.permission_blocks.iter().map(|b| b.id),
            "permission block",
        )?;
        unique_ids(self.roles.iter().map(|r| r.id), "role")?;
        unique_ids(
            self.role_assignments.iter().map(|a| a.id),
            "role assignment",
        )?;
        unique_ids(self.direct_policies.iter().map(|p| p.id), "direct policy")?;

        for tenant in &self.tenants {
            if tenant.name.trim().is_empty() {
                bail!("bootstrap tenant {} has an empty name", tenant.id);
            }
            check_object_attributes(&tenant.attributes, "tenant", tenant.id)?;
        }
        for entity in &self.entities {
            entity.validate()?;
        }
        for resource in &self.resources {
            if resource.kind.trim().is_empty() {
                bail!("bootstrap resource {} has an empty kind", resource.id);
            }
            check_object_attributes(&resource.attributes, "resource", resource.id)?;
            reject_legacy_parent_group_id(&resource.attributes, "resource", resource.id)?;
        }
        for group in &self.groups {
            if group.id == crate::identity::repo::AUTHENTICATED_USERS_GROUP_ID {
                bail!(
                    "bootstrap group {} is reserved for Atom's system-managed authenticated-users membership",
                    group.id
                );
            }
            if group.name.trim().is_empty() {
                bail!("bootstrap group {} has an empty name", group.id);
            }
            check_object_attributes(&group.attributes, "group", group.id)?;
        }
        for group in &self.object_groups {
            if group.name.trim().is_empty() {
                bail!("bootstrap object group {} has an empty name", group.id);
            }
            check_object_attributes(&group.attributes, "object group", group.id)?;
            if group.parent == Some(group.id) {
                bail!(
                    "bootstrap object group {} cannot be its own parent",
                    group.id
                );
            }
            // Membership rows carry a NOT NULL tenant_id, so a group with
            // members must declare its tenant.
            if group.tenant_id.is_none()
                && (!group.entities.is_empty() || !group.resources.is_empty())
            {
                bail!(
                    "bootstrap object group {} has members but no tenant_id",
                    group.id
                );
            }
        }
        for block in &self.permission_blocks {
            block.scope.validate(block.id)?;
            if let Some(conditions) = &block.conditions {
                if !conditions.is_object() {
                    bail!(
                        "permission block {} conditions must be a JSON object",
                        block.id
                    );
                }
            }
        }
        for role in &self.roles {
            if role.name.trim().is_empty() {
                bail!("bootstrap role {} has an empty name", role.id);
            }
        }

        let mut seen_names = HashSet::new();
        for capability in &self.capabilities {
            let name = capability.name.trim();
            if name.is_empty() {
                bail!("bootstrap capability has an empty name");
            }
            if !seen_names.insert(name.to_string()) {
                bail!("duplicate bootstrap capability name {name}");
            }
            let mut seen_apps = HashSet::new();
            for app in &capability.applicability {
                let key = (app.object_kind, app.object_type.clone());
                if !seen_apps.insert(key) {
                    bail!(
                        "capability {name} declares duplicate applicability {}:{}",
                        app.object_kind.as_str(),
                        app.object_type.as_deref().unwrap_or("")
                    );
                }
            }
        }

        let mut seen_admin_capabilities = HashSet::new();
        for capability in &self.tenant_defaults.admin_capabilities {
            let name = capability.trim();
            if name.is_empty() {
                bail!("tenant_defaults.admin_capabilities contains an empty name");
            }
            if !seen_admin_capabilities.insert(name.to_string()) {
                bail!("duplicate tenant-admin default capability {name}");
            }
        }

        let mut seen_rules = HashSet::new();
        for rule in &self.action_assignment_rules {
            let action = rule.action_name.trim();
            if action.is_empty() {
                bail!("bootstrap action_assignment_rule has an empty action_name");
            }
            let key = (
                rule.tenant_id,
                format!("{:?}", rule.entity_kind),
                action.to_string(),
                rule.object_kind,
                rule.object_type.clone(),
            );
            if !seen_rules.insert(key) {
                bail!(
                    "duplicate bootstrap action_assignment_rule for {} {} on {}:{}",
                    format!("{:?}", rule.entity_kind).to_lowercase(),
                    action,
                    rule.object_kind.as_str(),
                    rule.object_type.as_deref().unwrap_or("")
                );
            }
        }
        Ok(())
    }
}

impl BootstrapEntity {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("bootstrap entity {} has an empty name", self.id);
        }
        check_object_attributes(&self.attributes, "entity", self.id)?;
        reject_legacy_parent_group_id(&self.attributes, "entity", self.id)?;

        let mut passwords = 0;
        let mut shared_keys = 0;
        let mut access_tokens = HashSet::new();
        for cred in &self.credentials {
            match cred {
                BootstrapCredential::Password { .. } => passwords += 1,
                BootstrapCredential::SharedKey { .. } => {
                    shared_keys += 1;
                    if !CredentialKind::SharedKey.allowed_for(&self.kind) {
                        bail!(
                            "bootstrap entity {} is a human; shared keys are only valid for machine entities",
                            self.id
                        );
                    }
                }
                BootstrapCredential::AccessToken { token, name, .. } => {
                    if name.trim().is_empty() {
                        bail!(
                            "bootstrap entity {} declares an access token with an empty name",
                            self.id
                        );
                    }
                    let (cred_id, _) = crate::auth::parse_api_key(token.trim()).ok_or_else(
                        || anyhow!(
                            "bootstrap entity {} declares an access token that is not a valid atom_<id>_<secret> string",
                            self.id
                        ),
                    )?;
                    if !access_tokens.insert(cred_id) {
                        bail!(
                            "bootstrap entity {} declares more than one access token with credential id {cred_id}",
                            self.id
                        );
                    }
                }
            }
        }
        if passwords > 1 {
            bail!(
                "bootstrap entity {} declares more than one password credential",
                self.id
            );
        }
        if shared_keys > 1 {
            bail!(
                "bootstrap entity {} declares more than one shared_key credential",
                self.id
            );
        }
        Ok(())
    }
}

fn unique_ids(ids: impl Iterator<Item = Uuid>, label: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id) {
            bail!("duplicate bootstrap {label} id {id}");
        }
    }
    Ok(())
}

fn check_object_attributes(attributes: &Option<Value>, label: &str, id: Uuid) -> Result<()> {
    if let Some(attrs) = attributes {
        if !attrs.is_object() {
            bail!("bootstrap {label} {id} attributes must be a JSON object");
        }
    }
    Ok(())
}

fn reject_legacy_parent_group_id(attributes: &Option<Value>, label: &str, id: Uuid) -> Result<()> {
    if attributes
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|attrs| attrs.contains_key("parent_group_id"))
    {
        bail!(
            "bootstrap {label} {id}: the parent_group_id attribute is no longer supported; \
             use object_groups[].entities/resources for many-to-many membership"
        );
    }
    Ok(())
}

/// Read and parse a bootstrap file, validating its structure.
pub async fn load(path: &Path) -> Result<BootstrapConfig> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read bootstrap file {}", path.display()))?;
    parse(&contents).with_context(|| format!("invalid bootstrap file {}", path.display()))
}

fn parse(contents: &str) -> Result<BootstrapConfig> {
    let cfg: BootstrapConfig = serde_yaml::from_str(contents).context("failed to parse YAML")?;
    cfg.validate()?;
    Ok(cfg)
}

/// Generates the structural JSON Schema frozen as
/// `api/v1/bootstrap.schema.json`.
pub fn v1_json_schema() -> Result<Value> {
    serde_json::to_value(schemars::schema_for!(BootstrapConfig))
        .context("failed to serialize the bootstrap v1 JSON Schema")
}
/// Apply the bootstrap config against the database, in dependency order.
/// Idempotent.
pub async fn apply(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    cfg: &BootstrapConfig,
) -> Result<()> {
    apply_with_cache(pool, signing_keys, cfg, None).await
}

pub async fn apply_with_cache(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    cfg: &BootstrapConfig,
    cache: Option<&crate::cache::CacheClient>,
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("failed to begin bootstrap transaction")?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind("atom:config-bootstrap:v1")
        .execute(&mut *tx)
        .await
        .context("failed to acquire bootstrap advisory lock")?;
    sqlx::query(
        r#"LOCK TABLE
               tenants, entities, entity_emails, credentials, resources,
               principal_groups, principal_group_hierarchy, principal_group_members,
               object_groups, object_group_hierarchy, object_group_entities,
               object_group_resources, actions, action_applicability,
               action_assignment_rules, permission_blocks, permission_block_actions,
               roles, role_permission_blocks, role_assignments, direct_policies,
               protected_object_ids, tenant_admin_default_actions
           IN EXCLUSIVE MODE"#,
    )
    .execute(&mut *tx)
    .await
    .context("failed to acquire bootstrap write barrier")?;

    let mut entity_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM entities")
        .fetch_all(&mut *tx)
        .await
        .context("failed to enumerate bootstrap grants-cache subjects")?;
    entity_ids.extend(cfg.entities.iter().map(|entity| entity.id));
    entity_ids.sort_unstable();
    entity_ids.dedup();
    let grants_keys = entity_ids
        .into_iter()
        .map(crate::cache::keys::grants)
        .collect::<Vec<_>>();
    let lease = match cache {
        Some(cache) => match cache
            .begin(crate::cache::CacheCategory::Grants, &grants_keys)
            .await
        {
            Ok(lease) => Some(lease),
            Err(err) => {
                tx.rollback()
                    .await
                    .context("failed to roll back bootstrap after cache barrier failure")?;
                return Err(anyhow!("bootstrap cache barrier failed: {err}"));
            }
        },
        None => None,
    };

    let result = apply_in_tx(&mut tx, signing_keys, cfg).await;
    let result = match result {
        Ok(()) => tx
            .commit()
            .await
            .context("failed to commit bootstrap transaction"),
        Err(err) => match tx.rollback().await {
            Ok(()) => Err(err),
            Err(rollback_err) => {
                Err(err.context(format!("bootstrap rollback also failed: {rollback_err}")))
            }
        },
    };
    if let (Some(cache), Some(lease)) = (cache, lease) {
        cache.end(lease).await;
    }
    result
}

async fn apply_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    signing_keys: &SigningKeyConfig,
    cfg: &BootstrapConfig,
) -> Result<()> {
    for tenant in &cfg.tenants {
        ensure_tenant(tx, tenant).await?;
    }
    for entity in &cfg.entities {
        ensure_entity(tx, entity).await?;
        for cred in &entity.credentials {
            ensure_credential(tx, signing_keys, entity, cred).await?;
        }
    }
    for resource in &cfg.resources {
        ensure_resource(tx, resource).await?;
    }
    for group in &cfg.groups {
        ensure_group(tx, group).await?;
    }
    // Object group rows first, then hierarchy/membership, so a parent declared
    // later in the file still resolves.
    ensure_object_groups(tx, &cfg.object_groups).await?;
    // Product-specific actions must exist and have applicability before a
    // permission block that names them is validated. Guardrails must likewise
    // exist before role links or assignments are checked.
    for capability in &cfg.capabilities {
        ensure_capability(tx, capability).await?;
    }
    for rule in &cfg.action_assignment_rules {
        ensure_action_assignment_rule(tx, rule).await?;
    }
    reconcile_tenant_admin_defaults(tx, &cfg.tenant_defaults).await?;
    for block in &cfg.permission_blocks {
        ensure_permission_block(tx, block).await?;
    }
    for role in &cfg.roles {
        ensure_role(tx, role).await?;
    }
    for assignment in &cfg.role_assignments {
        ensure_role_assignment(tx, assignment).await?;
    }
    for policy in &cfg.direct_policies {
        ensure_direct_policy(tx, policy).await?;
    }
    Ok(())
}

async fn reconcile_tenant_admin_defaults(
    tx: &mut Transaction<'_, Postgres>,
    defaults: &BootstrapTenantDefaults,
) -> Result<()> {
    let capabilities = defaults
        .admin_capabilities
        .iter()
        .map(|name| name.trim().to_string())
        .collect::<Vec<_>>();

    let missing: Vec<String> = sqlx::query_scalar(
        r#"SELECT requested.name
           FROM unnest($1::text[]) AS requested(name)
           WHERE NOT EXISTS (SELECT 1 FROM actions WHERE actions.name = requested.name)
           ORDER BY requested.name"#,
    )
    .bind(&capabilities)
    .fetch_all(&mut **tx)
    .await
    .context("failed to validate tenant-admin default capabilities")?;
    if !missing.is_empty() {
        bail!(
            "unknown tenant_defaults.admin_capabilities: {}",
            missing.join(", ")
        );
    }

    sqlx::query("DELETE FROM tenant_admin_default_actions")
        .execute(&mut **tx)
        .await
        .context("failed to replace tenant-admin defaults")?;
    sqlx::query(
        r#"INSERT INTO tenant_admin_default_actions (action_id)
           SELECT id FROM actions WHERE name = ANY($1::text[])"#,
    )
    .bind(&capabilities)
    .execute(&mut **tx)
    .await
    .context("failed to persist tenant-admin defaults")?;

    let mut desired_capabilities = crate::tenants::repo::TENANT_ADMIN_BASE_CAPABILITIES
        .iter()
        .map(|name| (*name).to_string())
        .chain(capabilities)
        .collect::<Vec<_>>();
    desired_capabilities.sort();
    desired_capabilities.dedup();

    let roles = sqlx::query(
        r#"SELECT id, tenant_id
           FROM roles
           WHERE managed_by = 'system:tenant-admin' AND deleted_at IS NULL
           ORDER BY id"#,
    )
    .fetch_all(&mut **tx)
    .await
    .context("failed to enumerate system tenant-admin roles")?;

    for role in roles {
        let role_id: Uuid = role.try_get("id")?;
        let tenant_id: Uuid = role.try_get("tenant_id")?;
        let current_block_id: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT pb.id
               FROM role_permission_blocks rpb
               JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
               WHERE rpb.role_id = $1
                 AND pb.managed_by = 'system:tenant-admin'
               ORDER BY pb.id
               LIMIT 1"#,
        )
        .bind(role_id)
        .fetch_optional(&mut **tx)
        .await
        .with_context(|| format!("failed to inspect tenant-admin role {role_id}"))?;

        let current_names: Vec<String> = match current_block_id {
            Some(block_id) => sqlx::query_scalar(
                r#"SELECT a.name
                   FROM permission_block_actions pba
                   JOIN actions a ON a.id = pba.action_id
                   WHERE pba.permission_block_id = $1
                   ORDER BY a.name"#,
            )
            .bind(block_id)
            .fetch_all(&mut **tx)
            .await
            .with_context(|| format!("failed to inspect tenant-admin block {block_id}"))?,
            None => Vec::new(),
        };
        if current_names == desired_capabilities {
            continue;
        }

        let replacement_id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO permission_blocks
                  (tenant_id, scope_mode, effect, conditions, managed_by)
               VALUES ($1, 'tenant', 'allow', '{}'::jsonb, 'system:tenant-admin')
               RETURNING id"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await
        .with_context(|| format!("failed to create replacement block for role {role_id}"))?;
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               SELECT $1, id FROM actions WHERE name = ANY($2::text[])"#,
        )
        .bind(replacement_id)
        .bind(&desired_capabilities)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to populate replacement block {replacement_id}"))?;

        crate::guardrails::validate_role_permission_block_links(tx, role_id, &[replacement_id])
            .await
            .map_err(|err| anyhow!("tenant-admin role {role_id}: {err}"))?;

        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)"#,
        )
        .bind(role_id)
        .bind(replacement_id)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to link replacement block {replacement_id}"))?;

        if let Some(block_id) = current_block_id {
            sqlx::query(
                "DELETE FROM role_permission_blocks WHERE role_id = $1 AND permission_block_id = $2",
            )
            .bind(role_id)
            .bind(block_id)
            .execute(&mut **tx)
            .await
            .with_context(|| format!("failed to unlink old tenant-admin block {block_id}"))?;
            sqlx::query(
                r#"DELETE FROM permission_blocks pb
                   WHERE pb.id = $1
                     AND NOT EXISTS (
                         SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id
                     )"#,
            )
            .bind(block_id)
            .execute(&mut **tx)
            .await
            .with_context(|| format!("failed to garbage-collect old block {block_id}"))?;
        }
    }

    Ok(())
}

async fn ensure_tenant(tx: &mut Transaction<'_, Postgres>, tenant: &BootstrapTenant) -> Result<()> {
    let alias = validate_alias_opt(tenant.alias.clone())
        .map_err(|e| anyhow!("bootstrap tenant {}: {e}", tenant.id))?;
    let attributes = tenant
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO tenants (id, name, alias, status, tags, attributes, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(tenant.id)
    .bind(&tenant.name)
    .bind(&alias)
    .bind(&tenant.status)
    .bind(&tenant.tags)
    .bind(&attributes)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap tenant {}", tenant.id))?;

    let matches: Option<bool> = sqlx::query_scalar(
        r#"SELECT name = $2
                  AND alias IS NOT DISTINCT FROM $3
                  AND status = $4
                  AND tags = $5
                  AND attributes = $6
                  AND deleted_at IS NULL
           FROM tenants
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(tenant.id)
    .bind(&tenant.name)
    .bind(&alias)
    .bind(&tenant.status)
    .bind(&tenant.tags)
    .bind(&attributes)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to compare bootstrap tenant {}", tenant.id))?;
    if matches != Some(true) {
        bail!(
            "bootstrap tenant {} exists with different semantics or disappeared during reconciliation",
            tenant.id
        );
    }

    let stamped = sqlx::query("UPDATE tenants SET managed_by = $2 WHERE id = $1")
        .bind(tenant.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap tenant {}", tenant.id))?;
    if stamped.rows_affected() != 1 {
        bail!(
            "bootstrap tenant {} disappeared before it could be stamped",
            tenant.id
        );
    }
    let _ = result;
    Ok(())
}

/// Create the entity if its UUID is not already present. An existing row must
/// match the declaration exactly; it is never silently overwritten or claimed
/// after runtime drift. The row is stamped `managed_by='config'` so
/// update/delete/restore endpoints refuse to touch it via the API.
async fn ensure_entity(tx: &mut Transaction<'_, Postgres>, entity: &BootstrapEntity) -> Result<()> {
    let alias = validate_alias_opt(entity.alias.clone())
        .map_err(|e| anyhow!("bootstrap entity {}: {e}", entity.id))?;
    let attributes = entity
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let persisted_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
            .bind(entity.id)
            .fetch_optional(&mut **tx)
            .await
            .with_context(|| format!("failed to inspect bootstrap entity {} tenant", entity.id))?;
    let mut tenant_ids = vec![entity.tenant_id];
    tenant_ids.extend(persisted_tenant_id);
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids)
        .await
        .map_err(|e| anyhow!("bootstrap entity {} tenant lock: {e}", entity.id))?;
    let result = sqlx::query(
        r#"INSERT INTO entities (id, kind, name, alias, tenant_id, status, attributes, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(entity.id)
    .bind(&entity.kind)
    .bind(&entity.name)
    .bind(&alias)
    .bind(entity.tenant_id)
    .bind(&entity.status)
    .bind(&attributes)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap entity {}", entity.id))?;

    // A re-run never overwrites the entity row. Synchronize from the persisted
    // kind/attributes rather than from the YAML so claiming an existing row
    // cannot silently change its login identity.
    let persisted = sqlx::query(
        r#"SELECT kind, attributes,
                  kind = $2
                  AND name = $3
                  AND alias IS NOT DISTINCT FROM $4
                  AND tenant_id IS NOT DISTINCT FROM $5
                  AND status = $6
                  AND attributes = $7
                  AND deleted_at IS NULL AS matches
           FROM entities
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(entity.id)
    .bind(&entity.kind)
    .bind(&entity.name)
    .bind(&alias)
    .bind(entity.tenant_id)
    .bind(&entity.status)
    .bind(&attributes)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to compare bootstrap entity {}", entity.id))?
    .ok_or_else(|| {
        anyhow!(
            "bootstrap entity {} disappeared during reconciliation",
            entity.id
        )
    })?;
    let matches: bool = persisted
        .try_get("matches")
        .with_context(|| format!("failed to decode bootstrap entity {} state", entity.id))?;
    if !matches {
        bail!(
            "bootstrap entity {} exists with different semantics",
            entity.id
        );
    }
    let persisted_kind: EntityKind = persisted
        .try_get("kind")
        .with_context(|| format!("failed to decode bootstrap entity {} kind", entity.id))?;
    let persisted_attributes: Value = persisted
        .try_get("attributes")
        .with_context(|| format!("failed to decode bootstrap entity {} attributes", entity.id))?;
    identity::repo::sync_entity_email_from_attrs_in_tx(
        tx,
        entity.id,
        &persisted_kind,
        &persisted_attributes,
    )
    .await
    .map_err(|e| anyhow!("bootstrap entity {} email: {e}", entity.id))?;

    // Stamp even when the row already existed, so an entity created earlier via
    // the API becomes protected once it appears in the bootstrap file. The
    // entity and canonical email changes commit atomically.
    let stamped = sqlx::query("UPDATE entities SET managed_by = $2 WHERE id = $1")
        .bind(entity.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap entity {}", entity.id))?;
    if stamped.rows_affected() != 1 {
        bail!(
            "bootstrap entity {} disappeared before it could be stamped",
            entity.id
        );
    }
    let _ = result;
    Ok(())
}

/// Create or exactly reconcile a configured credential. Existing active rows
/// must securely verify the declared material and metadata; bootstrap never
/// picks an arbitrary credential or overwrites drift.
async fn ensure_credential(
    tx: &mut Transaction<'_, Postgres>,
    signing_keys: &SigningKeyConfig,
    entity: &BootstrapEntity,
    cred: &BootstrapCredential,
) -> Result<()> {
    match cred {
        BootstrapCredential::Password { secret } => {
            if identity::repo::lock_active_entity(tx, entity.id)
                .await
                .map_err(|e| anyhow!("bootstrap password for entity {}: {e}", entity.id))?
                .is_none()
            {
                bail!("bootstrap password entity {} is not active", entity.id);
            }
            let rows = sqlx::query("SELECT id, secret_hash, metadata, scoped, expires_at FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active' FOR UPDATE")
                .bind(entity.id).bind(CredentialKind::Password).fetch_all(&mut **tx).await?;
            let matches = rows
                .iter()
                .filter(|row| {
                    let hash = row
                        .try_get::<Option<String>, _>("secret_hash")
                        .ok()
                        .flatten();
                    let metadata = row.try_get::<Value, _>("metadata").ok();
                    let scoped = row.try_get::<bool, _>("scoped").ok();
                    let expires = row
                        .try_get::<Option<DateTime<Utc>>, _>("expires_at")
                        .ok()
                        .flatten();
                    hash.as_deref().is_some_and(|hash| {
                        identity::service::verify_secret(secret.as_bytes(), hash)
                    }) && metadata == Some(serde_json::json!({}))
                        && scoped == Some(false)
                        && expires.is_none()
                })
                .collect::<Vec<_>>();
            let credential_id = if rows.is_empty() {
                identity::service::create_password_in_tx(tx, entity.id, secret)
                    .await
                    .map_err(|e| anyhow!("bootstrap password for entity {}: {e}", entity.id))?
            } else if rows.len() == 1 && matches.len() == 1 {
                matches[0].try_get("id")?
            } else {
                bail!(
                    "bootstrap password for entity {} does not exactly match its active credential",
                    entity.id
                );
            };
            stamp_managed_credential_in_tx(tx, credential_id).await?;
        }
        BootstrapCredential::SharedKey { key, description } => {
            if identity::repo::lock_active_entity(tx, entity.id)
                .await
                .map_err(|e| anyhow!("bootstrap shared key for entity {}: {e}", entity.id))?
                .is_none()
            {
                bail!("bootstrap shared-key entity {} is not active", entity.id);
            }
            let metadata = serde_json::json!({ "description": description });
            let rows = sqlx::query("SELECT id, secret_hash, secret_lookup_hash, metadata, scoped, expires_at FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active' FOR UPDATE")
                .bind(entity.id).bind(CredentialKind::SharedKey).fetch_all(&mut **tx).await?;
            let matches = rows
                .iter()
                .filter(|row| {
                    let hash = row
                        .try_get::<Option<String>, _>("secret_hash")
                        .ok()
                        .flatten();
                    let lookup_hash = row
                        .try_get::<Option<Vec<u8>>, _>("secret_lookup_hash")
                        .ok()
                        .flatten();
                    let lookup_matches = match lookup_hash.as_deref() {
                        Some(stored) => {
                            signing_keys.key_encryption_key.as_ref().is_some_and(|kek| {
                                crate::crypto::hmac_sha256_verify(
                                    kek.expose(),
                                    key.as_bytes(),
                                    stored,
                                )
                            })
                        }
                        // Compatibility with rows created before the keyed
                        // lookup digest was introduced. Runtime
                        // authentication has the same Argon2 fallback.
                        None => true,
                    };
                    hash.as_deref()
                        .is_some_and(|hash| identity::service::verify_secret(key.as_bytes(), hash))
                        && lookup_matches
                        && row.try_get::<Value, _>("metadata").ok() == Some(metadata.clone())
                        && row.try_get::<bool, _>("scoped").ok() == Some(false)
                        && row
                            .try_get::<Option<DateTime<Utc>>, _>("expires_at")
                            .ok()
                            .flatten()
                            .is_none()
                })
                .collect::<Vec<_>>();
            let credential_id = if rows.is_empty() {
                identity::service::create_shared_key_in_tx(
                    tx,
                    signing_keys,
                    entity.id,
                    CreateSharedKey {
                        expires_at: None,
                        description: description.clone(),
                        key: Some(key.clone()),
                    },
                )
                .await
                .map_err(|e| anyhow!("bootstrap shared key for entity {}: {e}", entity.id))?
                .credential_id
            } else if rows.len() == 1 && matches.len() == 1 {
                matches[0].try_get("id")?
            } else {
                bail!("bootstrap shared key for entity {} does not exactly match its active credential", entity.id);
            };
            stamp_managed_credential_in_tx(tx, credential_id).await?;
        }
        BootstrapCredential::AccessToken {
            token,
            name,
            description,
        } => {
            ensure_bootstrap_access_token(tx, signing_keys, entity, token, name, description)
                .await?;
        }
    }
    Ok(())
}

/// Stamp every active credential of the given kind on the entity as
/// config-managed. Used for Password and SharedKey where the shared identity
/// service creates the row without a `managed_by` opinion.
async fn stamp_managed_credential_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    credential_id: Uuid,
) -> Result<()> {
    let stamped = sqlx::query("UPDATE credentials SET managed_by = $2 WHERE id = $1")
        .bind(credential_id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap credential {credential_id}"))?;
    if stamped.rows_affected() != 1 {
        bail!("bootstrap credential {credential_id} disappeared before it could be stamped");
    }
    Ok(())
}

/// Provision an unscoped access token from operator-supplied material. Parses
/// the full `atom_<id>_<secret>` string (same format `make_api_key` emits),
/// then inserts the credential row directly — no ceiling, no expiry. Idempotent
/// on the credential id.
async fn ensure_bootstrap_access_token(
    tx: &mut Transaction<'_, Postgres>,
    signing_keys: &SigningKeyConfig,
    entity: &BootstrapEntity,
    token: &str,
    name: &str,
    description: &Option<String>,
) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!(
            "bootstrap access token for entity {} has an empty name",
            entity.id
        );
    }
    let (cred_id, secret_bytes) = crate::auth::parse_api_key(token.trim()).ok_or_else(|| {
        anyhow!(
            "bootstrap access token for entity {} is not a valid atom_<id>_<secret> string",
            entity.id
        )
    })?;

    let identifier = token.trim().chars().take(13).collect::<String>();
    let metadata = serde_json::json!({ "name": name, "description": description });
    // Verifier layout mirrors `identity::access_tokens::create_access_token`:
    // keyed HMAC-SHA256 under the deployment KEK when present, argon2 fallback
    // otherwise. Same lookup semantics as API-minted tokens.
    let (secret_hash, secret_lookup_hash) = match signing_keys.key_encryption_key.as_ref() {
        Some(kek) => (
            None::<String>,
            Some(crate::crypto::hmac_sha256(kek.expose(), &secret_bytes)),
        ),
        None => (
            Some(
                identity::service::hash_secret(&secret_bytes)
                    .map_err(|e| anyhow!("bootstrap access token hash for {}: {e}", entity.id))?,
            ),
            None,
        ),
    };
    if identity::repo::lock_active_entity(tx, entity.id)
        .await
        .map_err(|e| anyhow!("bootstrap access token for entity {}: {e}", entity.id))?
        .is_none()
    {
        bail!("bootstrap access-token entity {} is not active", entity.id);
    }

    let inserted = sqlx::query(
        r#"INSERT INTO credentials
             (id, entity_id, kind, identifier, secret_hash, secret_lookup_hash,
              scoped, expires_at, metadata, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, false, NULL, $7, $8)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(cred_id)
    .bind(entity.id)
    .bind(CredentialKind::AccessToken)
    .bind(&identifier)
    .bind(secret_hash)
    .bind(secret_lookup_hash)
    .bind(&metadata)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap access token {cred_id}"))?;

    let row = sqlx::query(
        r#"SELECT entity_id, kind, status, identifier, secret_hash,
                  secret_lookup_hash, scoped, expires_at IS NULL AS no_expiry,
                  metadata
           FROM credentials
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(cred_id)
    .fetch_one(&mut **tx)
    .await
    .with_context(|| format!("failed to reconcile bootstrap access token {cred_id}"))?;
    let owner: Uuid = row.try_get("entity_id")?;
    let kind: CredentialKind = row.try_get("kind")?;
    let status: CredentialStatus = row.try_get("status")?;
    let persisted_identifier: Option<String> = row.try_get("identifier")?;
    let persisted_secret_hash: Option<String> = row.try_get("secret_hash")?;
    let persisted_lookup_hash: Option<Vec<u8>> = row.try_get("secret_lookup_hash")?;
    let scoped: bool = row.try_get("scoped")?;
    let no_expiry: bool = row.try_get("no_expiry")?;
    let persisted_metadata: Value = row.try_get("metadata")?;
    let verifier_matches = match (
        persisted_lookup_hash.as_deref(),
        persisted_secret_hash.as_deref(),
    ) {
        (Some(stored), None) => signing_keys.key_encryption_key.as_ref().is_some_and(|kek| {
            crate::crypto::hmac_sha256_verify(kek.expose(), &secret_bytes, stored)
        }),
        (None, Some(stored)) => identity::service::verify_secret(&secret_bytes, stored),
        _ => false,
    };
    if owner != entity.id
        || kind != CredentialKind::AccessToken
        || status != CredentialStatus::Active
        || persisted_identifier.as_deref() != Some(identifier.as_str())
        || scoped
        || !no_expiry
        || persisted_metadata != metadata
        || !verifier_matches
    {
        bail!(
            "bootstrap access token credential {cred_id} exists with different owner, kind, status, name, verifier, or token semantics"
        );
    }
    sqlx::query("UPDATE credentials SET managed_by = $2 WHERE id = $1")
        .bind(cred_id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap access token {cred_id}"))?;
    let _ = inserted;
    Ok(())
}

async fn ensure_group(tx: &mut Transaction<'_, Postgres>, group: &BootstrapGroup) -> Result<()> {
    let attributes = group
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    lock_bootstrap_principal_group_tenants(tx, group).await?;
    let result = sqlx::query(
        r#"INSERT INTO principal_groups (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(group.tenant_id)
    .bind(&group.description)
    .bind(&attributes)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap group {}", group.id))?;

    let matches: Option<bool> = sqlx::query_scalar(
        r#"SELECT name = $2
                  AND tenant_id IS NOT DISTINCT FROM $3
                  AND description IS NOT DISTINCT FROM $4
                  AND attributes = $5
                  AND status = 'active'
                  AND deleted_at IS NULL
           FROM principal_groups
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(group.tenant_id)
    .bind(&group.description)
    .bind(&attributes)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to compare bootstrap group {}", group.id))?;
    if matches != Some(true) {
        bail!(
            "bootstrap group {} exists with different semantics or disappeared during reconciliation",
            group.id
        );
    }

    let mut desired_members = group.members.clone();
    desired_members.sort_unstable();
    desired_members.dedup();
    if result.rows_affected() == 0 {
        let mut persisted_members: Vec<Uuid> = sqlx::query_scalar(
            "SELECT entity_id FROM principal_group_members WHERE group_id = $1 ORDER BY entity_id",
        )
        .bind(group.id)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| format!("failed to compare bootstrap group {} members", group.id))?;
        persisted_members.sort_unstable();
        if persisted_members != desired_members {
            bail!(
                "bootstrap group {} exists with different semantics",
                group.id
            );
        }
    }
    // Revalidate every declared edge, including pre-existing ones, through the
    // same lifecycle, tenant and assignment guardrails as the runtime API.
    for entity_id in &desired_members {
        identity::repo::add_config_group_member_in_tx(tx, group.id, *entity_id)
            .await
            .map_err(|e| anyhow!("bootstrap group {} member {entity_id}: {e}", group.id))?;
    }
    let stamped = sqlx::query("UPDATE principal_groups SET managed_by = $2 WHERE id = $1")
        .bind(group.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap group {}", group.id))?;
    if stamped.rows_affected() != 1 {
        bail!(
            "bootstrap group {} disappeared before it could be stamped",
            group.id
        );
    }
    let _ = result;
    Ok(())
}

/// Resolve every tenant a principal-group bootstrap declaration may touch
/// before the transaction inserts or locks the group row. This keeps bootstrap
/// membership validation on the same tenant(s)-first order as runtime group
/// membership and group-subject policy mutations, including invalid
/// cross-tenant declarations that will be rejected later.
async fn lock_bootstrap_principal_group_tenants(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group: &BootstrapGroup,
) -> Result<()> {
    let mut tenant_ids = vec![group.tenant_id];
    tenant_ids.extend(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM principal_groups WHERE id = $1",
        )
        .bind(group.id)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| format!("failed to inspect bootstrap group {} tenant", group.id))?,
    );
    tenant_ids.extend(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM entities WHERE id = ANY($1::uuid[])",
        )
        .bind(&group.members)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to inspect bootstrap group {} member tenants",
                group.id
            )
        })?,
    );
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids)
        .await
        .map_err(|e| anyhow!("bootstrap group {} tenant lock: {e}", group.id))
}

async fn ensure_resource(
    tx: &mut Transaction<'_, Postgres>,
    resource: &BootstrapResource,
) -> Result<()> {
    let alias = validate_alias_opt(resource.alias.clone())
        .map_err(|e| anyhow!("bootstrap resource {}: {e}", resource.id))?;
    let attributes = resource
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let persisted_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM resources WHERE id = $1")
            .bind(resource.id)
            .fetch_optional(&mut **tx)
            .await
            .with_context(|| {
                format!(
                    "failed to inspect bootstrap resource {} tenant",
                    resource.id
                )
            })?;
    let mut tenant_ids = vec![resource.tenant_id];
    tenant_ids.extend(persisted_tenant_id);
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids)
        .await
        .map_err(|e| anyhow!("bootstrap resource {} tenant lock: {e}", resource.id))?;

    let result = sqlx::query(
        r#"INSERT INTO resources
               (id, kind, name, alias, tenant_id, owner_id, attributes, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(resource.id)
    .bind(&resource.kind)
    .bind(&resource.name)
    .bind(&alias)
    .bind(resource.tenant_id)
    .bind(resource.owner_id)
    .bind(&attributes)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap resource {}", resource.id))?;
    let matches: Option<bool> = sqlx::query_scalar(
        r#"SELECT kind = $2
                  AND name IS NOT DISTINCT FROM $3
                  AND alias IS NOT DISTINCT FROM $4
                  AND tenant_id IS NOT DISTINCT FROM $5
                  AND owner_id IS NOT DISTINCT FROM $6
                  AND attributes = $7
                  AND deleted_at IS NULL
           FROM resources
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(resource.id)
    .bind(&resource.kind)
    .bind(&resource.name)
    .bind(&alias)
    .bind(resource.tenant_id)
    .bind(resource.owner_id)
    .bind(&attributes)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to compare bootstrap resource {}", resource.id))?;
    if matches != Some(true) {
        bail!(
            "bootstrap resource {} exists with different semantics or disappeared during reconciliation",
            resource.id
        );
    }
    let stamped = sqlx::query("UPDATE resources SET managed_by = $2 WHERE id = $1")
        .bind(resource.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap resource {}", resource.id))?;
    if stamped.rows_affected() != 1 {
        bail!(
            "bootstrap resource {} disappeared before it could be stamped",
            resource.id
        );
    }
    let _ = result;
    Ok(())
}

/// Insert the object group row only. Membership and hierarchy are applied in a
/// second pass ([`ensure_object_group_links`]) so a parent declared later in the
/// file still resolves.
async fn ensure_object_groups(
    tx: &mut Transaction<'_, Postgres>,
    groups: &[BootstrapObjectGroup],
) -> Result<()> {
    if groups.is_empty() {
        return Ok(());
    }
    lock_bootstrap_object_group_tenants(tx, groups).await?;
    crate::authz::repo::lock_group_hierarchy(tx)
        .await
        .map_err(|e| anyhow!("failed to lock bootstrap object-group hierarchy: {e}"))?;
    let mut ordered_groups = groups.iter().collect::<Vec<_>>();
    ordered_groups.sort_unstable_by_key(|group| group.id);
    let mut inserted_ids = HashSet::new();
    for group in &ordered_groups {
        if ensure_object_group_row(tx, group).await? {
            inserted_ids.insert(group.id);
        }
    }
    for group in ordered_groups {
        ensure_object_group_links(tx, group, inserted_ids.contains(&group.id)).await?;
    }
    Ok(())
}

/// Pre-lock the complete tenant set touched by the object-group batch before
/// taking the hierarchy advisory lock or inserting/locking any group row.
/// Persisted group ownership and every declared parent/member are included so
/// a semantically invalid declaration cannot acquire a foreign group row and
/// only then reach back for that foreign tenant while another mutation holds
/// the canonical tenant -> advisory -> group order.
async fn lock_bootstrap_object_group_tenants(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    groups: &[BootstrapObjectGroup],
) -> Result<()> {
    let mut tenant_ids = groups
        .iter()
        .map(|group| group.tenant_id)
        .collect::<Vec<_>>();
    let group_ids = groups
        .iter()
        .flat_map(|group| std::iter::once(group.id).chain(group.parent))
        .collect::<Vec<_>>();
    let entity_ids = groups
        .iter()
        .flat_map(|group| group.entities.iter().copied())
        .collect::<Vec<_>>();
    let resource_ids = groups
        .iter()
        .flat_map(|group| group.resources.iter().copied())
        .collect::<Vec<_>>();

    tenant_ids.extend(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM groups WHERE id = ANY($1::uuid[])",
        )
        .bind(&group_ids)
        .fetch_all(&mut **tx)
        .await
        .context("failed to inspect bootstrap object-group tenants")?,
    );
    tenant_ids.extend(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM entities WHERE id = ANY($1::uuid[])",
        )
        .bind(&entity_ids)
        .fetch_all(&mut **tx)
        .await
        .context("failed to inspect bootstrap object-group entity tenants")?,
    );
    tenant_ids.extend(
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM resources WHERE id = ANY($1::uuid[])",
        )
        .bind(&resource_ids)
        .fetch_all(&mut **tx)
        .await
        .context("failed to inspect bootstrap object-group resource tenants")?,
    );

    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids)
        .await
        .map_err(|e| anyhow!("bootstrap object-group tenant lock: {e}"))
}

async fn ensure_object_group_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group: &BootstrapObjectGroup,
) -> Result<bool> {
    let attributes = group
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    // Claim ownership only after hierarchy and membership reconcile below.
    // The row is still transaction-private here, and delaying the stamp lets
    // the shared hierarchy validator run without mistaking bootstrap's own
    // initial link for a forbidden API mutation.
    let result = sqlx::query(
        r#"INSERT INTO object_groups
               (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(group.tenant_id)
    .bind(&group.description)
    .bind(&attributes)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap object group {}", group.id))?;
    let inserted = result.rows_affected() > 0;
    let matches: Option<bool> = sqlx::query_scalar(
        r#"SELECT name = $2
                  AND tenant_id IS NOT DISTINCT FROM $3
                  AND description IS NOT DISTINCT FROM $4
                  AND attributes = $5
                  AND status = 'active'
                  AND deleted_at IS NULL
           FROM object_groups
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(group.tenant_id)
    .bind(&group.description)
    .bind(&attributes)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to compare bootstrap object group {}", group.id))?;
    if matches != Some(true) {
        bail!(
            "bootstrap object group {} exists with different semantics or disappeared during reconciliation",
            group.id
        );
    }
    Ok(inserted)
}

/// Apply an object group's parent link and entity/resource membership. Object
/// group membership is many-to-many, so membership rows conflict on
/// `(group_id, member_id)`: declaring a member adds it to that group and leaves
/// its other memberships alone, and re-running the bootstrap is a no-op.
async fn ensure_object_group_links(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group: &BootstrapObjectGroup,
    inserted: bool,
) -> Result<()> {
    crate::authz::repo::lock_group_closures_and_collect_grants_keys(tx, &[group.id])
        .await
        .map_err(|e| anyhow!("bootstrap object group {} hierarchy lock: {e}", group.id))?;

    let mut desired_entities = group.entities.clone();
    desired_entities.sort_unstable();
    desired_entities.dedup();
    let mut desired_resources = group.resources.clone();
    desired_resources.sort_unstable();
    desired_resources.dedup();
    if !inserted {
        let persisted_entities: Vec<Uuid> = sqlx::query_scalar(
            "SELECT entity_id FROM object_group_entities WHERE group_id = $1 ORDER BY entity_id",
        )
        .bind(group.id)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to compare bootstrap object group {} entity members",
                group.id
            )
        })?;
        let persisted_resources: Vec<Uuid> = sqlx::query_scalar(
            "SELECT resource_id FROM object_group_resources WHERE group_id = $1 ORDER BY resource_id",
        )
        .bind(group.id)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to compare bootstrap object group {} resource members",
                group.id
            )
        })?;
        if persisted_entities != desired_entities || persisted_resources != desired_resources {
            bail!(
                "bootstrap object group {} exists with different membership semantics",
                group.id
            );
        }
    }

    let existing_parent: Option<Uuid> =
        sqlx::query_scalar("SELECT parent_id FROM object_group_hierarchy WHERE child_id = $1")
            .bind(group.id)
            .fetch_optional(&mut **tx)
            .await
            .with_context(|| {
                format!(
                    "failed to inspect bootstrap object group {} parent",
                    group.id
                )
            })?;
    if let Some(parent_id) = existing_parent {
        if group.parent != Some(parent_id) {
            bail!(
                "bootstrap object group {} parent declaration differs from its existing parent",
                group.id
            );
        }
        validate_existing_object_group_parent_in_tx(tx, group.id, parent_id).await?;
    } else if inserted {
        if let Some(parent_id) = group.parent {
            identity::repo::set_group_parent_in_tx(tx, false, None, group.id, parent_id)
                .await
                .map_err(|e| {
                    anyhow!(
                        "failed to link bootstrap object group {} under parent {parent_id}: {e}",
                        group.id
                    )
                })?;
        }
    } else if group.parent.is_some() {
        bail!(
            "bootstrap object group {} parent declaration differs from its existing parent",
            group.id
        );
    }

    for entity_id in &desired_entities {
        identity::repo::add_config_entity_to_object_group_in_tx(tx, *entity_id, group.id)
            .await
            .map_err(|e| {
                anyhow!(
                    "failed to add entity {entity_id} to bootstrap object group {}: {e}",
                    group.id
                )
            })?;
    }

    for resource_id in &desired_resources {
        crate::authz::repo::add_config_resource_to_object_group_in_tx(tx, *resource_id, group.id)
            .await
            .map_err(|e| {
                anyhow!(
                    "failed to add resource {resource_id} to bootstrap object group {}: {e}",
                    group.id
                )
            })?;
    }
    let stamped = sqlx::query("UPDATE object_groups SET managed_by = $2 WHERE id = $1")
        .bind(group.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap object group {}", group.id))?;
    if stamped.rows_affected() != 1 {
        bail!(
            "bootstrap object group {} disappeared before it could be stamped",
            group.id
        );
    }
    let _ = inserted;
    Ok(())
}

async fn validate_existing_object_group_parent_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<()> {
    if child_id == parent_id {
        bail!("bootstrap object group {child_id} has an existing self-parent relation");
    }
    let relation = sqlx::query(
        r#"SELECT child.tenant_id AS child_tenant_id,
                  parent.tenant_id AS parent_tenant_id,
                  hierarchy.tenant_id AS hierarchy_tenant_id
           FROM object_group_hierarchy hierarchy
           JOIN object_groups child
             ON child.id = hierarchy.child_id AND child.deleted_at IS NULL
           JOIN object_groups parent
             ON parent.id = hierarchy.parent_id AND parent.deleted_at IS NULL
           WHERE hierarchy.child_id = $1 AND hierarchy.parent_id = $2"#,
    )
    .bind(child_id)
    .bind(parent_id)
    .fetch_optional(&mut **tx)
    .await
    .context("failed to validate existing bootstrap object-group hierarchy")?
    .ok_or_else(|| {
        anyhow!(
            "bootstrap object group {child_id} has an existing parent relation to a missing or deleted object group"
        )
    })?;
    let child_tenant_id: Option<Uuid> = relation.try_get("child_tenant_id")?;
    let parent_tenant_id: Option<Uuid> = relation.try_get("parent_tenant_id")?;
    let hierarchy_tenant_id: Option<Uuid> = relation.try_get("hierarchy_tenant_id")?;
    if child_tenant_id != parent_tenant_id || hierarchy_tenant_id != child_tenant_id {
        bail!("bootstrap object group {child_id} has an existing cross-tenant parent relation");
    }
    // `ensure_object_groups` locked the complete batch tenant set before its
    // hierarchy advisory lock. This call is only the lifecycle revalidation;
    // the row lock is a same-transaction reacquisition, never advisory->tenant.
    crate::tenants::repo::lock_optional_active_tenant(tx, child_tenant_id)
        .await
        .map_err(|e| anyhow!("bootstrap object group {child_id} parent tenant: {e}"))?;
    let locked: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM object_groups
           WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL
           ORDER BY id FOR UPDATE"#,
    )
    .bind(vec![child_id, parent_id])
    .fetch_all(&mut **tx)
    .await
    .context("failed to lock existing bootstrap object-group hierarchy")?;
    if locked.len() != 2 {
        bail!("bootstrap object group {child_id} parent or child is deleted");
    }
    let creates_cycle: bool = sqlx::query_scalar(
        r#"WITH RECURSIVE ancestors(id) AS (
               SELECT $1::uuid
               UNION
               SELECT hierarchy.parent_id
               FROM object_group_hierarchy hierarchy
               JOIN ancestors ON hierarchy.child_id = ancestors.id
           )
           SELECT EXISTS (SELECT 1 FROM ancestors WHERE id = $2)"#,
    )
    .bind(parent_id)
    .bind(child_id)
    .fetch_one(&mut **tx)
    .await
    .context("failed to check existing bootstrap object-group hierarchy cycle")?;
    if creates_cycle {
        bail!("bootstrap object group {child_id} has an existing hierarchy cycle");
    }
    Ok(())
}

async fn ensure_permission_block(
    tx: &mut Transaction<'_, Postgres>,
    block: &BootstrapPermissionBlock,
) -> Result<()> {
    let conditions = block
        .conditions
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let scope = &block.scope;

    let mut configured_action_ids = Vec::with_capacity(block.actions.len());
    for action_name in &block.actions {
        let action_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
            .bind(action_name)
            .fetch_optional(&mut **tx)
            .await
            .with_context(|| format!("failed to resolve action {action_name}"))?
            .ok_or_else(|| {
                anyhow!(
                    "permission block {}: unknown action {action_name}",
                    block.id
                )
            })?;
        configured_action_ids.push(action_id);
    }

    let desired = CreatePermissionBlock {
        tenant_id: scope.tenant_id,
        scope_mode: scope.mode.as_str().to_string(),
        object_kind: scope.object_kind.clone(),
        object_type: scope.object_type.clone(),
        object_id: scope.object_id,
        group_id: scope.group_id,
        effect: block.effect.clone(),
        conditions: conditions.clone(),
        action_ids: configured_action_ids.clone(),
    };
    crate::authz::repo::validate_permission_block_input_on_connection(tx, &desired)
        .await
        .map_err(|e| anyhow!("bootstrap permission block {}: {e}", block.id))?;

    configured_action_ids.sort_unstable();
    configured_action_ids.dedup();
    // Existing rows are idempotent only when their complete stored semantics,
    // including the action set, exactly match the normalized YAML declaration.
    let existing = sqlx::query(
        r#"SELECT tenant_id, scope_mode, object_kind, object_type, object_id,
                  group_id, effect, conditions
           FROM permission_blocks
           WHERE id = $1"#,
    )
    .bind(block.id)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to inspect bootstrap permission block {}", block.id))?;

    if let Some(row) = &existing {
        let persisted_action_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT action_id FROM permission_block_actions WHERE permission_block_id = $1 ORDER BY action_id",
        )
        .bind(block.id)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to inspect actions for bootstrap permission block {}",
                block.id
            )
        })?;
        let persisted = CreatePermissionBlock {
            tenant_id: row.try_get("tenant_id")?,
            scope_mode: row.try_get("scope_mode")?,
            object_kind: row.try_get("object_kind")?,
            object_type: row.try_get("object_type")?,
            object_id: row.try_get("object_id")?,
            group_id: row.try_get("group_id")?,
            effect: row.try_get("effect")?,
            conditions: row.try_get("conditions")?,
            action_ids: persisted_action_ids,
        };
        let semantics_match = persisted.tenant_id == desired.tenant_id
            && persisted.scope_mode == desired.scope_mode
            && persisted.object_kind == desired.object_kind
            && persisted.object_type == desired.object_type
            && persisted.object_id == desired.object_id
            && persisted.group_id == desired.group_id
            && persisted.effect == desired.effect
            && persisted.conditions == desired.conditions
            && persisted.action_ids == configured_action_ids;
        if !semantics_match {
            bail!(
                "bootstrap permission block {} exists with different semantics",
                block.id
            );
        }
        crate::authz::repo::validate_permission_block_input_on_connection(tx, &persisted)
            .await
            .map_err(|e| {
                anyhow!(
                    "existing bootstrap permission block {} is incompatible: {e}",
                    block.id
                )
            })?;
    }

    let result = sqlx::query(
        r#"INSERT INTO permission_blocks
             (id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(block.id)
    .bind(scope.tenant_id)
    .bind(scope.mode.as_str())
    .bind(&scope.object_kind)
    .bind(&scope.object_type)
    .bind(scope.object_id)
    .bind(scope.group_id)
    .bind(&block.effect)
    .bind(&conditions)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap permission block {}", block.id))?;
    if result.rows_affected() == 0 {
        let matches: bool = sqlx::query_scalar(
            r#"SELECT EXISTS (
                 SELECT 1 FROM permission_blocks
                 WHERE id = $1
                   AND tenant_id IS NOT DISTINCT FROM $2
                   AND scope_mode = $3
                   AND object_kind IS NOT DISTINCT FROM $4
                   AND object_type IS NOT DISTINCT FROM $5
                   AND object_id IS NOT DISTINCT FROM $6
                   AND group_id IS NOT DISTINCT FROM $7
                   AND effect = $8 AND conditions = $9
                 FOR UPDATE
               )"#,
        )
        .bind(block.id)
        .bind(scope.tenant_id)
        .bind(scope.mode.as_str())
        .bind(&scope.object_kind)
        .bind(&scope.object_type)
        .bind(scope.object_id)
        .bind(scope.group_id)
        .bind(&block.effect)
        .bind(&conditions)
        .fetch_one(&mut **tx)
        .await?;
        let persisted_actions: Vec<Uuid> = sqlx::query_scalar(
            "SELECT action_id FROM permission_block_actions WHERE permission_block_id = $1 ORDER BY action_id",
        )
        .bind(block.id)
        .fetch_all(&mut **tx)
        .await?;
        if !matches || persisted_actions != configured_action_ids {
            bail!(
                "bootstrap permission block {} exists with different semantics",
                block.id
            );
        }
    }
    for action_id in &configured_action_ids {
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(block.id)
        .bind(action_id)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to attach action to permission block {}", block.id))?;
    }
    sqlx::query("UPDATE permission_blocks SET managed_by = $2 WHERE id = $1")
        .bind(block.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap permission block {}", block.id))?;
    let _ = result;
    Ok(())
}

async fn ensure_role(tx: &mut Transaction<'_, Postgres>, role: &BootstrapRole) -> Result<()> {
    let persisted_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1")
            .bind(role.id)
            .fetch_optional(&mut **tx)
            .await
            .with_context(|| format!("failed to inspect bootstrap role {} tenant", role.id))?;
    let mut tenant_ids = vec![role.tenant_id];
    tenant_ids.extend(persisted_tenant_id);
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids)
        .await
        .map_err(|e| anyhow!("bootstrap role {} tenant lock: {e}", role.id))?;
    let result = sqlx::query(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(role.id)
    .bind(&role.name)
    .bind(role.tenant_id)
    .bind(&role.description)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap role {}", role.id))?;

    // Serialize the semantic comparison and all configured link inserts with
    // runtime role/block-link mutations. Without this canonical role lock, a
    // concurrent link change could land after the comparison but before the
    // managed_by stamp, leaving drift incorrectly marked config-managed.
    crate::authz::repo::lock_role(tx, role.id)
        .await
        .map_err(|e| anyhow!("failed to lock bootstrap role {}: {e}", role.id))?;

    let mut desired_block_ids = role.permission_blocks.clone();
    desired_block_ids.sort_unstable();
    desired_block_ids.dedup();
    if result.rows_affected() == 0 {
        let matches: bool = sqlx::query_scalar(
            r#"SELECT EXISTS (
                   SELECT 1 FROM roles
                   WHERE id = $1 AND name = $2
                     AND tenant_id IS NOT DISTINCT FROM $3
                     AND description IS NOT DISTINCT FROM $4
                     AND deleted_at IS NULL
               )"#,
        )
        .bind(role.id)
        .bind(&role.name)
        .bind(role.tenant_id)
        .bind(&role.description)
        .fetch_one(&mut **tx)
        .await
        .with_context(|| format!("failed to compare bootstrap role {}", role.id))?;
        let persisted_block_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1 ORDER BY permission_block_id",
        )
        .bind(role.id)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| format!("failed to compare bootstrap role {} links", role.id))?;
        if !matches || persisted_block_ids != desired_block_ids {
            bail!("bootstrap role {} exists with different semantics", role.id);
        }
    }

    let persisted_tenant_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(role.id)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("failed to inspect bootstrap role {}", role.id))?
    .ok_or_else(|| anyhow!("bootstrap role {} is deleted", role.id))?;

    for block_id in &desired_block_ids {
        let block_tenant_id: Option<Uuid> =
            sqlx::query_scalar("SELECT tenant_id FROM permission_blocks WHERE id = $1 FOR UPDATE")
                .bind(block_id)
                .fetch_optional(&mut **tx)
                .await
                .with_context(|| format!("failed to inspect permission block {block_id}"))?
                .ok_or_else(|| {
                    anyhow!(
                        "bootstrap role {} references unknown permission block {block_id}",
                        role.id
                    )
                })?;
        if block_tenant_id != persisted_tenant_id {
            bail!(
                "bootstrap role {} and permission block {block_id} must belong to the same tenant",
                role.id
            );
        }
        crate::guardrails::validate_role_permission_block_links(tx, role.id, &[*block_id])
            .await
            .map_err(|e| {
                anyhow!(
                    "bootstrap role {} permission block {block_id}: {e}",
                    role.id
                )
            })?;
        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(role.id)
        .bind(block_id)
        .execute(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to link permission block {block_id} to role {}",
                role.id
            )
        })?;
    }
    sqlx::query("UPDATE roles SET managed_by = $2 WHERE id = $1")
        .bind(role.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap role {}", role.id))?;
    let _ = result;
    Ok(())
}

async fn ensure_role_assignment(
    tx: &mut Transaction<'_, Postgres>,
    assignment: &BootstrapRoleAssignment,
) -> Result<()> {
    let desired = CreateRoleAssignment {
        tenant_id: assignment.tenant_id,
        subject_kind: assignment.subject.kind.clone(),
        subject_id: assignment.subject.id,
        role_id: assignment.role_id,
    };
    crate::authz::repo::prepare_role_assignment_in_tx(tx, &desired)
        .await
        .map_err(|e| anyhow!("bootstrap role assignment {}: {e}", assignment.id))?;
    crate::authz::repo::validate_role_assignment_in_tx(tx, &desired)
        .await
        .map_err(|e| anyhow!("bootstrap role assignment {}: {e}", assignment.id))?;

    let result = sqlx::query(
        r#"INSERT INTO role_assignments (id, tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(assignment.id)
    .bind(assignment.tenant_id)
    .bind(&assignment.subject.kind)
    .bind(assignment.subject.id)
    .bind(assignment.role_id)
    .execute(&mut **tx)
    .await
    .with_context(|| {
        format!(
            "failed to insert bootstrap role assignment {}",
            assignment.id
        )
    })?;

    let persisted = sqlx::query(
        r#"SELECT tenant_id, subject_kind, subject_id, role_id
           FROM role_assignments
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(assignment.id)
    .fetch_one(&mut **tx)
    .await
    .with_context(|| {
        format!(
            "failed to inspect bootstrap role assignment {}",
            assignment.id
        )
    })?;
    let persisted = CreateRoleAssignment {
        tenant_id: persisted.try_get("tenant_id")?,
        subject_kind: persisted.try_get("subject_kind")?,
        subject_id: persisted.try_get("subject_id")?,
        role_id: persisted.try_get("role_id")?,
    };
    if persisted.tenant_id != desired.tenant_id
        || persisted.subject_kind != desired.subject_kind
        || persisted.subject_id != desired.subject_id
        || persisted.role_id != desired.role_id
    {
        bail!(
            "bootstrap role assignment {} exists with different semantics",
            assignment.id
        );
    }
    crate::authz::repo::validate_role_assignment_in_tx(tx, &persisted)
        .await
        .map_err(|e| {
            anyhow!(
                "existing bootstrap role assignment {} is incompatible: {e}",
                assignment.id
            )
        })?;
    sqlx::query("UPDATE role_assignments SET managed_by = $2 WHERE id = $1")
        .bind(assignment.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to stamp bootstrap role assignment {}",
                assignment.id
            )
        })?;
    let _ = result;
    Ok(())
}

/// Insert a capability when absent, or claim an existing row only when its
/// persisted description and applicability exactly match the declaration.
/// The row is then stamped `managed_by='config'` so mutation endpoints
/// (`update_capability`, `delete_capability`) refuse to touch it out of band.
async fn ensure_capability(
    tx: &mut Transaction<'_, Postgres>,
    capability: &BootstrapCapability,
) -> Result<()> {
    let name = capability.name.trim().to_string();
    sqlx::query(
        r#"INSERT INTO actions (name, description, managed_by)
           VALUES ($1, $2, $3)
           ON CONFLICT (name) DO NOTHING"#,
    )
    .bind(&name)
    .bind(&capability.description)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to upsert bootstrap capability {name}"))?;
    let persisted = sqlx::query("SELECT id, description FROM actions WHERE name = $1 FOR UPDATE")
        .bind(&name)
        .fetch_one(&mut **tx)
        .await
        .with_context(|| format!("failed to inspect bootstrap capability {name}"))?;
    let action_id: Uuid = persisted.try_get("id")?;
    let description: Option<String> = persisted.try_get("description")?;
    if description != capability.description {
        bail!("bootstrap capability {name} exists with different semantics");
    }
    let stamped = sqlx::query("UPDATE actions SET managed_by = $2 WHERE id = $1")
        .bind(action_id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap capability {name}"))?;
    if stamped.rows_affected() != 1 {
        bail!("bootstrap capability {name} disappeared before it could be stamped");
    }

    let declared = capability
        .applicability
        .iter()
        .map(|app| {
            (
                app.object_kind.as_str().to_string(),
                app.object_type.clone(),
            )
        })
        .collect::<HashSet<_>>();
    let persisted = sqlx::query(
        r#"SELECT object_kind, object_type
           FROM action_applicability
           WHERE action_id = $1
           ORDER BY object_kind, object_type
           FOR UPDATE"#,
    )
    .bind(action_id)
    .fetch_all(&mut **tx)
    .await
    .with_context(|| format!("failed to inspect bootstrap applicability for {name}"))?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("object_kind")?,
            row.try_get::<Option<String>, _>("object_type")?,
        ))
    })
    .collect::<Result<HashSet<_>>>()?;
    let extras = persisted.difference(&declared).collect::<Vec<_>>();
    if !extras.is_empty() {
        bail!(
            "bootstrap capability {name} has persisted applicability not declared in config: {}",
            extras
                .iter()
                .map(|(kind, object_type)| format!(
                    "{kind}:{}",
                    object_type.as_deref().unwrap_or("<any>")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    for app in &capability.applicability {
        ensure_capability_applicability(tx, action_id, &name, app).await?;
    }
    let final_rows = sqlx::query(
        "SELECT object_kind, object_type FROM action_applicability WHERE action_id = $1",
    )
    .bind(action_id)
    .fetch_all(&mut **tx)
    .await
    .with_context(|| format!("failed to verify bootstrap applicability for {name}"))?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("object_kind")?,
            row.try_get::<Option<String>, _>("object_type")?,
        ))
    })
    .collect::<Result<HashSet<_>>>()?;
    if final_rows != declared {
        bail!("bootstrap capability {name} applicability reconciliation was incomplete");
    }
    Ok(())
}

async fn ensure_capability_applicability(
    tx: &mut Transaction<'_, Postgres>,
    action_id: Uuid,
    action_name: &str,
    app: &BootstrapCapabilityApplicability,
) -> Result<()> {
    // Two-step upsert: the unique index on this table is functional
    // (`COALESCE(object_type, '')`), which makes ON CONFLICT target awkward.
    // Insert-then-update is simpler and equally atomic per row.
    sqlx::query(
        r#"INSERT INTO action_applicability (action_id, object_kind, object_type, managed_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(action_id)
    .bind(app.object_kind.as_str())
    .bind(&app.object_type)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| {
        format!("failed to insert bootstrap applicability for capability {action_name}")
    })?;

    sqlx::query(
        r#"UPDATE action_applicability
              SET managed_by = $4
            WHERE action_id = $1
              AND object_kind = $2
              AND object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(action_id)
    .bind(app.object_kind.as_str())
    .bind(&app.object_type)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| {
        format!("failed to stamp bootstrap applicability for capability {action_name}")
    })?;
    Ok(())
}

async fn ensure_action_assignment_rule(
    tx: &mut Transaction<'_, Postgres>,
    rule: &BootstrapActionAssignmentRule,
) -> Result<()> {
    let normalized =
        crate::authz::repo::validate_and_normalize_action_assignment_rule_on_connection(
            tx,
            CreateActionAssignmentRule {
                tenant_id: rule.tenant_id,
                entity_kind: rule.entity_kind.clone(),
                action_name: rule.action_name.clone(),
                object_kind: rule.object_kind,
                object_type: rule.object_type.clone(),
                decision: rule.decision,
                is_absolute: rule.is_absolute,
            },
        )
        .await
        .map_err(|e| anyhow!("bootstrap action_assignment_rule: {e}"))?;

    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[normalized.tenant_id])
        .await
        .map_err(|e| {
            anyhow!(
                "bootstrap assignment rule for action {} tenant lock: {e}",
                normalized.action_name
            )
        })?;

    // The natural key is backed by a functional unique index. A conflicting
    // uncommitted insert blocks this statement; after it resolves, the locked
    // re-read below observes and validates the winning row.
    let inserted = sqlx::query(
        r#"INSERT INTO action_assignment_rules
               (tenant_id, entity_kind, action_name, object_kind, object_type,
                decision, is_absolute, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(normalized.tenant_id)
    .bind(&normalized.entity_kind)
    .bind(&normalized.action_name)
    .bind(normalized.object_kind)
    .bind(&normalized.object_type)
    .bind(normalized.decision)
    .bind(normalized.is_absolute)
    .bind(MANAGED_BY_CONFIG)
    .execute(&mut **tx)
    .await
    .with_context(|| {
        format!(
            "failed to insert bootstrap assignment rule for action {}",
            normalized.action_name
        )
    })?;

    let persisted = sqlx::query(
        r#"SELECT id, tenant_id, entity_kind, action_name, object_kind,
                  object_type, decision, is_absolute
           FROM action_assignment_rules
           WHERE tenant_id IS NOT DISTINCT FROM $1
             AND entity_kind = $2
             AND action_name = $3
             AND object_kind = $4
             AND object_type IS NOT DISTINCT FROM $5
           FOR UPDATE"#,
    )
    .bind(normalized.tenant_id)
    .bind(&normalized.entity_kind)
    .bind(&normalized.action_name)
    .bind(normalized.object_kind)
    .bind(&normalized.object_type)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| {
        format!(
            "failed to inspect bootstrap assignment rule for action {}",
            normalized.action_name
        )
    })?
    .ok_or_else(|| {
        anyhow!(
            "bootstrap action_assignment_rule for {} disappeared during reconciliation",
            normalized.action_name
        )
    })?;
    let id: Uuid = persisted.try_get("id")?;
    let tenant_id: Option<Uuid> = persisted.try_get("tenant_id")?;
    let entity_kind: EntityKind = persisted.try_get("entity_kind")?;
    let action_name: String = persisted.try_get("action_name")?;
    let object_kind: ObjectKind = persisted.try_get("object_kind")?;
    let object_type: Option<String> = persisted.try_get("object_type")?;
    let decision: ActionAssignmentDecision = persisted.try_get("decision")?;
    let is_absolute: bool = persisted.try_get("is_absolute")?;
    if tenant_id != normalized.tenant_id
        || entity_kind != normalized.entity_kind
        || action_name != normalized.action_name
        || object_kind != normalized.object_kind
        || object_type != normalized.object_type
        || decision != normalized.decision
        || is_absolute != normalized.is_absolute
    {
        bail!(
            "bootstrap action_assignment_rule for {} conflicts with an existing rule's semantics",
            normalized.action_name
        );
    }

    let stamped = sqlx::query("UPDATE action_assignment_rules SET managed_by = $2 WHERE id = $1")
        .bind(id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "failed to stamp bootstrap assignment rule for action {}",
                normalized.action_name
            )
        })?;
    if stamped.rows_affected() != 1 {
        bail!(
            "bootstrap action_assignment_rule for {} disappeared before it could be stamped",
            normalized.action_name
        );
    }
    let _ = inserted;
    Ok(())
}

async fn ensure_direct_policy(
    tx: &mut Transaction<'_, Postgres>,
    policy: &BootstrapDirectPolicy,
) -> Result<()> {
    let desired = CreateDirectPolicy {
        tenant_id: policy.tenant_id,
        subject_kind: policy.subject.kind.clone(),
        subject_id: policy.subject.id,
        permission_block_id: policy.permission_block_id,
    };
    crate::authz::repo::prepare_direct_policy_in_tx(tx, &desired)
        .await
        .map_err(|e| anyhow!("bootstrap direct policy {}: {e}", policy.id))?;
    crate::authz::repo::validate_direct_policy_in_tx(tx, &desired)
        .await
        .map_err(|e| anyhow!("bootstrap direct policy {}: {e}", policy.id))?;
    crate::guardrails::validate_direct_policy(tx, &desired)
        .await
        .map_err(|e| anyhow!("bootstrap direct policy {}: {e}", policy.id))?;

    let result = sqlx::query(
        r#"INSERT INTO direct_policies (id, tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(policy.id)
    .bind(policy.tenant_id)
    .bind(&policy.subject.kind)
    .bind(policy.subject.id)
    .bind(policy.permission_block_id)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("failed to insert bootstrap direct policy {}", policy.id))?;

    let persisted = sqlx::query(
        r#"SELECT tenant_id, subject_kind, subject_id, permission_block_id
           FROM direct_policies
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(policy.id)
    .fetch_one(&mut **tx)
    .await
    .with_context(|| format!("failed to inspect bootstrap direct policy {}", policy.id))?;
    let persisted = CreateDirectPolicy {
        tenant_id: persisted.try_get("tenant_id")?,
        subject_kind: persisted.try_get("subject_kind")?,
        subject_id: persisted.try_get("subject_id")?,
        permission_block_id: persisted.try_get("permission_block_id")?,
    };
    if persisted.tenant_id != desired.tenant_id
        || persisted.subject_kind != desired.subject_kind
        || persisted.subject_id != desired.subject_id
        || persisted.permission_block_id != desired.permission_block_id
    {
        bail!(
            "bootstrap direct policy {} exists with different semantics",
            policy.id
        );
    }
    crate::authz::repo::validate_direct_policy_in_tx(tx, &persisted)
        .await
        .map_err(|e| {
            anyhow!(
                "existing bootstrap direct policy {} is incompatible: {e}",
                policy.id
            )
        })?;
    crate::guardrails::validate_direct_policy(tx, &persisted)
        .await
        .map_err(|e| {
            anyhow!(
                "existing bootstrap direct policy {} is incompatible: {e}",
                policy.id
            )
        })?;
    sqlx::query("UPDATE direct_policies SET managed_by = $2 WHERE id = $1")
        .bind(policy.id)
        .bind(MANAGED_BY_CONFIG)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("failed to stamp bootstrap direct policy {}", policy.id))?;
    let _ = result;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_rbac_graph() {
        let yaml = r#"
tenants:
  - id: 33333333-3333-3333-3333-333333333333
    name: factory
    alias: factory
    tags: [demo]
    attributes: { region: eu }

entities:
  - id: 22222222-2222-2222-2222-222222222222
    kind: device
    name: gateway-01
    tenant_id: 33333333-3333-3333-3333-333333333333
    credentials:
      - kind: shared_key
        key: a-strong-device-secret

resources:
  - id: 99999999-9999-9999-9999-999999999999
    kind: channel
    name: temperature
    tenant_id: 33333333-3333-3333-3333-333333333333
    owner_id: 22222222-2222-2222-2222-222222222222

groups:
  - id: 77777777-7777-7777-7777-777777777777
    name: publishers
    tenant_id: 33333333-3333-3333-3333-333333333333
    members:
      - 22222222-2222-2222-2222-222222222222

object_groups:
  - id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    name: production-channels
    tenant_id: 33333333-3333-3333-3333-333333333333
    resources:
      - 99999999-9999-9999-9999-999999999999

permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: object_type
      tenant_id: 33333333-3333-3333-3333-333333333333
      object_kind: resource
      object_type: resource:channel
    actions: [publish, subscribe]
    effect: allow
  - id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
    scope:
      mode: group_direct_objects
      tenant_id: 33333333-3333-3333-3333-333333333333
      group_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
      object_kind: resource
      object_type: resource:channel
    actions: [read]
    effect: allow

roles:
  - id: 55555555-5555-5555-5555-555555555555
    name: publisher
    tenant_id: 33333333-3333-3333-3333-333333333333
    permission_blocks: [44444444-4444-4444-4444-444444444444]

role_assignments:
  - id: 66666666-6666-6666-6666-666666666666
    tenant_id: 33333333-3333-3333-3333-333333333333
    subject: { kind: entity, id: 22222222-2222-2222-2222-222222222222 }
    role_id: 55555555-5555-5555-5555-555555555555

direct_policies:
  - id: 88888888-8888-8888-8888-888888888888
    tenant_id: 33333333-3333-3333-3333-333333333333
    subject: { kind: group, id: 77777777-7777-7777-7777-777777777777 }
    permission_block_id: 44444444-4444-4444-4444-444444444444
"#;
        let cfg = parse(yaml).expect("parse");
        assert_eq!(cfg.tenants.len(), 1);
        assert_eq!(cfg.entities.len(), 1);
        assert_eq!(cfg.resources[0].kind, "channel");
        assert_eq!(cfg.groups[0].members.len(), 1);
        assert_eq!(cfg.object_groups[0].resources.len(), 1);
        assert_eq!(cfg.permission_blocks[0].scope.mode, ScopeMode::ObjectType);
        assert_eq!(cfg.permission_blocks[0].effect, Effect::Allow);
        assert_eq!(
            cfg.permission_blocks[1].scope.mode,
            ScopeMode::GroupDirectObjects
        );
        assert!(cfg.permission_blocks[1].scope.group_id.is_some());
        assert_eq!(cfg.roles[0].permission_blocks.len(), 1);
        assert_eq!(cfg.role_assignments[0].subject.kind, SubjectKind::Entity);
        assert_eq!(cfg.direct_policies[0].subject.kind, SubjectKind::Group);
    }

    #[test]
    fn parses_entities_with_credentials() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    attributes:
      role: admin
    credentials:
      - kind: password
        secret: change-me-please
  - id: 11111111-1111-1111-1111-111111111111
    kind: service
    name: ingest
    alias: ingest-svc
    credentials:
      - kind: shared_key
        key: super-secret-key
        description: ingest pipeline
"#;
        let cfg = parse(yaml).expect("parse");
        assert_eq!(cfg.entities.len(), 2);

        let admin = &cfg.entities[0];
        assert_eq!(admin.kind, EntityKind::Human);
        assert_eq!(admin.status, EntityStatus::Active);
        assert_eq!(
            admin.credentials,
            vec![BootstrapCredential::Password {
                secret: "change-me-please".to_string()
            }]
        );

        let svc = &cfg.entities[1];
        assert_eq!(svc.kind, EntityKind::Service);
        assert_eq!(svc.alias.as_deref(), Some("ingest-svc"));
        assert_eq!(
            svc.credentials,
            vec![BootstrapCredential::SharedKey {
                key: "super-secret-key".to_string(),
                description: Some("ingest pipeline".to_string()),
            }]
        );
    }

    #[test]
    fn empty_document_is_valid_and_empty() {
        let cfg = parse("{}").expect("parse");
        assert!(cfg.entities.is_empty());
        assert!(cfg.tenants.is_empty());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    typo_field: oops
"#;
        assert!(parse(yaml).is_err(), "unknown field should be rejected");
    }

    #[test]
    fn duplicate_entity_ids_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin-two
"#;
        let err = parse(yaml).expect_err("duplicate ids");
        assert!(err.to_string().contains("duplicate bootstrap entity id"));
    }

    #[test]
    fn authenticated_users_group_is_reserved_for_system_membership() {
        let yaml = r#"
groups:
  - id: 00000000-0000-0000-0000-000000000005
    name: authenticated-users
"#;
        let err = parse(yaml).expect_err("reserved system group");
        assert!(err
            .to_string()
            .contains("system-managed authenticated-users"));
    }

    #[test]
    fn shared_key_on_human_is_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    credentials:
      - kind: shared_key
        key: nope
"#;
        let err = parse(yaml).expect_err("human shared key");
        assert!(err.to_string().contains("shared keys are only valid"));
    }

    #[test]
    fn multiple_passwords_per_entity_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    credentials:
      - kind: password
        secret: one-secret
      - kind: password
        secret: two-secret
"#;
        let err = parse(yaml).expect_err("two passwords");
        assert!(err.to_string().contains("more than one password"));
    }

    #[test]
    fn non_object_attributes_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    attributes: "not-an-object"
"#;
        let err = parse(yaml).expect_err("scalar attributes");
        assert!(err.to_string().contains("must be a JSON object"));
    }

    #[test]
    fn entity_parent_group_attribute_is_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    attributes:
      parent_group_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
"#;
        let err = parse(yaml).expect_err("legacy entity parent group");
        assert!(err.to_string().contains("parent_group_id"));
        assert!(err.to_string().contains("object_groups[].entities"));
    }

    #[test]
    fn resource_parent_group_attribute_is_rejected() {
        let yaml = r#"
resources:
  - id: 99999999-9999-9999-9999-999999999999
    kind: channel
    attributes:
      parent_group_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
"#;
        let err = parse(yaml).expect_err("legacy resource parent group");
        assert!(err.to_string().contains("parent_group_id"));
        assert!(err
            .to_string()
            .contains("object_groups[].entities/resources"));
    }

    #[test]
    fn platform_scope_rejects_tenant_id() {
        let yaml = r#"
permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: platform
      tenant_id: 33333333-3333-3333-3333-333333333333
    actions: [read]
"#;
        let err = parse(yaml).expect_err("platform with tenant");
        assert!(err.to_string().contains("platform scope takes no"));
    }

    #[test]
    fn object_type_scope_requires_object_kind_and_type() {
        let yaml = r#"
permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: object_type
      tenant_id: 33333333-3333-3333-3333-333333333333
      object_type: resource:channel
    actions: [read]
"#;
        let err = parse(yaml).expect_err("missing object_kind");
        assert!(err.to_string().contains("object_type scope requires"));
    }

    #[test]
    fn duplicate_tenant_ids_are_rejected() {
        let yaml = r#"
tenants:
  - id: 33333333-3333-3333-3333-333333333333
    name: one
  - id: 33333333-3333-3333-3333-333333333333
    name: two
"#;
        let err = parse(yaml).expect_err("duplicate tenant ids");
        assert!(err.to_string().contains("duplicate bootstrap tenant id"));
    }

    #[test]
    fn group_scope_requires_group_id() {
        let yaml = r#"
permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: group_direct_objects
      tenant_id: 33333333-3333-3333-3333-333333333333
      object_kind: resource
    actions: [read]
"#;
        let err = parse(yaml).expect_err("missing group_id");
        assert!(err.to_string().contains("require tenant_id and group_id"));
    }

    #[test]
    fn group_object_scope_requires_entity_or_resource_kind() {
        let yaml = r#"
permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: group_direct_objects
      tenant_id: 33333333-3333-3333-3333-333333333333
      group_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
      object_kind: tenant
    actions: [read]
"#;
        let err = parse(yaml).expect_err("bad object_kind");
        assert!(err
            .to_string()
            .contains("object_kind of 'entity' or 'resource'"));
    }

    #[test]
    fn group_object_scope_requires_object_type() {
        let yaml = r#"
permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: group_direct_objects
      tenant_id: 33333333-3333-3333-3333-333333333333
      group_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
      object_kind: resource
    actions: [read]
"#;
        let err = parse(yaml).expect_err("missing object_type");
        assert!(err.to_string().contains("require object_type"));
    }

    #[test]
    fn group_id_rejected_on_non_group_scope() {
        let yaml = r#"
permission_blocks:
  - id: 44444444-4444-4444-4444-444444444444
    scope:
      mode: tenant
      tenant_id: 33333333-3333-3333-3333-333333333333
      group_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    actions: [read]
"#;
        let err = parse(yaml).expect_err("group_id on tenant scope");
        assert!(err
            .to_string()
            .contains("only group_* scopes take a group_id"));
    }

    #[test]
    fn object_group_with_members_requires_tenant() {
        let yaml = r#"
object_groups:
  - id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    name: channels
    resources:
      - 99999999-9999-9999-9999-999999999999
"#;
        let err = parse(yaml).expect_err("members without tenant");
        assert!(err.to_string().contains("has members but no tenant_id"));
    }

    #[test]
    fn object_group_cannot_be_its_own_parent() {
        let yaml = r#"
object_groups:
  - id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    name: channels
    tenant_id: 33333333-3333-3333-3333-333333333333
    parent: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
"#;
        let err = parse(yaml).expect_err("self parent");
        assert!(err.to_string().contains("cannot be its own parent"));
    }

    #[test]
    fn tenant_admin_defaults_parse_and_reject_duplicates() {
        let yaml = r#"
tenant_defaults:
  admin_capabilities: [alarm.acknowledge, alarm.silence]
"#;
        let cfg = parse(yaml).expect("tenant defaults");
        assert_eq!(
            cfg.tenant_defaults.admin_capabilities,
            ["alarm.acknowledge", "alarm.silence"]
        );

        let duplicate = r#"
tenant_defaults:
  admin_capabilities: [alarm.acknowledge, alarm.acknowledge]
"#;
        let err = parse(duplicate).expect_err("duplicate tenant-admin default");
        assert!(err
            .to_string()
            .contains("duplicate tenant-admin default capability"));
    }

    #[test]
    fn resource_requires_kind() {
        let yaml = r#"
resources:
  - id: 99999999-9999-9999-9999-999999999999
    kind: "  "
"#;
        let err = parse(yaml).expect_err("empty kind");
        assert!(err.to_string().contains("empty kind"));
    }

    #[test]
    fn generated_v1_schema_matches_the_frozen_artifact() {
        let generated = v1_json_schema().expect("generate bootstrap schema");
        let committed: Value =
            serde_json::from_str(include_str!("../api/v1/bootstrap.schema.json"))
                .expect("committed bootstrap schema");
        assert_eq!(generated, committed);
    }

    #[test]
    fn example_and_unknown_field_policy_match_the_v1_schema() {
        let schema: Value = serde_json::from_str(include_str!("../api/v1/bootstrap.schema.json"))
            .expect("committed bootstrap schema");
        let compiled = jsonschema::JSONSchema::compile(&schema).expect("compile bootstrap schema");

        let example_yaml = include_str!("../config/examples/bootstrap.yaml");
        parse(example_yaml).expect("example must satisfy runtime validation");
        let example: Value = serde_yaml::from_str(example_yaml).expect("example YAML");
        assert!(
            compiled.is_valid(&example),
            "example must satisfy the frozen structural schema"
        );

        // Serde intentionally cannot use deny_unknown_fields on this internally
        // tagged enum. The generated schema mirrors that compatibility surface:
        // unknown credential fields are accepted by both validators.
        let credential_extra = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    credentials:
      - kind: password
        secret: change-me-please
        extension_field: retained-for-v1-compatibility
"#;
        parse(credential_extra).expect("runtime accepts credential extension fields");
        let credential_extra: Value =
            serde_yaml::from_str(credential_extra).expect("credential extension YAML");
        assert!(compiled.is_valid(&credential_extra));

        let entity_extra = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    extension_field: rejected
"#;
        assert!(parse(entity_extra).is_err());
        let entity_extra: Value =
            serde_yaml::from_str(entity_extra).expect("entity extension YAML");
        assert!(!compiled.is_valid(&entity_extra));
    }

    #[test]
    fn scope_mode_spellings_match_the_v1_persisted_contract() {
        fn spelling(mode: ScopeMode) -> &'static str {
            match mode {
                ScopeMode::Platform
                | ScopeMode::Tenant
                | ScopeMode::ObjectKind
                | ScopeMode::ObjectType
                | ScopeMode::Object
                | ScopeMode::GroupDirectObjects
                | ScopeMode::GroupDescendantObjects
                | ScopeMode::GroupChildGroups
                | ScopeMode::GroupDescendantGroups => mode.as_str(),
            }
        }

        let runtime = [
            ScopeMode::Platform,
            ScopeMode::Tenant,
            ScopeMode::ObjectKind,
            ScopeMode::ObjectType,
            ScopeMode::Object,
            ScopeMode::GroupDirectObjects,
            ScopeMode::GroupDescendantObjects,
            ScopeMode::GroupChildGroups,
            ScopeMode::GroupDescendantGroups,
        ]
        .map(spelling);
        let contract: Value =
            serde_json::from_str(include_str!("../api/v1/persisted-semantics.json"))
                .expect("persisted-semantics contract");
        let frozen = contract["bootstrapScopeModes"]
            .as_array()
            .expect("bootstrap scope modes")
            .iter()
            .map(|value| value.as_str().expect("scope-mode string"))
            .collect::<Vec<_>>();
        assert_eq!(runtime.as_slice(), frozen);
    }
}
