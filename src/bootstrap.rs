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
//! is keyed on a stable UUID and inserted with `ON CONFLICT DO NOTHING`, so
//! re-running against an already-provisioned database is a no-op and never
//! clobbers runtime changes. It runs *alongside* the env-var bootstrap, not
//! instead of it.
//!
//! It provisions the full RBAC graph, applied in dependency order:
//! tenants → entities (+ credentials) → resources → principal groups
//! (+ members) → object groups (+ members, hierarchy) → permission blocks
//! (+ actions) → roles (+ block links) → role assignments → direct policies.
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
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::SigningKeyConfig;
use crate::identity;
use crate::models::alias::validate_alias_opt;
use crate::models::enums::{
    CredentialKind, Effect, EntityKind, EntityStatus, SubjectKind, TenantStatus,
};
use crate::models::token::CreateSharedKey;

/// Root of the bootstrap document. Every section is optional.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
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
}

/// A tenant (domain). `None` `tenant_id` on other records means platform scope.
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
}

/// A protected resource object (e.g. a `channel`). `kind` is a free-form label.
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
/// An entity or resource belongs to at most one object group. Membership rows
/// require a tenant, so a group with members must declare `tenant_id`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSubject {
    pub kind: SubjectKind,
    pub id: Uuid,
}

/// Grants a role to a subject.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRoleAssignment {
    pub id: Uuid,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub subject: BootstrapSubject,
    pub role_id: Uuid,
}

/// Grants a permission block directly to a subject.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapDirectPolicy {
    pub id: Uuid,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub subject: BootstrapSubject,
    pub permission_block_id: Uuid,
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
        }
        for group in &self.groups {
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
        Ok(())
    }
}

impl BootstrapEntity {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("bootstrap entity {} has an empty name", self.id);
        }
        check_object_attributes(&self.attributes, "entity", self.id)?;

        let mut passwords = 0;
        let mut shared_keys = 0;
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

/// Read and parse a bootstrap file, validating its structure.
pub fn load(path: &Path) -> Result<BootstrapConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bootstrap file {}", path.display()))?;
    parse(&contents).with_context(|| format!("invalid bootstrap file {}", path.display()))
}

fn parse(contents: &str) -> Result<BootstrapConfig> {
    let cfg: BootstrapConfig = serde_yaml::from_str(contents).context("failed to parse YAML")?;
    cfg.validate()?;
    Ok(cfg)
}

/// Apply the bootstrap config against the database, in dependency order.
/// Idempotent.
pub async fn apply(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    cfg: &BootstrapConfig,
) -> Result<()> {
    for tenant in &cfg.tenants {
        ensure_tenant(pool, tenant).await?;
    }
    for entity in &cfg.entities {
        ensure_entity(pool, entity).await?;
        for cred in &entity.credentials {
            ensure_credential(pool, signing_keys, entity, cred).await?;
        }
    }
    for resource in &cfg.resources {
        ensure_resource(pool, resource).await?;
    }
    for group in &cfg.groups {
        ensure_group(pool, group).await?;
    }
    // Object group rows first, then hierarchy/membership, so a parent declared
    // later in the file still resolves.
    for group in &cfg.object_groups {
        ensure_object_group(pool, group).await?;
    }
    for group in &cfg.object_groups {
        ensure_object_group_links(pool, group).await?;
    }
    for block in &cfg.permission_blocks {
        ensure_permission_block(pool, block).await?;
    }
    for role in &cfg.roles {
        ensure_role(pool, role).await?;
    }
    for assignment in &cfg.role_assignments {
        ensure_role_assignment(pool, assignment).await?;
    }
    for policy in &cfg.direct_policies {
        ensure_direct_policy(pool, policy).await?;
    }
    Ok(())
}

async fn ensure_tenant(pool: &PgPool, tenant: &BootstrapTenant) -> Result<()> {
    let alias = validate_alias_opt(tenant.alias.clone())
        .map_err(|e| anyhow!("bootstrap tenant {}: {e}", tenant.id))?;
    let attributes = tenant
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO tenants (id, name, alias, status, tags, attributes)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(tenant.id)
    .bind(&tenant.name)
    .bind(alias)
    .bind(&tenant.status)
    .bind(&tenant.tags)
    .bind(attributes)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap tenant {}", tenant.id))?;

    log_upsert(result.rows_affected(), "tenant", tenant.id);
    Ok(())
}

/// Create the entity if its UUID is not already present. Existing rows are left
/// untouched, so a bootstrap re-run never overwrites runtime edits.
async fn ensure_entity(pool: &PgPool, entity: &BootstrapEntity) -> Result<()> {
    let alias = validate_alias_opt(entity.alias.clone())
        .map_err(|e| anyhow!("bootstrap entity {}: {e}", entity.id))?;
    let attributes = entity
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO entities (id, kind, name, alias, tenant_id, status, attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(entity.id)
    .bind(&entity.kind)
    .bind(&entity.name)
    .bind(alias)
    .bind(entity.tenant_id)
    .bind(&entity.status)
    .bind(attributes)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap entity {}", entity.id))?;

    log_upsert(result.rows_affected(), "entity", entity.id);
    Ok(())
}

/// Create the credential only if the entity has no active credential of that
/// kind yet. Reuses the identity service so hashing, strength validation and
/// shared-key envelope encryption stay identical to the API path.
async fn ensure_credential(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity: &BootstrapEntity,
    cred: &BootstrapCredential,
) -> Result<()> {
    match cred {
        BootstrapCredential::Password { secret } => {
            if active_credential_exists(pool, entity.id, CredentialKind::Password).await? {
                tracing::info!(entity_id = %entity.id, "bootstrap: password already present, skipped");
                return Ok(());
            }
            identity::service::create_password(pool, entity.id, secret)
                .await
                .map_err(|e| anyhow!("bootstrap password for entity {}: {e}", entity.id))?;
            tracing::info!(entity_id = %entity.id, "bootstrap: password credential created");
        }
        BootstrapCredential::SharedKey { key, description } => {
            if active_credential_exists(pool, entity.id, CredentialKind::SharedKey).await? {
                tracing::info!(entity_id = %entity.id, "bootstrap: shared key already present, skipped");
                return Ok(());
            }
            identity::service::create_shared_key(
                pool,
                signing_keys,
                entity.id,
                CreateSharedKey {
                    expires_at: None,
                    description: description.clone(),
                    key: Some(key.clone()),
                },
            )
            .await
            .map_err(|e| anyhow!("bootstrap shared key for entity {}: {e}", entity.id))?;
            tracing::info!(entity_id = %entity.id, "bootstrap: shared key credential created");
        }
    }
    Ok(())
}

async fn ensure_group(pool: &PgPool, group: &BootstrapGroup) -> Result<()> {
    let attributes = group
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO principal_groups (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(group.tenant_id)
    .bind(&group.description)
    .bind(attributes)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap group {}", group.id))?;
    log_upsert(result.rows_affected(), "group", group.id);

    for entity_id in &group.members {
        sqlx::query(
            r#"INSERT INTO principal_group_members (group_id, entity_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(group.id)
        .bind(entity_id)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to add entity {entity_id} to bootstrap group {}",
                group.id
            )
        })?;
    }
    Ok(())
}

async fn ensure_resource(pool: &PgPool, resource: &BootstrapResource) -> Result<()> {
    let alias = validate_alias_opt(resource.alias.clone())
        .map_err(|e| anyhow!("bootstrap resource {}: {e}", resource.id))?;
    let attributes = resource
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO resources (id, kind, name, alias, tenant_id, owner_id, attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(resource.id)
    .bind(&resource.kind)
    .bind(&resource.name)
    .bind(alias)
    .bind(resource.tenant_id)
    .bind(resource.owner_id)
    .bind(attributes)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap resource {}", resource.id))?;
    log_upsert(result.rows_affected(), "resource", resource.id);
    Ok(())
}

/// Insert the object group row only. Membership and hierarchy are applied in a
/// second pass ([`ensure_object_group_links`]) so a parent declared later in the
/// file still resolves.
async fn ensure_object_group(pool: &PgPool, group: &BootstrapObjectGroup) -> Result<()> {
    let attributes = group
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO object_groups (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(group.tenant_id)
    .bind(&group.description)
    .bind(attributes)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap object group {}", group.id))?;
    log_upsert(result.rows_affected(), "object group", group.id);
    Ok(())
}

/// Apply an object group's parent link and entity/resource membership. An entity
/// or resource belongs to at most one object group, so membership rows conflict
/// on the member id and are left untouched if already present.
async fn ensure_object_group_links(pool: &PgPool, group: &BootstrapObjectGroup) -> Result<()> {
    if let Some(parent_id) = group.parent {
        sqlx::query(
            r#"INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id)
               VALUES ($1, $2, $3)
               ON CONFLICT (child_id) DO NOTHING"#,
        )
        .bind(parent_id)
        .bind(group.id)
        .bind(group.tenant_id)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to link object group {} under parent {parent_id}",
                group.id
            )
        })?;
    }

    for entity_id in &group.entities {
        sqlx::query(
            r#"INSERT INTO object_group_entities (group_id, entity_id, tenant_id)
               VALUES ($1, $2, $3)
               ON CONFLICT (entity_id) DO NOTHING"#,
        )
        .bind(group.id)
        .bind(entity_id)
        .bind(group.tenant_id)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to add entity {entity_id} to object group {}",
                group.id
            )
        })?;
    }

    for resource_id in &group.resources {
        sqlx::query(
            r#"INSERT INTO object_group_resources (group_id, resource_id, tenant_id)
               VALUES ($1, $2, $3)
               ON CONFLICT (resource_id) DO NOTHING"#,
        )
        .bind(group.id)
        .bind(resource_id)
        .bind(group.tenant_id)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to add resource {resource_id} to object group {}",
                group.id
            )
        })?;
    }
    Ok(())
}

async fn ensure_permission_block(pool: &PgPool, block: &BootstrapPermissionBlock) -> Result<()> {
    let conditions = block
        .conditions
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let scope = &block.scope;

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
    .bind(conditions)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap permission block {}", block.id))?;
    log_upsert(result.rows_affected(), "permission block", block.id);

    for action_name in &block.actions {
        let action_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
            .bind(action_name)
            .fetch_optional(pool)
            .await
            .with_context(|| format!("failed to resolve action {action_name}"))?
            .ok_or_else(|| {
                anyhow!(
                    "permission block {}: unknown action {action_name}",
                    block.id
                )
            })?;
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(block.id)
        .bind(action_id)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to attach action {action_name} to permission block {}",
                block.id
            )
        })?;
    }
    Ok(())
}

async fn ensure_role(pool: &PgPool, role: &BootstrapRole) -> Result<()> {
    let result = sqlx::query(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(role.id)
    .bind(&role.name)
    .bind(role.tenant_id)
    .bind(&role.description)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap role {}", role.id))?;
    log_upsert(result.rows_affected(), "role", role.id);

    for block_id in &role.permission_blocks {
        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(role.id)
        .bind(block_id)
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to link permission block {block_id} to role {}",
                role.id
            )
        })?;
    }
    Ok(())
}

async fn ensure_role_assignment(pool: &PgPool, assignment: &BootstrapRoleAssignment) -> Result<()> {
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
    .execute(pool)
    .await
    .with_context(|| {
        format!(
            "failed to insert bootstrap role assignment {}",
            assignment.id
        )
    })?;
    log_upsert(result.rows_affected(), "role assignment", assignment.id);
    Ok(())
}

async fn ensure_direct_policy(pool: &PgPool, policy: &BootstrapDirectPolicy) -> Result<()> {
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
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap direct policy {}", policy.id))?;
    log_upsert(result.rows_affected(), "direct policy", policy.id);
    Ok(())
}

async fn active_credential_exists(
    pool: &PgPool,
    entity_id: Uuid,
    kind: CredentialKind,
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active'",
    )
    .bind(entity_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .context("failed to check existing bootstrap credential")?;
    Ok(count > 0)
}

fn log_upsert(rows_affected: u64, label: &str, id: Uuid) {
    if rows_affected == 0 {
        tracing::info!(id = %id, "bootstrap: {label} already present, skipped");
    } else {
        tracing::info!(id = %id, "bootstrap: {label} created");
    }
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
    fn resource_requires_kind() {
        let yaml = r#"
resources:
  - id: 99999999-9999-9999-9999-999999999999
    kind: "  "
"#;
        let err = parse(yaml).expect_err("empty kind");
        assert!(err.to_string().contains("empty kind"));
    }
}
