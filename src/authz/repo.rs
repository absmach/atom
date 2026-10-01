//! Authorization domain operations and shared mutation orchestration.
//!
//! The focused repositories in `storage` select native PostgreSQL/SQLite SQL.
//! Validation, grant semantics, lock ordering, cache keys, and transaction/event
//! ownership remain here so both backends follow the same business rules.

mod storage;
use crate::db::DbExecutor;
use std::collections::{HashMap, HashSet};

use crate::db::Database;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    db::DbTransaction,
    error::{db_err, restore_conflict, AppError},
    models::{
        access::{
            AdminPageQuery, AuditLogItem, AuditLogResponse, AuthorizedObjectIdsQuery,
            AuthorizedObjectIdsResponse, ExpiringCredentialItem, ExpiringCredentialsQuery,
            ExpiringCredentialsResponse, OrphanPoliciesResponse, OrphanPolicyItem,
            SubjectRoleAssignment, SubjectRoleAssignmentList, SubjectRoleAssignmentsQuery,
        },
        action_assignment_rule::{
            ActionAssignmentRule, ActionAssignmentRuleList, CreateActionAssignmentRule,
            ListActionAssignmentRules,
        },
        alias::AliasObjectClass,
        api_endpoint::{ApiEndpoint, ApiEndpointList, ListApiEndpoints},
        capability::{
            Capability, CapabilityApplicability, CapabilityApplicabilityEntry,
            CapabilityApplicabilityInput, CapabilityApplicabilityList, CreateCapability,
            ListCapabilities,
        },
        enums::{
            ActionAssignmentDecision, CredentialKind, Effect, EntityKind, EntityOrderField,
            EntityStatus, GrantKind, GroupOrderField, ObjectKind, ResourceOrderField, ScopeKind,
            SortDir, SubjectKind, TenantStatus,
        },
        policy::{
            CreateDirectPolicy, CreatePermissionBlock, CreatePolicyBinding, CreateRoleAssignment,
            DirectPolicy, DirectPolicyList, ListDirectPolicies, ListPermissionBlocks,
            ListRoleAssignments, PermissionBlock, PermissionBlockList, PolicyBinding,
            RoleAssignment, RoleAssignmentList,
        },
        resource::Resource,
        role::{
            CreateRole, CreateRolePermissionBlock, ListRoles, Role, RoleDerivedKind, RoleList,
            RolePermissionBlock, UpdateRole,
        },
    },
};

/// Apply the canonical grant expansion to an already-filtered, ordered set of
/// flat protected-object candidates. Role, policy, and API-endpoint objects do
/// not participate in object groups, so their scope target carries empty group
/// arrays. Authorization is still performed before LIMIT/OFFSET and total is
/// the authorized total, not the raw candidate count.
#[allow(clippy::too_many_arguments)]
async fn authorize_flat_candidate_query(
    pool: &Database,
    subject_id: Uuid,
    ceiling_id: Option<Uuid>,
    object_kind: &str,
    actions: &[&str],
    filters: Value,
    candidate: FlatCandidate,
    limit: i64,
    offset: i64,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    storage::visibility::authorize_flat_candidate_query(
        pool,
        subject_id,
        ceiling_id,
        object_kind,
        actions,
        filters,
        candidate,
        limit,
        offset,
    )
    .await
}

pub async fn list_api_endpoints_authorized(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    params: ListApiEndpoints,
) -> Result<ApiEndpointList, AppError> {
    if params
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "draft" | "active" | "disabled"))
    {
        return Err(AppError::bad_request("unsupported api endpoint status"));
    }
    let authorized = authorize_flat_candidate_query(
        pool,
        auth.entity_id,
        auth.ceiling_credential_for(auth.entity_id),
        "api_endpoint",
        &["read", "manage"],
        serde_json::json!({"tenant_id": params.tenant_id, "status": params.status}),
        FlatCandidate::Endpoints,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        storage::visibility::selected_endpoints(pool, &authorized.ids)
            .await
            .map_err(db_err)?
    };
    Ok(ApiEndpointList {
        items,
        total: authorized.total,
    })
}

// ─── Resources ────────────────────────────────────────────────────────────────

// The resource repository — create/get/list/list_by_ids and the
// update/delete/restore/purge mutations — moved to `authz::resources` (the
// repository-per-domain pilot; see that module's doc comment).
// `fetch_resource` stays here — the object-group mutations below still read
// a resource from inside their own transaction through it.

/// Executor-generic resource fetch, so a mutation can read the row it just
/// wrote from inside its own transaction instead of re-reading it after the
/// commit.
async fn fetch_resource<'e, E>(executor: E, id: Uuid) -> Result<Resource, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    storage::objects::fetch_resource(executor, id).await
}

/// Canonical cleanup of the authorization rows that reference a set of
/// physically removed object UUIDs by bare value (no foreign key enforces these,
/// so a hard delete or FK cascade leaves them dangling):
///
/// - `permission_blocks.object_id` — object-scoped grants *on* any of the ids,
///   for every object kind (entity, resource, group, role, tenant, credential,
///   …). Deleting a block cascades to its actions, role links, and direct
///   policies.
/// - `direct_policies.subject_id` / `role_assignments.subject_id` — grants *to*
///   any of the ids as a subject (only entity/group ids ever match; harmless for
///   the rest). A direct policy / role assignment is itself a protected object
///   (`object_kind = 'policy'`, keyed by its row id), but the blocks targeting a
///   removed policy row are cleaned by a DB trigger (`purge_blocks_targeting_policy`
///   in the schema) that fires on any policy deletion — direct, bulk, or FK
///   cascade — so this helper does not sweep them, nor does any other call site.
///
/// Kind-agnostic by design: UUIDs are globally unique, so matching on the id set
/// alone is correct and lets every purge path — explicit per-object, explicit
/// tenant, and the background retention job — share one cleanup. Callers pass the
/// full set of doomed ids, including cascaded children (e.g. a purged entity's
/// credentials, a purged tenant's entities/groups/roles/resources).
pub(crate) async fn purge_authz_references_for_ids(
    tx: &mut DbTransaction<'_>,
    ids: &[Uuid],
) -> Result<(), AppError> {
    storage::blocks::purge_authz_references_for_ids(tx, ids).await
}

/// The UUIDs an alias path resolves to.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedAlias {
    pub tenant_id: Option<Uuid>,
    pub object_id: Uuid,
}

/// Resolve a human alias path to canonical UUIDs.
///
/// Two-level: first resolve the tenant (by id, or case-folded `alias`), then the
/// object (entity or resource) by its case-folded `alias` within that tenant.
/// Global objects are selected explicitly and resolve with no tenant UUID.
/// Resolution is capability-neutral — it reveals only the UUIDs; the actual
/// authorization gate is the subsequent `authz` check by UUID. Returns
/// `NotFound` if either level is missing.
pub async fn resolve_alias(
    pool: &Database,
    tenant_id: Option<Uuid>,
    tenant_alias: Option<&str>,
    global: bool,
    class: AliasObjectClass,
    object_alias: &str,
) -> Result<ResolvedAlias, AppError> {
    let tenant_alias = tenant_alias
        .map(str::trim)
        .filter(|alias| !alias.is_empty());
    let tenant_id = match (tenant_id, tenant_alias, global) {
        (Some(id), None, false) => {
            let id = storage::objects::active_tenant_optional(pool, &id)
                .await
                .map_err(db_err)?
                .ok_or_else(|| AppError::not_found(format!("active tenant {id} not found")))?;
            Some(id)
        }
        (None, Some(alias), false) => {
            let id = storage::objects::tenant_by_alias_optional(pool, alias)
                .await
                .map_err(db_err)?
                .ok_or_else(|| AppError::not_found(format!("tenant alias '{alias}' not found")))?;
            Some(id)
        }
        (None, None, true) => None,
        _ => {
            return Err(AppError::bad_request(
                "provide exactly one tenant selector: tenant_id, tenant_alias, or global",
            ))
        }
    };

    let object_alias = object_alias.trim().to_ascii_lowercase();
    if object_alias.is_empty() {
        return Err(AppError::bad_request("object_alias must not be empty"));
    }

    let object_id = storage::objects::alias_object_id(pool, tenant_id, class, &object_alias)
        .await?
        .ok_or_else(|| {
            let scope = tenant_id
                .map(|id| format!("tenant {id}"))
                .unwrap_or_else(|| "global scope".to_string());
            AppError::not_found(format!("alias '{object_alias}' not found in {scope}"))
        })?;

    Ok(ResolvedAlias {
        tenant_id,
        object_id,
    })
}

pub async fn get_resource_object_groups(
    pool: &Database,
    resource_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    storage::objects::get_resource_object_groups(pool, resource_id).await
}

pub async fn add_resource_to_object_group(
    pool: &Database,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    add_resource_to_object_group_with_audit(pool, false, None, resource_id, group_id).await
}

pub async fn add_resource_to_object_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let inserted = add_resource_to_object_group_in_tx(&mut tx, resource_id, group_id).await?;
    let resource = fetch_resource(&mut tx, resource_id).await?;
    if !inserted {
        tx.commit().await.map_err(db_err)?;
        return Ok(resource);
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: "resource",
        target_id: Some(resource_id),
        event: "resource.object_group.add",
    };
    let details = serde_json::json!({ "group_id": group_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(resource)
}

/// Remove the resource from **one** group, leaving its other memberships (and
/// the grants that flow through them) intact.
pub async fn remove_resource_from_object_group(
    pool: &Database,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    remove_resource_from_object_group_with_audit(pool, false, None, resource_id, group_id).await
}

pub async fn remove_resource_from_object_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let deleted = delete_resource_object_groups_in_tx(&mut tx, resource_id, Some(group_id)).await?;
    let resource = fetch_resource(&mut tx, resource_id).await?;
    if deleted == 0 {
        tx.commit().await.map_err(db_err)?;
        return Ok(resource);
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: "resource",
        target_id: Some(resource_id),
        event: "resource.object_group.remove",
    };
    let details = serde_json::json!({ "group_id": group_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(resource)
}

/// Remove the resource from **every** group it belongs to. Distinct from
/// [`remove_resource_from_object_group`] on purpose: with many-to-many
/// membership "clear the group" is ambiguous, so each caller states which it
/// means.
pub async fn clear_resource_object_groups(
    pool: &Database,
    resource_id: Uuid,
) -> Result<Resource, AppError> {
    clear_resource_object_groups_with_audit(pool, false, None, resource_id).await
}

pub async fn clear_resource_object_groups_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    resource_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let deleted = delete_resource_object_groups_in_tx(&mut tx, resource_id, None).await?;
    let resource = fetch_resource(&mut tx, resource_id).await?;
    if deleted == 0 {
        tx.commit().await.map_err(db_err)?;
        return Ok(resource);
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: "resource",
        target_id: Some(resource_id),
        event: "resource.object_groups.clear",
    };
    let details = serde_json::json!({});
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(resource)
}

pub(crate) async fn add_resource_to_object_group_in_tx(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<bool, AppError> {
    add_resource_to_object_group_in_tx_impl(tx, resource_id, group_id, true).await
}

/// Bootstrap-only replay of a declarative object-group resource membership.
/// Runtime callers use [`add_resource_to_object_group_in_tx`] and cannot
/// change a config-owned member set.
pub(crate) async fn add_config_resource_to_object_group_in_tx(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<bool, AppError> {
    add_resource_to_object_group_in_tx_impl(tx, resource_id, group_id, false).await
}

async fn add_resource_to_object_group_in_tx_impl(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    group_id: Uuid,
    enforce_api_ownership: bool,
) -> Result<bool, AppError> {
    let resource_tenant_id: Option<Option<Uuid>> =
        storage::objects::resource_tenant_optional(tx, &resource_id)
            .await
            .map_err(db_err)?;
    let Some(resource_tenant_id) = resource_tenant_id else {
        return Err(AppError::bad_request(
            "resource parent group reference is invalid",
        ));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, resource_tenant_id).await?;
    let row = storage::objects::resource_group_boundary_optional(
        tx,
        &resource_id,
        &group_id,
        &resource_tenant_id,
    )
    .await
    .map_err(db_err)?
    .ok_or_else(|| AppError::bad_request("resource parent group reference is invalid"))?;
    let resource_tenant_id: Option<Uuid> = row.resource_tenant_id;
    let group_tenant_id: Option<Uuid> = row.group_tenant_id;
    let Some(tenant_id) = resource_tenant_id else {
        return Err(AppError::bad_request(
            "platform resource cannot be placed in a group",
        ));
    };
    if group_tenant_id != Some(tenant_id) {
        return Err(AppError::bad_request(
            "resource and parent group must belong to the same tenant",
        ));
    }
    if enforce_api_ownership {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "object_groups", group_id).await?;
    }
    // Additive: membership is a set, so re-adding an existing membership is an
    // idempotent no-op rather than a silent move between groups.
    let result =
        storage::objects::insert_resource_membership(tx, &group_id, &resource_id, &tenant_id)
            .await
            .map_err(db_err)?;
    Ok(result > 0)
}

/// `group_id = Some(..)` removes one membership; `None` removes them all. The
/// two callers name which they mean, so neither can inherit the other's
/// behaviour by accident.
async fn delete_resource_object_groups_in_tx(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<u64, AppError> {
    let tenant_id: Option<Option<Uuid>> =
        storage::objects::resource_tenant_optional(tx, &resource_id)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "resource {resource_id} not found"
        )));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    let locked: Option<Uuid> =
        storage::objects::lock_resource_optional(tx, &resource_id, &tenant_id)
            .await
            .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!(
            "resource {resource_id} not found"
        )));
    }
    let mut affected_group_ids: Vec<Uuid> =
        storage::objects::resource_membership_groups(tx, &resource_id, &group_id)
            .await
            .map_err(db_err)?;
    affected_group_ids.dedup();
    // A clear-all is one atomic ownership decision: if any membership belongs
    // to a config-managed group, none of the API-managed memberships are
    // removed either.
    for affected_group_id in affected_group_ids {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "object_groups", affected_group_id)
            .await?;
    }
    let deleted = storage::objects::remove_resource_memberships(tx, &resource_id, &group_id)
        .await
        .map_err(db_err)?;
    Ok(deleted)
}

// ─── Roles ────────────────────────────────────────────────────────────────────

/// One fully-expanded effective grant for a subject: a single permission
/// block's scope/effect/conditions/action, reachable either directly (a direct
/// policy) or through a role the subject holds. Group membership is already
/// resolved (recursively) on the subject side, so every reader can evaluate a
/// flat list of grants without re-deriving "what does this subject have".
///
/// This is the single canonical grant representation consumed by the PDP and
/// (incrementally) the other authorization readers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveGrant {
    /// The assignment that confers this grant: the `direct_policies.id` or the
    /// `role_assignments.id` row. With shared blocks this is what identifies
    /// *which* assignment granted access, distinct from the block itself.
    pub assignment_id: Uuid,
    /// The permission block backing this grant (for `explain` provenance).
    pub block_id: Uuid,
    /// `None` for a direct policy; `Some(role_id)` when the grant is reached
    /// through a role assignment (kept for `explain` provenance).
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    /// How the subject reaches the grant: `"direct"` for an entity-targeted
    /// assignment, or `"group:<path>"` when reached through a principal group.
    pub via: String,
    /// Assignment-level tenant boundary (`direct_policies.tenant_id` /
    /// `role_assignments.tenant_id`). When `Some`, the grant applies only to
    /// objects owned by this tenant.
    pub tenant_boundary: Option<Uuid>,
    /// The permission block's own scope.
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub capability_id: Uuid,
    pub effect: Effect,
    pub conditions: Value,
}

/// The permission ceiling carried by a scoped access token. Each entry is an
/// allow-only `EffectiveGrant` shaped exactly like a permission-block grant, so
/// the existing PDP matcher (`match_grant`) and the coarse control-plane gate
/// (`gate_action_allows`) evaluate it with no parallel logic.
///
/// `scoped` records intent independently of `entries`: a scoped token whose limit
/// rows were deleted yields `entries = []` and must fail closed (deny everything),
/// never silently widen to the owner's full authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCeiling {
    pub entries: Vec<EffectiveGrant>,
}

/// Load the ceiling for a scoped access-token credential. Returns the (possibly
/// empty) set of allow grants the token is limited to.
pub async fn load_credential_ceiling(
    pool: &Database,
    credential_id: Uuid,
) -> Result<CredentialCeiling, AppError> {
    storage::visibility::load_credential_ceiling(pool, credential_id).await
}

pub async fn create_role_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateRole,
) -> Result<Role, AppError> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let role =
        storage::roles::insert_role(&mut tx, &id, &req.name, &req.tenant_id, &req.description)
            .await
            .map_err(db_err)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: role.tenant_id,
        target_kind: "role",
        target_id: Some(role.id),
        event: "role.create",
    };
    let details = serde_json::json!({});
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(role)
}

pub async fn create_role(pool: &Database, req: CreateRole) -> Result<Role, AppError> {
    create_role_with_audit(pool, false, None, req).await
}

pub async fn create_role_with_assignments(
    pool: &Database,
    req: CreateRole,
    capability_ids: &[Uuid],
    child_role_ids: &[Uuid],
    member_entity_ids: &[Uuid],
) -> Result<Role, AppError> {
    if !capability_ids.is_empty() && !child_role_ids.is_empty() {
        return Err(AppError::bad_request(
            "role cannot have both capabilities and child roles",
        ));
    }

    let id = Uuid::new_v4();
    let parsed_scope_kind = if req.tenant_id.is_some() {
        ScopeKind::Tenant
    } else {
        ScopeKind::Platform
    };
    let scope_ref = req.tenant_id.map(|tenant_id| tenant_id.to_string());
    validate_role_scope(
        pool,
        req.tenant_id,
        &parsed_scope_kind,
        scope_ref.as_deref(),
    )
    .await?;
    validate_capabilities_against_role_scope(
        pool,
        &parsed_scope_kind,
        scope_ref.as_deref(),
        capability_ids,
    )
    .await?;

    ensure_entities_exist(pool, member_entity_ids).await?;
    if child_role_ids.is_empty() {
        let mut conn = pool.acquire().await.map_err(db_err)?;
        crate::guardrails::validate_role_assignment_plan(
            &mut conn,
            member_entity_ids,
            capability_ids,
            req.tenant_id,
            parsed_scope_kind.clone(),
            scope_ref.as_deref(),
        )
        .await?;
    } else {
        validate_composite_children(pool, id, req.tenant_id, child_role_ids).await?;
        let mut conn = pool.acquire().await.map_err(db_err)?;
        crate::guardrails::validate_composite_role_assignment_plan(
            &mut conn,
            member_entity_ids,
            child_role_ids,
            req.tenant_id,
        )
        .await?;
    }

    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let mut locked_member_ids = member_entity_ids.to_vec();
    locked_member_ids.sort_unstable();
    locked_member_ids.dedup();
    for member_id in locked_member_ids {
        lock_live_subject(&mut tx, req.tenant_id, &SubjectKind::Entity, member_id).await?;
    }
    let role =
        storage::roles::insert_role(&mut tx, &id, &req.name, &req.tenant_id, &req.description)
            .await
            .map_err(db_err)?;

    for capability_id in capability_ids {
        insert_role_capability_as_permission_block(
            &mut tx,
            role.id,
            req.tenant_id,
            &parsed_scope_kind,
            scope_ref.as_deref(),
            *capability_id,
        )
        .await?;
    }

    let mut locked_child_role_ids = child_role_ids.to_vec();
    locked_child_role_ids.sort_unstable();
    locked_child_role_ids.dedup();
    for child_role_id in locked_child_role_ids {
        lock_role(&mut tx, child_role_id).await?;
    }
    for child_role_id in child_role_ids {
        copy_role_permission_blocks(&mut tx, role.id, *child_role_id).await?;
    }

    for member_id in member_entity_ids {
        storage::assignments::insert_entity_role_assignment(
            &mut tx,
            &req.tenant_id,
            member_id,
            &role.id,
        )
        .await
        .map_err(db_err)?;

        if let Some(tenant_id) = req.tenant_id {
            storage::objects::activate_human_membership(&mut tx, &tenant_id, member_id)
                .await
                .map_err(db_err)?;
        }
    }

    tx.commit().await.map_err(db_err)?;
    Ok(role)
}

pub async fn create_role_with_permission_blocks(
    pool: &Database,
    req: CreateRole,
    permission_blocks: &[CreateRolePermissionBlock],
    member_entity_ids: &[Uuid],
) -> Result<Role, AppError> {
    let id = Uuid::new_v4();
    if permission_blocks.is_empty() {
        return Err(AppError::bad_request("role permission blocks are required"));
    }
    validate_role_permission_blocks(pool, permission_blocks).await?;
    ensure_entities_exist(pool, member_entity_ids).await?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let mut locked_member_ids = member_entity_ids.to_vec();
    locked_member_ids.sort_unstable();
    locked_member_ids.dedup();
    for member_id in locked_member_ids {
        lock_live_subject(&mut tx, req.tenant_id, &SubjectKind::Entity, member_id).await?;
    }
    let role =
        storage::roles::insert_role(&mut tx, &id, &req.name, &req.tenant_id, &req.description)
            .await
            .map_err(db_err)?;

    for block in permission_blocks {
        insert_role_permission_block(&mut tx, role.id, block).await?;
    }

    for member_id in member_entity_ids {
        storage::assignments::insert_entity_role_assignment(
            &mut tx,
            &req.tenant_id,
            member_id,
            &role.id,
        )
        .await
        .map_err(db_err)?;

        if let Some(tenant_id) = req.tenant_id {
            storage::objects::activate_human_membership(&mut tx, &tenant_id, member_id)
                .await
                .map_err(db_err)?;
        }
    }

    tx.commit().await.map_err(db_err)?;
    Ok(role)
}

/// Serialize role-link mutations by taking a row lock on the role. Every path
/// that adds or removes `role_permission_blocks` rows for a role must hold this
/// first, so two such mutations on the same role cannot interleave (e.g. one
/// inserting a link after another has deleted the existing set). An FK insert
/// into role_permission_blocks takes a FOR KEY SHARE lock on the role row, which
/// conflicts with this FOR UPDATE. Returns not-found if the role is absent.
pub(crate) async fn lock_role(tx: &mut DbTransaction<'_>, role_id: Uuid) -> Result<(), AppError> {
    let tenant_id = read_live_role_tenant_id(tx, role_id).await?;
    lock_active_tenant_ids(tx, [tenant_id]).await?;
    lock_live_role_row(tx, role_id, tenant_id).await
}

async fn read_live_role_tenant_id(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    storage::roles::read_live_role_tenant_id(tx, role_id).await
}

async fn lock_live_role_row(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    storage::roles::lock_live_role_row(tx, role_id, expected_tenant_id).await
}

pub async fn replace_role_permission_block_links(
    pool: &Database,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<(), AppError> {
    replace_role_permission_block_links_with_audit(pool, false, None, role_id, permission_block_ids)
        .await
}

pub async fn replace_role_permission_block_links_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = replace_role_permission_block_links_in_tx(
        &mut tx,
        events_enabled,
        actor_id,
        role_id,
        permission_block_ids,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;
    // `_in_tx` already enqueued the outbox row via `observe_in_tx` before
    // returning — this is the post-commit stdout observability log
    // `commit_with_observation` would otherwise provide.
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "role",
            target_id: Some(role_id),
            event: "role.permission_blocks.replace",
        },
        &serde_json::json!({ "permission_block_ids": permission_block_ids }),
    );
    Ok(())
}

/// Body of [`replace_role_permission_block_links`]; caller contract per
/// [`create_role_assignment_in_tx`]. The resolver must already hold the role
/// lock via [`lock_role_and_collect_grants_keys`] on this `tx` — `lock_role`
/// below just re-acquires it (same-transaction no-op).
///
/// Every read runs on `tx`, never on a pooled connection: the validation
/// below is only meaningful under the role lock this transaction holds, and a
/// second connection acquired mid-transaction is a pool-exhaustion deadlock
/// under concurrency.
/// Returns the role's `tenant_id`, captured here rather than left for the
/// caller to re-derive post-commit — cheaper than an extra query, and safe
/// for any future case where the role itself stops existing by the time the
/// caller wants to log.
pub(crate) async fn replace_role_permission_block_links_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<Option<Uuid>, AppError> {
    let role_tenant_id: Option<Uuid> = storage::roles::live_role_tenant_optional(tx, &role_id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::not_found(format!("role {role_id} not found")))?;

    let mut unique_block_ids = permission_block_ids.to_vec();
    unique_block_ids.sort_unstable();
    unique_block_ids.dedup();

    if !unique_block_ids.is_empty() {
        let count: i64 =
            storage::blocks::count_tenant_blocks(tx, &unique_block_ids, &role_tenant_id)
                .await
                .map_err(db_err)?;
        if count != unique_block_ids.len() as i64 {
            return Err(AppError::bad_request(
                "role permission blocks must exist and belong to the same tenant as the role",
            ));
        }
    }
    lock_role(tx, role_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", role_id).await?;
    // Validate under the role lock so a concurrent role assignment cannot commit
    // a prohibited combination against stale state: any other role-link or
    // assignment mutator blocks on this lock and re-validates against our result.
    // Runs on this transaction's own connection — borrowing a second one from
    // the pool here would deadlock a saturated pool.
    crate::guardrails::validate_role_permission_block_links(tx, role_id, &unique_block_ids).await?;
    storage::roles::remove_role_links(tx, &role_id)
        .await
        .map_err(db_err)?;

    for permission_block_id in &unique_block_ids {
        storage::blocks::link_role_block(tx, &role_id, permission_block_id)
            .await
            .map_err(db_err)?;
    }

    crate::audit::observe_in_tx(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: role_tenant_id,
            target_kind: "role",
            target_id: Some(role_id),
            event: "role.permission_blocks.replace",
        },
        &serde_json::json!({ "permission_block_ids": unique_block_ids }),
    )
    .await?;
    Ok(role_tenant_id)
}

async fn insert_role_permission_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    block: &CreateRolePermissionBlock,
) -> Result<Uuid, AppError> {
    let (scope_mode, tenant_id, object_kind, object_type, object_id, group_id) =
        permission_block_scope_columns(block);
    let block_id: Uuid = storage::blocks::insert_allow_block(
        tx,
        scope_mode,
        &tenant_id,
        &object_kind,
        &object_type,
        &object_id,
        &group_id,
    )
    .await
    .map_err(db_err)?;

    for capability_id in &block.capability_ids {
        storage::blocks::link_block_action(tx, &block_id, capability_id)
            .await
            .map_err(db_err)?;
    }

    storage::blocks::link_role_block(tx, &role_id, &block_id)
        .await
        .map_err(db_err)?;

    Ok(block_id)
}

/// Permission blocks are shared: one block can be linked to several roles and to
/// direct policies. Delete only those among `block_ids` that, after the caller
/// has removed its own links, are no longer referenced by any role or direct
/// policy — so a block still in use elsewhere is never destroyed. This is the
/// garbage-collection half of the shared-immutable ownership model.
async fn delete_orphaned_blocks(
    tx: &mut DbTransaction<'_>,
    block_ids: &[Uuid],
) -> Result<(), AppError> {
    storage::blocks::delete_orphaned_blocks(tx, block_ids).await
}

/// Detach `block_ids` from `role_id`, then garbage-collect any that are now
/// orphaned. Replaces the previous `DELETE FROM permission_blocks` by role, which
/// cascaded through `role_permission_blocks`/`direct_policies` and so silently
/// removed blocks still linked to *other* roles.
async fn unlink_role_blocks_and_gc(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    block_ids: &[Uuid],
) -> Result<(), AppError> {
    if block_ids.is_empty() {
        return Ok(());
    }
    storage::blocks::unlink_role_blocks(tx, &role_id, block_ids)
        .await
        .map_err(db_err)?;
    delete_orphaned_blocks(tx, block_ids).await
}

/// Block ids currently linked to `role_id`.
async fn role_block_ids(tx: &mut DbTransaction<'_>, role_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    storage::blocks::role_block_ids(tx, role_id).await
}

type PermissionBlockScopeColumns<'a> = (
    &'a str,
    Option<Uuid>,
    Option<&'a str>,
    Option<&'a str>,
    Option<Uuid>,
    Option<Uuid>,
);

fn permission_block_scope_columns(
    block: &CreateRolePermissionBlock,
) -> PermissionBlockScopeColumns<'_> {
    match block.applies_to.as_str() {
        "platform" => ("platform", None, None, None, None, None),
        "tenant" => ("tenant", block.tenant_id, None, None, None, None),
        "object" => (
            "object",
            block.tenant_id,
            block.object_kind.as_deref(),
            block.object_type.as_deref(),
            block.object_id,
            None,
        ),
        "object_kind" => (
            "object_kind",
            block.tenant_id,
            block.object_kind.as_deref(),
            None,
            None,
            None,
        ),
        "object_type" => (
            "object_type",
            block.tenant_id,
            block.object_kind.as_deref(),
            block.object_type.as_deref(),
            None,
            None,
        ),
        "object_group_type" => (
            "group_direct_objects",
            block.tenant_id,
            block.object_kind.as_deref(),
            block.object_type.as_deref(),
            None,
            block.group_id,
        ),
        "object_group_tree_type" => (
            "group_descendant_objects",
            block.tenant_id,
            block.object_kind.as_deref(),
            block.object_type.as_deref(),
            None,
            block.group_id,
        ),
        "object_group_child_kind" => (
            "group_child_groups",
            block.tenant_id,
            None,
            None,
            None,
            block.group_id,
        ),
        "object_group_descendant_kind" => (
            "group_descendant_groups",
            block.tenant_id,
            None,
            None,
            None,
            block.group_id,
        ),
        _ => ("platform", None, None, None, None, None),
    }
}

async fn insert_role_capability_as_permission_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    tenant_id: Option<Uuid>,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
    capability_id: Uuid,
) -> Result<Uuid, AppError> {
    let block = permission_block_from_legacy_scope(tenant_id, scope_kind, scope_ref)?;
    let block_id: Uuid = storage::blocks::insert_legacy_allow_block(
        tx,
        block.scope_mode,
        &block.tenant_id,
        &block.object_kind,
        &block.object_type,
        &block.object_id,
        &block.group_id,
    )
    .await
    .map_err(db_err)?;
    storage::blocks::insert_block_action(tx, &block_id, &capability_id)
        .await
        .map_err(db_err)?;
    storage::blocks::insert_role_block(tx, &role_id, &block_id)
        .await
        .map_err(db_err)?;
    Ok(block_id)
}

async fn copy_role_permission_blocks(
    tx: &mut DbTransaction<'_>,
    target_role_id: Uuid,
    source_role_id: Uuid,
) -> Result<(), AppError> {
    storage::blocks::copy_role_permission_blocks(tx, target_role_id, source_role_id).await
}

struct PermissionBlockInsert {
    scope_mode: &'static str,
    tenant_id: Option<Uuid>,
    object_kind: Option<String>,
    object_type: Option<String>,
    object_id: Option<Uuid>,
    group_id: Option<Uuid>,
}

fn permission_block_from_legacy_scope(
    tenant_id: Option<Uuid>,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
) -> Result<PermissionBlockInsert, AppError> {
    let parse_group_id = |raw: Option<&str>| -> Result<Uuid, AppError> {
        raw.and_then(|value| value.split_once(':').map(|(id, _)| id).or(Some(value)))
            .ok_or_else(|| AppError::bad_request("group scope requires scope_ref"))?
            .parse::<Uuid>()
            .map_err(|_| AppError::bad_request("group scope_ref has invalid group UUID"))
    };

    match scope_kind {
        ScopeKind::Platform => Ok(PermissionBlockInsert {
            scope_mode: "platform",
            tenant_id: None,
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
        }),
        ScopeKind::Tenant => Ok(PermissionBlockInsert {
            scope_mode: "tenant",
            tenant_id,
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
        }),
        ScopeKind::ObjectKind => Ok(PermissionBlockInsert {
            scope_mode: "object_kind",
            tenant_id,
            object_kind: scope_ref.map(ToOwned::to_owned),
            object_type: None,
            object_id: None,
            group_id: None,
        }),
        ScopeKind::ObjectType => {
            let raw = scope_ref
                .ok_or_else(|| AppError::bad_request("object_type scope requires scope_ref"))?;
            let (object_kind, _) = raw
                .split_once(':')
                .ok_or_else(|| AppError::bad_request("object_type scope_ref must be namespaced"))?;
            Ok(PermissionBlockInsert {
                scope_mode: "object_type",
                tenant_id,
                object_kind: Some(object_kind.to_string()),
                object_type: Some(raw.to_string()),
                object_id: None,
                group_id: None,
            })
        }
        ScopeKind::Object => Ok(PermissionBlockInsert {
            scope_mode: "object",
            tenant_id,
            object_kind: None,
            object_type: None,
            object_id: scope_ref.and_then(|raw| raw.parse::<Uuid>().ok()),
            group_id: None,
        }),
        ScopeKind::GroupObjectType | ScopeKind::GroupTreeObjectType => {
            let raw = scope_ref
                .ok_or_else(|| AppError::bad_request("group object scope requires scope_ref"))?;
            let (group_id, object_type) = raw.split_once(':').ok_or_else(|| {
                AppError::bad_request("group object scope_ref must include object type")
            })?;
            let (object_kind, _) = object_type.split_once(':').ok_or_else(|| {
                AppError::bad_request("group object scope_ref object type must be namespaced")
            })?;
            Ok(PermissionBlockInsert {
                scope_mode: if matches!(scope_kind, ScopeKind::GroupObjectType) {
                    "group_direct_objects"
                } else {
                    "group_descendant_objects"
                },
                tenant_id,
                object_kind: Some(object_kind.to_string()),
                object_type: Some(object_type.to_string()),
                object_id: None,
                group_id: Some(group_id.parse::<Uuid>().map_err(|_| {
                    AppError::bad_request("group scope_ref has invalid group UUID")
                })?),
            })
        }
        ScopeKind::GroupChildKind | ScopeKind::GroupDescendantKind => Ok(PermissionBlockInsert {
            scope_mode: if matches!(scope_kind, ScopeKind::GroupChildKind) {
                "group_child_groups"
            } else {
                "group_descendant_groups"
            },
            tenant_id,
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: Some(parse_group_id(scope_ref)?),
        }),
    }
}

async fn validate_role_permission_blocks(
    pool: &Database,
    blocks: &[CreateRolePermissionBlock],
) -> Result<(), AppError> {
    for block in blocks {
        validate_permission_block_shape(block)?;
        let target = permission_block_target(pool, block).await?;
        validate_capabilities_against_target(pool, &block.capability_ids, target).await?;
    }
    Ok(())
}

fn validate_permission_block_shape(block: &CreateRolePermissionBlock) -> Result<(), AppError> {
    if block.capability_ids.is_empty() {
        return Err(AppError::bad_request(
            "permission block requires at least one capability",
        ));
    }
    match block.applies_to.as_str() {
        "platform" => Ok(()),
        "tenant" => block
            .tenant_id
            .map(|_| ())
            .ok_or_else(|| AppError::bad_request("tenant permission block requires tenantId")),
        "object" => block
            .object_id
            .map(|_| ())
            .ok_or_else(|| AppError::bad_request("object permission block requires objectId")),
        "object_kind" => block.object_kind.as_ref().map(|_| ()).ok_or_else(|| {
            AppError::bad_request("object_kind permission block requires objectKind")
        }),
        "object_type" => match (&block.object_kind, &block.object_type) {
            (Some(_), Some(_)) => Ok(()),
            _ => Err(AppError::bad_request(
                "object_type permission block requires objectKind and objectType",
            )),
        },
        "object_group_type" | "object_group_tree_type" => {
            match (block.group_id, &block.object_kind, &block.object_type) {
                (Some(_), Some(_), Some(_)) => Ok(()),
                _ => Err(AppError::bad_request(
                    "object group permission block requires groupId, objectKind, and objectType",
                )),
            }
        }
        "object_group_child_kind" | "object_group_descendant_kind" => {
            match (block.group_id, block.object_kind.as_deref()) {
                (Some(_), Some("group")) => Ok(()),
                _ => Err(AppError::bad_request(
                    "object group child permission block requires groupId and objectKind=group",
                )),
            }
        }
        other => Err(AppError::bad_request(format!(
            "unsupported permission block appliesTo '{other}'"
        ))),
    }
}

async fn permission_block_target(
    pool: &Database,
    block: &CreateRolePermissionBlock,
) -> Result<Option<CapabilityValidationTarget>, AppError> {
    match block.applies_to.as_str() {
        "tenant" | "platform" => Ok(None),
        "object" => match block.object_id {
            Some(object_id) => resolve_exact_object_target(pool, object_id)
                .await?
                .map(Some)
                .ok_or_else(|| {
                    AppError::bad_request("object permission block references unknown object")
                }),
            None => Err(AppError::bad_request(
                "object permission block requires objectId",
            )),
        },
        "object_kind" => {
            Ok(block
                .object_kind
                .as_ref()
                .map(|object_kind| CapabilityValidationTarget {
                    object_kind: object_kind.clone(),
                    object_type: None,
                }))
        }
        "object_type" | "object_group_type" | "object_group_tree_type" => Ok(block
            .object_kind
            .as_ref()
            .map(|object_kind| CapabilityValidationTarget {
                object_kind: object_kind.clone(),
                object_type: block.object_type.clone(),
            })),
        "object_group_child_kind" | "object_group_descendant_kind" => {
            Ok(Some(CapabilityValidationTarget {
                object_kind: "group".to_string(),
                object_type: None,
            }))
        }
        _ => Ok(None),
    }
}

pub async fn list_role_permission_blocks(
    pool: &Database,
    role_id: Uuid,
) -> Result<Vec<RolePermissionBlock>, AppError> {
    storage::blocks::list_role_permission_blocks(pool, role_id).await
}

pub async fn list_permission_blocks_for_role(
    pool: &Database,
    role_id: Uuid,
) -> Result<Vec<PermissionBlock>, AppError> {
    storage::blocks::list_permission_blocks_for_role(pool, role_id).await
}

pub async fn role_permission_block_capabilities(
    pool: &Database,
    block_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    storage::blocks::role_permission_block_capabilities(pool, block_id).await
}

pub async fn permission_block_capabilities(
    pool: &Database,
    block_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    role_permission_block_capabilities(pool, block_id).await
}

pub async fn get_permission_block(pool: &Database, id: Uuid) -> Result<PermissionBlock, AppError> {
    fetch_permission_block(pool, id).await
}

/// Executor-generic `get_permission_block`, so a mutation can read the row it
/// just wrote from inside its own transaction instead of after the commit.
async fn fetch_permission_block<'e, E>(executor: E, id: Uuid) -> Result<PermissionBlock, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    storage::blocks::fetch_permission_block(executor, id).await
}

pub async fn list_permission_blocks(
    pool: &Database,
    params: ListPermissionBlocks,
) -> Result<PermissionBlockList, AppError> {
    storage::blocks::list_permission_blocks(pool, params).await
}

/// Normalize and validate ABAC conditions for storage. `null` becomes `{}`;
/// any non-object value is rejected so the PDP never has to fail closed on
/// malformed policy at decision time (and matches the DB CHECK constraint).
fn normalize_conditions(conditions: Value) -> Result<Value, AppError> {
    if conditions.is_null() {
        return Ok(serde_json::json!({}));
    }
    if conditions.is_object() {
        return Ok(conditions);
    }
    Err(AppError::bad_request("conditions must be a JSON object"))
}

pub async fn create_permission_block(
    pool: &Database,
    req: CreatePermissionBlock,
) -> Result<PermissionBlock, AppError> {
    create_permission_block_with_audit(pool, false, None, req).await
}

pub async fn create_permission_block_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreatePermissionBlock,
) -> Result<PermissionBlock, AppError> {
    validate_permission_block_input(pool, &req).await?;
    let conditions = normalize_conditions(req.conditions)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let id: Uuid = storage::blocks::insert_permission_block(
        &mut tx,
        &req.tenant_id,
        &req.scope_mode,
        &req.object_kind.as_deref(),
        &req.object_type.as_deref(),
        &req.object_id,
        &req.group_id,
        &req.effect,
        &conditions,
    )
    .await
    .map_err(db_err)?;

    for action_id in req.action_ids {
        storage::blocks::link_block_action(&mut tx, &id, &action_id)
            .await
            .map_err(db_err)?;
    }
    let block = fetch_permission_block(&mut tx, id).await?;
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: req.tenant_id,
            target_kind: "permission_block",
            target_id: Some(id),
            event: "permission_block.create",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(block)
}

pub async fn delete_permission_block(pool: &Database, id: Uuid) -> Result<(), AppError> {
    delete_permission_block_with_audit(pool, false, None, id).await
}

pub async fn delete_permission_block_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<(), AppError> {
    // Blocks are shared: refuse to delete one still linked to a role or attached
    // to a direct policy, so an explicit delete cannot cascade live links away.
    //
    // The link FKs stay ON DELETE CASCADE (so tenant-wide cascade deletes still
    // complete — roles survive tenant deletion via SET NULL, and their link rows
    // are cleaned only by the block's cascade). To close the check-then-delete
    // race without RESTRICT, lock the block row FOR UPDATE first: an FK insert
    // into role_permission_blocks / direct_policies takes a FOR KEY SHARE lock on
    // the referenced block row, which conflicts with FOR UPDATE, so no link can
    // slip in between the reference check and the delete.
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id: Option<Option<Uuid>> = storage::blocks::block_tenant_optional(&mut tx, &id)
        .await
        .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "permission block {id} not found"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "permission_blocks", id).await?;
    let referenced: bool = storage::blocks::block_is_referenced(&mut tx, &id)
        .await
        .map_err(db_err)?;
    if referenced {
        return Err(AppError::bad_request(
            "permission block is still linked to a role or direct policy; unlink it first",
        ));
    }
    storage::blocks::remove_block(&mut tx, &id)
        .await
        .map_err(db_err)?;
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "permission_block",
            target_id: Some(id),
            event: "permission_block.delete",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(())
}

pub(crate) async fn validate_permission_block_input(
    pool: &Database,
    req: &CreatePermissionBlock,
) -> Result<(), AppError> {
    let mut connection = pool.acquire().await.map_err(db_err)?;
    validate_permission_block_input_on_connection(&mut connection, req).await
}

pub(crate) async fn validate_permission_block_input_on_connection(
    connection: &mut impl DbExecutor,
    req: &CreatePermissionBlock,
) -> Result<(), AppError> {
    if req.action_ids.is_empty() {
        return Err(AppError::bad_request(
            "permission block requires at least one action",
        ));
    }
    let target = permission_block_input_target_on_connection(connection, req).await?;
    validate_capabilities_against_target_on_connection(connection, &req.action_ids, target).await
}

async fn permission_block_input_target_on_connection(
    connection: &mut impl DbExecutor,
    req: &CreatePermissionBlock,
) -> Result<Option<CapabilityValidationTarget>, AppError> {
    match req.scope_mode.as_str() {
        "platform" => {
            if req.tenant_id.is_some()
                || req.object_kind.is_some()
                || req.object_type.is_some()
                || req.object_id.is_some()
                || req.group_id.is_some()
            {
                return Err(AppError::bad_request(
                    "platform permission block cannot include tenant or object fields",
                ));
            }
            Ok(None)
        }
        "tenant" => req
            .tenant_id
            .map(|_| None)
            .ok_or_else(|| AppError::bad_request("tenant permission block requires tenantId")),
        "object_kind" => {
            let object_kind = req.object_kind.clone().ok_or_else(|| {
                AppError::bad_request("object_kind permission block requires objectKind")
            })?;
            Ok(Some(CapabilityValidationTarget {
                object_kind,
                object_type: None,
            }))
        }
        "object_type" => match (&req.object_kind, &req.object_type) {
            (Some(object_kind), Some(object_type)) => Ok(Some(CapabilityValidationTarget {
                object_kind: object_kind.clone(),
                object_type: Some(object_type.clone()),
            })),
            _ => Err(AppError::bad_request(
                "object_type permission block requires objectKind and objectType",
            )),
        },
        "object" => {
            let object_id = req.object_id.ok_or_else(|| {
                AppError::bad_request("object permission block requires objectId")
            })?;
            resolve_exact_object_target_on_connection(connection, object_id)
                .await?
                .map(Some)
                .ok_or_else(|| {
                    AppError::bad_request("object permission block references unknown object")
                })
        }
        "group" => {
            validate_object_group_boundary(connection, req.tenant_id, req.group_id).await?;
            Ok(Some(CapabilityValidationTarget {
                object_kind: "group".to_string(),
                object_type: None,
            }))
        }
        "group_direct_objects" | "group_descendant_objects" => {
            validate_object_group_boundary(connection, req.tenant_id, req.group_id).await?;
            match (&req.object_kind, &req.object_type) {
                (Some(object_kind), Some(object_type)) => Ok(Some(CapabilityValidationTarget {
                    object_kind: object_kind.clone(),
                    object_type: Some(object_type.clone()),
                })),
                _ => Err(AppError::bad_request(
                    "object group object permission block requires objectKind and objectType",
                )),
            }
        }
        "group_child_groups" | "group_descendant_groups" => {
            validate_object_group_boundary(connection, req.tenant_id, req.group_id).await?;
            Ok(Some(CapabilityValidationTarget {
                object_kind: "group".to_string(),
                object_type: None,
            }))
        }
        other => Err(AppError::bad_request(format!(
            "unsupported permission block scopeMode '{other}'"
        ))),
    }
}

async fn validate_object_group_boundary(
    connection: &mut impl DbExecutor,
    tenant_id: Option<Uuid>,
    group_id: Option<Uuid>,
) -> Result<(), AppError> {
    let group_id =
        group_id.ok_or_else(|| AppError::bad_request("object group scope requires groupId"))?;
    let group_tenant_id: Option<Uuid> =
        storage::objects::object_group_tenant_optional(connection, &group_id)
            .await
            .map_err(db_err)?
            .ok_or_else(|| AppError::bad_request("object group scope references unknown group"))?;
    if tenant_id.is_some() && group_tenant_id != tenant_id {
        return Err(AppError::bad_request(
            "object group scope must reference a group in the same tenant",
        ));
    }
    Ok(())
}

pub async fn get_role(pool: &Database, id: Uuid) -> Result<Role, AppError> {
    storage::roles::get_role(pool, id).await
}

pub async fn list_roles(pool: &Database, mut params: ListRoles) -> Result<RoleList, AppError> {
    params.q = search_pattern(params.q);
    params.derived_kind = normalize_derived_kind(params.derived_kind)?;
    storage::roles::list_roles(pool, params).await
}

pub async fn list_roles_authorized(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    params: ListRoles,
) -> Result<RoleList, AppError> {
    let q = search_pattern(params.q);
    let derived_kind = params
        .derived_kind
        .as_deref()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .map(str::to_ascii_lowercase);
    if derived_kind
        .as_deref()
        .is_some_and(|kind| !matches!(kind, "simple" | "composite" | "empty"))
    {
        return Err(AppError::bad_request(
            "derivedKind must be simple, composite, or empty",
        ));
    }

    let authorized = authorize_flat_candidate_query(
        pool,
        auth.entity_id,
        auth.ceiling_credential_for(auth.entity_id),
        "role",
        &["read", "role.manage"],
        serde_json::json!({
            "tenant_id": params.tenant_id,
            "q": q,
            "derived_kind": derived_kind,
            "deleted": params.deleted.as_str(),
        }),
        FlatCandidate::Roles,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        storage::visibility::selected_roles(pool, &authorized.ids)
            .await
            .map_err(db_err)?
    };
    Ok(RoleList {
        items,
        total: authorized.total,
    })
}

pub async fn role_derived_kind(
    pool: &Database,
    role_id: Uuid,
) -> Result<RoleDerivedKind, AppError> {
    storage::roles::role_derived_kind(pool, role_id).await
}

async fn ensure_entities_exist(pool: &Database, entity_ids: &[Uuid]) -> Result<(), AppError> {
    if entity_ids.is_empty() {
        return Ok(());
    }
    let mut unique_entity_ids = entity_ids.to_vec();
    unique_entity_ids.sort_unstable();
    unique_entity_ids.dedup();
    let count: i64 = storage::objects::count_entities(pool, &unique_entity_ids)
        .await
        .map_err(db_err)?;
    if count != unique_entity_ids.len() as i64 {
        return Err(AppError::bad_request("invalid member reference"));
    }
    Ok(())
}

async fn validate_composite_children(
    pool: &Database,
    parent_role_id: Uuid,
    parent_tenant_id: Option<Uuid>,
    child_role_ids: &[Uuid],
) -> Result<(), AppError> {
    if child_role_ids.is_empty() {
        return Ok(());
    }
    let mut unique_child_ids = child_role_ids.to_vec();
    unique_child_ids.sort_unstable();
    unique_child_ids.dedup();
    if unique_child_ids.contains(&parent_role_id) {
        return Err(AppError::bad_request("role cannot include itself"));
    }

    let rows = storage::roles::composite_role_candidates(pool, &unique_child_ids)
        .await
        .map_err(db_err)?;

    if rows.len() != unique_child_ids.len() {
        return Err(AppError::bad_request("invalid child role reference"));
    }

    for row in rows {
        let child_id: Uuid = row.id;
        let tenant_id: Option<Uuid> = row.tenant_id;
        let has_capabilities: bool = row.has_capabilities;
        let has_children: bool = row.has_children;
        if tenant_id != parent_tenant_id {
            return Err(AppError::bad_request(
                "parent and child roles must belong to the same tenant",
            ));
        }
        if has_children {
            return Err(AppError::bad_request(
                "nested composite roles are not supported",
            ));
        }
        if !has_capabilities {
            return Err(AppError::bad_request(
                "composite child role must have capabilities",
            ));
        }
        if child_id == parent_role_id {
            return Err(AppError::bad_request("role cannot include itself"));
        }
    }

    Ok(())
}

fn parse_scope_kind_text(value: &str) -> Result<ScopeKind, AppError> {
    serde_json::from_value(serde_json::Value::String(value.to_string())).map_err(|_| {
        AppError::bad_request(format!(
            "invalid scope_kind '{value}' (expected one of platform, tenant, object_kind, object_type, object, group_object_type, group_tree_object_type, group_child_kind, group_descendant_kind)"
        ))
    })
}

async fn validate_role_scope(
    pool: &Database,
    tenant_id: Option<Uuid>,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
) -> Result<(), AppError> {
    match scope_kind {
        ScopeKind::Platform => Ok(()),
        ScopeKind::Tenant => {
            let Some(scope_ref) = scope_ref else {
                return Err(AppError::bad_request("tenant scope requires scope_ref"));
            };
            scope_ref
                .parse::<Uuid>()
                .map(|_| ())
                .map_err(|_| AppError::bad_request("tenant scope_ref must be a UUID"))
        }
        ScopeKind::ObjectKind => {
            if scope_ref.is_some() {
                Ok(())
            } else {
                Err(AppError::bad_request(
                    "object_kind scope requires scope_ref",
                ))
            }
        }
        ScopeKind::ObjectType => match scope_ref {
            Some(scope_ref) if scope_ref.split_once(':').is_some() => Ok(()),
            Some(_) => Err(AppError::bad_request(
                "object_type scope_ref must be namespaced as '<kind>:<sub-kind>'",
            )),
            None => Err(AppError::bad_request(
                "object_type scope requires scope_ref",
            )),
        },
        ScopeKind::Object => {
            let Some(scope_ref) = scope_ref else {
                return Err(AppError::bad_request("object scope requires scope_ref"));
            };
            scope_ref
                .parse::<Uuid>()
                .map(|_| ())
                .map_err(|_| AppError::bad_request("object scope_ref must be a UUID"))
        }
        ScopeKind::GroupObjectType
        | ScopeKind::GroupTreeObjectType
        | ScopeKind::GroupChildKind
        | ScopeKind::GroupDescendantKind => {
            let (group_id, rest) = parse_group_scope_ref(scope_ref)?;
            match scope_kind {
                ScopeKind::GroupObjectType | ScopeKind::GroupTreeObjectType => {
                    if rest.split_once(':').is_none() {
                        return Err(AppError::bad_request(
                            "group object scope_ref must include namespaced object type",
                        ));
                    }
                }
                ScopeKind::GroupChildKind | ScopeKind::GroupDescendantKind => {
                    if rest != "group" {
                        return Err(AppError::bad_request(
                            "group kind scope_ref must end with ':group'",
                        ));
                    }
                }
                ScopeKind::Platform
                | ScopeKind::Tenant
                | ScopeKind::ObjectKind
                | ScopeKind::ObjectType
                | ScopeKind::Object => {}
            }
            let group_tenant_id: Option<Uuid> =
                storage::objects::group_tenant_optional(pool, &group_id)
                    .await
                    .map_err(db_err)?
                    .ok_or_else(|| AppError::bad_request("group scope references unknown group"))?;
            if tenant_id.is_some() && group_tenant_id != tenant_id {
                return Err(AppError::bad_request(
                    "group scope must reference a group in the role tenant",
                ));
            }
            Ok(())
        }
    }
}

fn parse_group_scope_ref(scope_ref: Option<&str>) -> Result<(Uuid, &str), AppError> {
    let scope_ref =
        scope_ref.ok_or_else(|| AppError::bad_request("group scope requires scope_ref"))?;
    let (group_id, rest) = scope_ref
        .split_once(':')
        .ok_or_else(|| AppError::bad_request("group scope_ref must start with group UUID"))?;
    let group_id = group_id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("group scope_ref has invalid group UUID"))?;
    Ok((group_id, rest))
}

#[derive(Debug, Clone)]
struct CapabilityValidationTarget {
    object_kind: String,
    object_type: Option<String>,
}

impl CapabilityValidationTarget {
    fn label(&self) -> String {
        self.object_type
            .clone()
            .unwrap_or_else(|| self.object_kind.clone())
    }
}

async fn validate_capabilities_against_role_scope(
    pool: &Database,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
    capability_ids: &[Uuid],
) -> Result<(), AppError> {
    let target = role_scope_capability_target(pool, scope_kind, scope_ref).await?;
    validate_capabilities_against_target(pool, capability_ids, target).await
}

async fn role_scope_capability_target(
    pool: &Database,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
) -> Result<Option<CapabilityValidationTarget>, AppError> {
    match scope_kind {
        ScopeKind::Platform | ScopeKind::Tenant => Ok(None),
        ScopeKind::ObjectKind => {
            let scope_ref = scope_ref
                .ok_or_else(|| AppError::bad_request("object_kind scope requires scope_ref"))?;
            Ok(Some(CapabilityValidationTarget {
                object_kind: scope_ref.to_string(),
                object_type: None,
            }))
        }
        ScopeKind::ObjectType => {
            let (object_kind, object_type) = parse_namespaced_object_type(scope_ref)?;
            Ok(Some(CapabilityValidationTarget {
                object_kind,
                object_type: Some(object_type),
            }))
        }
        ScopeKind::Object => {
            let scope_ref = scope_ref
                .ok_or_else(|| AppError::bad_request("object scope requires scope_ref"))?;
            let object_id = scope_ref
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("object scope_ref must be a UUID"))?;
            resolve_exact_object_target(pool, object_id)
                .await?
                .map(Some)
                .ok_or_else(|| AppError::bad_request("object scope references unknown object"))
        }
        ScopeKind::GroupObjectType | ScopeKind::GroupTreeObjectType => {
            let (_, object_type_ref) = parse_group_scope_ref(scope_ref)?;
            let (object_kind, object_type) = parse_namespaced_object_type(Some(object_type_ref))?;
            Ok(Some(CapabilityValidationTarget {
                object_kind,
                object_type: Some(object_type),
            }))
        }
        ScopeKind::GroupChildKind | ScopeKind::GroupDescendantKind => {
            let (_, object_kind) = parse_group_scope_ref(scope_ref)?;
            if object_kind != "group" {
                return Err(AppError::bad_request(
                    "group kind scope_ref must end with ':group'",
                ));
            }
            Ok(Some(CapabilityValidationTarget {
                object_kind: "group".to_string(),
                object_type: None,
            }))
        }
    }
}

async fn validate_capabilities_against_target(
    pool: &Database,
    capability_ids: &[Uuid],
    target: Option<CapabilityValidationTarget>,
) -> Result<(), AppError> {
    let mut connection = pool.acquire().await.map_err(db_err)?;
    validate_capabilities_against_target_on_connection(&mut connection, capability_ids, target)
        .await
}

async fn validate_capabilities_against_target_on_connection(
    connection: &mut impl DbExecutor,
    capability_ids: &[Uuid],
    target: Option<CapabilityValidationTarget>,
) -> Result<(), AppError> {
    if capability_ids.is_empty() {
        return Ok(());
    }

    let mut unique_capability_ids = capability_ids.to_vec();
    unique_capability_ids.sort_unstable();
    unique_capability_ids.dedup();

    let rows = storage::actions::action_identities(connection, &unique_capability_ids)
        .await
        .map_err(db_err)?;
    let capability_names = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.id;
            let name: String = row.name.clone();
            Ok((id, name))
        })
        .collect::<Result<HashMap<Uuid, String>, AppError>>()?;

    if capability_names.len() != unique_capability_ids.len() {
        let missing = unique_capability_ids
            .iter()
            .find(|id| !capability_names.contains_key(id))
            .copied()
            .unwrap_or_default();
        return Err(AppError::bad_request(format!(
            "capability {missing} does not exist"
        )));
    }

    let Some(target) = target else {
        return Ok(());
    };

    let invalid_rows = storage::actions::inapplicable_actions(
        connection,
        &unique_capability_ids,
        &target.object_kind,
        &target.object_type,
    )
    .await
    .map_err(db_err)?;

    if let Some(row) = invalid_rows.first() {
        let name = row;
        return Err(AppError::bad_request(format!(
            "capability {name} is not applicable to {}",
            target.label()
        )));
    }

    Ok(())
}

fn parse_namespaced_object_type(value: Option<&str>) -> Result<(String, String), AppError> {
    let value =
        value.ok_or_else(|| AppError::bad_request("object_type scope requires scope_ref"))?;
    let (object_kind, _) = value.split_once(':').ok_or_else(|| {
        AppError::bad_request("object type must be namespaced as '<kind>:<sub-kind>'")
    })?;
    Ok((object_kind.to_string(), value.to_string()))
}

async fn resolve_exact_object_target(
    pool: &Database,
    object_id: Uuid,
) -> Result<Option<CapabilityValidationTarget>, AppError> {
    let mut connection = pool.acquire().await.map_err(db_err)?;
    resolve_exact_object_target_on_connection(&mut connection, object_id).await
}

async fn resolve_exact_object_target_on_connection(
    connection: &mut impl DbExecutor,
    object_id: Uuid,
) -> Result<Option<CapabilityValidationTarget>, AppError> {
    Ok(
        crate::protected_objects::lookup_on_connection(connection, object_id)
            .await?
            .filter(|object| object.live)
            .map(|object| CapabilityValidationTarget {
                object_kind: object.object_kind,
                object_type: object.object_type,
            }),
    )
}

pub async fn update_role_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateRole,
) -> Result<Role, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let role = update_role_in_tx(&mut tx, events_enabled, actor_id, id, req).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: role.tenant_id,
            target_kind: "role",
            target_id: Some(id),
            event: "role.update",
        },
        &serde_json::json!({}),
    );
    Ok(role)
}

/// Transaction body for a role metadata update. Cache-aware callers first
/// lock and enumerate every assignee with
/// [`lock_role_and_collect_grants_keys`], establish the Grants barrier, then
/// call this helper on that same transaction. The ownership check remains
/// here as the final defense for uncached and internal callers.
pub(crate) async fn update_role_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateRole,
) -> Result<Role, AppError> {
    let tenant_id: Option<Option<Uuid>> = storage::roles::live_role_tenant_optional(tx, &id)
        .await
        .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("role {id} not found")));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", id).await?;
    let role = storage::roles::update_role_fields(tx, &id, &req.name, &req.description)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found(format!("role {id} not found")),
            other => AppError::Database(other),
        })?;
    crate::audit::observe_in_tx(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: role.tenant_id,
            target_kind: "role",
            target_id: Some(id),
            event: "role.update",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(role)
}

pub async fn update_role(pool: &Database, id: Uuid, req: UpdateRole) -> Result<Role, AppError> {
    update_role_with_audit(pool, false, None, id, req).await
}

pub async fn delete_role_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = delete_role_in_tx(&mut tx, events_enabled, actor_id, id, deleted_by).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "role",
            target_id: Some(id),
            event: "role.delete",
        },
        &serde_json::json!({}),
    );
    Ok(())
}

/// Body of [`delete_role`]; caller contract per
/// [`create_role_assignment_in_tx`] — the resolver must already hold the
/// role lock via [`lock_role_and_collect_grants_keys`] on this `tx`. Returns
/// the role's `tenant_id`, captured here rather than left for the caller to
/// re-derive post-commit — a re-read after this commits would always miss
/// the now-deleted row.
pub(crate) async fn delete_role_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let tenant_id: Option<Option<Uuid>> = storage::roles::live_role_tenant_optional(tx, &id)
        .await
        .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("role {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", id).await?;
    let live: bool = storage::roles::role_is_live(tx, &id)
        .await
        .map_err(db_err)?;
    if !live {
        return Err(AppError::not_found(format!("role {id} not found")));
    }
    let result = storage::roles::tombstone_role(tx, &id, &deleted_by)
        .await
        .map_err(db_err)?;
    if result == 0 {
        return Err(AppError::not_found(format!("role {id} not found")));
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "role",
        target_id: Some(id),
        event: "role.delete",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant_id)
}

pub async fn delete_role(
    pool: &Database,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_role_with_audit(pool, false, None, id, deleted_by).await
}

pub async fn restore_role_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    restore_role_in_tx(&mut tx, events_enabled, actor_id, id, restored_by).await?;
    tx.commit().await.map_err(db_err)?;
    // The audit_logs row is deliberately written after commit (fire-and-forget,
    // never blocks an already-valid restore) — see `audit::commit_with_audit`'s
    // doc comment. The outbox row, by contrast, went in atomically with the
    // mutation inside `restore_role_in_tx` via `observe_in_tx`.
    let tenant_id = get_role(pool, id).await.ok().and_then(|r| r.tenant_id);
    crate::audit::write(
        pool,
        false,
        crate::audit::AuditEvent {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: Some("role"),
            target_id: Some(id),
            event: "role.restore",
            outcome: crate::models::enums::AuditOutcome::Allow,
            details: serde_json::json!({}),
        },
    )
    .await;
    Ok(())
}

/// Body of [`restore_role`]; caller contract per
/// [`create_role_assignment_in_tx`] — the resolver must already hold the
/// role lock via [`lock_role_and_collect_grants_keys`] on this `tx`.
pub(crate) async fn restore_role_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let _ = restored_by;
    let expected_tenant_id: Option<Option<Uuid>> =
        storage::roles::deleted_role_tenant_optional(tx, &id)
            .await
            .map_err(db_err)?;
    let Some(expected_tenant_id) = expected_tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted role {id} to restore"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", id).await?;
    let tenant_info: Option<(Option<Uuid>, bool)> =
        storage::roles::lock_deleted_role_tenant_optional(tx, &id, &expected_tenant_id)
            .await
            .map_err(db_err)?;
    let (tenant_id, _is_tenant_deleted) = match tenant_info {
        None => {
            return Err(AppError::not_found(format!(
                "no soft-deleted role {id} to restore"
            )))
        }
        Some((_, true)) => {
            return Err(AppError::conflict(
                "the role's tenant is soft-deleted; restore the tenant first",
            ))
        }
        Some((t_id, false)) => (t_id, false),
    };

    storage::roles::restore_role_fields(tx, &id)
        .await
        .map_err(restore_conflict)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "role",
        target_id: Some(id),
        event: "role.restore",
    };
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &serde_json::json!({})).await?;
    Ok(())
}

pub async fn restore_role(
    pool: &Database,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    restore_role_with_audit(pool, false, None, id, restored_by).await
}

pub async fn purge_role_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant_id: Option<Option<Uuid>> = storage::roles::role_tenant_optional(&mut tx, &id)
        .await
        .map_err(db_err)?;
    let Some(expected_tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted role {id} to purge"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", id).await?;

    let candidate_block_ids: Vec<Uuid> = storage::blocks::role_linked_blocks(&mut tx, &id)
        .await
        .map_err(db_err)?;

    let purged_tenant_id: Option<Option<Uuid>> =
        storage::roles::purge_deleted_role_optional(&mut tx, &id)
            .await
            .map_err(db_err)?;
    let tenant_id = purged_tenant_id
        .ok_or_else(|| AppError::not_found(format!("no soft-deleted role {id} to purge")))?;

    if !candidate_block_ids.is_empty() {
        storage::blocks::purge_orphaned_blocks(&mut tx, &candidate_block_ids)
            .await
            .map_err(db_err)?;
    }

    purge_authz_references_for_ids(&mut tx, &[id]).await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("role"),
        target_id: Some(id),
        event: "role.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(tenant_id)
}

pub async fn purge_role(pool: &Database, id: Uuid) -> Result<Option<Uuid>, AppError> {
    purge_role_with_audit(pool, false, None, id).await
}

pub async fn add_role_capability(
    pool: &Database,
    role_id: Uuid,
    cap_id: Uuid,
) -> Result<(), AppError> {
    let role = get_role(pool, role_id).await?;
    let scope_kind = if role.tenant_id.is_some() {
        ScopeKind::Tenant
    } else {
        ScopeKind::Platform
    };
    let scope_ref = role.tenant_id.map(|tenant_id| tenant_id.to_string());
    validate_capabilities_against_role_scope(pool, &scope_kind, scope_ref.as_deref(), &[cap_id])
        .await?;
    let mut conn = pool.acquire().await.map_err(db_err)?;
    crate::guardrails::validate_role_capability(&mut conn, role_id, cap_id).await?;
    drop(conn);
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_role(&mut tx, role_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", role_id).await?;
    insert_role_capability_as_permission_block(
        &mut tx,
        role_id,
        role.tenant_id,
        &scope_kind,
        scope_ref.as_deref(),
        cap_id,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn add_composite_role_child(
    pool: &Database,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> Result<(), AppError> {
    let parent = get_role(pool, parent_role_id).await?;
    validate_composite_children(pool, parent_role_id, parent.tenant_id, &[child_role_id]).await?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_role(&mut tx, parent_role_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", parent_role_id).await?;
    lock_role(&mut tx, child_role_id).await?;
    copy_role_permission_blocks(&mut tx, parent_role_id, child_role_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn replace_composite_role_children(
    pool: &Database,
    parent_role_id: Uuid,
    child_role_ids: &[Uuid],
) -> Result<(), AppError> {
    let parent = get_role(pool, parent_role_id).await?;
    validate_composite_children(pool, parent_role_id, parent.tenant_id, child_role_ids).await?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_role(&mut tx, parent_role_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", parent_role_id).await?;
    let mut locked_child_role_ids = child_role_ids.to_vec();
    locked_child_role_ids.sort_unstable();
    locked_child_role_ids.dedup();
    for child_role_id in locked_child_role_ids {
        lock_role(&mut tx, child_role_id).await?;
    }
    let old_block_ids = role_block_ids(&mut tx, parent_role_id).await?;
    unlink_role_blocks_and_gc(&mut tx, parent_role_id, &old_block_ids).await?;
    for child_role_id in child_role_ids {
        copy_role_permission_blocks(&mut tx, parent_role_id, *child_role_id).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn remove_role_capability(
    pool: &Database,
    role_id: Uuid,
    cap_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_role(&mut tx, role_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", role_id).await?;
    // Blocks this role links that grant `cap_id`. Unlink them from this role and
    // GC any now-orphaned; blocks the same `cap_id` reaches through other roles
    // are untouched.
    let block_ids: Vec<Uuid> = storage::blocks::role_blocks_for_action(&mut tx, &role_id, &cap_id)
        .await
        .map_err(db_err)?;
    unlink_role_blocks_and_gc(&mut tx, role_id, &block_ids).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

// ─── Capabilities ─────────────────────────────────────────────────────────────

pub async fn create_capability(
    pool: &Database,
    req: CreateCapability,
) -> Result<Capability, AppError> {
    create_capability_with_audit(pool, false, None, req).await
}

pub async fn create_capability_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateCapability,
) -> Result<Capability, AppError> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let capability = storage::actions::insert_action(&mut tx, &id, &req.name, &req.description)
        .await
        .map_err(db_err)?;

    let applicability = req.applicability.unwrap_or_default();
    if !applicability.is_empty() {
        replace_capability_applicability_in_tx(&mut tx, id, &applicability).await?;
    }
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: None,
            target_kind: "action",
            target_id: Some(capability.id),
            event: "action.create",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(capability)
}

pub async fn get_capability(pool: &Database, id: Uuid) -> Result<Capability, AppError> {
    storage::actions::get_capability(pool, id).await
}

pub async fn list_capabilities(
    pool: &Database,
    params: ListCapabilities,
) -> Result<crate::models::capability::CapabilityList, AppError> {
    storage::objects::list_capabilities(pool, params).await
}

pub async fn capability_applicability(
    pool: &Database,
    capability_id: Uuid,
) -> Result<Vec<CapabilityApplicability>, AppError> {
    storage::actions::capability_applicability(pool, capability_id).await
}

pub async fn list_capability_applicability(
    pool: &Database,
    action_name: Option<String>,
    object_kind: Option<String>,
    object_type: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<CapabilityApplicabilityList, AppError> {
    storage::actions::list_capability_applicability(
        pool,
        action_name,
        object_kind,
        object_type,
        limit,
        offset,
    )
    .await
}

pub async fn get_action_assignment_rule(
    pool: &Database,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    storage::actions::get_action_assignment_rule(pool, id).await
}

pub async fn list_action_assignment_rules(
    pool: &Database,
    params: ListActionAssignmentRules,
) -> Result<ActionAssignmentRuleList, AppError> {
    storage::actions::list_action_assignment_rules(pool, params).await
}

pub async fn create_action_assignment_rule(
    pool: &Database,
    req: CreateActionAssignmentRule,
) -> Result<ActionAssignmentRule, AppError> {
    create_action_assignment_rule_with_audit(pool, false, None, req, "internal").await
}

/// `transport` is supplied by the caller: the repo cannot know which surface
/// invoked it, and the audit trail records it (see `grpc.rs` / `graphql`).
pub async fn create_action_assignment_rule_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateActionAssignmentRule,
    transport: &str,
) -> Result<ActionAssignmentRule, AppError> {
    let req = validate_and_normalize_action_assignment_rule(pool, req).await?;
    let action_name = req.action_name.clone();
    let object_type = req.object_type.clone();

    let duplicate: bool = storage::actions::assignment_rule_exists(
        pool,
        &req.tenant_id,
        &req.entity_kind,
        &action_name,
        &req.object_kind,
        &object_type,
    )
    .await
    .map_err(db_err)?;
    if duplicate {
        return Err(AppError::conflict("action assignment rule already exists"));
    }

    let mut tx = pool.begin().await.map_err(db_err)?;
    let rule = storage::actions::insert_assignment_rule(
        &mut tx,
        &req.tenant_id,
        &req.entity_kind,
        &action_name,
        &req.object_kind,
        &object_type,
        &req.decision,
        &req.is_absolute,
    )
    .await
    .map_err(db_err)?;
    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: rule.tenant_id,
        target_kind: Some("action_assignment_rule"),
        target_id: Some(rule.id),
        event: "action_assignment_rule.create",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({
            "entity_kind": &rule.entity_kind,
            "action_name": &rule.action_name,
            "object_kind": rule.object_kind.as_str(),
            "object_type": &rule.object_type,
            "decision": &rule.decision,
            "is_absolute": rule.is_absolute,
            "transport": transport,
        }),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(rule)
}

pub(crate) async fn validate_and_normalize_action_assignment_rule(
    pool: &Database,
    req: CreateActionAssignmentRule,
) -> Result<CreateActionAssignmentRule, AppError> {
    let mut connection = pool.acquire().await.map_err(db_err)?;
    validate_and_normalize_action_assignment_rule_on_connection(&mut connection, req).await
}

pub(crate) async fn validate_and_normalize_action_assignment_rule_on_connection(
    connection: &mut impl DbExecutor,
    mut req: CreateActionAssignmentRule,
) -> Result<CreateActionAssignmentRule, AppError> {
    req.action_name = req.action_name.trim().to_string();
    if req.action_name.is_empty() {
        return Err(AppError::bad_request("actionName is required"));
    }
    if req.decision == ActionAssignmentDecision::RequireOverride {
        return Err(AppError::bad_request(
            "require_override guardrail creation is not available in v1",
        ));
    }
    if req.tenant_id.is_some() && req.decision != ActionAssignmentDecision::Deny {
        return Err(AppError::bad_request(
            "tenant-specific guardrail rules can only deny in v1",
        ));
    }
    if req.tenant_id.is_some() && req.is_absolute {
        return Err(AppError::bad_request(
            "tenant-specific guardrail rules cannot be absolute",
        ));
    }

    req.object_type = normalize_optional_text(req.object_type);
    validate_rule_object_type(req.object_kind, req.object_type.as_deref())?;

    let action_exists: bool = storage::actions::action_exists_by_name(connection, &req.action_name)
        .await
        .map_err(db_err)?;
    if !action_exists {
        return Err(AppError::bad_request(format!(
            "actionName references unknown action {}",
            req.action_name
        )));
    }
    Ok(req)
}

pub async fn delete_action_assignment_rule(
    pool: &Database,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    delete_action_assignment_rule_with_audit(pool, false, None, id, "internal").await
}

/// See [`create_action_assignment_rule_with_audit`] for `transport`.
pub async fn delete_action_assignment_rule_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    transport: &str,
) -> Result<ActionAssignmentRule, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id: Option<Option<Uuid>> =
        storage::actions::assignment_rule_tenant_optional(&mut tx, &id)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "action assignment rule {id} not found"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "action_assignment_rules", id)
        .await?;
    let rule = storage::actions::remove_assignment_rule(&mut tx, &id)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                AppError::not_found(format!("action assignment rule {id} not found"))
            }
            other => AppError::Database(other),
        })?;
    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: rule.tenant_id,
        target_kind: Some("action_assignment_rule"),
        target_id: Some(rule.id),
        event: "action_assignment_rule.delete",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({
            "entity_kind": &rule.entity_kind,
            "action_name": &rule.action_name,
            "object_kind": rule.object_kind.as_str(),
            "object_type": &rule.object_type,
            "decision": &rule.decision,
            "is_absolute": rule.is_absolute,
            "transport": transport,
        }),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(rule)
}

async fn ensure_not_config_managed_applicability_in_tx(
    tx: &mut DbTransaction<'_>,
    capability_id: Uuid,
    object_kind: &str,
    object_type: Option<&str>,
) -> Result<(), AppError> {
    let action_locked: Option<Uuid> = storage::actions::lock_action_optional(tx, &capability_id)
        .await
        .map_err(db_err)?;
    if action_locked.is_none() {
        return Err(AppError::not_found(format!(
            "capability {capability_id} not found"
        )));
    }
    let managed_by: Option<Option<String>> = storage::actions::applicability_ownership_optional(
        tx,
        &capability_id,
        object_kind,
        &object_type,
    )
    .await
    .map_err(db_err)?;
    match managed_by {
        None => Ok(()),
        Some(Some(value)) if value == "config" => Err(AppError::conflict(
            "capability applicability is managed by the bootstrap config file and cannot be modified via the API",
        )),
        _ => Ok(()),
    }
}

pub async fn add_capability_applicability(
    pool: &Database,
    capability_id: Uuid,
    object_kind: String,
    object_type: Option<String>,
) -> Result<CapabilityApplicabilityEntry, AppError> {
    add_capability_applicability_with_audit(
        pool,
        false,
        None,
        capability_id,
        object_kind,
        object_type,
    )
    .await
}

pub async fn add_capability_applicability_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    capability_id: Uuid,
    object_kind: String,
    object_type: Option<String>,
) -> Result<CapabilityApplicabilityEntry, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    let exists = storage::actions::action_exists(&mut tx, &capability_id)
        .await
        .map_err(db_err)?;
    if !exists {
        return Err(AppError::not_found(format!(
            "capability {capability_id} not found"
        )));
    }

    let insert =
        storage::actions::insert_applicability(&mut tx, &capability_id, &object_kind, &object_type)
            .await
            .map_err(db_err)?;

    let entry =
        storage::actions::applicability_entry(&mut tx, &capability_id, &object_kind, &object_type)
            .await
            .map_err(db_err)?;

    if insert == 0 {
        tx.commit().await.map_err(db_err)?;
    } else {
        crate::audit::commit_with_observation(
            tx,
            events_enabled,
            &crate::audit::AuditMeta {
                actor_entity_id: actor_id,
                tenant_id: None,
                target_kind: "action",
                target_id: Some(capability_id),
                event: "action_applicability.add",
            },
            &serde_json::json!({ "object_kind": object_kind, "object_type": object_type }),
        )
        .await?;
    }
    Ok(entry)
}

pub async fn remove_capability_applicability(
    pool: &Database,
    capability_id: Uuid,
    object_kind: String,
    object_type: Option<String>,
) -> Result<(), AppError> {
    remove_capability_applicability_with_audit(
        pool,
        false,
        None,
        capability_id,
        object_kind,
        object_type,
    )
    .await
}

pub async fn remove_capability_applicability_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    capability_id: Uuid,
    object_kind: String,
    object_type: Option<String>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    ensure_not_config_managed_applicability_in_tx(
        &mut tx,
        capability_id,
        &object_kind,
        object_type.as_deref(),
    )
    .await?;
    let result =
        storage::actions::remove_applicability(&mut tx, &capability_id, &object_kind, &object_type)
            .await
            .map_err(db_err)?;

    if result == 0 {
        return Err(AppError::not_found(
            "capability applicability row not found",
        ));
    }
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: None,
            target_kind: "action",
            target_id: Some(capability_id),
            event: "action_applicability.remove",
        },
        &serde_json::json!({ "object_kind": object_kind, "object_type": object_type }),
    )
    .await
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_rule_object_type(
    object_kind: ObjectKind,
    object_type: Option<&str>,
) -> Result<(), AppError> {
    if let Some(object_type) = object_type {
        let (prefix, suffix) = object_type.split_once(':').ok_or_else(|| {
            AppError::bad_request("objectType must be namespaced as object_kind:type")
        })?;
        if prefix != object_kind.as_str() || suffix.is_empty() {
            return Err(AppError::bad_request(
                "objectType namespace must match objectKind",
            ));
        }
    }
    Ok(())
}

pub async fn update_capability(
    pool: &Database,
    id: Uuid,
    req: crate::models::capability::UpdateCapability,
) -> Result<Capability, AppError> {
    update_capability_with_audit(pool, false, None, id, req).await
}

pub async fn update_capability_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: crate::models::capability::UpdateCapability,
) -> Result<Capability, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "actions", id).await?;
    let updated = storage::actions::update_action_fields(&mut tx, &id, &req.name, &req.description)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found(format!("capability {id} not found")),
            other => AppError::Database(other),
        })?;

    if let Some(applicability) = req.applicability {
        replace_capability_applicability_in_tx(&mut tx, id, &applicability).await?;
    }

    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: None,
            target_kind: "action",
            target_id: Some(id),
            event: "action.update",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(updated)
}

async fn replace_capability_applicability_in_tx(
    tx: &mut DbTransaction<'_>,
    capability_id: Uuid,
    applicability: &[CapabilityApplicabilityInput],
) -> Result<(), AppError> {
    // Refuse to blow away applicability rows that were declared in the
    // bootstrap config, even when the parent capability itself is API-managed.
    let has_managed: bool = storage::actions::action_has_config_applicability(tx, &capability_id)
        .await
        .map_err(db_err)?;
    if has_managed {
        return Err(AppError::conflict(
            "capability has applicability rows managed by the bootstrap config file; \
             use addCapabilityApplicability / removeCapabilityApplicability instead",
        ));
    }

    storage::actions::clear_applicability(tx, &capability_id)
        .await
        .map_err(db_err)?;

    let mut seen = HashSet::new();
    for item in applicability {
        if !seen.insert((item.object_kind.as_str(), item.object_type.as_deref())) {
            continue;
        }
        storage::actions::insert_applicability(
            tx,
            &capability_id,
            &item.object_kind,
            &item.object_type,
        )
        .await
        .map_err(db_err)?;
    }

    Ok(())
}

pub async fn delete_capability(pool: &Database, id: Uuid) -> Result<(), AppError> {
    delete_capability_with_audit(pool, false, None, id).await
}

pub async fn delete_capability_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    // The action row is the FK serialization point for every
    // permission_block_actions insert. Lock it before checking ownership so a
    // concurrent bootstrap cannot add and stamp a declarative block link after
    // our check but before the cascading delete.
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "actions", id).await?;
    let config_owned_link: bool = storage::actions::action_has_config_links(&mut tx, &id)
        .await
        .map_err(db_err)?;
    if config_owned_link {
        return Err(AppError::conflict(
            "capability is linked to a permission block managed by the bootstrap config file and cannot be deleted via the API",
        ));
    }
    let result = storage::actions::remove_action(&mut tx, &id)
        .await
        .map_err(db_err)?;
    if result == 0 {
        return Err(AppError::not_found(format!("capability {id} not found")));
    }
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: None,
            target_kind: "action",
            target_id: Some(id),
            event: "action.delete",
        },
        &serde_json::json!({}),
    )
    .await
}

// ─── Policy Bindings ──────────────────────────────────────────────────────────

async fn lock_live_subject(
    tx: &mut DbTransaction<'_>,
    assignment_tenant_id: Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<(), AppError> {
    let subject_tenant_id = read_live_subject_tenant_id(tx, subject_kind, subject_id).await?;
    lock_active_tenant_ids(tx, [assignment_tenant_id, subject_tenant_id]).await?;
    lock_live_subject_row(tx, subject_kind, subject_id, subject_tenant_id).await
}

async fn read_live_subject_tenant_id(
    tx: &mut DbTransaction<'_>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    storage::assignments::read_live_subject_tenant_id(tx, subject_kind, subject_id).await
}

async fn lock_active_tenant_ids<const N: usize>(
    tx: &mut DbTransaction<'_>,
    tenant_ids: [Option<Uuid>; N],
) -> Result<(), AppError> {
    let mut tenant_ids = tenant_ids.into_iter().flatten().collect::<Vec<_>>();
    tenant_ids.sort_unstable();
    tenant_ids.dedup();
    for tenant_id in tenant_ids {
        crate::tenants::repo::lock_active_tenant(tx, tenant_id).await?;
    }
    Ok(())
}

async fn lock_live_subject_row(
    tx: &mut DbTransaction<'_>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    storage::assignments::lock_live_subject_row(tx, subject_kind, subject_id, expected_tenant_id)
        .await
}

/// Prepare a role-assignment mutation under the canonical lock order.
///
/// All relevant tenant rows are locked in UUID order first. The role is then
/// locked so this path agrees with role/block-link mutations; for a group
/// subject, the hierarchy advisory lock and full descendant closure follow.
/// Finally the live subject predicate is revalidated under its row lock.
/// Holding these locks in the caller's transaction makes both guardrail
/// validation and the affected grants-cache keys stable through the insert.
///
/// Callers may invoke this twice in one transaction (the cache barrier path
/// prepares before `cache.begin`, and the insert helper defensively prepares
/// again). Re-acquiring transaction-owned row/advisory locks is safe.
pub(crate) async fn prepare_role_assignment_in_tx(
    tx: &mut DbTransaction<'_>,
    req: &CreateRoleAssignment,
) -> Result<Vec<String>, AppError> {
    // Read all tenant ownership first, then lock the complete tenant set in a
    // stable order before taking either the role or subject row. This avoids a
    // cross-tenant invalid request creating a tenant/role lock inversion while
    // it is on the way to being rejected by boundary validation.
    let role_tenant_id = read_live_role_tenant_id(tx, req.role_id).await?;
    let subject_tenant_id =
        read_live_subject_tenant_id(tx, &req.subject_kind, req.subject_id).await?;
    lock_active_tenant_ids(tx, [req.tenant_id, role_tenant_id, subject_tenant_id]).await?;
    lock_live_role_row(tx, req.role_id, role_tenant_id).await?;
    let grants_keys = match &req.subject_kind {
        SubjectKind::Entity => vec![crate::cache::keys::grants(req.subject_id)],
        SubjectKind::Group => {
            lock_group_closures_and_collect_grants_keys(tx, &[req.subject_id]).await?
        }
    };
    // For a group subject the closure helper already owns the root row lock.
    // Re-checking the live/tenant predicate under that lock catches status,
    // deletion, or ownership drift since the initial unlocked pre-read.
    lock_live_subject_row(tx, &req.subject_kind, req.subject_id, subject_tenant_id).await?;
    Ok(grants_keys)
}

/// Prepare a direct-policy mutation while matching group-membership lock
/// order: active tenant row(s), hierarchy advisory lock, then group row(s).
/// The subject's live predicate is revalidated under the resulting row lock.
/// This prevents a membership change from racing between guardrail
/// validation/cache-key enumeration and the policy insert.
pub(crate) async fn prepare_direct_policy_in_tx(
    tx: &mut DbTransaction<'_>,
    req: &CreateDirectPolicy,
) -> Result<Vec<String>, AppError> {
    let subject_tenant_id =
        read_live_subject_tenant_id(tx, &req.subject_kind, req.subject_id).await?;
    lock_active_tenant_ids(tx, [req.tenant_id, subject_tenant_id]).await?;
    let grants_keys = match &req.subject_kind {
        SubjectKind::Entity => vec![crate::cache::keys::grants(req.subject_id)],
        SubjectKind::Group => {
            lock_group_closures_and_collect_grants_keys(tx, &[req.subject_id]).await?
        }
    };
    lock_live_subject_row(tx, &req.subject_kind, req.subject_id, subject_tenant_id).await?;
    Ok(grants_keys)
}

pub async fn create_policy(
    pool: &Database,
    req: CreatePolicyBinding,
) -> Result<PolicyBinding, AppError> {
    let mut conn = pool.acquire().await.map_err(db_err)?;
    crate::guardrails::validate_policy(&mut conn, &req).await?;
    drop(conn);
    let id = Uuid::new_v4();
    let membership_tenant_id = req.tenant_id;
    let membership_entity_id = req.subject_id;
    let should_sync_membership = req.tenant_id.is_some()
        && req.subject_kind == SubjectKind::Entity
        && req.effect == Effect::Allow;
    let conditions = normalize_conditions(req.conditions)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_live_subject(&mut tx, req.tenant_id, &req.subject_kind, req.subject_id).await?;
    match req.grant_kind {
        GrantKind::Role => {
            lock_role(&mut tx, req.grant_id).await?;
            if req.effect != Effect::Allow || conditions != serde_json::json!({}) {
                return Err(AppError::bad_request(
                    "role assignment supports only allow effect without conditions; use direct policy for deny or conditional grants",
                ));
            }
            storage::assignments::insert_policy_role_assignment(
                &mut tx,
                &id,
                &req.tenant_id,
                &req.subject_kind,
                &req.subject_id,
                &req.grant_id,
            )
            .await
            .map_err(db_err)?;
        }
        GrantKind::Capability => {
            let block = permission_block_from_legacy_scope(
                req.tenant_id,
                &req.scope_kind,
                req.scope_ref.as_deref(),
            )?;
            let permission_block_id: Uuid = storage::blocks::insert_legacy_permission_block(
                &mut tx,
                &block.tenant_id,
                block.scope_mode,
                &block.object_kind,
                &block.object_type,
                &block.object_id,
                &block.group_id,
                &req.effect,
                &conditions,
            )
            .await
            .map_err(db_err)?;
            storage::blocks::insert_block_action(&mut tx, &permission_block_id, &req.grant_id)
                .await
                .map_err(db_err)?;
            storage::assignments::insert_policy_direct_assignment(
                &mut tx,
                &id,
                &req.tenant_id,
                &req.subject_kind,
                &req.subject_id,
                &permission_block_id,
            )
            .await
            .map_err(db_err)?;
        }
    }
    if should_sync_membership {
        if let Some(tenant_id) = membership_tenant_id {
            sync_tenant_membership_for_policy(&mut tx, tenant_id, membership_entity_id).await?;
        }
    }
    tx.commit().await.map_err(db_err)?;

    get_policy(pool, id).await
}

async fn sync_tenant_membership_for_policy(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    storage::assignments::sync_tenant_membership_for_policy(tx, tenant_id, entity_id).await
}

pub async fn get_policy(pool: &Database, id: Uuid) -> Result<PolicyBinding, AppError> {
    storage::assignments::get_policy(pool, id).await
}

pub async fn create_role_assignment_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateRoleAssignment,
) -> Result<RoleAssignment, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let assignment = create_role_assignment_in_tx(&mut tx, events_enabled, actor_id, req).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: assignment.tenant_id,
            target_kind: "role_assignment",
            target_id: Some(assignment.id),
            event: "role_assignment.create",
        },
        &serde_json::json!({}),
    );
    Ok(assignment)
}

/// Body of [`create_role_assignment`], callable directly against a caller-held
/// `tx` (not committed here). The helper always runs
/// [`prepare_role_assignment_in_tx`] itself, so uncached/internal callers hold
/// the same live-subject and group-closure locks as the cache-aware transport.
/// A cache-aware caller prepares once before `cache.begin()` and this helper
/// safely re-acquires the transaction-owned locks before validation/insert.
/// Every other `_in_tx` twin in this module and `identity::repo` follows this
/// same convention: caller locks + begins the cache barrier first, this kind
/// of function re-acquires (never re-validates) those locks, and the caller
/// commits.
pub(crate) async fn create_role_assignment_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateRoleAssignment,
) -> Result<RoleAssignment, AppError> {
    prepare_role_assignment_in_tx(tx, &req).await?;
    // Validate under the role/subject/closure locks so a concurrent block-link
    // or group-membership mutation cannot change the assignment's effective
    // entity set after the guardrail decision. A block-link mutation waits on
    // the same role lock and re-validates against the assignment inserted here.
    // Validation must run on `tx` for that to hold at all — the pool variant
    // would neither see the locked state nor respect the locks.
    validate_role_assignment_in_tx(tx, &req).await?;
    let assignment = storage::assignments::insert_role_assignment(
        tx,
        &req.tenant_id,
        &req.subject_kind,
        &req.subject_id,
        &req.role_id,
    )
    .await
    .map_err(db_err)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: assignment.tenant_id,
        target_kind: "role_assignment",
        target_id: Some(assignment.id),
        event: "role_assignment.create",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(assignment)
}

pub async fn create_role_assignment(
    pool: &Database,
    req: CreateRoleAssignment,
) -> Result<RoleAssignment, AppError> {
    create_role_assignment_with_audit(pool, false, None, req).await
}

/// Returns `true` when a new assignment row was actually inserted, so callers
/// can tell a real state change from an idempotent no-op and decide whether the
/// operation is worth publishing as a domain event.
pub(crate) async fn create_role_assignment_if_missing_in_tx(
    tx: &mut DbTransaction<'_>,
    req: &CreateRoleAssignment,
) -> Result<bool, AppError> {
    prepare_role_assignment_in_tx(tx, req).await?;
    validate_role_assignment_in_tx(tx, req).await?;
    let inserted = storage::assignments::insert_missing_role_assignment(
        tx,
        &req.tenant_id,
        &req.subject_kind.clone(),
        &req.subject_id,
        &req.role_id,
    )
    .await
    .map_err(db_err)?;
    Ok(inserted > 0)
}

pub(crate) async fn lock_live_entity_subject_in_tx(
    tx: &mut DbTransaction<'_>,
    assignment_tenant_id: Option<Uuid>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    lock_live_subject(tx, assignment_tenant_id, &SubjectKind::Entity, entity_id).await
}

pub async fn list_role_assignments(
    pool: &Database,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    storage::assignments::list_role_assignments(pool, params).await
}

pub async fn list_role_assignments_authorized(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    let authorized = authorize_flat_candidate_query(
        pool,
        auth.entity_id,
        auth.ceiling_credential_for(auth.entity_id),
        "policy",
        &["read", "policy.manage", "manage"],
        serde_json::json!({
            "tenant_id": params.tenant_id,
            "subject_kind": params.subject_kind,
            "subject_id": params.subject_id,
            "role_id": params.role_id,
        }),
        FlatCandidate::Assignments,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        storage::visibility::selected_role_assignments(pool, &authorized.ids)
            .await
            .map_err(db_err)?
    };
    Ok(RoleAssignmentList {
        items,
        total: authorized.total,
    })
}

pub async fn get_role_assignment(pool: &Database, id: Uuid) -> Result<RoleAssignment, AppError> {
    storage::assignments::get_role_assignment(pool, id).await
}

pub async fn delete_role_assignment(pool: &Database, id: Uuid) -> Result<(), AppError> {
    delete_role_assignment_with_audit(pool, false, None, id).await
}

pub async fn delete_role_assignment_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = delete_role_assignment_in_tx(&mut tx, events_enabled, actor_id, id).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "role_assignment",
            target_id: Some(id),
            event: "role_assignment.delete",
        },
        &serde_json::json!({}),
    );
    Ok(())
}

/// Body of [`delete_role_assignment`]; caller contract per
/// [`create_role_assignment_in_tx`] — the group-subject resolver path must
/// already hold the subject's group closure lock on this `tx`. Returns the
/// assignment's `tenant_id`, captured here rather than left for the caller
/// to re-derive post-commit — the row is gone by then.
pub(crate) async fn delete_role_assignment_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let tenant_id: Option<Option<Uuid>> =
        storage::assignments::role_assignment_tenant_optional(tx, &id)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "role assignment {id} not found"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "role_assignments", id).await?;
    // A role assignment is a 'policy' protected object; the policy-object cleanup trigger
    // sweeps the permission blocks targeting it when this row is deleted.
    let result = storage::assignments::remove_role_assignment(tx, &id)
        .await
        .map_err(db_err)?;
    if result == 0 {
        return Err(AppError::not_found(format!(
            "role assignment {id} not found"
        )));
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "role_assignment",
        target_id: Some(id),
        event: "role_assignment.delete",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant_id)
}

pub async fn create_direct_policy_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateDirectPolicy,
) -> Result<DirectPolicy, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let policy = create_direct_policy_in_tx(&mut tx, events_enabled, actor_id, req).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: policy.tenant_id,
            target_kind: "direct_policy",
            target_id: Some(policy.id),
            event: "direct_policy.create",
        },
        &serde_json::json!({}),
    );
    Ok(policy)
}

/// Body of [`create_direct_policy`]; caller contract per
/// [`create_role_assignment_in_tx`]. Always prepares the live subject and its
/// group closure before validating on `tx`, rather than on a pooled connection
/// — see [`replace_role_permission_block_links_in_tx`].
pub(crate) async fn create_direct_policy_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateDirectPolicy,
) -> Result<DirectPolicy, AppError> {
    prepare_direct_policy_in_tx(tx, &req).await?;
    validate_direct_policy_in_tx(tx, &req).await?;
    crate::guardrails::validate_direct_policy(tx, &req).await?;
    let block_tenant_id: Option<Option<Uuid>> =
        storage::blocks::lock_block_tenant_optional(tx, &req.permission_block_id)
            .await
            .map_err(db_err)?;
    if block_tenant_id != Some(req.tenant_id) {
        return Err(AppError::bad_request(
            "direct policy references a missing or cross-tenant permission block",
        ));
    }
    let policy = storage::assignments::insert_direct_policy(
        tx,
        &req.tenant_id,
        &req.subject_kind,
        &req.subject_id,
        &req.permission_block_id,
    )
    .await
    .map_err(db_err)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: policy.tenant_id,
        target_kind: "direct_policy",
        target_id: Some(policy.id),
        event: "direct_policy.create",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(policy)
}

pub async fn create_direct_policy(
    pool: &Database,
    req: CreateDirectPolicy,
) -> Result<DirectPolicy, AppError> {
    create_direct_policy_with_audit(pool, false, None, req).await
}

/// `object_kind` / `object_type` only make sense alongside `object_id`: the
/// reverse-lookup predicate is inert without it, so accepting them on their own
/// would silently return the *unfiltered* listing. Reject instead.
fn validate_direct_policy_object_filter(
    object_id: Option<Uuid>,
    object_kind: Option<ObjectKind>,
    object_type: Option<&str>,
) -> Result<(), AppError> {
    if object_id.is_none() && (object_kind.is_some() || object_type.is_some()) {
        return Err(AppError::bad_request(
            "objectKind and objectType are co-filters for objectId and require it",
        ));
    }
    if let Some(object_type) = object_type {
        let (prefix, suffix) = object_type.split_once(':').ok_or_else(|| {
            AppError::bad_request("objectType must be namespaced as object_kind:type")
        })?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(AppError::bad_request(
                "objectType must be namespaced as object_kind:type",
            ));
        }
        if object_kind.is_some_and(|kind| kind.as_str() != prefix) {
            return Err(AppError::bad_request(
                "objectType namespace must match objectKind",
            ));
        }
    }
    Ok(())
}

/// Lists direct policies, filtered by subject, by object, or by both.
///
/// **The object filter is a policy lookup, not effective access.** With
/// `object_id` set, the result is every direct policy whose permission block
/// *names* that object: `object` (direct), `group` (the object is the named
/// group), `group_direct_objects`/`group_descendant_objects` (member/
/// descendant-member of the block's group), or `group_child_groups`/
/// `group_descendant_groups` (a group covered by the block's hierarchy
/// scope). Blocks that reach the object without naming it (`platform`,
/// `tenant`, `object_kind`, `object_type`) are **not** returned — reading
/// this as "everyone who can access X" will under-report.
pub async fn list_direct_policies(
    pool: &Database,
    mut params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    params.object_type = normalize_optional_text(params.object_type);
    validate_direct_policy_object_filter(
        params.object_id,
        params.object_kind,
        params.object_type.as_deref(),
    )?;
    storage::assignments::list_direct_policies(pool, params).await
}

pub async fn list_direct_policies_authorized(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    let object_type = normalize_optional_text(params.object_type);
    validate_direct_policy_object_filter(
        params.object_id,
        params.object_kind,
        object_type.as_deref(),
    )?;
    let authorized = authorize_flat_candidate_query(
        pool,
        auth.entity_id,
        auth.ceiling_credential_for(auth.entity_id),
        "policy",
        &["read", "policy.manage", "manage"],
        serde_json::json!({
            "tenant_id": params.tenant_id,
            "subject_kind": params.subject_kind,
            "subject_id": params.subject_id,
            "permission_block_id": params.permission_block_id,
            "object_id": params.object_id,
            "object_kind": params.object_kind,
            "object_type": object_type,
        }),
        FlatCandidate::DirectPolicies,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        storage::visibility::selected_direct_policies(pool, &authorized.ids)
            .await
            .map_err(db_err)?
    };
    Ok(DirectPolicyList {
        items,
        total: authorized.total,
    })
}

pub async fn get_direct_policy(pool: &Database, id: Uuid) -> Result<DirectPolicy, AppError> {
    storage::assignments::get_direct_policy(pool, id).await
}

pub async fn delete_direct_policy_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = delete_direct_policy_in_tx(&mut tx, events_enabled, actor_id, id).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "direct_policy",
            target_id: Some(id),
            event: "direct_policy.delete",
        },
        &serde_json::json!({}),
    );
    Ok(())
}

/// Body of [`delete_direct_policy`]; caller contract per
/// [`create_role_assignment_in_tx`]. Returns the policy's `tenant_id`,
/// captured here rather than left for the caller to re-derive post-commit —
/// the row is gone by then.
pub(crate) async fn delete_direct_policy_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let policy_tenant_id: Option<Option<Uuid>> =
        storage::assignments::direct_policy_tenant_optional(tx, &id)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = policy_tenant_id else {
        return Err(AppError::not_found(format!("direct policy {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "direct_policies", id).await?;
    let block_id: Option<Uuid> = storage::assignments::remove_direct_policy_optional(tx, &id)
        .await
        .map_err(db_err)?;
    let Some(block_id) = block_id else {
        return Err(AppError::not_found(format!("direct policy {id} not found")));
    };
    // The block is shared: GC it only if removing this policy left it
    // unreferenced (mirrors delete_policy). Blocks targeting this policy *as an
    // object* are swept by the policy-object cleanup trigger on the delete above.
    delete_orphaned_blocks(tx, &[block_id]).await?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "direct_policy",
        target_id: Some(id),
        event: "direct_policy.delete",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant_id)
}

pub async fn delete_direct_policy(pool: &Database, id: Uuid) -> Result<(), AppError> {
    delete_direct_policy_with_audit(pool, false, None, id).await
}

pub(crate) async fn validate_role_assignment_in_tx(
    tx: &mut DbTransaction<'_>,
    req: &CreateRoleAssignment,
) -> Result<(), AppError> {
    let role_tenant_id: Option<Uuid> = storage::roles::live_role_tenant_optional(tx, &req.role_id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::bad_request("role assignment references unknown role"))?;
    if role_tenant_id != req.tenant_id {
        return Err(AppError::bad_request(
            "role assignment tenantId must match role tenantId",
        ));
    }
    validate_subject_boundary_in_tx(tx, req.tenant_id, &req.subject_kind, req.subject_id).await?;
    crate::guardrails::validate_role_assignment_on_connection(
        tx,
        req.tenant_id,
        req.subject_kind.clone(),
        req.subject_id,
        req.role_id,
    )
    .await
}

pub(crate) async fn validate_direct_policy_in_tx(
    tx: &mut DbTransaction<'_>,
    req: &CreateDirectPolicy,
) -> Result<(), AppError> {
    let block_tenant_id: Option<Uuid> =
        storage::blocks::block_tenant_optional(tx, &req.permission_block_id)
            .await
            .map_err(db_err)?
            .ok_or_else(|| {
                AppError::bad_request("direct policy references unknown permission block")
            })?;
    if block_tenant_id != req.tenant_id {
        return Err(AppError::bad_request(
            "direct policy tenantId must match permission block tenantId",
        ));
    }
    validate_subject_boundary_in_tx(tx, req.tenant_id, &req.subject_kind, req.subject_id).await
}

async fn validate_subject_boundary_in_tx(
    tx: &mut DbTransaction<'_>,
    tenant_id: Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<(), AppError> {
    match subject_kind {
        SubjectKind::Entity => {
            let entity_tenant_id: Option<Uuid> =
                storage::assignments::live_entity_tenant_optional(tx, &subject_id)
                    .await
                    .map_err(db_err)?
                    .ok_or_else(|| AppError::bad_request("assignment references unknown entity"))?;
            if let Some(tenant_id) = tenant_id {
                let member: bool =
                    storage::assignments::active_membership(tx, &tenant_id, &subject_id)
                        .await
                        .map_err(db_err)?;
                if entity_tenant_id != Some(tenant_id) && !member {
                    return Err(AppError::bad_request(
                        "tenant assignment subject entity must belong to the tenant",
                    ));
                }
            } else if entity_tenant_id.is_some() {
                return Err(AppError::bad_request(
                    "platform assignment cannot target tenant-owned entity",
                ));
            }
        }
        SubjectKind::Group => {
            let group_tenant_id: Option<Uuid> =
                storage::assignments::live_principal_group_tenant_optional(tx, &subject_id)
                    .await
                    .map_err(db_err)?
                    .ok_or_else(|| {
                        AppError::bad_request("assignment references unknown principal group")
                    })?;
            if group_tenant_id != tenant_id {
                return Err(AppError::bad_request(
                    "assignment subject principal group must be in the same tenant",
                ));
            }
        }
    }
    Ok(())
}

pub async fn subject_role_assignments(
    pool: &Database,
    mut params: SubjectRoleAssignmentsQuery,
) -> Result<SubjectRoleAssignmentList, AppError> {
    params.q = search_pattern(params.q);
    params.derived_kind = normalize_derived_kind(params.derived_kind)?;
    storage::assignments::subject_role_assignments(pool, params).await
}

pub async fn delete_policy(pool: &Database, id: Uuid) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let direct_tenant_id: Option<Option<Uuid>> =
        storage::assignments::direct_policy_tenant_optional(&mut tx, &id)
            .await
            .map_err(db_err)?;
    if let Some(tenant_id) = direct_tenant_id {
        crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
        crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "direct_policies", id).await?;
        let block_id: Uuid = storage::assignments::remove_direct_policy(&mut tx, &id)
            .await
            .map_err(db_err)?;
        // The block is shared: GC it only if removing this policy left it
        // unreferenced. A block still linked to a role or another policy stays.
        // Blocks targeting this policy as an object are swept by the policy-object cleanup
        // trigger on the delete above.
        delete_orphaned_blocks(&mut tx, &[block_id]).await?;
        tx.commit().await.map_err(db_err)?;
        return Ok(());
    }

    let assignment_tenant_id: Option<Option<Uuid>> =
        storage::assignments::role_assignment_tenant_optional(&mut tx, &id)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = assignment_tenant_id else {
        return Err(AppError::not_found(format!("policy {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "role_assignments", id).await?;
    let result = storage::assignments::remove_role_assignment(&mut tx, &id)
        .await
        .map_err(db_err)?;
    debug_assert_eq!(result, 1);
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

/// Best-effort ownership lookup for exact-object policy scopes. `None` means
/// no object with that UUID exists in the known Atom object tables; `Some(None)`
/// means the object is platform/global.
pub async fn object_tenant_id_by_id(
    pool: &Database,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    Ok(crate::protected_objects::lookup(pool, id)
        .await?
        .filter(|object| object.live)
        .map(|object| object.tenant_id))
}

/// Ceiling-aware listing entry point for request-path callers. The scoped-token
/// ceiling is derived here from the caller's `AuthContext`
/// (`ceiling_credential_for`), never passed by hand, so a call site cannot
/// forget to apply it — the same rule as `engine::evaluate`. A delegated
/// listing about another subject is unaffected (the derivation yields `None`).
pub async fn authorized_object_ids(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    params: AuthorizedObjectIdsQuery,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let ceiling_credential_id = auth.ceiling_credential_for(params.subject_id);
    authorized_object_ids_with_ceiling(pool, params, ceiling_credential_id).await
}

/// Low-level listing taking an explicit ceiling credential. For tests;
/// production code must call [`authorized_object_ids`], which derives the
/// ceiling from the authenticated context.
pub async fn authorized_object_ids_with_ceiling(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    match params.object_kind.as_str() {
        "entity" => authorized_entity_ids(pool, params, ceiling_credential_id).await,
        "resource" => authorized_resource_ids(pool, params, ceiling_credential_id).await,
        "group" => authorized_group_ids(pool, params, ceiling_credential_id).await,
        "role" | "policy" | "api_endpoint" => {
            authorized_flat_object_ids(pool, params, ceiling_credential_id).await
        }
        other => Err(AppError::bad_request(format!(
            "authorized object listing does not support object kind '{other}'"
        ))),
    }
}

async fn authorized_flat_object_ids(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    if params.object_type.is_some() {
        return Ok(AuthorizedObjectIdsResponse {
            ids: Vec::new(),
            total: 0,
        });
    }
    let q = search_pattern(params.q);
    let id = search_pattern(params.id);

    let candidate_sql = match params.object_kind.as_str() {
        "role" => FlatCandidate::RoleObjects,
        "policy" => FlatCandidate::PolicyObjects,
        "api_endpoint" => FlatCandidate::EndpointObjects,
        _ => unreachable!("flat protected-object dispatch is exhaustive"),
    };
    authorize_flat_candidate_query(
        pool,
        params.subject_id,
        ceiling_credential_id,
        &params.object_kind,
        &[params.action.as_str()],
        serde_json::json!({"tenant_id": params.tenant_id, "q": q, "id": id}),
        candidate_sql,
        params.limit,
        params.offset,
    )
    .await
}

async fn authorized_entity_ids(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    storage::visibility::authorized_entity_ids(pool, params, ceiling_credential_id).await
}

#[derive(Debug, Clone, Copy)]
enum AuthorizedResourceProjection {
    Ids,
    Kinds,
}

async fn authorized_resource_ids(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let rows = authorized_resource_rows(
        pool,
        params,
        ceiling_credential_id,
        AuthorizedResourceProjection::Ids,
    )
    .await?;
    rows_to_authorized_object_ids(rows)
}

/// Ceiling-aware kind listing for request-path callers; the ceiling is derived
/// from the caller's `AuthContext`, same as [`authorized_object_ids`].
pub async fn authorized_resource_kinds(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    subject_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    let ceiling_credential_id = auth.ceiling_credential_for(subject_id);
    authorized_resource_kinds_with_ceiling(pool, subject_id, tenant_id, ceiling_credential_id).await
}

/// Low-level kind listing taking an explicit ceiling credential. For tests;
/// production code must call [`authorized_resource_kinds`].
pub async fn authorized_resource_kinds_with_ceiling(
    pool: &Database,
    subject_id: Uuid,
    tenant_id: Option<Uuid>,
    ceiling_credential_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    let rows = authorized_resource_rows(
        pool,
        AuthorizedObjectIdsQuery {
            subject_id,
            action: "read".to_string(),
            object_kind: "resource".to_string(),
            object_type: None,
            tenant_id,
            id: None,
            q: None,
            attributes_contains: None,
            external_id: None,
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id: None,
            include_descendants: false,
            limit: 500,
            offset: 0,
            entity_order: Default::default(),
            resource_order: Default::default(),
            group_order: Default::default(),
            dir: Default::default(),
        },
        ceiling_credential_id,
        AuthorizedResourceProjection::Kinds,
    )
    .await?;

    rows.into_iter()
        .map(|row| {
            row.kind
                .ok_or_else(|| AppError::bad_request("missing authorized resource kind"))
        })
        .collect()
}

async fn authorized_resource_rows(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
    projection: AuthorizedResourceProjection,
) -> Result<Vec<AuthorizedPageRow>, AppError> {
    storage::visibility::authorized_resource_rows(pool, params, ceiling_credential_id, projection)
        .await
}

async fn authorized_group_ids(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    storage::visibility::authorized_group_ids(pool, params, ceiling_credential_id).await
}

fn rows_to_authorized_object_ids(
    rows: Vec<AuthorizedPageRow>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let mut total = 0;
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        ids.push(
            row.id
                .ok_or_else(|| AppError::bad_request("missing authorized object id"))?,
        );
        total = row.total;
    }
    Ok(AuthorizedObjectIdsResponse { ids, total })
}

pub async fn audit_logs(
    pool: &Database,
    params: crate::models::access::AuditQuery,
    allowed_tenant_ids: Option<Vec<Uuid>>,
) -> Result<AuditLogResponse, AppError> {
    storage::visibility::audit_logs(pool, params, allowed_tenant_ids).await
}

/// Tenants in which `entity_id` effectively holds `action_name` for `object_kind`,
/// via a tenant-scoped or `object_kind`-scoped grant. Used to scope tenant-bounded
/// listings (e.g. audit logs); platform-wide access is handled by the caller.
///
/// Reads the single canonical grant expansion so role-linked blocks carry their
/// real effect and conditions: a role whose only matching block is a *deny* does
/// not grant access (deny overrides), and a conditional allow is not listable
/// without request context. The grant's assignment tenant boundary is honoured.
pub async fn tenant_ids_for_action_on_object_kind(
    pool: &Database,
    entity_id: Uuid,
    action_name: &str,
    object_kind: &str,
) -> Result<Vec<Uuid>, AppError> {
    let Some(action_id): Option<Uuid> =
        storage::actions::action_by_name_optional(pool, action_name)
            .await
            .map_err(db_err)?
    else {
        return Ok(Vec::new());
    };

    let grants = effective_grants_for_subject(pool, entity_id).await?;
    let mut allowed: HashSet<Uuid> = HashSet::new();
    let mut denied: HashSet<Uuid> = HashSet::new();
    for grant in &grants {
        if grant.capability_id != action_id {
            continue;
        }
        // The tenant this grant pertains to for `object_kind`: a tenant-scoped
        // grant names it directly; an object_kind-scoped grant applies within its
        // assignment tenant.
        let tenant = match grant.scope_kind {
            ScopeKind::Tenant => grant
                .scope_ref
                .as_deref()
                .and_then(|s| s.parse::<Uuid>().ok()),
            ScopeKind::ObjectKind if grant.scope_ref.as_deref() == Some(object_kind) => {
                grant.tenant_boundary
            }
            _ => continue,
        };
        let Some(tenant) = tenant else {
            continue;
        };
        // Honour the assignment tenant boundary, as the PDP does.
        if grant
            .tenant_boundary
            .is_some_and(|boundary| boundary != tenant)
        {
            continue;
        }
        match grant.effect {
            // Any deny removes the tenant (deny overrides; conservative for a
            // conditional deny, which we cannot evaluate without context).
            Effect::Deny => {
                denied.insert(tenant);
            }
            // Only an unconditional allow is listable without request context.
            Effect::Allow if grant.conditions.as_object().is_some_and(|m| m.is_empty()) => {
                allowed.insert(tenant);
            }
            Effect::Allow => {}
        }
    }
    Ok(allowed
        .into_iter()
        .filter(|t| !denied.contains(t))
        .collect())
}

pub async fn orphan_policies(
    pool: &Database,
    params: AdminPageQuery,
) -> Result<OrphanPoliciesResponse, AppError> {
    storage::visibility::orphan_policies(pool, params).await
}

pub async fn expiring_credentials(
    pool: &Database,
    params: ExpiringCredentialsQuery,
) -> Result<ExpiringCredentialsResponse, AppError> {
    storage::visibility::expiring_credentials(pool, params).await
}

// ─── Engine helpers ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AuthzSubjectRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) kind: EntityKind,
    pub(crate) tenant_id: Option<Uuid>,
    pub(crate) status: EntityStatus,
    pub(crate) attributes: Value,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AuthzTenantRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) status: TenantStatus,
    pub(crate) deleted_at: Option<chrono::DateTime<Utc>>,
    pub(crate) attributes: Value,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AuthzObjectRecord {
    pub(crate) id: Uuid,
    pub(crate) kind: String,
    pub(crate) name: Option<String>,
    pub(crate) tenant_id: Option<Uuid>,
    pub(crate) attributes: Value,
    /// Every object group the object belongs to. Object group membership is
    /// many-to-many, so this is loaded as an aggregate on the object's own row —
    /// a join projecting the group would multiply rows and `fetch_optional`
    /// would then keep one arbitrary group, silently dropping the grants held
    /// through the rest.
    #[sqlx(try_from = "crate::db::UuidList")]
    pub(crate) parent_group_ids: Vec<Uuid>,
}

pub(crate) async fn load_authz_subject(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<AuthzSubjectRecord>, AppError> {
    storage::visibility::load_authz_subject(pool, entity_id).await
}

pub(crate) async fn load_authz_tenant(
    pool: &Database,
    tenant_id: Uuid,
) -> Result<Option<AuthzTenantRecord>, AppError> {
    storage::visibility::load_authz_tenant(pool, tenant_id).await
}

pub(crate) async fn load_authz_resource(
    pool: &Database,
    resource_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_resource(pool, resource_id).await
}

pub(crate) async fn load_authz_entity_object(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_entity_object(pool, entity_id).await
}

pub(crate) async fn load_authz_group_object(
    pool: &Database,
    group_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_group_object(pool, group_id).await
}

pub(crate) async fn load_authz_credential_object(
    pool: &Database,
    credential_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_credential_object(pool, credential_id).await
}

/// Recursive ancestors of every supplied group, de-duplicated. An object can be
/// in several groups in different subtrees, so the tree scopes must be evaluated
/// against the union of their ancestors, not one branch's.
pub(crate) async fn group_ancestor_ids(
    pool: &Database,
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    storage::visibility::group_ancestor_ids(pool, group_ids).await
}

/// Canonical grant expansion for a subject: the single flat list of effective
/// grants (direct policies and role-linked blocks), with the subject's group
/// membership resolved recursively. Each grant carries the permission block's
/// real scope, effect and conditions plus the assignment-level tenant boundary,
/// so a reader can decide access by matching tenant → block scope → action →
/// conditions and applying the effect (deny overrides allow).
pub async fn effective_grants_for_subject(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<EffectiveGrant>, AppError> {
    storage::visibility::effective_grants_for_subject(pool, entity_id).await
}

/// Locks every root group's owning tenant row first, then the hierarchy
/// advisory lock, then every group in the closure rooted at `root_group_ids`
/// (each root plus every descendant subgroup, via a `group_hierarchy`
/// descent) `FOR UPDATE`. Object-group rows are locked before principal-group
/// rows, and each physical table is locked in stable UUID order. This matches
/// the canonical physical-group ordering used by mutations that can touch both
/// group classes. The member entity ids across that (now-locked) closure are
/// returned.
///
/// # Why this exists
///
/// A plain "enumerate current members, then invalidate" has a real race: a
/// group-subject mutation (direct policy / role assignment / role
/// block-links / group status-or-hierarchy change) can enumerate members at
/// one instant, while `identity::repo::add_group_member` concurrently
/// commits a *new* member in between that enumeration and the mutation's own
/// commit. That new member's `grants` key is never in the enumerated set, so
/// it never gets invalidated — a stale cached grant (or a stale cached
/// *lack* of one) can then survive until the grants TTL. (Reported by
/// external review, 2026-07-29.)
///
/// `add_group_member`/`remove_group_member` already lock the group's row in
/// `principal_groups` `FOR UPDATE` before changing membership. Locking that
/// same row here — and holding it for the caller's entire transaction,
/// through commit — closes the race: neither side's transaction can commit
/// while the other holds the lock, so whichever runs first is fully visible
/// (including its own cache invalidation) before the other's enumeration or
/// commit proceeds.
///
/// # Contract for callers
///
/// The returned ids are only exhaustive as long as the lock stays held: the
/// caller must keep `tx` open (no commit) from this call through the end of
/// its own mutation's commit, and should call `cache.begin()` on the
/// resulting keys *before* that commit — mirroring `guarded_mutation`'s
/// begin/mutate/end shape, just with `mutate` running against this
/// already-open, already-locked `tx` instead of opening its own.
pub async fn lock_group_closures_and_collect_member_ids(
    tx: &mut DbTransaction<'_>,
    root_group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    if root_group_ids.is_empty() {
        return Ok(Vec::new());
    }

    lock_group_tenant_rows(tx, root_group_ids).await?;
    lock_group_closures_after_tenant_rows(tx, root_group_ids).await
}

/// Prepare a hierarchy mutation under the global
/// tenant(s) -> hierarchy-advisory -> group-row order.
///
/// A reparent can name two different tenants on an invalid request. Both
/// ownership sets must therefore be discovered and locked before the advisory
/// lock; locking only the child tenant and discovering the parent later would
/// recreate the inversion while the request is on its way to being rejected.
/// The returned keys cover the child subtree, which is exactly the set whose
/// inherited grants can change when that child is attached or detached.
pub(crate) async fn prepare_group_hierarchy_mutation_in_tx(
    tx: &mut DbTransaction<'_>,
    child_id: Uuid,
    parent_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    let mut group_ids = vec![child_id];
    group_ids.extend(parent_id);
    lock_group_tenant_rows(tx, &group_ids).await?;
    Ok(lock_group_closures_after_tenant_rows(tx, &[child_id])
        .await?
        .into_iter()
        .map(crate::cache::keys::grants)
        .collect())
}

/// Read every tenant ownership row before taking any lock, then lock the
/// complete tenant set in UUID order. `groups` intentionally includes both
/// principal and object rows and does not filter tombstones: restore/delete
/// preparation needs the same ordering barrier as live mutations, and a mixed
/// principal/object closure must contribute both ownership sets.
async fn lock_group_tenant_rows(
    tx: &mut DbTransaction<'_>,
    group_ids: &[Uuid],
) -> Result<(), AppError> {
    let tenant_ids: Vec<Option<Uuid>> = storage::objects::group_tenants(tx, group_ids)
        .await
        .map_err(db_err)?;
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids).await
}

async fn lock_group_closures_after_tenant_rows(
    tx: &mut DbTransaction<'_>,
    root_group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    // Hierarchy rows can be inserted or removed without an existing row lock
    // to wait on. Serialize closure enumeration with every hierarchy mutation
    // so a newly attached subtree cannot enter the graph between enumeration
    // and the locks below.
    lock_group_hierarchy(tx).await?;

    let mut closure: Vec<Uuid> = storage::objects::descendant_groups(tx, root_group_ids)
        .await
        .map_err(db_err)?;
    closure.sort_unstable();
    closure.dedup();

    // Every mutation that can encounter both group classes uses object ->
    // principal ordering; reversing that order here could deadlock with a
    // mutation already holding an object row. Object-only roots still need
    // this lock so their hierarchy cannot be changed while the prepared
    // closure is in use.
    storage::objects::lock_object_groups(tx, &closure)
        .await
        .map_err(db_err)?;

    storage::objects::lock_principal_groups(tx, &closure)
        .await
        .map_err(db_err)?;

    storage::objects::group_member_ids(tx, &closure)
        .await
        .map_err(db_err)
}

pub(crate) async fn load_authz_role_object(
    pool: &Database,
    role_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_role_object(pool, role_id).await
}

pub(crate) async fn load_authz_policy_object(
    pool: &Database,
    policy_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_policy_object(pool, policy_id).await
}

pub(crate) async fn load_authz_api_endpoint_object(
    pool: &Database,
    endpoint_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    storage::visibility::load_authz_api_endpoint_object(pool, endpoint_id).await
}

/// Serializes recursive group-closure reads with hierarchy mutations. A
/// transaction-scoped advisory lock is used because an attach/detach may
/// create or delete the hierarchy row, leaving no row lock for a reader to
/// wait on.
pub async fn lock_group_hierarchy(tx: &mut DbTransaction<'_>) -> Result<(), AppError> {
    storage::objects::lock_group_hierarchy(tx).await
}

/// [`lock_group_closures_and_collect_member_ids`], mapped straight to
/// `atom:v1:grants:*` cache keys — the form every locked group-subject
/// mutation call site actually wants.
pub async fn lock_group_closures_and_collect_grants_keys(
    tx: &mut DbTransaction<'_>,
    root_group_ids: &[Uuid],
) -> Result<Vec<String>, AppError> {
    Ok(
        lock_group_closures_and_collect_member_ids(tx, root_group_ids)
            .await?
            .into_iter()
            .map(crate::cache::keys::grants)
            .collect(),
    )
}

/// Like [`lock_group_closures_and_collect_grants_keys`], for a role: locks
/// the role row itself plus every group in the closure of every group
/// directly assigned this role, and returns the combined set of affected
/// `atom:v1:grants:*` keys (entity-direct assignees plus every locked
/// group's members). Entity-direct assignees need no lock of their own —
/// the affected key is exactly their `subject_id`, deterministic and
/// race-free.
///
/// Locks the owning tenant first, then the role row, then assigned
/// group closures. This is the same tenant -> role -> hierarchy/group order
/// used by [`prepare_role_assignment_in_tx`]; taking the role first here and
/// reaching for its tenant later inside the mutation creates a real inversion
/// with concurrent assignment creation.
///
/// The role-row lock deliberately has no `deleted_at` filter because
/// `restore_role` is a caller and operates on an already soft-deleted role.
/// The caller's mutation separately validates the alive/deleted state it
/// requires; this preparation only establishes the canonical lock order and
/// captures the stable current assignee set.
pub async fn lock_role_and_collect_grants_keys(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Vec<String>, AppError> {
    let role_tenant_id: Option<Option<Uuid>> = storage::roles::role_tenant_optional(tx, &role_id)
        .await
        .map_err(db_err)?;
    let Some(role_tenant_id) = role_tenant_id else {
        return Err(AppError::not_found(format!("role {role_id} not found")));
    };
    if let Some(tenant_id) = role_tenant_id {
        // Do not impose a lifecycle predicate here: restore_role deliberately
        // accepts a soft-deleted role and owns the user-facing decision about
        // whether its tenant state permits restoration. This row lock is only
        // for the canonical tenant -> role order.
        let tenant_locked: Option<Uuid> = storage::objects::lock_tenant_optional(tx, &tenant_id)
            .await
            .map_err(db_err)?;
        if tenant_locked.is_none() {
            return Err(AppError::not_found(format!(
                "role {role_id} tenant {tenant_id} not found"
            )));
        }
    }
    let locked: Option<Uuid> =
        storage::roles::lock_role_row_optional(tx, &role_id, &role_tenant_id)
            .await
            .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("role {role_id} not found")));
    }
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", role_id).await?;
    let entity_subject_ids: Vec<Uuid> = storage::assignments::role_entity_subjects(tx, &role_id)
        .await
        .map_err(db_err)?;
    let group_subject_ids: Vec<Uuid> = storage::assignments::role_group_subjects(tx, &role_id)
        .await
        .map_err(db_err)?;
    let mut member_ids = lock_group_closures_and_collect_member_ids(tx, &group_subject_ids).await?;
    member_ids.extend(entity_subject_ids);
    member_ids.sort_unstable();
    member_ids.dedup();
    Ok(member_ids
        .into_iter()
        .map(crate::cache::keys::grants)
        .collect())
}

/// Locks a role and a group (in that order) for the one mutation that needs
/// both in the same transaction: creating a role assignment for a group
/// subject. **Lock order matters here**: [`lock_role_and_collect_grants_keys`]
/// (used by `replaceRolePermissionBlocks`/`deleteRole`/`restoreRole`) always
/// locks the owning tenant, then the role, then the closures of every group
/// assigned it. If
/// `createRoleAssignment` locked the *subject group* first and only reached
/// the role lock afterward (inside `create_role_assignment_in_tx`'s own
/// `lock_role` call — which is exactly what the original code did), a
/// concurrent pair of requests could deadlock: one holding the descendant
/// group's row while waiting on the role, the other holding the role while
/// waiting on that same descendant group (reached via an ancestor group
/// already assigned the role). Postgres detects the cycle and aborts one
/// side. (Reported by external review, 2026-07-29.)
///
/// Locking the tenant and role before the group closure makes
/// `createRoleAssignment`'s order match every role-mutation path, closing the
/// inversion. The newer creation path uses
/// [`prepare_role_assignment_in_tx`] directly; this helper remains the
/// equivalent role/group utility for callers that already have those ids.
pub async fn lock_role_then_group_closure_and_collect_grants_keys(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    subject_group_id: Uuid,
) -> Result<Vec<String>, AppError> {
    lock_role(tx, role_id).await?;
    lock_group_closures_and_collect_grants_keys(tx, &[subject_group_id]).await
}

pub async fn find_capability_ids_by_name(
    pool: &Database,
    name: &str,
    object_kind: &str,
    object_type: &str,
) -> Result<Vec<Uuid>, AppError> {
    storage::actions::find_capability_ids_by_name(pool, name, object_kind, object_type).await
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_id() -> Uuid {
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("uuid")
    }

    #[test]
    fn object_filter_accepts_a_bare_object_id() {
        assert!(validate_direct_policy_object_filter(Some(device_id()), None, None).is_ok());
    }

    #[test]
    fn object_filter_accepts_a_subject_only_listing() {
        assert!(validate_direct_policy_object_filter(None, None, None).is_ok());
    }

    #[test]
    fn object_filter_rejects_co_filters_without_an_object_id() {
        assert!(
            validate_direct_policy_object_filter(None, Some(ObjectKind::Entity), None).is_err(),
            "objectKind alone would silently return the unfiltered listing"
        );
        assert!(
            validate_direct_policy_object_filter(None, None, Some("entity:device")).is_err(),
            "objectType alone would silently return the unfiltered listing"
        );
    }

    #[test]
    fn object_filter_requires_a_namespaced_object_type() {
        assert!(
            validate_direct_policy_object_filter(Some(device_id()), None, Some("device")).is_err()
        );
        assert!(
            validate_direct_policy_object_filter(Some(device_id()), None, Some("entity:")).is_err()
        );
        assert!(
            validate_direct_policy_object_filter(Some(device_id()), None, Some(":device")).is_err()
        );
        assert!(validate_direct_policy_object_filter(
            Some(device_id()),
            None,
            Some("entity:device")
        )
        .is_ok());
    }

    #[test]
    fn object_filter_requires_the_type_namespace_to_match_the_kind() {
        assert!(validate_direct_policy_object_filter(
            Some(device_id()),
            Some(ObjectKind::Resource),
            Some("entity:device"),
        )
        .is_err());
        assert!(validate_direct_policy_object_filter(
            Some(device_id()),
            Some(ObjectKind::Entity),
            Some("entity:device"),
        )
        .is_ok());
    }
}

#[derive(sqlx::FromRow)]
struct AuthorizedPageRow {
    #[sqlx(default)]
    id: Option<Uuid>,
    #[sqlx(default)]
    kind: Option<String>,
    #[sqlx(default)]
    total: i64,
}

#[derive(Clone, Copy)]
enum FlatCandidate {
    Endpoints,
    Roles,
    Assignments,
    RoleObjects,
    PolicyObjects,
    EndpointObjects,
    DirectPolicies,
}

#[derive(sqlx::FromRow)]
struct ResourceGroupBoundary {
    resource_tenant_id: Option<Uuid>,
    group_tenant_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct CompositeRoleCandidate {
    id: Uuid,
    tenant_id: Option<Uuid>,
    has_capabilities: bool,
    has_children: bool,
}

#[derive(sqlx::FromRow)]
struct ActionIdentity {
    id: Uuid,
    name: String,
}

fn normalize_derived_kind(value: Option<String>) -> Result<Option<String>, AppError> {
    let value = value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_ascii_lowercase);
    if value
        .as_deref()
        .is_some_and(|kind| !matches!(kind, "simple" | "composite" | "empty"))
    {
        return Err(AppError::bad_request(
            "derivedKind must be simple, composite, or empty",
        ));
    }
    Ok(value)
}
