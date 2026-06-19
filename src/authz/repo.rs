use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::Utc;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::{
        access::{
            AccessItem, AccessQuery, AdminPageQuery, AuditLogItem, AuditLogResponse,
            AuthorizedObjectIdsQuery, AuthorizedObjectIdsResponse, CapabilitySource,
            CapabilitySummary, EffectiveCapabilitiesQuery, EffectiveCapabilitiesResponse,
            EffectiveCapability, EntityAccessResponse, EntitySummary, ExpiringCredentialItem,
            ExpiringCredentialsQuery, ExpiringCredentialsResponse, GrantSummary, GroupAccessItem,
            GroupAccessQuery, GroupAccessResponse, GroupInfo, OrphanPoliciesResponse,
            OrphanPolicyItem, ResourceAccessEntity, ResourceAccessItem, ResourceAccessQuery,
            ResourceAccessResponse, ResourceSummary, RoleHolderGroup, RoleHolderItem,
            RoleHoldersQuery, RoleHoldersResponse, RoleSummary, RoleWithCapabilities,
            SubjectRoleAssignment, SubjectRoleAssignmentList, SubjectRoleAssignmentsQuery,
            UnprotectedResourceItem, UnprotectedResourcesQuery, UnprotectedResourcesResponse,
        },
        action_assignment_rule::{
            ActionAssignmentRule, ActionAssignmentRuleList, CreateActionAssignmentRule,
            ListActionAssignmentRules,
        },
        alias::AliasObjectClass,
        capability::{
            Capability, CapabilityApplicability, CapabilityApplicabilityEntry,
            CapabilityApplicabilityInput, CapabilityApplicabilityList, CreateCapability,
            ListCapabilities,
        },
        entity::Entity,
        enums::{
            ActionAssignmentDecision, CredentialKind, Effect, GrantKind, ObjectKind, ScopeKind,
            SubjectKind,
        },
        group::Group,
        policy::{
            CreateDirectPolicy, CreatePermissionBlock, CreatePolicyBinding, CreateRoleAssignment,
            DirectPolicy, DirectPolicyList, ListDirectPolicies, ListPermissionBlocks, ListPolicies,
            ListRoleAssignments, PermissionBlock, PermissionBlockList, PolicyBinding, PolicyList,
            RoleAssignment, RoleAssignmentList,
        },
        resource::{CreateResource, ListResources, Resource, ResourceList, UpdateResource},
        role::{
            CreateRole, CreateRolePermissionBlock, ListRoles, Role, RoleDerivedKind, RoleList,
            RolePermissionBlock, UpdateRole,
        },
    },
};

// ─── Resources ────────────────────────────────────────────────────────────────

pub async fn create_resource(pool: &PgPool, req: CreateResource) -> Result<Resource, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = if req.attributes.is_null() {
        serde_json::json!({})
    } else {
        req.attributes
    };
    let parent_group_id = parent_group_id_from_attrs(&attrs)?;
    let alias = crate::models::alias::validate_alias_opt(req.alias)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    let resource = sqlx::query_as::<_, Resource>(
        r#"INSERT INTO resources (id, kind, name, alias, tenant_id, owner_id, attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, kind, name, alias, tenant_id, owner_id, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.kind)
    .bind(req.name)
    .bind(alias)
    .bind(req.tenant_id)
    .bind(req.owner_id)
    .bind(attrs)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if let Some(parent_group_id) = parent_group_id {
        set_resource_parent_group_in_tx(&mut tx, resource.id, parent_group_id).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(resource)
}

pub async fn get_resource(pool: &PgPool, id: Uuid) -> Result<Resource, AppError> {
    sqlx::query_as::<_, Resource>(
        "SELECT id, kind, name, alias, tenant_id, owner_id, attributes, created_at, updated_at FROM resources WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_resources_by_ids(pool: &PgPool, ids: &[Uuid]) -> Result<Vec<Resource>, AppError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query_as::<_, Resource>(
        r#"SELECT id, kind, name, alias, tenant_id, owner_id, attributes, created_at, updated_at
           FROM resources
           WHERE id = ANY($1::uuid[])
           ORDER BY array_position($1::uuid[], id)"#,
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn list_resources(
    pool: &PgPool,
    params: ListResources,
) -> Result<ResourceList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let kind = params.kind;
    let tenant_id = params.tenant_id;
    let parent_group_id = params.parent_group_id;
    let include_descendants = params.include_descendants;
    let q = search_pattern(params.q);

    let items = sqlx::query_as::<_, Resource>(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $4::uuid WHERE $4::uuid IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $5::boolean
           )
           SELECT r.id, r.kind, r.name, r.alias, r.tenant_id, r.owner_id, r.attributes, r.created_at, r.updated_at
           FROM resources r
           LEFT JOIN group_resource_parents grp ON grp.resource_id = r.id
           WHERE ($1::text IS NULL OR r.kind = $1)
             AND ($2::uuid IS NULL OR r.tenant_id = $2)
             AND ($3::text IS NULL OR r.name ILIKE $3 OR r.alias ILIKE $3 OR r.attributes::text ILIKE $3)
             AND ($4::uuid IS NULL OR grp.group_id IN (SELECT id FROM target_groups))
           ORDER BY r.created_at DESC
           LIMIT $6 OFFSET $7"#,
    )
    .bind(kind.clone())
    .bind(tenant_id)
    .bind(q.clone())
    .bind(parent_group_id)
    .bind(include_descendants)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $4::uuid WHERE $4::uuid IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $5::boolean
           )
           SELECT COUNT(*)
           FROM resources r
           LEFT JOIN group_resource_parents grp ON grp.resource_id = r.id
           WHERE ($1::text IS NULL OR r.kind = $1)
             AND ($2::uuid IS NULL OR r.tenant_id = $2)
             AND ($3::text IS NULL OR r.name ILIKE $3 OR r.alias ILIKE $3 OR r.attributes::text ILIKE $3)
             AND ($4::uuid IS NULL OR grp.group_id IN (SELECT id FROM target_groups))"#,
    )
    .bind(kind)
    .bind(tenant_id)
    .bind(q)
    .bind(parent_group_id)
    .bind(include_descendants)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ResourceList { items, total })
}

pub async fn update_resource(
    pool: &PgPool,
    id: Uuid,
    req: UpdateResource,
) -> Result<Resource, AppError> {
    let parent_group_id = req
        .attributes
        .as_ref()
        .and_then(|attrs| attrs.get("parent_group_id"))
        .map(parent_group_id_from_value)
        .transpose()?;
    let alias = crate::models::alias::validate_alias_update(req.alias)?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let resource = sqlx::query_as::<_, Resource>(
        r#"UPDATE resources
           SET name       = COALESCE($2, name),
               attributes = COALESCE($3, attributes),
               alias      = CASE WHEN $4 THEN $5 ELSE alias END,
               updated_at = now()
           WHERE id = $1
           RETURNING id, kind, name, alias, tenant_id, owner_id, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.attributes)
    .bind(alias_is_set)
    .bind(alias)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })?;
    if let Some(parent_group_id) = parent_group_id {
        match parent_group_id {
            Some(parent_group_id) => {
                set_resource_parent_group_in_tx(&mut tx, resource.id, parent_group_id).await?;
            }
            None => clear_resource_parent_group_in_tx(&mut tx, resource.id).await?,
        }
    }
    tx.commit().await.map_err(db_err)?;
    Ok(resource)
}

pub async fn delete_resource(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }
    Ok(())
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
    pool: &PgPool,
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
        (Some(id), None, false) => Some(id),
        (None, Some(alias), false) => {
            let id = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM tenants WHERE lower(alias) = lower($1)",
            )
            .bind(alias)
            .fetch_optional(pool)
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

    let sql = match class {
        AliasObjectClass::Entity => {
            "SELECT id FROM entities \
             WHERE tenant_id IS NOT DISTINCT FROM $1::uuid \
               AND lower(alias) = $2"
        }
        AliasObjectClass::Resource => {
            "SELECT id FROM resources \
             WHERE tenant_id IS NOT DISTINCT FROM $1::uuid \
               AND lower(alias) = $2"
        }
    };

    let object_id = sqlx::query_scalar::<_, Uuid>(sql)
        .bind(tenant_id)
        .bind(&object_alias)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
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

pub async fn get_resource_parent_group(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar("SELECT group_id FROM group_resource_parents WHERE resource_id = $1")
        .bind(resource_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

pub async fn set_resource_parent_group(
    pool: &PgPool,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    set_resource_parent_group_in_tx(&mut tx, resource_id, group_id).await?;
    tx.commit().await.map_err(db_err)?;
    get_resource(pool, resource_id).await
}

pub async fn clear_resource_parent_group(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    clear_resource_parent_group_in_tx(&mut tx, resource_id).await?;
    tx.commit().await.map_err(db_err)?;
    get_resource(pool, resource_id).await
}

async fn set_resource_parent_group_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<(), AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT r.tenant_id AS resource_tenant_id, g.tenant_id AS group_tenant_id
           FROM resources r
           CROSS JOIN object_groups g
           WHERE r.id = $1 AND g.id = $2"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?
    .ok_or_else(|| AppError::bad_request("resource parent group reference is invalid"))?;
    let resource_tenant_id: Option<Uuid> = row.try_get("resource_tenant_id").map_err(db_err)?;
    let group_tenant_id: Option<Uuid> = row.try_get("group_tenant_id").map_err(db_err)?;
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
    sqlx::query(
        r#"INSERT INTO object_group_resources (group_id, resource_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (resource_id) DO UPDATE
           SET group_id = EXCLUDED.group_id,
               tenant_id = EXCLUDED.tenant_id,
               updated_at = now()"#,
    )
    .bind(group_id)
    .bind(resource_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn clear_resource_parent_group_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    resource_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM object_group_resources WHERE resource_id = $1")
        .bind(resource_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

fn parent_group_id_from_attrs(attrs: &Value) -> Result<Option<Uuid>, AppError> {
    attrs
        .get("parent_group_id")
        .map(parent_group_id_from_value)
        .transpose()
        .map(Option::flatten)
}

fn parent_group_id_from_value(value: &Value) -> Result<Option<Uuid>, AppError> {
    match value.as_str().map(str::trim) {
        Some("") | None => Ok(None),
        Some(raw) => raw
            .parse::<Uuid>()
            .map(Some)
            .map_err(|_| AppError::bad_request("parent_group_id must be a UUID")),
    }
}

// ─── Roles ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExpandedRoleGrant {
    pub root_role_id: Uuid,
    pub role_id: Uuid,
    pub role_name: String,
    pub role_path: String,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub capability_id: Uuid,
}

pub async fn create_role(pool: &PgPool, req: CreateRole) -> Result<Role, AppError> {
    let id = Uuid::new_v4();
    sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn create_role_with_assignments(
    pool: &PgPool,
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
        crate::guardrails::validate_role_assignment_plan(
            pool,
            member_entity_ids,
            capability_ids,
            req.tenant_id,
            parsed_scope_kind.clone(),
            scope_ref.as_deref(),
        )
        .await?;
    } else {
        validate_composite_children(pool, id, req.tenant_id, child_role_ids).await?;
        crate::guardrails::validate_composite_role_assignment_plan(
            pool,
            member_entity_ids,
            child_role_ids,
            req.tenant_id,
        )
        .await?;
    }

    let mut tx = pool.begin().await.map_err(db_err)?;
    let role = sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .fetch_one(&mut *tx)
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

    for child_role_id in child_role_ids {
        copy_role_permission_blocks(&mut tx, role.id, *child_role_id).await?;
    }

    for member_id in member_entity_ids {
        sqlx::query(
            r#"INSERT INTO role_assignments
                 (tenant_id, subject_kind, subject_id, role_id)
               VALUES ($1, 'entity', $2, $3)"#,
        )
        .bind(req.tenant_id)
        .bind(member_id)
        .bind(role.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if let Some(tenant_id) = req.tenant_id {
            sqlx::query(
                r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
                   SELECT $1, $2, 'active'
                   WHERE EXISTS (
                       SELECT 1 FROM entities
                       WHERE id = $2 AND kind = 'human'
                   )
                   ON CONFLICT (tenant_id, entity_id)
                   DO UPDATE SET status = 'active'"#,
            )
            .bind(tenant_id)
            .bind(member_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
    }

    tx.commit().await.map_err(db_err)?;
    Ok(role)
}

pub async fn create_role_with_permission_blocks(
    pool: &PgPool,
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
    let role = sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    for block in permission_blocks {
        insert_role_permission_block(&mut tx, role.id, block).await?;
    }

    for member_id in member_entity_ids {
        sqlx::query(
            r#"INSERT INTO role_assignments
                 (tenant_id, subject_kind, subject_id, role_id)
               VALUES ($1, 'entity', $2, $3)"#,
        )
        .bind(req.tenant_id)
        .bind(member_id)
        .bind(role.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if let Some(tenant_id) = req.tenant_id {
            sqlx::query(
                r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
                   SELECT $1, $2, 'active'
                   WHERE EXISTS (
                       SELECT 1 FROM entities
                       WHERE id = $2 AND kind = 'human'
                   )
                   ON CONFLICT (tenant_id, entity_id)
                   DO UPDATE SET status = 'active'"#,
            )
            .bind(tenant_id)
            .bind(member_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
    }

    tx.commit().await.map_err(db_err)?;
    Ok(role)
}

pub async fn replace_role_permission_blocks(
    pool: &PgPool,
    role_id: Uuid,
    permission_blocks: &[CreateRolePermissionBlock],
) -> Result<(), AppError> {
    if permission_blocks.is_empty() {
        return Err(AppError::bad_request("role permission blocks are required"));
    }
    validate_role_permission_blocks(pool, permission_blocks).await?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query(
        r#"DELETE FROM permission_blocks
           WHERE id IN (
             SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1
           )"#,
    )
    .bind(role_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    for block in permission_blocks {
        insert_role_permission_block(&mut tx, role_id, block).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn replace_role_permission_block_links(
    pool: &PgPool,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<(), AppError> {
    let role_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?
            .ok_or_else(|| AppError::not_found(format!("role {role_id} not found")))?;

    let mut unique_block_ids = permission_block_ids.to_vec();
    unique_block_ids.sort_unstable();
    unique_block_ids.dedup();

    if !unique_block_ids.is_empty() {
        let count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM permission_blocks
               WHERE id = ANY($1::uuid[])
                 AND tenant_id IS NOT DISTINCT FROM $2"#,
        )
        .bind(&unique_block_ids)
        .bind(role_tenant_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
        if count != unique_block_ids.len() as i64 {
            return Err(AppError::bad_request(
                "role permission blocks must exist and belong to the same tenant as the role",
            ));
        }
    }
    crate::guardrails::validate_role_permission_block_links(pool, role_id, &unique_block_ids)
        .await?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query("DELETE FROM role_permission_blocks WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    for permission_block_id in unique_block_ids {
        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(role_id)
        .bind(permission_block_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    tx.commit().await.map_err(db_err)
}

async fn insert_role_permission_block(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    block: &CreateRolePermissionBlock,
) -> Result<Uuid, AppError> {
    let (scope_mode, tenant_id, object_kind, object_type, object_id, group_id) =
        permission_block_scope_columns(block);
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
             (scope_mode, tenant_id, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, 'allow', '{}'::jsonb)
           RETURNING id"#,
    )
    .bind(scope_mode)
    .bind(tenant_id)
    .bind(object_kind)
    .bind(object_type)
    .bind(object_id)
    .bind(group_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;

    for capability_id in &block.capability_ids {
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(block_id)
        .bind(capability_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }

    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    Ok(block_id)
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
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    tenant_id: Option<Uuid>,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
    capability_id: Uuid,
) -> Result<Uuid, AppError> {
    let block = permission_block_from_legacy_scope(tenant_id, scope_kind, scope_ref)?;
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
             (scope_mode, tenant_id, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, 'allow', '{}'::jsonb)
           RETURNING id"#,
    )
    .bind(block.scope_mode)
    .bind(block.tenant_id)
    .bind(block.object_kind)
    .bind(block.object_type)
    .bind(block.object_id)
    .bind(block.group_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
           VALUES ($1, $2)"#,
    )
    .bind(block_id)
    .bind(capability_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
           VALUES ($1, $2)"#,
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(block_id)
}

async fn copy_role_permission_blocks(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    target_role_id: Uuid,
    source_role_id: Uuid,
) -> Result<(), AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT pb.id, pb.tenant_id, pb.scope_mode, pb.object_kind, pb.object_type,
                  pb.object_id, pb.group_id, pb.effect, pb.conditions
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE rpb.role_id = $1"#,
    )
    .bind(source_role_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)?;

    for row in rows {
        let source_block_id: Uuid = row.try_get("id").map_err(db_err)?;
        let copied_block_id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO permission_blocks
                 (tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id"#,
        )
        .bind(row.try_get::<Option<Uuid>, _>("tenant_id").map_err(db_err)?)
        .bind(row.try_get::<String, _>("scope_mode").map_err(db_err)?)
        .bind(row.try_get::<Option<String>, _>("object_kind").map_err(db_err)?)
        .bind(row.try_get::<Option<String>, _>("object_type").map_err(db_err)?)
        .bind(row.try_get::<Option<Uuid>, _>("object_id").map_err(db_err)?)
        .bind(row.try_get::<Option<Uuid>, _>("group_id").map_err(db_err)?)
        .bind(row.try_get::<String, _>("effect").map_err(db_err)?)
        .bind(row.try_get::<Value, _>("conditions").map_err(db_err)?)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_err)?;
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               SELECT $1, action_id
               FROM permission_block_actions
               WHERE permission_block_id = $2"#,
        )
        .bind(copied_block_id)
        .bind(source_block_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)"#,
        )
        .bind(target_role_id)
        .bind(copied_block_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }

    Ok(())
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
    pool: &PgPool,
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
    pool: &PgPool,
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
    pool: &PgPool,
    role_id: Uuid,
) -> Result<Vec<RolePermissionBlock>, AppError> {
    sqlx::query_as::<_, RolePermissionBlock>(
        r#"SELECT pb.id,
                  rpb.role_id,
                  CASE
                    WHEN pb.scope_mode = 'group_direct_objects' THEN 'object_group_type'
                    WHEN pb.scope_mode = 'group_descendant_objects' THEN 'object_group_tree_type'
                    WHEN pb.scope_mode = 'group_child_groups' THEN 'object_group_child_kind'
                    WHEN pb.scope_mode = 'group_descendant_groups' THEN 'object_group_descendant_kind'
                    ELSE pb.scope_mode
                  END AS applies_to,
                  pb.object_id,
                  pb.object_kind,
                  pb.object_type,
                  pb.tenant_id,
                  pb.group_id,
                  pb.created_at,
                  pb.updated_at
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE rpb.role_id = $1
           ORDER BY pb.created_at, pb.id"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn list_permission_blocks_for_role(
    pool: &PgPool,
    role_id: Uuid,
) -> Result<Vec<PermissionBlock>, AppError> {
    sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT pb.id,
                  pb.tenant_id,
                  pb.scope_mode,
                  pb.object_kind,
                  pb.object_type,
                  pb.object_id,
                  pb.group_id,
                  pb.effect,
                  pb.conditions,
                  pb.created_at,
                  pb.updated_at
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE rpb.role_id = $1
           ORDER BY pb.created_at, pb.id"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn role_permission_block_capabilities(
    pool: &PgPool,
    block_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"SELECT c.id, c.name, c.description, c.created_at, c.updated_at
           FROM actions c
           JOIN permission_block_actions pba ON pba.action_id = c.id
           WHERE pba.permission_block_id = $1
           ORDER BY c.name"#,
    )
    .bind(block_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn permission_block_capabilities(
    pool: &PgPool,
    block_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    role_permission_block_capabilities(pool, block_id).await
}

pub async fn get_permission_block(pool: &PgPool, id: Uuid) -> Result<PermissionBlock, AppError> {
    sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id,
                  effect, conditions, created_at, updated_at
           FROM permission_blocks
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("permission block {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_permission_blocks(
    pool: &PgPool,
    params: ListPermissionBlocks,
) -> Result<PermissionBlockList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id,
                  effect, conditions, created_at, updated_at
           FROM permission_blocks
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR scope_mode = $2)
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(params.tenant_id)
    .bind(params.scope_mode.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM permission_blocks
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR scope_mode = $2)"#,
    )
    .bind(params.tenant_id)
    .bind(params.scope_mode)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(PermissionBlockList { items, total })
}

pub async fn create_permission_block(
    pool: &PgPool,
    req: CreatePermissionBlock,
) -> Result<PermissionBlock, AppError> {
    validate_permission_block_input(pool, &req).await?;
    let conditions = if req.conditions.is_null() {
        serde_json::json!({})
    } else {
        req.conditions
    };
    let mut tx = pool.begin().await.map_err(db_err)?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
             (tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id"#,
    )
    .bind(req.tenant_id)
    .bind(&req.scope_mode)
    .bind(req.object_kind.as_deref())
    .bind(req.object_type.as_deref())
    .bind(req.object_id)
    .bind(req.group_id)
    .bind(req.effect)
    .bind(conditions)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    for action_id in req.action_ids {
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(id)
        .bind(action_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }
    tx.commit().await.map_err(db_err)?;
    get_permission_block(pool, id).await
}

pub async fn delete_permission_block(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM permission_blocks WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!(
            "permission block {id} not found"
        )));
    }
    Ok(())
}

async fn validate_permission_block_input(
    pool: &PgPool,
    req: &CreatePermissionBlock,
) -> Result<(), AppError> {
    if req.action_ids.is_empty() {
        return Err(AppError::bad_request(
            "permission block requires at least one action",
        ));
    }
    let target = permission_block_input_target(pool, req).await?;
    validate_capabilities_against_target(pool, &req.action_ids, target).await
}

async fn permission_block_input_target(
    pool: &PgPool,
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
            resolve_exact_object_target(pool, object_id)
                .await?
                .map(Some)
                .ok_or_else(|| {
                    AppError::bad_request("object permission block references unknown object")
                })
        }
        "group" => {
            validate_object_group_boundary(pool, req.tenant_id, req.group_id).await?;
            Ok(Some(CapabilityValidationTarget {
                object_kind: "group".to_string(),
                object_type: None,
            }))
        }
        "group_direct_objects" | "group_descendant_objects" => {
            validate_object_group_boundary(pool, req.tenant_id, req.group_id).await?;
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
            validate_object_group_boundary(pool, req.tenant_id, req.group_id).await?;
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
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    group_id: Option<Uuid>,
) -> Result<(), AppError> {
    let group_id =
        group_id.ok_or_else(|| AppError::bad_request("object group scope requires groupId"))?;
    let group_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM object_groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(pool)
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

pub async fn get_role(pool: &PgPool, id: Uuid) -> Result<Role, AppError> {
    sqlx::query_as::<_, Role>(
        r#"SELECT id, name, tenant_id, description, created_at, updated_at
           FROM roles WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("role {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_roles(pool: &PgPool, params: ListRoles) -> Result<RoleList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);
    let derived_kind = params
        .derived_kind
        .as_deref()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .map(str::to_ascii_lowercase);

    if let Some(kind) = derived_kind.as_deref() {
        match kind {
            "simple" | "composite" | "empty" => {}
            _ => {
                return Err(AppError::bad_request(
                    "derivedKind must be simple, composite, or empty",
                ));
            }
        }
    }

    let items = sqlx::query_as::<_, Role>(
        r#"SELECT id, name, tenant_id, description, created_at, updated_at
           FROM roles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR name ILIKE $2 OR description ILIKE $2)
             AND (
               $3::text IS NULL
               OR ($3 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
               OR ($3 = 'composite' AND FALSE)
               OR ($3 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
             )
           ORDER BY name LIMIT $4 OFFSET $5"#,
    )
    .bind(params.tenant_id)
    .bind(q.clone())
    .bind(derived_kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM roles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR name ILIKE $2 OR description ILIKE $2)
             AND (
               $3::text IS NULL
               OR ($3 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
               OR ($3 = 'composite' AND FALSE)
               OR ($3 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
             )"#,
    )
    .bind(params.tenant_id)
    .bind(q)
    .bind(derived_kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleList { items, total })
}

pub async fn role_derived_kind(pool: &PgPool, role_id: Uuid) -> Result<RoleDerivedKind, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT
              EXISTS (SELECT 1 FROM role_permission_blocks WHERE role_id = $1) AS has_permission_blocks,
              FALSE AS has_children"#,
    )
    .bind(role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let has_permission_blocks: bool = row.try_get("has_permission_blocks").map_err(db_err)?;
    let has_children: bool = row.try_get("has_children").map_err(db_err)?;
    let has_simple_permissions = has_permission_blocks;
    Ok(match (has_simple_permissions, has_children) {
        (true, false) => RoleDerivedKind::Simple,
        (false, true) => RoleDerivedKind::Composite,
        (false, false) => RoleDerivedKind::Empty,
        (true, true) => {
            return Err(AppError::bad_request(
                "role cannot have both permissions and child roles",
            ))
        }
    })
}

pub async fn child_roles(pool: &PgPool, role_id: Uuid) -> Result<Vec<Role>, AppError> {
    let _ = (pool, role_id);
    Ok(Vec::new())
}

pub async fn parent_roles(pool: &PgPool, role_id: Uuid) -> Result<Vec<Role>, AppError> {
    let _ = (pool, role_id);
    Ok(Vec::new())
}

async fn ensure_entities_exist(pool: &PgPool, entity_ids: &[Uuid]) -> Result<(), AppError> {
    if entity_ids.is_empty() {
        return Ok(());
    }
    let mut unique_entity_ids = entity_ids.to_vec();
    unique_entity_ids.sort_unstable();
    unique_entity_ids.dedup();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entities WHERE id = ANY($1::uuid[])")
        .bind(&unique_entity_ids)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    if count != unique_entity_ids.len() as i64 {
        return Err(AppError::bad_request("invalid member reference"));
    }
    Ok(())
}

async fn validate_composite_children(
    pool: &PgPool,
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

    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT r.id, r.tenant_id,
                  EXISTS (SELECT 1 FROM effective_role_actions() rc WHERE rc.role_id = r.id) AS has_capabilities,
                  FALSE AS has_children
           FROM roles r
           WHERE r.id = ANY($1::uuid[])"#,
    )
    .bind(&unique_child_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    if rows.len() != unique_child_ids.len() {
        return Err(AppError::bad_request("invalid child role reference"));
    }

    for row in rows {
        let child_id: Uuid = row.try_get("id").map_err(db_err)?;
        let tenant_id: Option<Uuid> = row.try_get("tenant_id").map_err(db_err)?;
        let has_capabilities: bool = row.try_get("has_capabilities").map_err(db_err)?;
        let has_children: bool = row.try_get("has_children").map_err(db_err)?;
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
    pool: &PgPool,
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
                sqlx::query_scalar("SELECT tenant_id FROM groups WHERE id = $1")
                    .bind(group_id)
                    .fetch_optional(pool)
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
    pool: &PgPool,
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
    capability_ids: &[Uuid],
) -> Result<(), AppError> {
    let target = role_scope_capability_target(pool, scope_kind, scope_ref).await?;
    validate_capabilities_against_target(pool, capability_ids, target).await
}

async fn role_scope_capability_target(
    pool: &PgPool,
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
    pool: &PgPool,
    capability_ids: &[Uuid],
    target: Option<CapabilityValidationTarget>,
) -> Result<(), AppError> {
    if capability_ids.is_empty() {
        return Ok(());
    }

    let mut unique_capability_ids = capability_ids.to_vec();
    unique_capability_ids.sort_unstable();
    unique_capability_ids.dedup();

    use sqlx::Row;
    let rows = sqlx::query("SELECT id, name FROM actions WHERE id = ANY($1::uuid[])")
        .bind(&unique_capability_ids)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    let capability_names = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.try_get("id").map_err(db_err)?;
            let name: String = row.try_get("name").map_err(db_err)?;
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

    let invalid_rows = sqlx::query(
        r#"SELECT c.name
           FROM actions c
           WHERE c.id = ANY($1::uuid[])
             AND NOT EXISTS (
               SELECT 1
               FROM action_applicability ca
               WHERE ca.action_id = c.id
                 AND ca.object_kind = $2
                 AND ($3::text IS NULL OR ca.object_type IS NULL OR ca.object_type = $3)
             )
           ORDER BY c.name"#,
    )
    .bind(&unique_capability_ids)
    .bind(&target.object_kind)
    .bind(&target.object_type)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    if let Some(row) = invalid_rows.first() {
        let name: String = row.try_get("name").map_err(db_err)?;
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
    pool: &PgPool,
    object_id: Uuid,
) -> Result<Option<CapabilityValidationTarget>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT object_kind, object_type
           FROM (
             SELECT 'entity'::text AS object_kind, ('entity:' || kind)::text AS object_type
             FROM entities
             WHERE id = $1
             UNION ALL
             SELECT 'resource'::text AS object_kind, ('resource:' || kind)::text AS object_type
             FROM resources
             WHERE id = $1
             UNION ALL
             SELECT 'group'::text AS object_kind, NULL::text AS object_type
             FROM groups
             WHERE id = $1
             UNION ALL
             SELECT 'tenant'::text AS object_kind, NULL::text AS object_type
             FROM tenants
             WHERE id = $1
             UNION ALL
             SELECT 'role'::text AS object_kind, NULL::text AS object_type
             FROM roles
             WHERE id = $1
             UNION ALL
             SELECT 'policy'::text AS object_kind, NULL::text AS object_type
             FROM effective_access_edges()
             WHERE id = $1
             UNION ALL
             SELECT 'credential'::text AS object_kind, NULL::text AS object_type
             FROM credentials
             WHERE id = $1
           ) AS objects
           LIMIT 1"#,
    )
    .bind(object_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    row.map(|row| {
        Ok(CapabilityValidationTarget {
            object_kind: row.try_get("object_kind").map_err(db_err)?,
            object_type: row.try_get("object_type").map_err(db_err)?,
        })
    })
    .transpose()
}

pub async fn update_role(pool: &PgPool, id: Uuid, req: UpdateRole) -> Result<Role, AppError> {
    sqlx::query_as::<_, Role>(
        r#"UPDATE roles
           SET name        = COALESCE($2, name),
               description = COALESCE($3, description),
               updated_at  = now()
           WHERE id = $1
           RETURNING id, name, tenant_id, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.description)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("role {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn delete_role(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("role {id} not found")));
    }
    Ok(())
}

pub async fn add_role_capability(
    pool: &PgPool,
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
    crate::guardrails::validate_role_capability(pool, role_id, cap_id).await?;
    let mut tx = pool.begin().await.map_err(db_err)?;
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
    pool: &PgPool,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    copy_role_permission_blocks(&mut tx, parent_role_id, child_role_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn remove_composite_role_child(
    pool: &PgPool,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> Result<(), AppError> {
    let _ = (pool, parent_role_id, child_role_id);
    Ok(())
}

pub async fn replace_composite_role_children(
    pool: &PgPool,
    parent_role_id: Uuid,
    child_role_ids: &[Uuid],
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query(
        r#"DELETE FROM permission_blocks
           WHERE id IN (
             SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1
           )"#,
    )
    .bind(parent_role_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    for child_role_id in child_role_ids {
        copy_role_permission_blocks(&mut tx, parent_role_id, *child_role_id).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn remove_role_capability(
    pool: &PgPool,
    role_id: Uuid,
    cap_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"DELETE FROM permission_blocks
           WHERE id IN (
             SELECT rpb.permission_block_id
             FROM role_permission_blocks rpb
             JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
             WHERE rpb.role_id = $1 AND pba.action_id = $2
           )"#,
    )
    .bind(role_id)
    .bind(cap_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn get_role_capabilities(
    pool: &PgPool,
    role_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"SELECT c.id, c.name, c.description, c.created_at, c.updated_at
           FROM actions c
           JOIN effective_role_actions() rc ON rc.capability_id = c.id
           WHERE rc.role_id = $1"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

// ─── Capabilities ─────────────────────────────────────────────────────────────

pub async fn create_capability(
    pool: &PgPool,
    req: CreateCapability,
) -> Result<Capability, AppError> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let capability = sqlx::query_as::<_, Capability>(
        r#"INSERT INTO actions (id, name, description)
           VALUES ($1, $2, $3)
           RETURNING id, name, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.description)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    let applicability = req.applicability.unwrap_or_default();
    if !applicability.is_empty() {
        replace_capability_applicability_in_tx(&mut tx, id, &applicability).await?;
    }
    tx.commit().await.map_err(AppError::Database)?;
    Ok(capability)
}

pub async fn get_capability(pool: &PgPool, id: Uuid) -> Result<Capability, AppError> {
    sqlx::query_as::<_, Capability>(
        "SELECT id, name, description, created_at, updated_at FROM actions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("capability {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_capabilities(
    pool: &PgPool,
    params: ListCapabilities,
) -> Result<crate::models::capability::CapabilityList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let items = sqlx::query_as::<_, Capability>(
        r#"SELECT id, name, description, created_at, updated_at FROM actions c
           WHERE (
               $1::text IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM action_applicability ca
                   WHERE ca.action_id = c.id
                     AND ca.object_kind = $1
                     AND ($2::text IS NULL OR ca.object_type IS NULL OR ca.object_type = $2)
               )
           )
           ORDER BY name LIMIT $3 OFFSET $4"#,
    )
    .bind(&params.object_kind)
    .bind(&params.object_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM actions c
           WHERE (
               $1::text IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM action_applicability ca
                   WHERE ca.action_id = c.id
                     AND ca.object_kind = $1
                     AND ($2::text IS NULL OR ca.object_type IS NULL OR ca.object_type = $2)
               )
           )"#,
    )
    .bind(&params.object_kind)
    .bind(&params.object_type)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(crate::models::capability::CapabilityList { items, total })
}

pub async fn capability_applicability(
    pool: &PgPool,
    capability_id: Uuid,
) -> Result<Vec<CapabilityApplicability>, AppError> {
    sqlx::query_as::<_, CapabilityApplicability>(
        r#"SELECT object_kind, object_type
           FROM action_applicability
           WHERE action_id = $1
           ORDER BY object_kind, object_type NULLS FIRST"#,
    )
    .bind(capability_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn list_capability_applicability(
    pool: &PgPool,
    action_name: Option<String>,
    object_kind: Option<String>,
    object_type: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<CapabilityApplicabilityList, AppError> {
    let limit = limit.clamp(1, 100);
    let offset = offset.max(0);
    let action_name = action_name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let object_kind = object_kind
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let object_type = object_type
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let action_pattern = action_name.as_ref().map(|value| format!("%{value}%"));

    let items = sqlx::query_as::<_, CapabilityApplicabilityEntry>(
        r#"SELECT c.id AS capability_id,
                  c.name AS capability_name,
                  c.description,
                  ca.object_kind,
                  ca.object_type,
                  ca.created_at
           FROM action_applicability ca
           JOIN actions c ON c.id = ca.action_id
           WHERE ($3::text IS NULL OR c.name ILIKE $3)
             AND ($4::text IS NULL OR ca.object_kind = $4)
             AND ($5::text IS NULL OR ca.object_type = $5)
           ORDER BY c.name, ca.object_kind, ca.object_type NULLS FIRST
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(&action_pattern)
    .bind(&object_kind)
    .bind(&object_type)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM action_applicability ca
           JOIN actions c ON c.id = ca.action_id
           WHERE ($1::text IS NULL OR c.name ILIKE $1)
             AND ($2::text IS NULL OR ca.object_kind = $2)
             AND ($3::text IS NULL OR ca.object_type = $3)"#,
    )
    .bind(&action_pattern)
    .bind(&object_kind)
    .bind(&object_type)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(CapabilityApplicabilityList { items, total })
}

pub async fn get_action_assignment_rule(
    pool: &PgPool,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    sqlx::query_as::<_, ActionAssignmentRule>(
        r#"SELECT id, tenant_id, entity_kind, action_name, object_kind, object_type,
                  decision, is_absolute, created_at
           FROM action_assignment_rules
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::not_found(format!("action assignment rule {id} not found"))
        }
        other => AppError::Database(other),
    })
}

pub async fn list_action_assignment_rules(
    pool: &PgPool,
    params: ListActionAssignmentRules,
) -> Result<ActionAssignmentRuleList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let action_name = normalize_optional_text(params.action_name);
    let action_pattern = action_name.as_ref().map(|value| format!("%{value}%"));
    let object_type = normalize_optional_text(params.object_type);

    let items = sqlx::query_as::<_, ActionAssignmentRule>(
        r#"SELECT id, tenant_id, entity_kind, action_name, object_kind, object_type,
                  decision, is_absolute, created_at
           FROM action_assignment_rules
           WHERE tenant_id IS NOT DISTINCT FROM $3
             AND ($4::text IS NULL OR entity_kind = $4)
             AND ($5::text IS NULL OR action_name ILIKE $5)
             AND ($6::text IS NULL OR object_kind = $6)
             AND ($7::text IS NULL OR object_type = $7)
             AND ($8::text IS NULL OR decision = $8)
           ORDER BY entity_kind, action_name, object_kind, object_type NULLS FIRST, decision
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(params.tenant_id)
    .bind(&params.entity_kind)
    .bind(&action_pattern)
    .bind(params.object_kind)
    .bind(&object_type)
    .bind(params.decision)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM action_assignment_rules
           WHERE tenant_id IS NOT DISTINCT FROM $1
             AND ($2::text IS NULL OR entity_kind = $2)
             AND ($3::text IS NULL OR action_name ILIKE $3)
             AND ($4::text IS NULL OR object_kind = $4)
             AND ($5::text IS NULL OR object_type = $5)
             AND ($6::text IS NULL OR decision = $6)"#,
    )
    .bind(params.tenant_id)
    .bind(&params.entity_kind)
    .bind(&action_pattern)
    .bind(params.object_kind)
    .bind(&object_type)
    .bind(params.decision)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ActionAssignmentRuleList { items, total })
}

pub async fn create_action_assignment_rule(
    pool: &PgPool,
    req: CreateActionAssignmentRule,
) -> Result<ActionAssignmentRule, AppError> {
    let action_name = req.action_name.trim().to_string();
    if action_name.is_empty() {
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

    let object_type = normalize_optional_text(req.object_type);
    validate_rule_object_type(req.object_kind, object_type.as_deref())?;

    let action_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM actions WHERE name = $1)")
            .bind(&action_name)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    if !action_exists {
        return Err(AppError::bad_request(format!(
            "actionName references unknown action {action_name}"
        )));
    }

    let duplicate: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
             SELECT 1
             FROM action_assignment_rules
             WHERE tenant_id IS NOT DISTINCT FROM $1
               AND entity_kind = $2
               AND action_name = $3
               AND object_kind = $4
               AND object_type IS NOT DISTINCT FROM $5
           )"#,
    )
    .bind(req.tenant_id)
    .bind(&req.entity_kind)
    .bind(&action_name)
    .bind(req.object_kind)
    .bind(&object_type)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    if duplicate {
        return Err(AppError::conflict("action assignment rule already exists"));
    }

    sqlx::query_as::<_, ActionAssignmentRule>(
        r#"INSERT INTO action_assignment_rules
             (tenant_id, entity_kind, action_name, object_kind, object_type, decision, is_absolute)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, tenant_id, entity_kind, action_name, object_kind, object_type,
                     decision, is_absolute, created_at"#,
    )
    .bind(req.tenant_id)
    .bind(req.entity_kind)
    .bind(action_name)
    .bind(req.object_kind)
    .bind(object_type)
    .bind(req.decision)
    .bind(req.is_absolute)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn delete_action_assignment_rule(
    pool: &PgPool,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    sqlx::query_as::<_, ActionAssignmentRule>(
        r#"DELETE FROM action_assignment_rules
           WHERE id = $1
           RETURNING id, tenant_id, entity_kind, action_name, object_kind, object_type,
                     decision, is_absolute, created_at"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::not_found(format!("action assignment rule {id} not found"))
        }
        other => AppError::Database(other),
    })
}

pub async fn add_capability_applicability(
    pool: &PgPool,
    capability_id: Uuid,
    object_kind: String,
    object_type: Option<String>,
) -> Result<CapabilityApplicabilityEntry, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM actions WHERE id = $1)")
            .bind(capability_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
    if !exists {
        return Err(AppError::not_found(format!(
            "capability {capability_id} not found"
        )));
    }

    sqlx::query(
        r#"INSERT INTO action_applicability (action_id, object_kind, object_type)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(capability_id)
    .bind(&object_kind)
    .bind(&object_type)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let entry = sqlx::query_as::<_, CapabilityApplicabilityEntry>(
        r#"SELECT c.id AS capability_id,
                  c.name AS capability_name,
                  c.description,
                  ca.object_kind,
                  ca.object_type,
                  ca.created_at
           FROM action_applicability ca
           JOIN actions c ON c.id = ca.action_id
           WHERE ca.action_id = $1
             AND ca.object_kind = $2
             AND ca.object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(capability_id)
    .bind(&object_kind)
    .bind(&object_type)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(AppError::Database)?;
    Ok(entry)
}

pub async fn remove_capability_applicability(
    pool: &PgPool,
    capability_id: Uuid,
    object_kind: String,
    object_type: Option<String>,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"DELETE FROM action_applicability
           WHERE action_id = $1
             AND object_kind = $2
             AND object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(capability_id)
    .bind(object_kind)
    .bind(object_type)
    .execute(pool)
    .await
    .map_err(db_err)?;

    if result.rows_affected() == 0 {
        return Err(AppError::not_found(
            "capability applicability row not found",
        ));
    }
    Ok(())
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
    pool: &PgPool,
    id: Uuid,
    req: crate::models::capability::UpdateCapability,
) -> Result<Capability, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let updated = sqlx::query_as::<_, Capability>(
        r#"UPDATE actions
           SET name          = COALESCE($2, name),
               description   = COALESCE($3, description),
               updated_at    = now()
           WHERE id = $1
           RETURNING id, name, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.description)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("capability {id} not found")),
        other => AppError::Database(other),
    })?;

    if let Some(applicability) = req.applicability {
        replace_capability_applicability_in_tx(&mut tx, id, &applicability).await?;
    }

    tx.commit().await.map_err(AppError::Database)?;
    Ok(updated)
}

async fn replace_capability_applicability_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    capability_id: Uuid,
    applicability: &[CapabilityApplicabilityInput],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM action_applicability WHERE action_id = $1")
        .bind(capability_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;

    let mut seen = HashSet::new();
    for item in applicability {
        if !seen.insert((item.object_kind.as_str(), item.object_type.as_deref())) {
            continue;
        }
        sqlx::query(
            r#"INSERT INTO action_applicability (action_id, object_kind, object_type)
               VALUES ($1, $2, $3)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(capability_id)
        .bind(&item.object_kind)
        .bind(&item.object_type)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }

    Ok(())
}

pub async fn delete_capability(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM actions WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("capability {id} not found")));
    }
    Ok(())
}

// ─── Policy Bindings ──────────────────────────────────────────────────────────

pub async fn create_policy(
    pool: &PgPool,
    req: CreatePolicyBinding,
) -> Result<PolicyBinding, AppError> {
    crate::guardrails::validate_policy(pool, &req).await?;
    let id = Uuid::new_v4();
    let membership_tenant_id = req.tenant_id;
    let membership_entity_id = req.subject_id;
    let should_sync_membership = req.tenant_id.is_some()
        && req.subject_kind == SubjectKind::Entity
        && req.effect == Effect::Allow;
    let conditions = if req.conditions.is_null() {
        serde_json::json!({})
    } else {
        req.conditions
    };
    let mut tx = pool.begin().await.map_err(db_err)?;
    match req.grant_kind {
        GrantKind::Role => {
            if req.effect != Effect::Allow || conditions != serde_json::json!({}) {
                return Err(AppError::bad_request(
                    "role assignment supports only allow effect without conditions; use direct policy for deny or conditional grants",
                ));
            }
            sqlx::query(
                r#"INSERT INTO role_assignments
                     (id, tenant_id, subject_kind, subject_id, role_id)
                   VALUES ($1, $2, $3, $4, $5)"#,
            )
            .bind(id)
            .bind(req.tenant_id)
            .bind(req.subject_kind)
            .bind(req.subject_id)
            .bind(req.grant_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        GrantKind::Capability => {
            let block = permission_block_from_legacy_scope(
                req.tenant_id,
                &req.scope_kind,
                req.scope_ref.as_deref(),
            )?;
            let permission_block_id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO permission_blocks
                     (tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   RETURNING id"#,
            )
            .bind(block.tenant_id)
            .bind(block.scope_mode)
            .bind(block.object_kind)
            .bind(block.object_type)
            .bind(block.object_id)
            .bind(block.group_id)
            .bind(req.effect)
            .bind(conditions)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            sqlx::query(
                r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
                   VALUES ($1, $2)"#,
            )
            .bind(permission_block_id)
            .bind(req.grant_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            sqlx::query(
                r#"INSERT INTO direct_policies
                     (id, tenant_id, subject_kind, subject_id, permission_block_id)
                   VALUES ($1, $2, $3, $4, $5)"#,
            )
            .bind(id)
            .bind(req.tenant_id)
            .bind(req.subject_kind)
            .bind(req.subject_id)
            .bind(permission_block_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
    }
    tx.commit().await.map_err(db_err)?;

    let policy = get_policy(pool, id).await?;

    if should_sync_membership {
        if let Some(tenant_id) = membership_tenant_id {
            sync_tenant_membership_for_policy(pool, tenant_id, membership_entity_id).await?;
        }
    }

    Ok(policy)
}

async fn sync_tenant_membership_for_policy(
    pool: &PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
           SELECT $1, $2, 'active'
           WHERE EXISTS (
               SELECT 1 FROM entities
               WHERE id = $2 AND kind = 'human'
           )
           ON CONFLICT (tenant_id, entity_id)
           DO UPDATE SET status = 'active'"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(pool)
    .await
    .map_err(db_err)?;

    Ok(())
}

pub async fn get_policy(pool: &PgPool, id: Uuid) -> Result<PolicyBinding, AppError> {
    sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at
           FROM effective_access_edges() WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("policy {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_policies(pool: &PgPool, params: ListPolicies) -> Result<PolicyList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let tenant_id = params.tenant_id;
    let subject_id = params.subject_id;
    let subject_kind = params.subject_kind;

    let items = sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at
           FROM effective_access_edges()
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::uuid IS NULL OR subject_id = $2)
             AND ($3::text IS NULL OR subject_kind = $3)
           ORDER BY created_at DESC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(subject_kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM effective_access_edges()
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::uuid IS NULL OR subject_id = $2)
             AND ($3::text IS NULL OR subject_kind = $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(subject_kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(PolicyList { items, total })
}

pub async fn role_policies(
    pool: &PgPool,
    role_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<PolicyList, AppError> {
    let limit = limit.clamp(1, 100);
    let offset = offset.max(0);

    let items = sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, grant_kind, grant_id,
                  scope_kind, scope_ref, effect, conditions, created_at
           FROM effective_access_edges()
           WHERE grant_kind = 'role' AND grant_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(role_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM effective_access_edges()
           WHERE grant_kind = 'role' AND grant_id = $1"#,
    )
    .bind(role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(PolicyList { items, total })
}

pub async fn create_role_assignment(
    pool: &PgPool,
    req: CreateRoleAssignment,
) -> Result<RoleAssignment, AppError> {
    validate_role_assignment(pool, &req).await?;
    sqlx::query_as::<_, RoleAssignment>(
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, $2, $3, $4)
           RETURNING id, tenant_id, subject_kind, subject_id, role_id, created_at"#,
    )
    .bind(req.tenant_id)
    .bind(req.subject_kind)
    .bind(req.subject_id)
    .bind(req.role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn list_role_assignments(
    pool: &PgPool,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, RoleAssignment>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at
           FROM role_assignments
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR role_id = $4)
           ORDER BY created_at DESC
           LIMIT $5 OFFSET $6"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind.clone())
    .bind(params.subject_id)
    .bind(params.role_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM role_assignments
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR role_id = $4)"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind)
    .bind(params.subject_id)
    .bind(params.role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleAssignmentList { items, total })
}

pub async fn get_role_assignment(pool: &PgPool, id: Uuid) -> Result<RoleAssignment, AppError> {
    sqlx::query_as::<_, RoleAssignment>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at
           FROM role_assignments
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("role assignment {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn delete_role_assignment(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM role_assignments WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!(
            "role assignment {id} not found"
        )));
    }
    Ok(())
}

pub async fn create_direct_policy(
    pool: &PgPool,
    req: CreateDirectPolicy,
) -> Result<DirectPolicy, AppError> {
    validate_direct_policy(pool, &req).await?;
    crate::guardrails::validate_direct_policy(pool, &req).await?;
    sqlx::query_as::<_, DirectPolicy>(
        r#"INSERT INTO direct_policies
             (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, $2, $3, $4)
           RETURNING id, tenant_id, subject_kind, subject_id, permission_block_id, created_at"#,
    )
    .bind(req.tenant_id)
    .bind(req.subject_kind)
    .bind(req.subject_id)
    .bind(req.permission_block_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn list_direct_policies(
    pool: &PgPool,
    params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, DirectPolicy>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, permission_block_id, created_at
           FROM direct_policies
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR permission_block_id = $4)
           ORDER BY created_at DESC
           LIMIT $5 OFFSET $6"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind.clone())
    .bind(params.subject_id)
    .bind(params.permission_block_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM direct_policies
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR permission_block_id = $4)"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind)
    .bind(params.subject_id)
    .bind(params.permission_block_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(DirectPolicyList { items, total })
}

pub async fn get_direct_policy(pool: &PgPool, id: Uuid) -> Result<DirectPolicy, AppError> {
    sqlx::query_as::<_, DirectPolicy>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, permission_block_id, created_at
           FROM direct_policies
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("direct policy {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn delete_direct_policy(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM direct_policies WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("direct policy {id} not found")));
    }
    Ok(())
}

async fn validate_role_assignment(
    pool: &PgPool,
    req: &CreateRoleAssignment,
) -> Result<(), AppError> {
    let role_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1")
            .bind(req.role_id)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?
            .ok_or_else(|| AppError::bad_request("role assignment references unknown role"))?;
    if role_tenant_id != req.tenant_id {
        return Err(AppError::bad_request(
            "role assignment tenantId must match role tenantId",
        ));
    }
    validate_subject_boundary(pool, req.tenant_id, &req.subject_kind, req.subject_id).await?;
    crate::guardrails::validate_role_assignment(
        pool,
        req.tenant_id,
        req.subject_kind.clone(),
        req.subject_id,
        req.role_id,
    )
    .await
}

async fn validate_direct_policy(pool: &PgPool, req: &CreateDirectPolicy) -> Result<(), AppError> {
    let block_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM permission_blocks WHERE id = $1")
            .bind(req.permission_block_id)
            .fetch_optional(pool)
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
    validate_subject_boundary(pool, req.tenant_id, &req.subject_kind, req.subject_id).await
}

async fn validate_subject_boundary(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<(), AppError> {
    match subject_kind {
        SubjectKind::Entity => {
            let entity_tenant_id: Option<Uuid> =
                sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
                    .bind(subject_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(db_err)?
                    .ok_or_else(|| AppError::bad_request("assignment references unknown entity"))?;
            if let Some(tenant_id) = tenant_id {
                let member: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS (
                         SELECT 1 FROM tenant_memberships
                         WHERE tenant_id = $1 AND entity_id = $2 AND status = 'active'
                       )"#,
                )
                .bind(tenant_id)
                .bind(subject_id)
                .fetch_one(pool)
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
                sqlx::query_scalar("SELECT tenant_id FROM principal_groups WHERE id = $1")
                    .bind(subject_id)
                    .fetch_optional(pool)
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
    pool: &PgPool,
    params: SubjectRoleAssignmentsQuery,
) -> Result<SubjectRoleAssignmentList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);
    let derived_kind = params
        .derived_kind
        .as_deref()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .map(str::to_ascii_lowercase);

    if let Some(kind) = derived_kind.as_deref() {
        match kind {
            "simple" | "composite" | "empty" => {}
            _ => {
                return Err(AppError::bad_request(
                    "derivedKind must be simple, composite, or empty",
                ));
            }
        }
    }

    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT
             pb.id AS policy_id,
             pb.tenant_id AS policy_tenant_id,
             pb.subject_kind,
             pb.subject_id,
             pb.grant_kind,
             pb.grant_id,
             pb.scope_kind AS policy_scope_kind,
             pb.scope_ref AS policy_scope_ref,
             pb.effect,
             pb.conditions,
             pb.created_at AS policy_created_at,
             r.id AS role_id,
             r.name AS role_name,
             r.tenant_id AS role_tenant_id,
             r.description AS role_description,
             r.created_at AS role_created_at,
             r.updated_at AS role_updated_at
           FROM effective_access_edges() pb
           JOIN roles r ON pb.grant_kind = 'role' AND pb.grant_id = r.id
           WHERE ($1::uuid IS NULL OR pb.tenant_id = $1)
             AND pb.subject_kind = $2
             AND pb.subject_id = $3
             AND ($4::text IS NULL OR r.name ILIKE $4 OR r.description ILIKE $4)
             AND (
               $5::text IS NULL
               OR ($5 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
               OR ($5 = 'composite' AND FALSE)
               OR ($5 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
             )
           ORDER BY pb.created_at DESC
           LIMIT $6 OFFSET $7"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind.clone())
    .bind(params.subject_id)
    .bind(q.clone())
    .bind(derived_kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let items = rows
        .into_iter()
        .map(|row| {
            Ok(SubjectRoleAssignment {
                policy: PolicyBinding {
                    id: row.try_get("policy_id").map_err(db_err)?,
                    tenant_id: row.try_get("policy_tenant_id").map_err(db_err)?,
                    subject_kind: row.try_get("subject_kind").map_err(db_err)?,
                    subject_id: row.try_get("subject_id").map_err(db_err)?,
                    grant_kind: row.try_get("grant_kind").map_err(db_err)?,
                    grant_id: row.try_get("grant_id").map_err(db_err)?,
                    scope_kind: row.try_get("policy_scope_kind").map_err(db_err)?,
                    scope_ref: row.try_get("policy_scope_ref").map_err(db_err)?,
                    effect: row.try_get("effect").map_err(db_err)?,
                    conditions: row.try_get("conditions").map_err(db_err)?,
                    created_at: row.try_get("policy_created_at").map_err(db_err)?,
                },
                role: Role {
                    id: row.try_get("role_id").map_err(db_err)?,
                    name: row.try_get("role_name").map_err(db_err)?,
                    tenant_id: row.try_get("role_tenant_id").map_err(db_err)?,
                    description: row.try_get("role_description").map_err(db_err)?,
                    created_at: row.try_get("role_created_at").map_err(db_err)?,
                    updated_at: row.try_get("role_updated_at").map_err(db_err)?,
                },
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM effective_access_edges() pb
           JOIN roles r ON pb.grant_kind = 'role' AND pb.grant_id = r.id
           WHERE ($1::uuid IS NULL OR pb.tenant_id = $1)
             AND pb.subject_kind = $2
             AND pb.subject_id = $3
             AND ($4::text IS NULL OR r.name ILIKE $4 OR r.description ILIKE $4)
             AND (
               $5::text IS NULL
               OR ($5 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
               OR ($5 = 'composite' AND FALSE)
               OR ($5 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
             )"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind)
    .bind(params.subject_id)
    .bind(q)
    .bind(derived_kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(SubjectRoleAssignmentList { items, total })
}

pub async fn delete_policy(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let direct_block_id: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM direct_policies WHERE id = $1 RETURNING permission_block_id",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    if let Some(block_id) = direct_block_id {
        sqlx::query("DELETE FROM permission_blocks WHERE id = $1")
            .bind(block_id)
            .execute(pool)
            .await
            .map_err(db_err)?;
        return Ok(());
    }

    let result = sqlx::query("DELETE FROM role_assignments WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("policy {id} not found")));
    }
    Ok(())
}

/// Best-effort ownership lookup for exact-object policy scopes. `None` means
/// no object with that UUID exists in the known Atom object tables; `Some(None)`
/// means the object is platform/global.
pub async fn object_tenant_id_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    let row = sqlx::query(
        r#"SELECT tenant_id FROM (
             SELECT tenant_id FROM entities WHERE id = $1
             UNION ALL
             SELECT tenant_id FROM groups WHERE id = $1
             UNION ALL
             SELECT tenant_id FROM resources WHERE id = $1
             UNION ALL
             SELECT tenant_id FROM roles WHERE id = $1
             UNION ALL
             SELECT tenant_id FROM effective_access_edges() WHERE id = $1
             UNION ALL
             SELECT t.id AS tenant_id FROM tenants t WHERE t.id = $1
             UNION ALL
             SELECT e.tenant_id FROM credentials c JOIN entities e ON e.id = c.entity_id WHERE c.id = $1
             UNION ALL
             SELECT tenant_id FROM audit_logs WHERE id = $1
           ) matches
           LIMIT 1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    row.map(|r| {
        use sqlx::Row;
        r.try_get::<Option<Uuid>, _>("tenant_id").map_err(db_err)
    })
    .transpose()
}

// ─── Query Views ──────────────────────────────────────────────────────────────

pub async fn entity_access(
    pool: &PgPool,
    entity_id: Uuid,
    params: AccessQuery,
) -> Result<EntityAccessResponse, AppError> {
    let entity = sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, alias, tenant_id, profile_id, profile_version_id,
                  status, attributes, created_at, updated_at
           FROM entities
           WHERE id = $1"#,
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {entity_id} not found")),
        other => AppError::Database(other),
    })?;

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let action_cap = optional_capability_id(pool, params.action.as_deref()).await?;
    if params.action.is_some() && action_cap.is_none() {
        return Ok(EntityAccessResponse {
            entity_id: entity.id,
            entity_name: entity.name,
            entity_kind: entity.kind,
            items: Vec::new(),
            total: 0,
        });
    }

    let items = sqlx::query(
        r#"WITH bindings AS (
             SELECT pb.*, 'direct'::text AS via
             FROM effective_access_edges() pb
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $1
             UNION ALL
             SELECT pb.*, ('group:' || g.name)::text AS via
             FROM effective_access_edges() pb
             JOIN group_members gm ON gm.group_id = pb.subject_id
             JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
             WHERE pb.subject_kind = 'group' AND gm.entity_id = $1
           ), expanded AS (
             SELECT b.id AS policy_id, b.grant_kind, b.grant_id, b.scope_kind, b.scope_ref,
                    b.effect, b.conditions, b.via, r.id AS resource_id, r.kind AS resource_kind,
                    r.name AS resource_name, r.tenant_id AS resource_tenant_id,
                    role.id AS role_id, role.name AS role_name
             FROM bindings b
             JOIN resources r ON
               b.scope_kind = 'platform'
               OR (b.scope_kind = 'object_kind' AND b.scope_ref = 'resource')
               OR (b.scope_kind = 'object_type' AND b.scope_ref = 'resource:' || r.kind)
               OR (b.scope_kind = 'object' AND b.scope_ref = r.id::text)
             LEFT JOIN roles role ON b.grant_kind = 'role' AND role.id = b.grant_id
             WHERE ($2::uuid IS NULL OR r.tenant_id = $2)
               AND ($3::text IS NULL OR r.kind = $3)
               AND ($4::text IS NULL OR b.effect = $4)
               AND (
                 $5::uuid IS NULL
                 OR (b.grant_kind = 'capability' AND b.grant_id = $5)
                 OR (b.grant_kind = 'role' AND EXISTS (
                   SELECT 1 FROM effective_role_actions() rc
                   WHERE rc.role_id = b.grant_id AND rc.capability_id = $5
                 ))
               )
           )
           SELECT e.*,
                  COALESCE(jsonb_agg(jsonb_build_object(
                    'id', c.id,
                    'name', c.name
                  ) ORDER BY c.name) FILTER (WHERE c.id IS NOT NULL), '[]'::jsonb) AS capabilities
           FROM expanded e
           LEFT JOIN effective_role_actions() rc ON e.grant_kind = 'role' AND rc.role_id = e.grant_id
           LEFT JOIN actions c ON
             (e.grant_kind = 'capability' AND c.id = e.grant_id)
             OR (e.grant_kind = 'role' AND c.id = rc.capability_id)
           GROUP BY e.policy_id, e.grant_kind, e.grant_id, e.scope_kind, e.scope_ref,
                    e.effect, e.conditions, e.via, e.resource_id, e.resource_kind,
                    e.resource_name, e.resource_tenant_id, e.role_id, e.role_name
           ORDER BY e.resource_kind, e.resource_name NULLS LAST, e.policy_id
           LIMIT $6 OFFSET $7"#,
    )
    .bind(entity_id)
    .bind(params.tenant_id)
    .bind(params.resource_kind.clone())
    .bind(params.effect.clone())
    .bind(action_cap)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"WITH bindings AS (
             SELECT pb.* FROM effective_access_edges() pb
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $1
             UNION ALL
             SELECT pb.* FROM effective_access_edges() pb
             JOIN group_members gm ON gm.group_id = pb.subject_id
             WHERE pb.subject_kind = 'group' AND gm.entity_id = $1
           )
           SELECT COUNT(*)
           FROM bindings b
           JOIN resources r ON
             b.scope_kind = 'platform'
             OR (b.scope_kind = 'object_kind' AND b.scope_ref = 'resource')
             OR (b.scope_kind = 'object_type' AND b.scope_ref = 'resource:' || r.kind)
             OR (b.scope_kind = 'object' AND b.scope_ref = r.id::text)
           WHERE ($2::uuid IS NULL OR r.tenant_id = $2)
             AND ($3::text IS NULL OR r.kind = $3)
             AND ($4::text IS NULL OR b.effect = $4)
             AND (
               $5::uuid IS NULL
               OR (b.grant_kind = 'capability' AND b.grant_id = $5)
               OR (b.grant_kind = 'role' AND EXISTS (
                 SELECT 1 FROM effective_role_actions() rc
                 WHERE rc.role_id = b.grant_id AND rc.capability_id = $5
               ))
             )"#,
    )
    .bind(entity_id)
    .bind(params.tenant_id)
    .bind(params.resource_kind)
    .bind(params.effect)
    .bind(action_cap)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(EntityAccessResponse {
        entity_id: entity.id,
        entity_name: entity.name,
        entity_kind: entity.kind,
        items: rows_to_access_items(items)?,
        total,
    })
}

pub async fn resource_access(
    pool: &PgPool,
    resource_id: Uuid,
    params: ResourceAccessQuery,
) -> Result<ResourceAccessResponse, AppError> {
    use sqlx::Row;

    let resource = get_resource(pool, resource_id).await?;
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let action_cap = optional_capability_id(pool, params.action.as_deref()).await?;
    let resource_id_str = resource_id.to_string();
    if params.action.is_some() && action_cap.is_none() {
        return Ok(ResourceAccessResponse {
            resource_id,
            resource: ResourceSummary {
                id: resource.id,
                kind: resource.kind,
                name: resource.name,
                tenant_id: resource.tenant_id,
            },
            items: Vec::new(),
            total: 0,
        });
    }

    let base_sql = r#"WITH covered AS (
             SELECT pb.*, e.id AS entity_id, e.name AS entity_name, e.kind AS entity_kind,
                    e.tenant_id AS entity_tenant_id, 'direct'::text AS via
             FROM effective_access_edges() pb
             JOIN entities e ON pb.subject_kind = 'entity' AND e.id = pb.subject_id
             WHERE pb.scope_kind = 'platform'
                OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource')
                OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || $1)
                OR (pb.scope_kind = 'object' AND pb.scope_ref = $2)
             UNION ALL
             SELECT pb.*, e.id AS entity_id, e.name AS entity_name, e.kind AS entity_kind,
                    e.tenant_id AS entity_tenant_id, ('group:' || g.name)::text AS via
             FROM effective_access_edges() pb
             JOIN groups g ON pb.subject_kind = 'group' AND g.id = pb.subject_id
             JOIN group_members gm ON gm.group_id = g.id
             JOIN entities e ON e.id = gm.entity_id
             WHERE pb.scope_kind = 'platform'
                OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource')
                OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || $1)
                OR (pb.scope_kind = 'object' AND pb.scope_ref = $2)
           ), filtered AS (
             SELECT c.*, role.id AS role_id, role.name AS role_name
             FROM covered c
             LEFT JOIN roles role ON c.grant_kind = 'role' AND role.id = c.grant_id
             WHERE ($3::text IS NULL OR c.entity_kind = $3)
               AND ($4::text IS NULL OR c.effect = $4)
               AND (
                 $5::uuid IS NULL
                 OR (c.grant_kind = 'capability' AND c.grant_id = $5)
                 OR (c.grant_kind = 'role' AND EXISTS (
                   SELECT 1 FROM effective_role_actions() rc
                   WHERE rc.role_id = c.grant_id AND rc.capability_id = $5
                 ))
               )
           )"#;

    let rows = sqlx::query(&format!(
        r#"{base_sql}
           SELECT f.id AS policy_id, f.grant_kind, f.grant_id, f.scope_kind, f.scope_ref,
                  f.effect, f.conditions, f.via, f.entity_id, f.entity_name, f.entity_kind,
                  f.entity_tenant_id, f.role_id, f.role_name,
                  COALESCE(jsonb_agg(jsonb_build_object(
                    'id', cap.id,
                    'name', cap.name
                  ) ORDER BY cap.name) FILTER (WHERE cap.id IS NOT NULL), '[]'::jsonb) AS capabilities
           FROM filtered f
           LEFT JOIN effective_role_actions() rc ON f.grant_kind = 'role' AND rc.role_id = f.grant_id
           LEFT JOIN actions cap ON
             (f.grant_kind = 'capability' AND cap.id = f.grant_id)
             OR (f.grant_kind = 'role' AND cap.id = rc.capability_id)
           GROUP BY f.id, f.grant_kind, f.grant_id, f.scope_kind, f.scope_ref, f.effect,
                    f.conditions, f.via, f.entity_id, f.entity_name, f.entity_kind,
                    f.entity_tenant_id, f.role_id, f.role_name
           ORDER BY f.entity_name, f.id
           LIMIT $6 OFFSET $7"#
    ))
    .bind(&resource.kind)
    .bind(&resource_id_str)
    .bind(params.entity_kind.clone())
    .bind(params.effect.clone())
    .bind(action_cap)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(&format!("{base_sql} SELECT COUNT(*) FROM filtered"))
        .bind(&resource.kind)
        .bind(&resource_id_str)
        .bind(params.entity_kind)
        .bind(params.effect)
        .bind(action_cap)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    let items = rows
        .into_iter()
        .map(|row| {
            let caps: Value = row.try_get("capabilities").map_err(db_err)?;
            Ok(ResourceAccessItem {
                entity: ResourceAccessEntity {
                    id: row.try_get("entity_id").map_err(db_err)?,
                    name: row.try_get("entity_name").map_err(db_err)?,
                    kind: row.try_get("entity_kind").map_err(db_err)?,
                    tenant_id: row.try_get("entity_tenant_id").map_err(db_err)?,
                },
                effect: row.try_get("effect").map_err(db_err)?,
                scope_kind: row.try_get("scope_kind").map_err(db_err)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                policy_id: row.try_get("policy_id").map_err(db_err)?,
                grant: grant_from_row(&row, caps)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
                via: row.try_get("via").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    Ok(ResourceAccessResponse {
        resource_id,
        resource: ResourceSummary {
            id: resource.id,
            kind: resource.kind,
            name: resource.name,
            tenant_id: resource.tenant_id,
        },
        items,
        total,
    })
}

pub async fn group_access(
    pool: &PgPool,
    group_id: Uuid,
    params: GroupAccessQuery,
) -> Result<GroupAccessResponse, AppError> {
    let group = get_group_with_count(pool, group_id).await?;
    let query = AccessQuery {
        tenant_id: None,
        resource_kind: params.resource_kind,
        action: params.action,
        effect: params.effect,
        limit: params.limit,
        offset: params.offset,
    };
    let response = subject_access(pool, SubjectKind::Group, group_id, query, false).await?;
    Ok(GroupAccessResponse {
        group_id,
        group: GroupInfo {
            name: group.1.name,
            tenant_id: group.1.tenant_id,
            member_count: group.0,
        },
        items: response
            .items
            .into_iter()
            .map(|item| GroupAccessItem {
                resource: item.resource,
                effect: item.effect,
                scope_kind: item.scope_kind,
                scope_ref: item.scope_ref,
                policy_id: item.policy_id,
                grant: item.grant,
                conditions: item.conditions,
            })
            .collect(),
        total: response.total,
    })
}

async fn subject_access(
    pool: &PgPool,
    subject_kind: SubjectKind,
    subject_id: Uuid,
    params: AccessQuery,
    include_groups: bool,
) -> Result<EntityAccessResponse, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let action_cap = optional_capability_id(pool, params.action.as_deref()).await?;
    let tenant_id = params.tenant_id;
    let resource_kind = params.resource_kind.clone();
    let effect = params.effect.clone();
    if params.action.is_some() && action_cap.is_none() {
        return Ok(EntityAccessResponse {
            entity_id: subject_id,
            entity_name: String::new(),
            entity_kind: crate::models::enums::EntityKind::Service,
            items: Vec::new(),
            total: 0,
        });
    }

    let group_clause = if include_groups {
        r#"UNION ALL
           SELECT pb.*, ('group:' || g.name)::text AS via
           FROM effective_access_edges() pb
           JOIN group_members gm ON gm.group_id = pb.subject_id
           JOIN groups g ON g.id = gm.group_id
           WHERE pb.subject_kind = 'group' AND gm.entity_id = $2"#
    } else {
        ""
    };
    let direct_via = if subject_kind == SubjectKind::Group {
        "'group'::text"
    } else {
        "'direct'::text"
    };
    let base_sql = format!(
        r#"WITH bindings AS (
             SELECT pb.*, {direct_via} AS via
             FROM effective_access_edges() pb
             WHERE pb.subject_kind = $1 AND pb.subject_id = $2
             {group_clause}
           ), expanded AS (
             SELECT b.id AS policy_id, b.grant_kind, b.grant_id, b.scope_kind, b.scope_ref,
                    b.effect, b.conditions, b.via, r.id AS resource_id, r.kind AS resource_kind,
                    r.name AS resource_name, r.tenant_id AS resource_tenant_id,
                    role.id AS role_id, role.name AS role_name
             FROM bindings b
             JOIN resources r ON
               b.scope_kind = 'platform'
               OR (b.scope_kind = 'object_kind' AND b.scope_ref = 'resource')
               OR (b.scope_kind = 'object_type' AND b.scope_ref = 'resource:' || r.kind)
               OR (b.scope_kind = 'object' AND b.scope_ref = r.id::text)
             LEFT JOIN roles role ON b.grant_kind = 'role' AND role.id = b.grant_id
             WHERE ($3::uuid IS NULL OR r.tenant_id = $3)
               AND ($4::text IS NULL OR r.kind = $4)
               AND ($5::text IS NULL OR b.effect = $5)
               AND (
                 $6::uuid IS NULL
                 OR (b.grant_kind = 'capability' AND b.grant_id = $6)
                 OR (b.grant_kind = 'role' AND EXISTS (
                   SELECT 1 FROM effective_role_actions() rc
                   WHERE rc.role_id = b.grant_id AND rc.capability_id = $6
                 ))
               )
           )"#
    );
    let sql = format!(
        r#"{base_sql}
           SELECT e.*,
                  COALESCE(jsonb_agg(jsonb_build_object(
                    'id', c.id,
                    'name', c.name
                  ) ORDER BY c.name) FILTER (WHERE c.id IS NOT NULL), '[]'::jsonb) AS capabilities
           FROM expanded e
           LEFT JOIN effective_role_actions() rc ON e.grant_kind = 'role' AND rc.role_id = e.grant_id
           LEFT JOIN actions c ON
             (e.grant_kind = 'capability' AND c.id = e.grant_id)
             OR (e.grant_kind = 'role' AND c.id = rc.capability_id)
           GROUP BY e.policy_id, e.grant_kind, e.grant_id, e.scope_kind, e.scope_ref,
                    e.effect, e.conditions, e.via, e.resource_id, e.resource_kind,
                    e.resource_name, e.resource_tenant_id, e.role_id, e.role_name
           ORDER BY e.resource_kind, e.resource_name NULLS LAST, e.policy_id
           LIMIT $7 OFFSET $8"#
    );
    let rows = sqlx::query(&sql)
        .bind(subject_kind.clone())
        .bind(subject_id)
        .bind(tenant_id)
        .bind(resource_kind.clone())
        .bind(effect.clone())
        .bind(action_cap)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(&format!("{base_sql} SELECT COUNT(*) FROM expanded"))
        .bind(subject_kind)
        .bind(subject_id)
        .bind(tenant_id)
        .bind(resource_kind)
        .bind(effect)
        .bind(action_cap)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    Ok(EntityAccessResponse {
        entity_id: subject_id,
        entity_name: String::new(),
        entity_kind: crate::models::enums::EntityKind::Service,
        total,
        items: rows_to_access_items(rows)?,
    })
}

pub async fn role_holders(
    pool: &PgPool,
    role_id: Uuid,
    params: RoleHoldersQuery,
) -> Result<RoleHoldersResponse, AppError> {
    use sqlx::Row;
    let role = get_role(pool, role_id).await?;
    let capabilities = get_role_capabilities(pool, role_id)
        .await?
        .into_iter()
        .map(|cap| CapabilitySummary {
            id: cap.id,
            name: cap.name,
        })
        .collect();
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let rows = sqlx::query(
        r#"SELECT pb.id AS policy_id, pb.subject_kind, pb.effect, pb.scope_kind, pb.scope_ref,
                  pb.conditions,
                  e.id AS entity_id, e.name AS entity_name, e.kind AS entity_kind,
                  e.tenant_id AS entity_tenant_id,
                  g.id AS group_id, g.name AS group_name, g.tenant_id AS group_tenant_id,
                  COALESCE(gmc.member_count, 0)::bigint AS member_count
           FROM effective_access_edges() pb
           LEFT JOIN entities e ON pb.subject_kind = 'entity' AND e.id = pb.subject_id
           LEFT JOIN groups g ON pb.subject_kind = 'group' AND g.id = pb.subject_id
           LEFT JOIN (
             SELECT group_id, COUNT(*) AS member_count
             FROM group_members GROUP BY group_id
           ) gmc ON gmc.group_id = g.id
           WHERE pb.grant_kind = 'role'
             AND pb.grant_id = $1
             AND ($2::uuid IS NULL OR e.tenant_id = $2 OR g.tenant_id = $2)
             AND ($3::text IS NULL OR pb.subject_kind = $3)
           ORDER BY pb.created_at DESC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(role_id)
    .bind(params.tenant_id)
    .bind(params.subject_kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM effective_access_edges() pb
           LEFT JOIN entities e ON pb.subject_kind = 'entity' AND e.id = pb.subject_id
           LEFT JOIN groups g ON pb.subject_kind = 'group' AND g.id = pb.subject_id
           WHERE pb.grant_kind = 'role'
             AND pb.grant_id = $1
             AND ($2::uuid IS NULL OR e.tenant_id = $2 OR g.tenant_id = $2)
             AND ($3::text IS NULL OR pb.subject_kind = $3)"#,
    )
    .bind(role_id)
    .bind(params.tenant_id)
    .bind(params.subject_kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    let items = rows
        .into_iter()
        .map(|row| {
            let subject_kind: SubjectKind = row.try_get("subject_kind").map_err(db_err)?;
            let entity = match subject_kind {
                SubjectKind::Entity => Some(EntitySummary {
                    id: row.try_get("entity_id").map_err(db_err)?,
                    name: row.try_get("entity_name").map_err(db_err)?,
                    kind: row.try_get("entity_kind").map_err(db_err)?,
                    tenant_id: row.try_get("entity_tenant_id").map_err(db_err)?,
                }),
                SubjectKind::Group => None,
            };
            let group = match subject_kind {
                SubjectKind::Entity => None,
                SubjectKind::Group => Some(RoleHolderGroup {
                    id: row.try_get("group_id").map_err(db_err)?,
                    name: row.try_get("group_name").map_err(db_err)?,
                    tenant_id: row.try_get("group_tenant_id").map_err(db_err)?,
                    member_count: row.try_get("member_count").map_err(db_err)?,
                }),
            };
            Ok(RoleHolderItem {
                subject_kind,
                entity,
                group,
                policy_id: row.try_get("policy_id").map_err(db_err)?,
                effect: row.try_get("effect").map_err(db_err)?,
                scope_kind: row.try_get("scope_kind").map_err(db_err)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    Ok(RoleHoldersResponse {
        role: RoleWithCapabilities {
            id: role.id,
            name: role.name,
            tenant_id: role.tenant_id,
            description: role.description,
            capabilities,
        },
        items,
        total,
    })
}

pub async fn authorized_object_ids(
    pool: &PgPool,
    params: AuthorizedObjectIdsQuery,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    match params.object_kind.as_str() {
        "entity" => authorized_entity_ids(pool, params).await,
        "resource" => authorized_resource_ids(pool, params).await,
        other => Err(AppError::bad_request(format!(
            "authorized object listing does not support object kind '{other}'"
        ))),
    }
}

async fn authorized_entity_ids(
    pool: &PgPool,
    params: AuthorizedObjectIdsQuery,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);

    let sql = r#"WITH RECURSIVE subject_groups(group_id) AS (
                   SELECT gm.group_id
                   FROM group_members gm
                   JOIN groups g ON g.id = gm.group_id
                    AND g.status = 'active'
                    AND g.group_type = 'principal'
                   WHERE gm.entity_id = $1
               ),
               target_groups(id) AS (
                   SELECT $8::uuid WHERE $8::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $9::boolean
               ),
               candidates AS (
                   SELECT e.id, e.kind::text AS sub_kind, e.tenant_id, e.created_at,
                          gep.group_id AS parent_group_id
                   FROM entities e
                   LEFT JOIN group_entity_parents gep ON gep.entity_id = e.id
                   WHERE ($3::uuid IS NULL OR e.tenant_id = $3)
                     AND ($4::text IS NULL OR e.kind::text = $4 OR 'entity:' || e.kind::text = $4)
                     AND ($5::text IS NULL OR e.name ILIKE $5 OR e.attributes::text ILIKE $5)
                     AND ($6::uuid IS NULL OR e.profile_id = $6)
                     AND ($7::text IS NULL OR e.status::text = $7)
                     AND ($8::uuid IS NULL OR gep.group_id IN (SELECT id FROM target_groups))
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = c.parent_group_id
                   UNION ALL
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               matching_capabilities AS (
                   SELECT c.id AS capability_id, ca.object_kind, ca.object_type
                   FROM actions c
                   JOIN action_applicability ca ON ca.action_id = c.id
                   WHERE c.name = $2
               ),
               role_grants AS (
                   SELECT rpb.role_id AS root_role_id,
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
                          pba.action_id AS capability_id
                   FROM role_permission_blocks rpb
                   JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
                   JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
               ),
               authorized AS (
                   SELECT c.id, c.created_at
                   FROM candidates c
                   WHERE EXISTS (
                       SELECT 1
                       FROM effective_access_edges() pb
                       WHERE ((pb.subject_kind = 'entity' AND pb.subject_id = $1)
                           OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM subject_groups)))
                         AND pb.effect = 'allow'
                         AND pb.conditions = '{}'::jsonb
                         AND (
                             (
                               pb.grant_kind = 'capability'
                               AND EXISTS (
                                   SELECT 1 FROM matching_capabilities mc
                                   WHERE mc.capability_id = pb.grant_id
                                     AND mc.object_kind = 'entity'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                               )
                               AND (
                                   pb.scope_kind = 'platform'
                                   OR (pb.scope_kind = 'tenant' AND pb.scope_ref = c.tenant_id::text)
                                   OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'entity')
                                   OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'entity:' || c.sub_kind)
                                   OR (pb.scope_kind = 'object' AND pb.scope_ref = c.id::text)
                                   OR (pb.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND pb.scope_ref = c.parent_group_id::text || ':entity:' || c.sub_kind)
                                   OR (pb.scope_kind = 'group_tree_object_type' AND EXISTS (
                                       SELECT 1 FROM candidate_ancestors ca
                                       WHERE ca.object_id = c.id
                                         AND pb.scope_ref = ca.ancestor_id::text || ':entity:' || c.sub_kind
                                   ))
                               )
                             )
                             OR (
                               pb.grant_kind = 'role'
                               AND EXISTS (
                                   SELECT 1
                                   FROM role_grants rg
                                   JOIN matching_capabilities mc ON mc.capability_id = rg.capability_id
                                   WHERE rg.root_role_id = pb.grant_id
                                     AND mc.object_kind = 'entity'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                                     AND (
                                         rg.scope_kind = 'platform'
                                         OR (rg.scope_kind = 'tenant' AND rg.scope_ref = c.tenant_id::text)
                                         OR (rg.scope_kind = 'object_kind' AND rg.scope_ref = 'entity')
                                         OR (rg.scope_kind = 'object_type' AND rg.scope_ref = 'entity:' || c.sub_kind)
                                         OR (rg.scope_kind = 'object' AND rg.scope_ref = c.id::text)
                                         OR (rg.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND rg.scope_ref = c.parent_group_id::text || ':entity:' || c.sub_kind)
                                         OR (rg.scope_kind = 'group_tree_object_type' AND EXISTS (
                                             SELECT 1 FROM candidate_ancestors ca
                                             WHERE ca.object_id = c.id
                                               AND rg.scope_ref = ca.ancestor_id::text || ':entity:' || c.sub_kind
                                         ))
                                     )
                               )
                             )
                         )
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM effective_access_edges() pb
                         WHERE ((pb.subject_kind = 'entity' AND pb.subject_id = $1)
                           OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM subject_groups)))
                         AND pb.effect = 'deny'
                         AND (
                             (
                               pb.grant_kind = 'capability'
                               AND EXISTS (
                                   SELECT 1 FROM matching_capabilities mc
                                   WHERE mc.capability_id = pb.grant_id
                                     AND mc.object_kind = 'entity'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                               )
                               AND (
                                   pb.scope_kind = 'platform'
                                   OR (pb.scope_kind = 'tenant' AND pb.scope_ref = c.tenant_id::text)
                                   OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'entity')
                                   OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'entity:' || c.sub_kind)
                                   OR (pb.scope_kind = 'object' AND pb.scope_ref = c.id::text)
                                   OR (pb.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND pb.scope_ref = c.parent_group_id::text || ':entity:' || c.sub_kind)
                                   OR (pb.scope_kind = 'group_tree_object_type' AND EXISTS (
                                       SELECT 1 FROM candidate_ancestors ca
                                       WHERE ca.object_id = c.id
                                         AND pb.scope_ref = ca.ancestor_id::text || ':entity:' || c.sub_kind
                                   ))
                               )
                             )
                             OR (
                               pb.grant_kind = 'role'
                               AND EXISTS (
                                   SELECT 1
                                   FROM role_grants rg
                                   JOIN matching_capabilities mc ON mc.capability_id = rg.capability_id
                                   WHERE rg.root_role_id = pb.grant_id
                                     AND mc.object_kind = 'entity'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                                     AND (
                                         rg.scope_kind = 'platform'
                                         OR (rg.scope_kind = 'tenant' AND rg.scope_ref = c.tenant_id::text)
                                         OR (rg.scope_kind = 'object_kind' AND rg.scope_ref = 'entity')
                                         OR (rg.scope_kind = 'object_type' AND rg.scope_ref = 'entity:' || c.sub_kind)
                                         OR (rg.scope_kind = 'object' AND rg.scope_ref = c.id::text)
                                         OR (rg.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND rg.scope_ref = c.parent_group_id::text || ':entity:' || c.sub_kind)
                                         OR (rg.scope_kind = 'group_tree_object_type' AND EXISTS (
                                             SELECT 1 FROM candidate_ancestors ca
                                             WHERE ca.object_id = c.id
                                               AND rg.scope_ref = ca.ancestor_id::text || ':entity:' || c.sub_kind
                                         ))
                                     )
                               )
                             )
                         )
                   )
               )
               SELECT id, COUNT(*) OVER() AS total
               FROM authorized
               ORDER BY created_at DESC
               LIMIT $10 OFFSET $11"#;

    let rows = sqlx::query(sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.object_type)
        .bind(q)
        .bind(params.profile_id)
        .bind(params.entity_status.map(|status| match status {
            crate::models::enums::EntityStatus::Active => "active".to_string(),
            crate::models::enums::EntityStatus::Inactive => "inactive".to_string(),
            crate::models::enums::EntityStatus::Suspended => "suspended".to_string(),
        }))
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    rows_to_authorized_object_ids(rows)
}

async fn authorized_resource_ids(
    pool: &PgPool,
    params: AuthorizedObjectIdsQuery,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);

    let sql = r#"WITH RECURSIVE subject_groups(group_id) AS (
                   SELECT gm.group_id
                   FROM group_members gm
                   JOIN groups g ON g.id = gm.group_id
                    AND g.status = 'active'
                    AND g.group_type = 'principal'
                   WHERE gm.entity_id = $1
               ),
               target_groups(id) AS (
                   SELECT $6::uuid WHERE $6::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $7::boolean
               ),
               candidates AS (
                   SELECT r.id, r.kind AS sub_kind, r.tenant_id, r.created_at,
                          grp.group_id AS parent_group_id
                   FROM resources r
                   LEFT JOIN group_resource_parents grp ON grp.resource_id = r.id
                   WHERE ($3::uuid IS NULL OR r.tenant_id = $3)
                     AND ($4::text IS NULL OR r.kind = $4 OR 'resource:' || r.kind = $4)
                     AND ($5::text IS NULL OR r.name ILIKE $5 OR r.attributes::text ILIKE $5)
                     AND ($6::uuid IS NULL OR grp.group_id IN (SELECT id FROM target_groups))
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = c.parent_group_id
                   UNION ALL
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               matching_capabilities AS (
                   SELECT c.id AS capability_id, ca.object_kind, ca.object_type
                   FROM actions c
                   JOIN action_applicability ca ON ca.action_id = c.id
                   WHERE c.name = $2
               ),
               role_grants AS (
                   SELECT rpb.role_id AS root_role_id,
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
                          pba.action_id AS capability_id
                   FROM role_permission_blocks rpb
                   JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
                   JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
               ),
               authorized AS (
                   SELECT c.id, c.created_at
                   FROM candidates c
                   WHERE EXISTS (
                       SELECT 1
                       FROM effective_access_edges() pb
                       WHERE ((pb.subject_kind = 'entity' AND pb.subject_id = $1)
                           OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM subject_groups)))
                         AND pb.effect = 'allow'
                         AND pb.conditions = '{}'::jsonb
                         AND (
                             (
                               pb.grant_kind = 'capability'
                               AND EXISTS (
                                   SELECT 1 FROM matching_capabilities mc
                                   WHERE mc.capability_id = pb.grant_id
                                     AND mc.object_kind = 'resource'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                               )
                               AND (
                                   pb.scope_kind = 'platform'
                                   OR (pb.scope_kind = 'tenant' AND pb.scope_ref = c.tenant_id::text)
                                   OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource')
                                   OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || c.sub_kind)
                                   OR (pb.scope_kind = 'object' AND pb.scope_ref = c.id::text)
                                   OR (pb.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND pb.scope_ref = c.parent_group_id::text || ':resource:' || c.sub_kind)
                                   OR (pb.scope_kind = 'group_tree_object_type' AND EXISTS (
                                       SELECT 1 FROM candidate_ancestors ca
                                       WHERE ca.object_id = c.id
                                         AND pb.scope_ref = ca.ancestor_id::text || ':resource:' || c.sub_kind
                                   ))
                               )
                             )
                             OR (
                               pb.grant_kind = 'role'
                               AND EXISTS (
                                   SELECT 1
                                   FROM role_grants rg
                                   JOIN matching_capabilities mc ON mc.capability_id = rg.capability_id
                                   WHERE rg.root_role_id = pb.grant_id
                                     AND mc.object_kind = 'resource'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                                     AND (
                                         rg.scope_kind = 'platform'
                                         OR (rg.scope_kind = 'tenant' AND rg.scope_ref = c.tenant_id::text)
                                         OR (rg.scope_kind = 'object_kind' AND rg.scope_ref = 'resource')
                                         OR (rg.scope_kind = 'object_type' AND rg.scope_ref = 'resource:' || c.sub_kind)
                                         OR (rg.scope_kind = 'object' AND rg.scope_ref = c.id::text)
                                         OR (rg.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND rg.scope_ref = c.parent_group_id::text || ':resource:' || c.sub_kind)
                                         OR (rg.scope_kind = 'group_tree_object_type' AND EXISTS (
                                             SELECT 1 FROM candidate_ancestors ca
                                             WHERE ca.object_id = c.id
                                               AND rg.scope_ref = ca.ancestor_id::text || ':resource:' || c.sub_kind
                                         ))
                                     )
                               )
                             )
                         )
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM effective_access_edges() pb
                         WHERE ((pb.subject_kind = 'entity' AND pb.subject_id = $1)
                           OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM subject_groups)))
                         AND pb.effect = 'deny'
                         AND (
                             (
                               pb.grant_kind = 'capability'
                               AND EXISTS (
                                   SELECT 1 FROM matching_capabilities mc
                                   WHERE mc.capability_id = pb.grant_id
                                     AND mc.object_kind = 'resource'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                               )
                               AND (
                                   pb.scope_kind = 'platform'
                                   OR (pb.scope_kind = 'tenant' AND pb.scope_ref = c.tenant_id::text)
                                   OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource')
                                   OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || c.sub_kind)
                                   OR (pb.scope_kind = 'object' AND pb.scope_ref = c.id::text)
                                   OR (pb.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND pb.scope_ref = c.parent_group_id::text || ':resource:' || c.sub_kind)
                                   OR (pb.scope_kind = 'group_tree_object_type' AND EXISTS (
                                       SELECT 1 FROM candidate_ancestors ca
                                       WHERE ca.object_id = c.id
                                         AND pb.scope_ref = ca.ancestor_id::text || ':resource:' || c.sub_kind
                                   ))
                               )
                             )
                             OR (
                               pb.grant_kind = 'role'
                               AND EXISTS (
                                   SELECT 1
                                   FROM role_grants rg
                                   JOIN matching_capabilities mc ON mc.capability_id = rg.capability_id
                                   WHERE rg.root_role_id = pb.grant_id
                                     AND mc.object_kind = 'resource'
                                     AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                                     AND (
                                         rg.scope_kind = 'platform'
                                         OR (rg.scope_kind = 'tenant' AND rg.scope_ref = c.tenant_id::text)
                                         OR (rg.scope_kind = 'object_kind' AND rg.scope_ref = 'resource')
                                         OR (rg.scope_kind = 'object_type' AND rg.scope_ref = 'resource:' || c.sub_kind)
                                         OR (rg.scope_kind = 'object' AND rg.scope_ref = c.id::text)
                                         OR (rg.scope_kind = 'group_object_type' AND c.parent_group_id IS NOT NULL AND rg.scope_ref = c.parent_group_id::text || ':resource:' || c.sub_kind)
                                         OR (rg.scope_kind = 'group_tree_object_type' AND EXISTS (
                                             SELECT 1 FROM candidate_ancestors ca
                                             WHERE ca.object_id = c.id
                                               AND rg.scope_ref = ca.ancestor_id::text || ':resource:' || c.sub_kind
                                         ))
                                     )
                               )
                             )
                         )
                   )
               )
               SELECT id, COUNT(*) OVER() AS total
               FROM authorized
               ORDER BY created_at DESC
               LIMIT $8 OFFSET $9"#;

    let rows = sqlx::query(sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.object_type)
        .bind(q)
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    rows_to_authorized_object_ids(rows)
}

fn rows_to_authorized_object_ids(
    rows: Vec<sqlx::postgres::PgRow>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    use sqlx::Row;

    let mut total = 0;
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        ids.push(row.try_get("id").map_err(db_err)?);
        total = row.try_get("total").map_err(db_err)?;
    }
    Ok(AuthorizedObjectIdsResponse { ids, total })
}

pub async fn effective_capabilities(
    pool: &PgPool,
    entity_id: Uuid,
    params: EffectiveCapabilitiesQuery,
) -> Result<EffectiveCapabilitiesResponse, AppError> {
    use sqlx::Row;
    let entity = sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, alias, tenant_id, profile_id, profile_version_id,
                  status, attributes, created_at, updated_at
           FROM entities
           WHERE id = $1"#,
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {entity_id} not found")),
        other => AppError::Database(other),
    })?;

    let rows = sqlx::query(
        r#"WITH bindings AS (
             SELECT pb.*, 'direct'::text AS via
             FROM effective_access_edges() pb
             LEFT JOIN roles r ON pb.grant_kind = 'role' AND r.id = pb.grant_id
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $1
               AND ($2::uuid IS NULL OR r.tenant_id = $2)
             UNION ALL
             SELECT pb.*, ('group:' || g.name)::text AS via
             FROM effective_access_edges() pb
             JOIN group_members gm ON gm.group_id = pb.subject_id
             JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
             LEFT JOIN roles r ON pb.grant_kind = 'role' AND r.id = pb.grant_id
             WHERE pb.subject_kind = 'group' AND gm.entity_id = $1
               AND ($2::uuid IS NULL OR g.tenant_id = $2 OR r.tenant_id = $2)
           )
           SELECT c.id AS capability_id, c.name AS capability_name,
                  b.grant_kind, b.grant_id, role.name AS role_name, b.id AS policy_id,
                  b.scope_kind, b.scope_ref, b.effect, b.via
           FROM bindings b
           LEFT JOIN roles role ON b.grant_kind = 'role' AND role.id = b.grant_id
           LEFT JOIN effective_role_actions() rc ON b.grant_kind = 'role' AND rc.role_id = b.grant_id
           JOIN actions c ON
             (b.grant_kind = 'capability' AND c.id = b.grant_id)
             OR (b.grant_kind = 'role' AND c.id = rc.capability_id)
           WHERE (
             $3::text IS NULL
             OR EXISTS (
               SELECT 1 FROM action_applicability ca
               WHERE ca.action_id = c.id
                 AND ca.object_kind = $3
                 AND ($4::text IS NULL OR ca.object_type IS NULL OR ca.object_type = $4)
             )
           )
           ORDER BY c.name, b.created_at DESC"#,
    )
    .bind(entity_id)
    .bind(params.tenant_id)
    .bind(params.object_kind)
    .bind(params.object_type)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut caps: BTreeMap<(String, Uuid), EffectiveCapability> = BTreeMap::new();
    for row in rows {
        let cap_id: Uuid = row.try_get("capability_id").map_err(db_err)?;
        let cap_name: String = row.try_get("capability_name").map_err(db_err)?;
        let entry = caps
            .entry((cap_name.clone(), cap_id))
            .or_insert_with(|| EffectiveCapability {
                id: cap_id,
                name: cap_name,
                sources: Vec::new(),
            });
        let grant_kind: GrantKind = row.try_get("grant_kind").map_err(db_err)?;
        entry.sources.push(CapabilitySource {
            kind: grant_kind.clone(),
            role_id: match grant_kind {
                GrantKind::Capability => None,
                GrantKind::Role => Some(row.try_get("grant_id").map_err(db_err)?),
            },
            role_name: row.try_get("role_name").map_err(db_err)?,
            policy_id: row.try_get("policy_id").map_err(db_err)?,
            scope_kind: row.try_get("scope_kind").map_err(db_err)?,
            scope_ref: row.try_get("scope_ref").map_err(db_err)?,
            effect: row.try_get("effect").map_err(db_err)?,
            via: row.try_get("via").map_err(db_err)?,
        });
    }

    Ok(EffectiveCapabilitiesResponse {
        entity_id: entity.id,
        entity_name: entity.name,
        entity_kind: entity.kind,
        capabilities: caps.into_values().collect(),
    })
}

pub async fn audit_logs(
    pool: &PgPool,
    params: crate::models::access::AuditQuery,
    allowed_tenant_ids: Option<Vec<Uuid>>,
) -> Result<AuditLogResponse, AppError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, AuditLogItem>(
        r#"SELECT id, entity_id, tenant_id, event, outcome, details, created_at
           FROM audit_logs
           WHERE ($1::uuid IS NULL OR entity_id = $1)
             AND ($2::text IS NULL OR event = $2)
             AND ($3::text IS NULL OR outcome = $3)
             AND ($4::timestamptz IS NULL OR created_at >= $4)
             AND ($5::timestamptz IS NULL OR created_at < $5)
             AND ($6::uuid IS NULL OR tenant_id = $6)
             AND ($7::uuid[] IS NULL OR tenant_id = ANY($7))
           ORDER BY created_at DESC
           LIMIT $8 OFFSET $9"#,
    )
    .bind(params.entity_id)
    .bind(params.event.clone())
    .bind(params.outcome.clone())
    .bind(params.from)
    .bind(params.to)
    .bind(params.tenant_id)
    .bind(allowed_tenant_ids.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM audit_logs
           WHERE ($1::uuid IS NULL OR entity_id = $1)
             AND ($2::text IS NULL OR event = $2)
             AND ($3::text IS NULL OR outcome = $3)
             AND ($4::timestamptz IS NULL OR created_at >= $4)
             AND ($5::timestamptz IS NULL OR created_at < $5)
             AND ($6::uuid IS NULL OR tenant_id = $6)
             AND ($7::uuid[] IS NULL OR tenant_id = ANY($7))"#,
    )
    .bind(params.entity_id)
    .bind(params.event)
    .bind(params.outcome)
    .bind(params.from)
    .bind(params.to)
    .bind(params.tenant_id)
    .bind(allowed_tenant_ids.as_deref())
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(AuditLogResponse { items, total })
}

pub async fn tenant_ids_for_capability(
    pool: &PgPool,
    entity_id: Uuid,
    capability_name: &str,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"WITH RECURSIVE group_paths(group_id) AS (
               SELECT gm.group_id
               FROM group_members gm
               JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
               WHERE gm.entity_id = $1
               UNION ALL
               SELECT gh.parent_id
               FROM group_hierarchy gh
               JOIN group_paths gp ON gp.group_id = gh.child_id
               JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active'
           )
           SELECT DISTINCT pb.scope_ref::uuid
           FROM effective_access_edges() pb
           WHERE (
               (pb.subject_kind = 'entity' AND pb.subject_id = $1)
               OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM group_paths))
           )
             AND pb.effect = 'allow'
             AND pb.scope_kind = 'tenant'
             AND pb.scope_ref IS NOT NULL
             AND (
               (pb.grant_kind = 'capability' AND pb.grant_id IN (
                   SELECT id FROM actions WHERE name = $2
               ))
               OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                   SELECT role_id
                   FROM effective_role_actions() rc
                   JOIN actions c ON c.id = rc.capability_id
                   WHERE c.name = $2
                   UNION
                   SELECT NULL::uuid WHERE FALSE
               ))
             )"#,
    )
    .bind(entity_id)
    .bind(capability_name)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn tenant_ids_for_action_on_object_kind(
    pool: &PgPool,
    entity_id: Uuid,
    action_name: &str,
    object_kind: &str,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"WITH RECURSIVE group_paths(group_id) AS (
               SELECT gm.group_id
               FROM group_members gm
               JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
               WHERE gm.entity_id = $1
               UNION ALL
               SELECT gh.parent_id
               FROM group_hierarchy gh
               JOIN group_paths gp ON gp.group_id = gh.child_id
               JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active'
           )
           SELECT DISTINCT
             CASE
               WHEN pb.scope_kind = 'tenant' THEN pb.scope_ref::uuid
               ELSE pb.tenant_id
             END AS tenant_id
           FROM effective_access_edges() pb
           WHERE (
               (pb.subject_kind = 'entity' AND pb.subject_id = $1)
               OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM group_paths))
           )
             AND pb.effect = 'allow'
             AND (
               (pb.scope_kind = 'tenant' AND pb.scope_ref IS NOT NULL)
               OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = $3 AND pb.tenant_id IS NOT NULL)
             )
             AND (
               (pb.grant_kind = 'capability' AND pb.grant_id IN (
                   SELECT id FROM actions WHERE name = $2
               ))
               OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                   SELECT role_id
                   FROM effective_role_actions() rc
                   JOIN actions c ON c.id = rc.capability_id
                   WHERE c.name = $2
                   UNION
                   SELECT NULL::uuid WHERE FALSE
               ))
             )"#,
    )
    .bind(entity_id)
    .bind(action_name)
    .bind(object_kind)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn orphan_policies(
    pool: &PgPool,
    params: AdminPageQuery,
) -> Result<OrphanPoliciesResponse, AppError> {
    use sqlx::Row;
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let rows = sqlx::query(
        r#"WITH orphaned AS (
             SELECT ra.id,
                    ra.tenant_id,
                    'role_assignment'::text AS source_kind,
                    ra.subject_kind,
                    ra.subject_id,
                    ra.role_id,
                    NULL::uuid AS permission_block_id,
                    ra.created_at,
                    CASE
                      WHEN (ra.subject_kind = 'entity' AND e.id IS NULL)
                        OR (ra.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN r.id IS NULL
                      THEN 'role_not_found'
                    END AS orphan_reason
             FROM role_assignments ra
             LEFT JOIN entities e ON ra.subject_kind = 'entity' AND ra.subject_id = e.id
             LEFT JOIN principal_groups g ON ra.subject_kind = 'group' AND ra.subject_id = g.id
             LEFT JOIN roles r ON ra.role_id = r.id
             UNION ALL
             SELECT dp.id,
                    dp.tenant_id,
                    'direct_policy'::text AS source_kind,
                    dp.subject_kind,
                    dp.subject_id,
                    NULL::uuid AS role_id,
                    dp.permission_block_id,
                    dp.created_at,
                    CASE
                      WHEN (dp.subject_kind = 'entity' AND e.id IS NULL)
                        OR (dp.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN pb.id IS NULL
                      THEN 'permission_block_not_found'
                    END AS orphan_reason
             FROM direct_policies dp
             LEFT JOIN entities e ON dp.subject_kind = 'entity' AND dp.subject_id = e.id
             LEFT JOIN principal_groups g ON dp.subject_kind = 'group' AND dp.subject_id = g.id
             LEFT JOIN permission_blocks pb ON dp.permission_block_id = pb.id
           )
           SELECT * FROM orphaned
           WHERE orphan_reason IS NOT NULL
           ORDER BY created_at DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"WITH orphaned AS (
             SELECT CASE
                      WHEN (ra.subject_kind = 'entity' AND e.id IS NULL)
                        OR (ra.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN r.id IS NULL
                      THEN 'role_not_found'
                    END AS orphan_reason
             FROM role_assignments ra
             LEFT JOIN entities e ON ra.subject_kind = 'entity' AND ra.subject_id = e.id
             LEFT JOIN principal_groups g ON ra.subject_kind = 'group' AND ra.subject_id = g.id
             LEFT JOIN roles r ON ra.role_id = r.id
             UNION ALL
             SELECT CASE
                      WHEN (dp.subject_kind = 'entity' AND e.id IS NULL)
                        OR (dp.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN pb.id IS NULL
                      THEN 'permission_block_not_found'
                    END AS orphan_reason
             FROM direct_policies dp
             LEFT JOIN entities e ON dp.subject_kind = 'entity' AND dp.subject_id = e.id
             LEFT JOIN principal_groups g ON dp.subject_kind = 'group' AND dp.subject_id = g.id
             LEFT JOIN permission_blocks pb ON dp.permission_block_id = pb.id
           )
           SELECT COUNT(*) FROM orphaned WHERE orphan_reason IS NOT NULL"#,
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(OrphanPolicyItem {
                id: row.try_get("id").map_err(db_err)?,
                tenant_id: row.try_get("tenant_id").map_err(db_err)?,
                source_kind: row.try_get("source_kind").map_err(db_err)?,
                subject_kind: row.try_get("subject_kind").map_err(db_err)?,
                subject_id: row.try_get("subject_id").map_err(db_err)?,
                role_id: row.try_get("role_id").map_err(db_err)?,
                permission_block_id: row.try_get("permission_block_id").map_err(db_err)?,
                created_at: row.try_get("created_at").map_err(db_err)?,
                orphan_reason: row.try_get("orphan_reason").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(OrphanPoliciesResponse { items, total })
}

pub async fn unprotected_resources(
    pool: &PgPool,
    params: UnprotectedResourcesQuery,
) -> Result<UnprotectedResourcesResponse, AppError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, Resource>(
        r#"SELECT id, kind, name, alias, tenant_id, owner_id, attributes, created_at, updated_at
           FROM resources r
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR kind = $2)
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb
               WHERE pb.scope_kind = 'object' AND pb.scope_ref = r.id::text
             )
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb
               WHERE pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || r.kind
             )
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb
               WHERE pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource'
             )
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb WHERE pb.scope_kind = 'platform'
             )
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(params.tenant_id)
    .bind(params.kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM resources r
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR kind = $2)
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb
               WHERE pb.scope_kind = 'object' AND pb.scope_ref = r.id::text
             )
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb
               WHERE pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || r.kind
             )
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb
               WHERE pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource'
             )
             AND NOT EXISTS (
               SELECT 1 FROM effective_access_edges() pb WHERE pb.scope_kind = 'platform'
             )"#,
    )
    .bind(params.tenant_id)
    .bind(params.kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(UnprotectedResourcesResponse {
        items: items
            .into_iter()
            .map(|r| UnprotectedResourceItem {
                id: r.id,
                kind: r.kind,
                name: r.name,
                tenant_id: r.tenant_id,
                owner_id: r.owner_id,
                created_at: r.created_at,
            })
            .collect(),
        total,
    })
}

pub async fn expiring_credentials(
    pool: &PgPool,
    params: ExpiringCredentialsQuery,
) -> Result<ExpiringCredentialsResponse, AppError> {
    use sqlx::Row;
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let days = params.days.max(0);
    let rows = sqlx::query(
        r#"SELECT c.id, c.entity_id, e.name AS entity_name, e.kind AS entity_kind,
                  c.kind, c.status, c.expires_at, c.created_at
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.status = 'active'
             AND c.expires_at IS NOT NULL
             AND c.expires_at <= now() + ($1::text || ' days')::interval
             AND ($2::uuid IS NULL OR c.entity_id = $2)
             AND ($3::text IS NULL OR c.kind = $3)
           ORDER BY c.expires_at ASC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(days.to_string())
    .bind(params.entity_id)
    .bind(params.kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM credentials c
           WHERE c.status = 'active'
             AND c.expires_at IS NOT NULL
             AND c.expires_at <= now() + ($1::text || ' days')::interval
             AND ($2::uuid IS NULL OR c.entity_id = $2)
             AND ($3::text IS NULL OR c.kind = $3)"#,
    )
    .bind(days.to_string())
    .bind(params.entity_id)
    .bind(params.kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let now = Utc::now();
    let items = rows
        .into_iter()
        .map(|row| {
            let expires_at = row.try_get("expires_at").map_err(db_err)?;
            Ok(ExpiringCredentialItem {
                id: row.try_get("id").map_err(db_err)?,
                entity_id: row.try_get("entity_id").map_err(db_err)?,
                entity_name: row.try_get("entity_name").map_err(db_err)?,
                entity_kind: row.try_get("entity_kind").map_err(db_err)?,
                kind: row.try_get::<CredentialKind, _>("kind").map_err(db_err)?,
                status: row.try_get("status").map_err(db_err)?,
                expires_at,
                days_remaining: (expires_at - now).num_days(),
                created_at: row.try_get("created_at").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(ExpiringCredentialsResponse { items, total })
}

async fn optional_capability_id(
    pool: &PgPool,
    action: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    match action {
        Some(name) => sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
            .bind(name)
            .fetch_optional(pool)
            .await
            .map_err(db_err),
        None => Ok(None),
    }
}

fn rows_to_access_items(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<AccessItem>, AppError> {
    use sqlx::Row;
    rows.into_iter()
        .map(|row| {
            let caps: Value = row.try_get("capabilities").map_err(db_err)?;
            Ok(AccessItem {
                resource: ResourceSummary {
                    id: row.try_get("resource_id").map_err(db_err)?,
                    kind: row.try_get("resource_kind").map_err(db_err)?,
                    name: row.try_get("resource_name").map_err(db_err)?,
                    tenant_id: row.try_get("resource_tenant_id").map_err(db_err)?,
                },
                effect: row.try_get("effect").map_err(db_err)?,
                scope_kind: row.try_get("scope_kind").map_err(db_err)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                policy_id: row.try_get("policy_id").map_err(db_err)?,
                grant: grant_from_row(&row, caps)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
                via: row.try_get("via").map_err(db_err)?,
            })
        })
        .collect()
}

fn grant_from_row(row: &sqlx::postgres::PgRow, caps: Value) -> Result<GrantSummary, AppError> {
    use sqlx::Row;
    let kind: GrantKind = row.try_get("grant_kind").map_err(db_err)?;
    let capabilities = serde_json::from_value::<Vec<CapabilitySummary>>(caps)
        .map_err(|e| AppError::bad_request(format!("invalid capability aggregate: {e}")))?;
    let role = match kind {
        GrantKind::Capability => None,
        GrantKind::Role => Some(RoleSummary {
            id: row.try_get("role_id").map_err(db_err)?,
            name: row.try_get("role_name").map_err(db_err)?,
        }),
    };
    Ok(GrantSummary {
        kind,
        role,
        capabilities,
    })
}

async fn get_group_with_count(pool: &PgPool, group_id: Uuid) -> Result<(i64, Group), AppError> {
    let group = sqlx::query_as::<_, Group>(
        r#"SELECT g.id, g.name, g.tenant_id, g.group_type, g.description, gh.parent_id,
                  g.status, g.attributes, g.created_at, g.updated_at
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE g.id = $1"#,
    )
    .bind(group_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("group {group_id} not found")),
        other => AppError::Database(other),
    })?;
    let count = sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
        .bind(group_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    Ok((count, group))
}

// ─── Engine helpers ───────────────────────────────────────────────────────────

pub async fn load_bindings_for_entity(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Vec<PolicyBinding>, AppError> {
    sqlx::query_as::<_, PolicyBinding>(
        r#"WITH RECURSIVE group_paths(group_id, path) AS (
               SELECT gm.group_id, g.name
               FROM group_members gm
               JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
               WHERE gm.entity_id = $1
               UNION ALL
               SELECT gh.parent_id, parent.name || ' -> ' || gp.path
               FROM group_hierarchy gh
               JOIN group_paths gp ON gp.group_id = gh.child_id
               JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active'
           )
           SELECT pb.id, pb.tenant_id, pb.subject_kind, pb.subject_id, pb.grant_kind, pb.grant_id,
                  pb.scope_kind, pb.scope_ref, pb.effect, pb.conditions, pb.created_at
           FROM effective_access_edges() pb
           WHERE
             (pb.subject_kind = 'entity' AND pb.subject_id = $1)
             OR
             (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM group_paths))"#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// Batch load capability IDs for multiple roles in a single query.
/// Returns a map of role_id → Vec<capability_id>.
pub async fn capability_ids_for_roles(
    pool: &PgPool,
    role_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Uuid>>, AppError> {
    if role_ids.is_empty() {
        return Ok(HashMap::new());
    }

    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT role_id, capability_id FROM effective_role_actions() WHERE role_id = ANY($1::uuid[])",
    )
    .bind(role_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for row in rows {
        let role_id: Uuid = row.try_get("role_id").map_err(db_err)?;
        let cap_id: Uuid = row.try_get("capability_id").map_err(db_err)?;
        map.entry(role_id).or_default().push(cap_id);
    }

    Ok(map)
}

/// Batch-load role grants from canonical permission blocks.
pub async fn expanded_role_grants_for_roles(
    pool: &PgPool,
    role_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<ExpandedRoleGrant>>, AppError> {
    if role_ids.is_empty() {
        return Ok(HashMap::new());
    }

    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT r.id AS root_role_id,
                  r.id AS role_id,
                  r.name AS role_name,
                  r.name AS role_path,
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
                  pba.action_id AS capability_id
           FROM roles r
           JOIN role_permission_blocks rpb ON rpb.role_id = r.id
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
           WHERE r.id = ANY($1::uuid[])"#,
    )
    .bind(role_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut map: HashMap<Uuid, Vec<ExpandedRoleGrant>> = HashMap::new();
    for row in rows {
        let scope_kind_text: String = row.try_get("scope_kind").map_err(db_err)?;
        let scope_kind = parse_scope_kind_text(&scope_kind_text)?;
        let root_role_id: Uuid = row.try_get("root_role_id").map_err(db_err)?;
        map.entry(root_role_id)
            .or_default()
            .push(ExpandedRoleGrant {
                root_role_id,
                role_id: row.try_get("role_id").map_err(db_err)?,
                role_name: row.try_get("role_name").map_err(db_err)?,
                role_path: row.try_get("role_path").map_err(db_err)?,
                scope_kind,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                capability_id: row.try_get("capability_id").map_err(db_err)?,
            });
    }

    Ok(map)
}

pub async fn find_capability_ids_by_name(
    pool: &PgPool,
    name: &str,
    object_kind: &str,
    object_type: &str,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT c.id
           FROM actions c
           JOIN action_applicability ca ON ca.action_id = c.id
           WHERE c.name = $1
             AND ca.object_kind = $2
             AND (ca.object_type IS NULL OR ca.object_type = $3)
           ORDER BY c.id"#,
    )
    .bind(name)
    .bind(object_kind)
    .bind(format!("{object_kind}:{object_type}"))
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}
