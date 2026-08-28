use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
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
        resource::{CreateResource, ListResources, Resource, ResourceList, UpdateResource},
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
    pool: &PgPool,
    subject_id: Uuid,
    ceiling_id: Option<Uuid>,
    object_kind: &str,
    actions: &[&str],
    filters: Value,
    candidate_sql: &str,
    limit: i64,
    offset: i64,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let action_names = actions
        .iter()
        .map(|action| (*action).to_string())
        .collect::<Vec<_>>();
    let sql = format!(
        r#"WITH candidates AS ({candidate_sql}),
           grants AS (
               SELECT * FROM subject_effective_grants($1)
           ),
           {ceiling},
           caps AS (
               SELECT a.id
               FROM actions a
               JOIN action_applicability aa ON aa.action_id = a.id
               WHERE a.name = ANY($2::text[])
                 AND aa.object_kind = $3
                 AND aa.object_type IS NULL
           ),
           authorized AS (
               SELECT candidate.id, candidate.ordinality
               FROM candidates candidate
               WHERE candidate.tenant_id IS NULL
                  OR EXISTS (
                       SELECT 1 FROM tenants tenant
                       WHERE tenant.id = candidate.tenant_id
                         AND tenant.status = 'active'
                         AND tenant.deleted_at IS NULL
                  )
               INTERSECT
               SELECT candidate.id, candidate.ordinality
               FROM candidates candidate
               WHERE EXISTS (
                   SELECT 1
                   FROM caps cap
                   WHERE EXISTS (
                       SELECT 1 FROM grants effective_grant
                       WHERE effective_grant.capability_id = cap.id
                         AND effective_grant.effect = 'allow'
                         AND effective_grant.conditions = '{{}}'::jsonb
                         AND (effective_grant.tenant_boundary IS NULL OR effective_grant.tenant_boundary = candidate.tenant_id)
                         AND grant_scope_matches(
                               effective_grant.scope_kind, effective_grant.scope_ref, $3, $3,
                               candidate.id, candidate.tenant_id,
                               '{{}}'::uuid[], '{{}}'::uuid[])
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants effective_grant
                       WHERE effective_grant.capability_id = cap.id
                         AND effective_grant.effect = 'deny'
                         AND (effective_grant.tenant_boundary IS NULL OR effective_grant.tenant_boundary = candidate.tenant_id)
                         AND grant_scope_matches(
                               effective_grant.scope_kind, effective_grant.scope_ref, $3, $3,
                               candidate.id, candidate.tenant_id,
                               '{{}}'::uuid[], '{{}}'::uuid[])
                   )
                   AND ($4::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling token_scope
                       WHERE token_scope.action_id = cap.id
                         AND (token_scope.tenant_id IS NULL OR token_scope.tenant_id = candidate.tenant_id)
                         AND grant_scope_matches(
                               token_scope.scope_kind, token_scope.scope_ref, $3, $3,
                               candidate.id, candidate.tenant_id,
                               '{{}}'::uuid[], '{{}}'::uuid[])
                   ))
               )
           ),
           totals AS (SELECT count(*)::bigint AS total FROM authorized),
           page AS (
               SELECT id FROM authorized ORDER BY ordinality LIMIT $6 OFFSET $7
           )
           SELECT page.id, totals.total
           FROM totals
           LEFT JOIN LATERAL (SELECT id FROM page) page ON TRUE"#,
        ceiling = ceiling_cte("$4")
    );
    let rows = sqlx::query(&sql)
        .bind(subject_id)
        .bind(action_names)
        .bind(object_kind)
        .bind(ceiling_id)
        .bind(filters)
        .bind(limit.clamp(1, 100))
        .bind(offset.max(0))
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    let total = rows
        .first()
        .map(|row| row.try_get::<i64, _>("total").map_err(db_err))
        .transpose()?
        .unwrap_or(0);
    let ids = rows
        .into_iter()
        .filter_map(|row| row.try_get::<Option<Uuid>, _>("id").ok().flatten())
        .collect();
    Ok(AuthorizedObjectIdsResponse { ids, total })
}

const API_ENDPOINT_CANDIDATES: &str = r#"
    SELECT id, tenant_id,
           row_number() OVER (ORDER BY tenant_id NULLS FIRST, key, id) AS ordinality
    FROM api_endpoints
    WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
           OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
      AND (NULLIF($5->>'status', '') IS NULL OR status = ($5->>'status'))"#;

pub async fn list_api_endpoints_authorized(
    pool: &PgPool,
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
        API_ENDPOINT_CANDIDATES,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, ApiEndpoint>(
            r#"SELECT id, tenant_id, key, name, description, method, path,
                      operation_kind, graphql, auth_mode, service_entity_id,
                      variables_mapping, request_schema, response_mapping, status,
                      created_by, updated_by, created_at, updated_at
               FROM api_endpoints
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
        )
        .bind(&authorized.ids)
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    };
    Ok(ApiEndpointList {
        items,
        total: authorized.total,
    })
}

// ─── Resources ────────────────────────────────────────────────────────────────

fn resource_order_by(order: ResourceOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (ResourceOrderField::CreatedAt, SortDir::Asc) => "r.created_at ASC, r.id ASC",
        (ResourceOrderField::CreatedAt, SortDir::Desc) => "r.created_at DESC, r.id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Asc) => "r.updated_at ASC, r.id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Desc) => "r.updated_at DESC NULLS LAST, r.id ASC",
        (ResourceOrderField::Name, SortDir::Asc) => "lower(r.name) ASC, r.id ASC",
        (ResourceOrderField::Name, SortDir::Desc) => "lower(r.name) DESC NULLS LAST, r.id ASC",
        (ResourceOrderField::Kind, SortDir::Asc) => "r.kind ASC, r.id ASC",
        (ResourceOrderField::Kind, SortDir::Desc) => "r.kind DESC, r.id ASC",
    }
}

fn authorized_entity_order_by(order: EntityOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (EntityOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (EntityOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (EntityOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC, id ASC",
        (EntityOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (EntityOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::Name, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::Username, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::Username, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::FirstName, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::FirstName, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::LastName, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::LastName, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::Email, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::Email, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::Kind, SortDir::Asc) => "sub_kind ASC, id ASC",
        (EntityOrderField::Kind, SortDir::Desc) => "sub_kind DESC, id ASC",
        (EntityOrderField::Status, SortDir::Asc) => "status ASC, id ASC",
        (EntityOrderField::Status, SortDir::Desc) => "status DESC, id ASC",
    }
}

fn authorized_resource_order_by(order: ResourceOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (ResourceOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (ResourceOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC, id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (ResourceOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (ResourceOrderField::Name, SortDir::Desc) => "lower(name) DESC NULLS LAST, id ASC",
        (ResourceOrderField::Kind, SortDir::Asc) => "sub_kind ASC, id ASC",
        (ResourceOrderField::Kind, SortDir::Desc) => "sub_kind DESC, id ASC",
    }
}

fn authorized_group_order_by(order: GroupOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (GroupOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (GroupOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (GroupOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC, id ASC",
        (GroupOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (GroupOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (GroupOrderField::Name, SortDir::Desc) => "lower(name) DESC, id ASC",
        (GroupOrderField::Status, SortDir::Asc) => "status ASC, id ASC",
        (GroupOrderField::Status, SortDir::Desc) => "status DESC, id ASC",
    }
}

pub async fn create_resource_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateResource,
) -> Result<Resource, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = if req.attributes.is_null() {
        serde_json::json!({})
    } else {
        req.attributes
    };
    reject_parent_group_attribute(&attrs)?;
    let alias = crate::models::alias::validate_alias_opt(req.alias)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let resource = sqlx::query_as::<_, Resource>(
        r#"INSERT INTO resources (id, kind, name, alias, tenant_id, owner_id, attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, kind, name, alias, tenant_id, owner_id, attributes,
                     deleted_at, deleted_by, created_at, updated_at"#,
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
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: "resource",
        target_id: Some(resource.id),
        event: "resource.create",
    };
    let details = serde_json::json!({
        "kind": resource.kind,
        "name": resource.name,
        "alias": resource.alias,
        "attributes": resource.attributes,
    });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(resource)
}

pub async fn create_resource(pool: &PgPool, req: CreateResource) -> Result<Resource, AppError> {
    create_resource_with_audit(pool, false, None, req).await
}

pub async fn get_resource(pool: &PgPool, id: Uuid) -> Result<Resource, AppError> {
    fetch_resource(pool, id).await
}

/// Executor-generic `get_resource`, so a mutation can read the row it just wrote
/// from inside its own transaction instead of re-reading it after the commit.
async fn fetch_resource<'e, E>(executor: E, id: Uuid) -> Result<Resource, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, Resource>(
        "SELECT id, kind, name, alias, tenant_id, owner_id, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by FROM resources WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(executor)
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
        r#"SELECT id, kind, name, alias, tenant_id, owner_id, attributes, deleted_at, deleted_by, created_at, updated_at
           FROM resources
           WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL
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
    let deleted = params.deleted.as_str();
    let q = search_pattern(params.q);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = resource_order_by(params.order, params.dir);

    let items_sql = format!(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $4::uuid WHERE $4::uuid IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $5::boolean
           )
           SELECT r.id, r.kind, r.name, r.alias, r.tenant_id, r.owner_id, r.attributes,
                  r.deleted_at, r.deleted_by, r.created_at, r.updated_at, r.managed_by
           FROM resources r
           WHERE ($1::text IS NULL OR r.kind = $1)
             AND ($2::uuid IS NULL OR r.tenant_id = $2)
             AND ($3::text IS NULL OR r.name ILIKE $3 OR r.alias ILIKE $3 OR r.attributes::text ILIKE $3)
             AND ($4::uuid IS NULL OR EXISTS (
                     SELECT 1 FROM group_resource_parents grp
                     WHERE grp.resource_id = r.id
                       AND grp.group_id IN (SELECT id FROM target_groups)))
             AND ($9::jsonb IS NULL OR r.attributes @> $9::jsonb)
             AND ($8::text = 'all'
                  OR ($8::text = 'live' AND r.deleted_at IS NULL)
                  OR ($8::text = 'deleted' AND r.deleted_at IS NOT NULL))
           ORDER BY {order_by}
           LIMIT $6 OFFSET $7"#,
    );
    let items = sqlx::query_as::<_, Resource>(&items_sql)
        .bind(kind.clone())
        .bind(tenant_id)
        .bind(q.clone())
        .bind(parent_group_id)
        .bind(include_descendants)
        .bind(limit)
        .bind(offset)
        .bind(deleted)
        .bind(attributes_contains.clone())
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
           WHERE ($1::text IS NULL OR r.kind = $1)
             AND ($2::uuid IS NULL OR r.tenant_id = $2)
             AND ($3::text IS NULL OR r.name ILIKE $3 OR r.alias ILIKE $3 OR r.attributes::text ILIKE $3)
             AND ($4::uuid IS NULL OR EXISTS (
                     SELECT 1 FROM group_resource_parents grp
                     WHERE grp.resource_id = r.id
                       AND grp.group_id IN (SELECT id FROM target_groups)))
             AND ($7::jsonb IS NULL OR r.attributes @> $7::jsonb)
             AND ($6::text = 'all'
                  OR ($6::text = 'live' AND r.deleted_at IS NULL)
                  OR ($6::text = 'deleted' AND r.deleted_at IS NOT NULL))"#,
    )
    .bind(kind)
    .bind(tenant_id)
    .bind(q)
    .bind(parent_group_id)
    .bind(include_descendants)
    .bind(deleted)
    .bind(attributes_contains)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ResourceList { items, total })
}

pub async fn update_resource_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateResource,
    updated_fields: Vec<&'static str>,
) -> Result<Resource, AppError> {
    if let Some(attrs) = req.attributes.as_ref() {
        reject_parent_group_attribute(attrs)?;
    }
    let alias = crate::models::alias::validate_alias_update(req.alias)?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("resource {id} not found")));
    };
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, tenant_id).await?;
    let locked: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM resources
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL
           FOR UPDATE"#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;
    let resource = sqlx::query_as::<_, Resource>(
        r#"UPDATE resources
           SET name       = COALESCE($2, name),
               attributes = COALESCE($3, attributes),
               alias      = CASE WHEN $4 THEN $5 ELSE alias END,
               updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING id, kind, name, alias, tenant_id, owner_id, attributes,
                     deleted_at, deleted_by, created_at, updated_at"#,
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
    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.update",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({ "updated_fields": updated_fields }),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(resource)
}

pub async fn update_resource(
    pool: &PgPool,
    id: Uuid,
    req: UpdateResource,
) -> Result<Resource, AppError> {
    update_resource_with_audit(pool, false, None, id, req, Vec::new()).await
}

pub async fn delete_resource_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("resource {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM resources WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if !live {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }
    let result = sqlx::query(
        "UPDATE resources SET deleted_at = now(), deleted_by = $2
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(deleted_by)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }
    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.delete",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(())
}

pub async fn delete_resource(
    pool: &PgPool,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_resource_with_audit(pool, false, None, id, deleted_by).await
}

pub async fn restore_resource_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let _ = restored_by;
    let mut tx = pool.begin().await.map_err(db_err)?;

    let expected_tenant_id: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(expected_tenant_id) = expected_tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted resource {id} to restore"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;

    let tenant_info: Option<(Option<Uuid>, bool)> = sqlx::query_as(
        "SELECT r.tenant_id, (t.deleted_at IS NOT NULL)
         FROM resources r
         LEFT JOIN tenants t ON t.id = r.tenant_id
         WHERE r.id = $1
           AND r.tenant_id IS NOT DISTINCT FROM $2
           AND r.deleted_at IS NOT NULL",
    )
    .bind(id)
    .bind(expected_tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let (tenant_id, _is_tenant_deleted) = match tenant_info {
        None => {
            return Err(AppError::not_found(format!(
                "no soft-deleted resource {id} to restore"
            )))
        }
        Some((_, true)) => {
            return Err(AppError::conflict(
                "the resource's tenant is soft-deleted; restore the tenant first",
            ))
        }
        Some((t_id, false)) => (t_id, false),
    };

    sqlx::query(
        "UPDATE resources SET deleted_at = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(restore_conflict)?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.restore",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(())
}

pub async fn restore_resource(
    pool: &PgPool,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    restore_resource_with_audit(pool, false, None, id, restored_by).await
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
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ids: &[Uuid],
) -> Result<(), AppError> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query("DELETE FROM permission_blocks WHERE object_id = ANY($1)")
        .bind(ids)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM direct_policies WHERE subject_id = ANY($1)")
        .bind(ids)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM role_assignments WHERE subject_id = ANY($1)")
        .bind(ids)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Physically remove an already-soft-deleted resource, bypassing the purge
/// retention window. Irreversible: FK cascades drop its group links. A soft
/// delete is required first.
///
/// Object-scoped permission blocks granting access *on* the resource reference
/// it by `object_id`, which has no foreign key, so they are removed explicitly
/// (deleting a block cascades to its actions, role links, and direct policies).
/// Resources are never a subject, so there is no subject-side cleanup.
pub async fn purge_resource_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM resources WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(expected_tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted resource {id} to purge"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;

    let purged_tenant_id: Option<Option<Uuid>> = sqlx::query_scalar(
        "DELETE FROM resources WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let tenant_id = purged_tenant_id
        .ok_or_else(|| AppError::not_found(format!("no soft-deleted resource {id} to purge")))?;

    purge_authz_references_for_ids(&mut tx, &[id]).await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(tenant_id)
}

pub async fn purge_resource(pool: &PgPool, id: Uuid) -> Result<Option<Uuid>, AppError> {
    purge_resource_with_audit(pool, false, None, id).await
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
        (Some(id), None, false) => {
            let id = sqlx::query_scalar::<_, Uuid>(
                r#"SELECT id FROM tenants
                   WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?
            .ok_or_else(|| AppError::not_found(format!("active tenant {id} not found")))?;
            Some(id)
        }
        (None, Some(alias), false) => {
            let id = sqlx::query_scalar::<_, Uuid>(
                r#"SELECT id FROM tenants
                   WHERE lower(alias) = lower($1)
                     AND status = 'active'
                     AND deleted_at IS NULL"#,
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
               AND lower(alias) = $2 \
               AND deleted_at IS NULL"
        }
        AliasObjectClass::Resource => {
            "SELECT id FROM resources \
             WHERE tenant_id IS NOT DISTINCT FROM $1::uuid \
               AND lower(alias) = $2 \
               AND deleted_at IS NULL"
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

pub async fn get_resource_object_groups(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT grp.group_id
           FROM group_resource_parents grp
           JOIN object_groups g ON g.id = grp.group_id AND g.deleted_at IS NULL
           WHERE grp.resource_id = $1
           ORDER BY grp.created_at, grp.group_id"#,
    )
    .bind(resource_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn add_resource_to_object_group(
    pool: &PgPool,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    add_resource_to_object_group_with_audit(pool, false, None, resource_id, group_id).await
}

pub async fn add_resource_to_object_group_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let inserted = add_resource_to_object_group_in_tx(&mut tx, resource_id, group_id).await?;
    let resource = fetch_resource(&mut *tx, resource_id).await?;
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
    pool: &PgPool,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    remove_resource_from_object_group_with_audit(pool, false, None, resource_id, group_id).await
}

pub async fn remove_resource_from_object_group_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let deleted = delete_resource_object_groups_in_tx(&mut tx, resource_id, Some(group_id)).await?;
    let resource = fetch_resource(&mut *tx, resource_id).await?;
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
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<Resource, AppError> {
    clear_resource_object_groups_with_audit(pool, false, None, resource_id).await
}

pub async fn clear_resource_object_groups_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    resource_id: Uuid,
) -> Result<Resource, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let deleted = delete_resource_object_groups_in_tx(&mut tx, resource_id, None).await?;
    let resource = fetch_resource(&mut *tx, resource_id).await?;
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
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<bool, AppError> {
    add_resource_to_object_group_in_tx_impl(tx, resource_id, group_id, true).await
}

/// Bootstrap-only replay of a declarative object-group resource membership.
/// Runtime callers use [`add_resource_to_object_group_in_tx`] and cannot
/// change a config-owned member set.
pub(crate) async fn add_config_resource_to_object_group_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    resource_id: Uuid,
    group_id: Uuid,
) -> Result<bool, AppError> {
    add_resource_to_object_group_in_tx_impl(tx, resource_id, group_id, false).await
}

async fn add_resource_to_object_group_in_tx_impl(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    resource_id: Uuid,
    group_id: Uuid,
    enforce_api_ownership: bool,
) -> Result<bool, AppError> {
    use sqlx::Row;
    let resource_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NULL")
            .bind(resource_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    let Some(resource_tenant_id) = resource_tenant_id else {
        return Err(AppError::bad_request(
            "resource parent group reference is invalid",
        ));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, resource_tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT r.tenant_id AS resource_tenant_id, g.tenant_id AS group_tenant_id
           FROM resources r
           CROSS JOIN object_groups g
           WHERE r.id = $1 AND g.id = $2
             AND r.tenant_id IS NOT DISTINCT FROM $3
             AND r.deleted_at IS NULL
             AND g.deleted_at IS NULL
           FOR UPDATE OF r, g"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .bind(resource_tenant_id)
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
    if enforce_api_ownership {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "object_groups", group_id).await?;
    }
    // Additive: membership is a set, so re-adding an existing membership is an
    // idempotent no-op rather than a silent move between groups.
    let result = sqlx::query(
        r#"INSERT INTO object_group_resources (group_id, resource_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (group_id, resource_id) DO NOTHING"#,
    )
    .bind(group_id)
    .bind(resource_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}

/// `group_id = Some(..)` removes one membership; `None` removes them all. The
/// two callers name which they mean, so neither can inherit the other's
/// behaviour by accident.
async fn delete_resource_object_groups_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    resource_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<u64, AppError> {
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NULL")
            .bind(resource_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "resource {resource_id} not found"
        )));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    let locked: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM resources
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL
           FOR UPDATE"#,
    )
    .bind(resource_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!(
            "resource {resource_id} not found"
        )));
    }
    let mut affected_group_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT group_id FROM object_group_resources
           WHERE resource_id = $1 AND ($2::uuid IS NULL OR group_id = $2)
           ORDER BY group_id"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .fetch_all(&mut **tx)
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
    let deleted = sqlx::query(
        r#"DELETE FROM object_group_resources
           WHERE resource_id = $1 AND ($2::uuid IS NULL OR group_id = $2)"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?
    .rows_affected();
    Ok(deleted)
}

/// Object group membership is a set, and a scalar attribute cannot express one.
/// The attribute write path is gone: membership is mutated only through the
/// explicit `addResourceToObjectGroup` / `removeResourceFromObjectGroup` /
/// `clearResourceObjectGroups` mutations. Rejecting the attribute rather than
/// ignoring it keeps the break loud — a caller that still sends it would
/// otherwise believe it had placed the resource in a group.
fn reject_parent_group_attribute(attrs: &Value) -> Result<(), AppError> {
    if attrs.get("parent_group_id").is_some() {
        return Err(AppError::bad_request(
            "the parent_group_id attribute is no longer supported; \
             use addResourceToObjectGroup / removeResourceFromObjectGroup",
        ));
    }
    Ok(())
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
    pool: &PgPool,
    credential_id: Uuid,
) -> Result<CredentialCeiling, AppError> {
    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT l.id        AS limit_id,
                  s.scope_kind AS scope_kind,
                  s.scope_ref  AS scope_ref,
                  l.tenant_id  AS tenant_id,
                  l.conditions AS conditions,
                  la.action_id AS action_id
           FROM credential_permission_limits l
           JOIN credential_permission_limit_scopes s ON s.limit_id = l.id
           JOIN credential_permission_limit_actions la ON la.limit_id = l.id
           WHERE l.credential_id = $1"#,
    )
    .bind(credential_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let entries = rows
        .into_iter()
        .map(|row| {
            let limit_id: Uuid = row.try_get("limit_id").map_err(db_err)?;
            Ok(EffectiveGrant {
                assignment_id: limit_id,
                block_id: limit_id,
                role_id: None,
                role_name: None,
                via: "access_token_ceiling".to_string(),
                // Honor the row's tenant restriction the same way an assignment
                // tenant boundary does. `object_kind`/`object_type` ceilings can
                // carry a `tenant_id` that the scope_ref alone does not encode; a
                // NULL tenant_id (platform/object modes, or a tenant-agnostic kind)
                // leaves the entry unrestricted, matching `match_grant`.
                tenant_boundary: row.try_get("tenant_id").map_err(db_err)?,
                scope_kind: row.try_get("scope_kind").map_err(db_err)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                capability_id: row.try_get("action_id").map_err(db_err)?,
                effect: Effect::Allow,
                conditions: row.try_get("conditions").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    Ok(CredentialCeiling { entries })
}

pub async fn create_role_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateRole,
) -> Result<Role, AppError> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let role = sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .fetch_one(&mut *tx)
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

pub async fn create_role(pool: &PgPool, req: CreateRole) -> Result<Role, AppError> {
    create_role_with_audit(pool, false, None, req).await
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
    let role = sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at"#,
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
                       WHERE id = $2
                         AND kind = 'human'
                         AND status = 'active'
                         AND deleted_at IS NULL
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
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let mut locked_member_ids = member_entity_ids.to_vec();
    locked_member_ids.sort_unstable();
    locked_member_ids.dedup();
    for member_id in locked_member_ids {
        lock_live_subject(&mut tx, req.tenant_id, &SubjectKind::Entity, member_id).await?;
    }
    let role = sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at"#,
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
                       WHERE id = $2
                         AND kind = 'human'
                         AND status = 'active'
                         AND deleted_at IS NULL
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

/// Serialize role-link mutations by taking a row lock on the role. Every path
/// that adds or removes `role_permission_blocks` rows for a role must hold this
/// first, so two such mutations on the same role cannot interleave (e.g. one
/// inserting a link after another has deleted the existing set). An FK insert
/// into role_permission_blocks takes a FOR KEY SHARE lock on the role row, which
/// conflicts with this FOR UPDATE. Returns not-found if the role is absent.
pub(crate) async fn lock_role(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
) -> Result<(), AppError> {
    let tenant_id = read_live_role_tenant_id(tx, role_id).await?;
    lock_active_tenant_ids(tx, [tenant_id]).await?;
    lock_live_role_row(tx, role_id, tenant_id).await
}

async fn read_live_role_tenant_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL")
        .bind(role_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::not_found(format!("role {role_id} not found")))
}

async fn lock_live_role_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM roles
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL
           FOR UPDATE"#,
    )
    .bind(role_id)
    .bind(expected_tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("role {role_id} not found")));
    }
    Ok(())
}

pub async fn replace_role_permission_block_links(
    pool: &PgPool,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<(), AppError> {
    replace_role_permission_block_links_with_audit(pool, false, None, role_id, permission_block_ids)
        .await
}

pub async fn replace_role_permission_block_links_with_audit(
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<Option<Uuid>, AppError> {
    let role_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL")
            .bind(role_id)
            .fetch_optional(&mut **tx)
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
        .fetch_one(&mut **tx)
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
    crate::guardrails::validate_role_permission_block_links(&mut *tx, role_id, &unique_block_ids)
        .await?;
    sqlx::query("DELETE FROM role_permission_blocks WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;

    for permission_block_id in &unique_block_ids {
        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(role_id)
        .bind(permission_block_id)
        .execute(&mut **tx)
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

/// Permission blocks are shared: one block can be linked to several roles and to
/// direct policies. Delete only those among `block_ids` that, after the caller
/// has removed its own links, are no longer referenced by any role or direct
/// policy — so a block still in use elsewhere is never destroyed. This is the
/// garbage-collection half of the shared-immutable ownership model.
async fn delete_orphaned_blocks(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    block_ids: &[Uuid],
) -> Result<(), AppError> {
    if block_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"DELETE FROM permission_blocks pb
           WHERE pb.id = ANY($1)
             AND pb.managed_by IS DISTINCT FROM 'config'
             AND NOT EXISTS (
                 SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id
             )
             AND NOT EXISTS (
                 SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id
             )"#,
    )
    .bind(block_ids)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Detach `block_ids` from `role_id`, then garbage-collect any that are now
/// orphaned. Replaces the previous `DELETE FROM permission_blocks` by role, which
/// cascaded through `role_permission_blocks`/`direct_policies` and so silently
/// removed blocks still linked to *other* roles.
async fn unlink_role_blocks_and_gc(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    block_ids: &[Uuid],
) -> Result<(), AppError> {
    if block_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "DELETE FROM role_permission_blocks WHERE role_id = $1 AND permission_block_id = ANY($2)",
    )
    .bind(role_id)
    .bind(block_ids)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    delete_orphaned_blocks(tx, block_ids).await
}

/// Block ids currently linked to `role_id`.
async fn role_block_ids(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar("SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1")
        .bind(role_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)
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
           JOIN roles r ON r.id = rpb.role_id AND r.deleted_at IS NULL
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
    fetch_permission_block(pool, id).await
}

/// Executor-generic `get_permission_block`, so a mutation can read the row it
/// just wrote from inside its own transaction instead of after the commit.
async fn fetch_permission_block<'e, E>(executor: E, id: Uuid) -> Result<PermissionBlock, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id,
                  effect, conditions, created_at, updated_at
           FROM permission_blocks
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(executor)
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
                  effect, conditions, created_at, updated_at, managed_by
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
    pool: &PgPool,
    req: CreatePermissionBlock,
) -> Result<PermissionBlock, AppError> {
    create_permission_block_with_audit(pool, false, None, req).await
}

pub async fn create_permission_block_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreatePermissionBlock,
) -> Result<PermissionBlock, AppError> {
    validate_permission_block_input(pool, &req).await?;
    let conditions = normalize_conditions(req.conditions)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
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
    let block = fetch_permission_block(&mut *tx, id).await?;
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

pub async fn delete_permission_block(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    delete_permission_block_with_audit(pool, false, None, id).await
}

pub async fn delete_permission_block_with_audit(
    pool: &PgPool,
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
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM permission_blocks WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "permission block {id} not found"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "permission_blocks", id).await?;
    let referenced: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM role_permission_blocks WHERE permission_block_id = $1)
              OR EXISTS (SELECT 1 FROM direct_policies WHERE permission_block_id = $1)"#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if referenced {
        return Err(AppError::bad_request(
            "permission block is still linked to a role or direct policy; unlink it first",
        ));
    }
    sqlx::query("DELETE FROM permission_blocks WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
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
    pool: &PgPool,
    req: &CreatePermissionBlock,
) -> Result<(), AppError> {
    let mut connection = pool.acquire().await.map_err(db_err)?;
    validate_permission_block_input_on_connection(&mut connection, req).await
}

pub(crate) async fn validate_permission_block_input_on_connection(
    connection: &mut sqlx::PgConnection,
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
    connection: &mut sqlx::PgConnection,
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
    connection: &mut sqlx::PgConnection,
    tenant_id: Option<Uuid>,
    group_id: Option<Uuid>,
) -> Result<(), AppError> {
    let group_id =
        group_id.ok_or_else(|| AppError::bad_request("object group scope requires groupId"))?;
    let group_tenant_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT tenant_id FROM object_groups WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(group_id)
    .fetch_optional(connection)
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
        r#"SELECT id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at
           FROM roles WHERE id = $1 AND deleted_at IS NULL"#,
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
    let deleted = params.deleted.as_str();

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
        r#"SELECT id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at, managed_by
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
             AND ($6::text = 'all'
                  OR ($6::text = 'live' AND deleted_at IS NULL)
                  OR ($6::text = 'deleted' AND deleted_at IS NOT NULL))
           ORDER BY name LIMIT $4 OFFSET $5"#,
    )
    .bind(params.tenant_id)
    .bind(q.clone())
    .bind(derived_kind.clone())
    .bind(limit)
    .bind(offset)
    .bind(deleted)
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
             )
             AND ($4::text = 'all'
                  OR ($4::text = 'live' AND deleted_at IS NULL)
                  OR ($4::text = 'deleted' AND deleted_at IS NOT NULL))"#,
    )
    .bind(params.tenant_id)
    .bind(q)
    .bind(derived_kind)
    .bind(deleted)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleList { items, total })
}

pub async fn list_roles_authorized(
    pool: &PgPool,
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
    const CANDIDATES: &str = r#"SELECT id, tenant_id,
                  row_number() OVER (ORDER BY name, id) AS ordinality
           FROM roles
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
                  OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL
                  OR name ILIKE ($5->>'q') OR description ILIKE ($5->>'q'))
             AND (
               NULLIF($5->>'derived_kind', '') IS NULL
               OR ($5->>'derived_kind' = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
               OR ($5->>'derived_kind' = 'composite' AND FALSE)
               OR ($5->>'derived_kind' = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
             )
             AND ($5->>'deleted' = 'all'
                  OR ($5->>'deleted' = 'live' AND deleted_at IS NULL)
                  OR ($5->>'deleted' = 'deleted' AND deleted_at IS NOT NULL))"#;
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
        CANDIDATES,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, Role>(
            r#"SELECT id, name, tenant_id, description, deleted_at, deleted_by,
                      created_at, updated_at, managed_by
               FROM roles
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
        )
        .bind(&authorized.ids)
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    };
    Ok(RoleList {
        items,
        total: authorized.total,
    })
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
           WHERE r.id = ANY($1::uuid[]) AND r.deleted_at IS NULL"#,
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
    let mut connection = pool.acquire().await.map_err(db_err)?;
    validate_capabilities_against_target_on_connection(&mut connection, capability_ids, target)
        .await
}

async fn validate_capabilities_against_target_on_connection(
    connection: &mut sqlx::PgConnection,
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
        .fetch_all(&mut *connection)
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
    .fetch_all(&mut *connection)
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
    let mut connection = pool.acquire().await.map_err(db_err)?;
    resolve_exact_object_target_on_connection(&mut connection, object_id).await
}

async fn resolve_exact_object_target_on_connection(
    connection: &mut sqlx::PgConnection,
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
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateRole,
) -> Result<Role, AppError> {
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("role {id} not found")));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", id).await?;
    let role = sqlx::query_as::<_, Role>(
        r#"UPDATE roles
           SET name        = COALESCE($2, name),
               description = COALESCE($3, description),
               updated_at  = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING id, name, tenant_id, description, deleted_at, deleted_by,
                     created_at, updated_at, managed_by"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.description)
    .fetch_one(&mut **tx)
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

pub async fn update_role(pool: &PgPool, id: Uuid, req: UpdateRole) -> Result<Role, AppError> {
    update_role_with_audit(pool, false, None, id, req).await
}

pub async fn delete_role_with_audit(
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("role {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", id).await?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    if !live {
        return Err(AppError::not_found(format!("role {id} not found")));
    }
    let result = sqlx::query(
        "UPDATE roles SET deleted_at = now(), deleted_by = $2
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(deleted_by)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    if result.rows_affected() == 0 {
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
    pool: &PgPool,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_role_with_audit(pool, false, None, id, deleted_by).await
}

pub async fn restore_role_with_audit(
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let _ = restored_by;
    let expected_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NOT NULL")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    let Some(expected_tenant_id) = expected_tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted role {id} to restore"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", id).await?;
    let tenant_info: Option<(Option<Uuid>, bool)> = sqlx::query_as(
        "SELECT r.tenant_id, (t.deleted_at IS NOT NULL)
         FROM roles r
         LEFT JOIN tenants t ON t.id = r.tenant_id
         WHERE r.id = $1
           AND r.tenant_id IS NOT DISTINCT FROM $2
           AND r.deleted_at IS NOT NULL",
    )
    .bind(id)
    .bind(expected_tenant_id)
    .fetch_optional(&mut **tx)
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

    sqlx::query(
        "UPDATE roles SET deleted_at = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .execute(&mut **tx)
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
    pool: &PgPool,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    restore_role_with_audit(pool, false, None, id, restored_by).await
}

pub async fn purge_role_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(expected_tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted role {id} to purge"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", id).await?;

    let candidate_block_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT permission_block_id FROM role_permission_blocks WHERE role_id = $1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;

    let purged_tenant_id: Option<Option<Uuid>> = sqlx::query_scalar(
        "DELETE FROM roles WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let tenant_id = purged_tenant_id
        .ok_or_else(|| AppError::not_found(format!("no soft-deleted role {id} to purge")))?;

    if !candidate_block_ids.is_empty() {
        sqlx::query(
            r#"DELETE FROM permission_blocks pb
               WHERE pb.id = ANY($1)
                 AND pb.managed_by IS DISTINCT FROM 'config'
                 AND NOT EXISTS (
                     SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id
                 )"#,
        )
        .bind(&candidate_block_ids)
        .execute(&mut *tx)
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

pub async fn purge_role(pool: &PgPool, id: Uuid) -> Result<Option<Uuid>, AppError> {
    purge_role_with_audit(pool, false, None, id).await
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
    pool: &PgPool,
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
    pool: &PgPool,
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
    pool: &PgPool,
    role_id: Uuid,
    cap_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_role(&mut tx, role_id).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "roles", role_id).await?;
    // Blocks this role links that grant `cap_id`. Unlink them from this role and
    // GC any now-orphaned; blocks the same `cap_id` reaches through other roles
    // are untouched.
    let block_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT rpb.permission_block_id
           FROM role_permission_blocks rpb
           JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
           WHERE rpb.role_id = $1 AND pba.action_id = $2"#,
    )
    .bind(role_id)
    .bind(cap_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    unlink_role_blocks_and_gc(&mut tx, role_id, &block_ids).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

// ─── Capabilities ─────────────────────────────────────────────────────────────

pub async fn create_capability(
    pool: &PgPool,
    req: CreateCapability,
) -> Result<Capability, AppError> {
    create_capability_with_audit(pool, false, None, req).await
}

pub async fn create_capability_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
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

pub async fn get_capability(pool: &PgPool, id: Uuid) -> Result<Capability, AppError> {
    sqlx::query_as::<_, Capability>(
        "SELECT id, name, description, created_at, updated_at, managed_by FROM actions WHERE id = $1",
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
        r#"SELECT id, name, description, created_at, updated_at, managed_by FROM actions c
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
        r#"SELECT object_kind, object_type, managed_by
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
                  ca.created_at,
                  ca.managed_by
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
                  decision, is_absolute, created_at, managed_by
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
                  decision, is_absolute, created_at, managed_by
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
    create_action_assignment_rule_with_audit(pool, false, None, req, "internal").await
}

/// `transport` is supplied by the caller: the repo cannot know which surface
/// invoked it, and the audit trail records it (see `grpc.rs` / `graphql`).
pub async fn create_action_assignment_rule_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateActionAssignmentRule,
    transport: &str,
) -> Result<ActionAssignmentRule, AppError> {
    let req = validate_and_normalize_action_assignment_rule(pool, req).await?;
    let action_name = req.action_name.clone();
    let object_type = req.object_type.clone();

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

    let mut tx = pool.begin().await.map_err(db_err)?;
    let rule = sqlx::query_as::<_, ActionAssignmentRule>(
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
    .fetch_one(&mut *tx)
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
    pool: &PgPool,
    req: CreateActionAssignmentRule,
) -> Result<CreateActionAssignmentRule, AppError> {
    let mut connection = pool.acquire().await.map_err(db_err)?;
    validate_and_normalize_action_assignment_rule_on_connection(&mut connection, req).await
}

pub(crate) async fn validate_and_normalize_action_assignment_rule_on_connection(
    connection: &mut sqlx::PgConnection,
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

    let action_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM actions WHERE name = $1)")
            .bind(&req.action_name)
            .fetch_one(connection)
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
    pool: &PgPool,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    delete_action_assignment_rule_with_audit(pool, false, None, id, "internal").await
}

/// See [`create_action_assignment_rule_with_audit`] for `transport`.
pub async fn delete_action_assignment_rule_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    transport: &str,
) -> Result<ActionAssignmentRule, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM action_assignment_rules WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
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
    let rule = sqlx::query_as::<_, ActionAssignmentRule>(
        r#"DELETE FROM action_assignment_rules
           WHERE id = $1
           RETURNING id, tenant_id, entity_kind, action_name, object_kind, object_type,
                     decision, is_absolute, created_at"#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
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
    tx: &mut Transaction<'_, Postgres>,
    capability_id: Uuid,
    object_kind: &str,
    object_type: Option<&str>,
) -> Result<(), AppError> {
    let action_locked: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM actions WHERE id = $1 FOR UPDATE")
            .bind(capability_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    if action_locked.is_none() {
        return Err(AppError::not_found(format!(
            "capability {capability_id} not found"
        )));
    }
    let managed_by: Option<Option<String>> = sqlx::query_scalar(
        r#"SELECT managed_by FROM action_applicability
           WHERE action_id = $1
             AND object_kind = $2
             AND object_type IS NOT DISTINCT FROM $3
           FOR UPDATE"#,
    )
    .bind(capability_id)
    .bind(object_kind)
    .bind(object_type)
    .fetch_optional(&mut **tx)
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
    pool: &PgPool,
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
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
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

    let insert = sqlx::query(
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
                  ca.created_at,
                  ca.managed_by
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

    if insert.rows_affected() == 0 {
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
    pool: &PgPool,
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
    pool: &PgPool,
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
    let result = sqlx::query(
        r#"DELETE FROM action_applicability
           WHERE action_id = $1
             AND object_kind = $2
             AND object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(capability_id)
    .bind(&object_kind)
    .bind(&object_type)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    if result.rows_affected() == 0 {
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
    pool: &PgPool,
    id: Uuid,
    req: crate::models::capability::UpdateCapability,
) -> Result<Capability, AppError> {
    update_capability_with_audit(pool, false, None, id, req).await
}

pub async fn update_capability_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: crate::models::capability::UpdateCapability,
) -> Result<Capability, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "actions", id).await?;
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
    tx: &mut Transaction<'_, Postgres>,
    capability_id: Uuid,
    applicability: &[CapabilityApplicabilityInput],
) -> Result<(), AppError> {
    // Refuse to blow away applicability rows that were declared in the
    // bootstrap config, even when the parent capability itself is API-managed.
    let has_managed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM action_applicability
                        WHERE action_id = $1 AND managed_by = 'config')",
    )
    .bind(capability_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    if has_managed {
        return Err(AppError::conflict(
            "capability has applicability rows managed by the bootstrap config file; \
             use addCapabilityApplicability / removeCapabilityApplicability instead",
        ));
    }

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
    delete_capability_with_audit(pool, false, None, id).await
}

pub async fn delete_capability_with_audit(
    pool: &PgPool,
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
    let config_owned_link: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1
               FROM permission_block_actions pba
               JOIN permission_blocks pb ON pb.id = pba.permission_block_id
               WHERE pba.action_id = $1 AND pb.managed_by = 'config'
           )"#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if config_owned_link {
        return Err(AppError::conflict(
            "capability is linked to a permission block managed by the bootstrap config file and cannot be deleted via the API",
        ));
    }
    let result = sqlx::query("DELETE FROM actions WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
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
    tx: &mut Transaction<'_, Postgres>,
    assignment_tenant_id: Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<(), AppError> {
    let subject_tenant_id = read_live_subject_tenant_id(tx, subject_kind, subject_id).await?;
    lock_active_tenant_ids(tx, [assignment_tenant_id, subject_tenant_id]).await?;
    lock_live_subject_row(tx, subject_kind, subject_id, subject_tenant_id).await
}

async fn read_live_subject_tenant_id(
    tx: &mut Transaction<'_, Postgres>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let subject_tenant_id: Option<Option<Uuid>> = match subject_kind {
        SubjectKind::Entity => sqlx::query_scalar(
            r#"SELECT tenant_id FROM entities
                   WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
        )
        .bind(subject_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?,
        SubjectKind::Group => sqlx::query_scalar(
            r#"SELECT tenant_id FROM principal_groups
                   WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
        )
        .bind(subject_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?,
    };
    let Some(subject_tenant_id) = subject_tenant_id else {
        return Err(AppError::bad_request(
            "assignment references a deleted, disabled, or unknown subject",
        ));
    };
    Ok(subject_tenant_id)
}

async fn lock_active_tenant_ids<const N: usize>(
    tx: &mut Transaction<'_, Postgres>,
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
    tx: &mut Transaction<'_, Postgres>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let table = match subject_kind {
        SubjectKind::Entity => "entities",
        SubjectKind::Group => "principal_groups",
    };
    let sql = format!(
        r#"SELECT id FROM {table}
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status = 'active'
             AND deleted_at IS NULL
           FOR UPDATE"#
    );
    let locked: Option<Uuid> = sqlx::query_scalar(&sql)
        .bind(subject_id)
        .bind(expected_tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::bad_request(
            "assignment subject changed during validation",
        ));
    }
    Ok(())
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
    tx: &mut Transaction<'_, Postgres>,
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
    tx: &mut Transaction<'_, Postgres>,
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
    pool: &PgPool,
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
    if should_sync_membership {
        if let Some(tenant_id) = membership_tenant_id {
            sync_tenant_membership_for_policy(&mut tx, tenant_id, membership_entity_id).await?;
        }
    }
    tx.commit().await.map_err(db_err)?;

    get_policy(pool, id).await
}

async fn sync_tenant_membership_for_policy(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
           SELECT $1, $2, 'active'
           WHERE EXISTS (
               SELECT 1 FROM entities
               WHERE id = $2
                 AND kind = 'human'
                 AND status = 'active'
                 AND deleted_at IS NULL
           )
           ON CONFLICT (tenant_id, entity_id)
           DO UPDATE SET status = 'active'"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&mut **tx)
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

pub async fn create_role_assignment_with_audit(
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
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
    let assignment = sqlx::query_as::<_, RoleAssignment>(
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, $2, $3, $4)
           RETURNING id, tenant_id, subject_kind, subject_id, role_id, created_at"#,
    )
    .bind(req.tenant_id)
    .bind(req.subject_kind)
    .bind(req.subject_id)
    .bind(req.role_id)
    .fetch_one(&mut **tx)
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
    pool: &PgPool,
    req: CreateRoleAssignment,
) -> Result<RoleAssignment, AppError> {
    create_role_assignment_with_audit(pool, false, None, req).await
}

/// Returns `true` when a new assignment row was actually inserted, so callers
/// can tell a real state change from an idempotent no-op and decide whether the
/// operation is worth publishing as a domain event.
pub(crate) async fn create_role_assignment_if_missing_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    req: &CreateRoleAssignment,
) -> Result<bool, AppError> {
    prepare_role_assignment_in_tx(tx, req).await?;
    validate_role_assignment_in_tx(tx, req).await?;
    let inserted = sqlx::query(
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           SELECT $1, $2, $3, $4
           WHERE NOT EXISTS (
               SELECT 1 FROM role_assignments
               WHERE tenant_id IS NOT DISTINCT FROM $1
                 AND subject_kind = $2
                 AND subject_id = $3
                 AND role_id = $4
           )"#,
    )
    .bind(req.tenant_id)
    .bind(req.subject_kind.clone())
    .bind(req.subject_id)
    .bind(req.role_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?
    .rows_affected();
    Ok(inserted > 0)
}

pub(crate) async fn lock_live_entity_subject_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    assignment_tenant_id: Option<Uuid>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    lock_live_subject(tx, assignment_tenant_id, &SubjectKind::Entity, entity_id).await
}

pub async fn list_role_assignments(
    pool: &PgPool,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, RoleAssignment>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at, managed_by
           FROM role_assignments
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR role_id = $4)
             AND EXISTS (SELECT 1 FROM roles r WHERE r.id = role_assignments.role_id AND r.deleted_at IS NULL)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = role_assignments.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = role_assignments.subject_id AND sg.deleted_at IS NULL))
             )
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
             AND ($4::uuid IS NULL OR role_id = $4)
             AND EXISTS (SELECT 1 FROM roles r WHERE r.id = role_assignments.role_id AND r.deleted_at IS NULL)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = role_assignments.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = role_assignments.subject_id AND sg.deleted_at IS NULL))
             )"#,
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

pub async fn list_role_assignments_authorized(
    pool: &PgPool,
    auth: &crate::auth::AuthContext,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    const CANDIDATES: &str = r#"SELECT id, tenant_id,
                  row_number() OVER (ORDER BY created_at DESC, id) AS ordinality
           FROM role_assignments
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
                  OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'subject_kind', '') IS NULL
                  OR subject_kind = ($5->>'subject_kind'))
             AND (NULLIF($5->>'subject_id', '')::uuid IS NULL
                  OR subject_id = NULLIF($5->>'subject_id', '')::uuid)
             AND (NULLIF($5->>'role_id', '')::uuid IS NULL
                  OR role_id = NULLIF($5->>'role_id', '')::uuid)
             AND EXISTS (SELECT 1 FROM roles r WHERE r.id = role_assignments.role_id AND r.deleted_at IS NULL)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = role_assignments.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = role_assignments.subject_id AND sg.deleted_at IS NULL))
             )"#;
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
        CANDIDATES,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, RoleAssignment>(
            r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at, managed_by
               FROM role_assignments
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
        )
        .bind(&authorized.ids)
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    };
    Ok(RoleAssignmentList {
        items,
        total: authorized.total,
    })
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
    delete_role_assignment_with_audit(pool, false, None, id).await
}

pub async fn delete_role_assignment_with_audit(
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM role_assignments WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut **tx)
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
    let result = sqlx::query("DELETE FROM role_assignments WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
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
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateDirectPolicy,
) -> Result<DirectPolicy, AppError> {
    prepare_direct_policy_in_tx(tx, &req).await?;
    validate_direct_policy_in_tx(tx, &req).await?;
    crate::guardrails::validate_direct_policy(tx, &req).await?;
    let block_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM permission_blocks WHERE id = $1 FOR UPDATE")
            .bind(req.permission_block_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    if block_tenant_id != Some(req.tenant_id) {
        return Err(AppError::bad_request(
            "direct policy references a missing or cross-tenant permission block",
        ));
    }
    let policy = sqlx::query_as::<_, DirectPolicy>(
        r#"INSERT INTO direct_policies
             (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, $2, $3, $4)
           RETURNING id, tenant_id, subject_kind, subject_id, permission_block_id, created_at"#,
    )
    .bind(req.tenant_id)
    .bind(req.subject_kind)
    .bind(req.subject_id)
    .bind(req.permission_block_id)
    .fetch_one(&mut **tx)
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
    pool: &PgPool,
    req: CreateDirectPolicy,
) -> Result<DirectPolicy, AppError> {
    create_direct_policy_with_audit(pool, false, None, req).await
}

/// Resolves the object's own object groups and every ancestor of those
/// groups, carrying `(object_kind, object_type)` in the shape a permission
/// block records it, so a block's declared scope can be compared the way the
/// PDP compares it (`grant_scope_matches`, migration 001).
///
/// Anchored at the object and walks *upward*, so cost is bounded by tree
/// depth, not block count. The membership joins return every matching row —
/// an object in several groups must produce a match for each.
const DIRECT_POLICY_OBJECT_CTE: &str = r#"WITH RECURSIVE object_parent_groups(group_id, object_kind, object_type) AS (
             SELECT oge.group_id, 'entity'::text, 'entity:' || e.kind
             FROM object_group_entities oge
             JOIN entities e ON e.id = oge.entity_id
             WHERE oge.entity_id = $5::uuid AND e.deleted_at IS NULL
             UNION ALL
             SELECT ogr.group_id, 'resource'::text, 'resource:' || r.kind
             FROM object_group_resources ogr
             JOIN resources r ON r.id = ogr.resource_id
             WHERE ogr.resource_id = $5::uuid AND r.deleted_at IS NULL
             UNION ALL
             SELECT ogh.parent_id, 'group'::text, 'group:object'
             FROM object_group_hierarchy ogh
             JOIN object_groups og ON og.id = ogh.child_id
             WHERE ogh.child_id = $5::uuid AND og.deleted_at IS NULL
           ),
           object_ancestor_groups(group_id, object_kind, object_type) AS (
             SELECT ogh.parent_id, opg.object_kind, opg.object_type
             FROM object_parent_groups opg
             JOIN object_group_hierarchy ogh ON ogh.child_id = opg.group_id
             UNION ALL
             SELECT ogh.parent_id, oag.object_kind, oag.object_type
             FROM object_ancestor_groups oag
             JOIN object_group_hierarchy ogh ON ogh.child_id = oag.group_id
           )"#;

/// The reverse-lookup predicate: does this policy's permission block name the
/// object in `$5`, narrowed by the optional `$6` / `$7` co-filters?
///
/// Only scope modes that name a specific object, or a group object directly /
/// through a group hierarchy, are considered. A `group_descendant_objects` block
/// matches through *strict* ancestors of the object's own group, mirroring the
/// PDP: an object directly in the block's group is the `group_direct_objects`
/// case, not the descendant case.
const DIRECT_POLICY_OBJECT_PREDICATE: &str = r#"($5::uuid IS NULL OR EXISTS (
               SELECT 1 FROM permission_blocks pb
               WHERE pb.id = direct_policies.permission_block_id
                 AND ($6::text IS NULL OR pb.object_kind IS NULL OR pb.object_kind = $6)
                 AND ($7::text IS NULL OR pb.object_type IS NULL OR pb.object_type = $7)
                 AND (
                   (pb.scope_mode = 'object' AND pb.object_id = $5)
                   OR (pb.scope_mode = 'group'
                       AND pb.group_id = $5
                       AND ($6::text IS NULL OR $6 = 'group')
                       AND ($7::text IS NULL OR $7 = 'group:object')
                       AND EXISTS (
                         SELECT 1 FROM object_groups og
                         WHERE og.id = $5
                           AND og.deleted_at IS NULL))
                   OR (pb.scope_mode = 'group_direct_objects' AND EXISTS (
                         SELECT 1 FROM object_parent_groups opg
                         WHERE opg.group_id = pb.group_id
                           AND opg.object_kind = pb.object_kind
                           AND opg.object_type = pb.object_type))
                   OR (pb.scope_mode = 'group_descendant_objects' AND EXISTS (
                         SELECT 1 FROM object_ancestor_groups oag
                         WHERE oag.group_id = pb.group_id
                           AND oag.object_kind = pb.object_kind
                           AND oag.object_type = pb.object_type))
                   OR (pb.scope_mode = 'group_child_groups'
                       AND ($6::text IS NULL OR $6 = 'group')
                       AND ($7::text IS NULL OR $7 = 'group:object')
                       AND EXISTS (
                         SELECT 1 FROM object_parent_groups opg
                         WHERE opg.group_id = pb.group_id
                           AND opg.object_kind = 'group'))
                   OR (pb.scope_mode = 'group_descendant_groups'
                       AND ($6::text IS NULL OR $6 = 'group')
                       AND ($7::text IS NULL OR $7 = 'group:object')
                       AND (
                         EXISTS (
                           SELECT 1 FROM object_parent_groups opg
                           WHERE opg.group_id = pb.group_id
                             AND opg.object_kind = 'group')
                         OR EXISTS (
                           SELECT 1 FROM object_ancestor_groups oag
                           WHERE oag.group_id = pb.group_id
                             AND oag.object_kind = 'group')))
                 )
             ))"#;

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
    pool: &PgPool,
    params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let object_type = normalize_optional_text(params.object_type);
    validate_direct_policy_object_filter(
        params.object_id,
        params.object_kind,
        object_type.as_deref(),
    )?;
    let items_sql = format!(
        r#"{DIRECT_POLICY_OBJECT_CTE}
           SELECT id, tenant_id, subject_kind, subject_id, permission_block_id, created_at, managed_by
           FROM direct_policies
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR permission_block_id = $4)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = direct_policies.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = direct_policies.subject_id AND sg.deleted_at IS NULL))
             )
             AND {DIRECT_POLICY_OBJECT_PREDICATE}
           ORDER BY created_at DESC
           LIMIT $8 OFFSET $9"#
    );
    let items = sqlx::query_as::<_, DirectPolicy>(&items_sql)
        .bind(params.tenant_id)
        .bind(params.subject_kind.clone())
        .bind(params.subject_id)
        .bind(params.permission_block_id)
        .bind(params.object_id)
        .bind(params.object_kind)
        .bind(&object_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    let total_sql = format!(
        r#"{DIRECT_POLICY_OBJECT_CTE}
           SELECT COUNT(*)
           FROM direct_policies
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR permission_block_id = $4)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = direct_policies.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = direct_policies.subject_id AND sg.deleted_at IS NULL))
             )
             AND {DIRECT_POLICY_OBJECT_PREDICATE}"#
    );
    let total = sqlx::query_scalar(&total_sql)
        .bind(params.tenant_id)
        .bind(params.subject_kind)
        .bind(params.subject_id)
        .bind(params.permission_block_id)
        .bind(params.object_id)
        .bind(params.object_kind)
        .bind(&object_type)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    Ok(DirectPolicyList { items, total })
}

pub async fn list_direct_policies_authorized(
    pool: &PgPool,
    auth: &crate::auth::AuthContext,
    params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    let object_type = normalize_optional_text(params.object_type);
    validate_direct_policy_object_filter(
        params.object_id,
        params.object_kind,
        object_type.as_deref(),
    )?;
    let object_cte =
        DIRECT_POLICY_OBJECT_CTE.replace("$5::uuid", "NULLIF($5->>'object_id', '')::uuid");
    let object_predicate = DIRECT_POLICY_OBJECT_PREDICATE
        .replace("$5::uuid", "__OBJECT_ID__")
        .replace("$5", "__OBJECT_ID__")
        .replace("$6::text", "__OBJECT_KIND__")
        .replace("$6", "__OBJECT_KIND__")
        .replace("$7::text", "__OBJECT_TYPE__")
        .replace("$7", "__OBJECT_TYPE__")
        .replace("__OBJECT_ID__", "NULLIF($5->>'object_id', '')::uuid")
        .replace("__OBJECT_KIND__", "NULLIF($5->>'object_kind', '')")
        .replace("__OBJECT_TYPE__", "NULLIF($5->>'object_type', '')");
    let candidates_sql = format!(
        r#"{object_cte}
           SELECT id, tenant_id,
                  row_number() OVER (ORDER BY created_at DESC, id) AS ordinality
           FROM direct_policies
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
                  OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'subject_kind', '') IS NULL
                  OR subject_kind = ($5->>'subject_kind'))
             AND (NULLIF($5->>'subject_id', '')::uuid IS NULL
                  OR subject_id = NULLIF($5->>'subject_id', '')::uuid)
             AND (NULLIF($5->>'permission_block_id', '')::uuid IS NULL
                  OR permission_block_id = NULLIF($5->>'permission_block_id', '')::uuid)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = direct_policies.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = direct_policies.subject_id AND sg.deleted_at IS NULL))
             )
             AND {object_predicate}"#
    );
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
        &candidates_sql,
        params.limit,
        params.offset,
    )
    .await?;
    let items = if authorized.ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, DirectPolicy>(
            r#"SELECT id, tenant_id, subject_kind, subject_id, permission_block_id,
                      created_at, managed_by
               FROM direct_policies
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
        )
        .bind(&authorized.ids)
        .fetch_all(pool)
        .await
        .map_err(db_err)?
    };
    Ok(DirectPolicyList {
        items,
        total: authorized.total,
    })
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

pub async fn delete_direct_policy_with_audit(
    pool: &PgPool,
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
    tx: &mut Transaction<'_, Postgres>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let policy_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM direct_policies WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = policy_tenant_id else {
        return Err(AppError::not_found(format!("direct policy {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "direct_policies", id).await?;
    let block_id: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM direct_policies WHERE id = $1 RETURNING permission_block_id",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
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

pub async fn delete_direct_policy(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    delete_direct_policy_with_audit(pool, false, None, id).await
}

pub(crate) async fn validate_role_assignment_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    req: &CreateRoleAssignment,
) -> Result<(), AppError> {
    let role_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL")
            .bind(req.role_id)
            .fetch_optional(&mut **tx)
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
    tx: &mut Transaction<'_, Postgres>,
    req: &CreateDirectPolicy,
) -> Result<(), AppError> {
    let block_tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM permission_blocks WHERE id = $1")
            .bind(req.permission_block_id)
            .fetch_optional(&mut **tx)
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
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<(), AppError> {
    match subject_kind {
        SubjectKind::Entity => {
            let entity_tenant_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT tenant_id FROM entities WHERE id = $1 AND deleted_at IS NULL",
            )
            .bind(subject_id)
            .fetch_optional(&mut **tx)
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
                .fetch_one(&mut **tx)
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
            let group_tenant_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT tenant_id FROM principal_groups WHERE id = $1 AND deleted_at IS NULL",
            )
            .bind(subject_id)
            .fetch_optional(&mut **tx)
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
                    deleted_at: None,
                    deleted_by: None,
                    created_at: row.try_get("role_created_at").map_err(db_err)?,
                    updated_at: row.try_get("role_updated_at").map_err(db_err)?,
                    // Explain view; only surfaces role identity, not lifecycle
                    // metadata. Leave managed_by unset — the UI reads it via
                    // list_roles / get_role, not this SELECT.
                    managed_by: None,
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
    let mut tx = pool.begin().await.map_err(db_err)?;
    let direct_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM direct_policies WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    if let Some(tenant_id) = direct_tenant_id {
        crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
        crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "direct_policies", id).await?;
        let block_id: Uuid = sqlx::query_scalar(
            "DELETE FROM direct_policies WHERE id = $1 RETURNING permission_block_id",
        )
        .bind(id)
        .fetch_one(&mut *tx)
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
        sqlx::query_scalar("SELECT tenant_id FROM role_assignments WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(tenant_id) = assignment_tenant_id else {
        return Err(AppError::not_found(format!("policy {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "role_assignments", id).await?;
    let result = sqlx::query("DELETE FROM role_assignments WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    debug_assert_eq!(result.rows_affected(), 1);
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

/// Best-effort ownership lookup for exact-object policy scopes. `None` means
/// no object with that UUID exists in the known Atom object tables; `Some(None)`
/// means the object is platform/global.
pub async fn object_tenant_id_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    Ok(crate::protected_objects::lookup(pool, id)
        .await?
        .filter(|object| object.live)
        .map(|object| object.tenant_id))
}

/// SQL CTE selecting the unconditional ceiling entries of the caller's scoped
/// access token (empty result when the bound credential id is NULL / the token
/// is unscoped). Conditional entries are excluded: like the coarse gates, a
/// listing has no per-request context to evaluate them, so they fail closed
/// here and per-object authzCheck remains the path that can honour them.
///
/// Single source for every ceiling-aware listing (entity/resource/group and
/// tenant visibility) — splice via [`ceiling_cte`] so the fail-closed rule
/// cannot drift between readers.
const CEILING_CTE: &str = r#"ceiling AS (
                   SELECT s.scope_kind, s.scope_ref, l.tenant_id, la.action_id
                   FROM credential_permission_limits l
                   JOIN credential_permission_limit_scopes s ON s.limit_id = l.id
                   JOIN credential_permission_limit_actions la ON la.limit_id = l.id
                   WHERE l.credential_id = __CEILING_PARAM__::uuid
                     AND l.conditions = '{}'::jsonb
               )"#;

/// Render [`CEILING_CTE`] with the bind position that carries the scoped
/// token's credential id (e.g. `"$12"`).
pub(crate) fn ceiling_cte(param: &str) -> String {
    CEILING_CTE.replace("__CEILING_PARAM__", param)
}

/// Ceiling-aware listing entry point for request-path callers. The scoped-token
/// ceiling is derived here from the caller's `AuthContext`
/// (`ceiling_credential_for`), never passed by hand, so a call site cannot
/// forget to apply it — the same rule as `engine::evaluate`. A delegated
/// listing about another subject is unaffected (the derivation yields `None`).
pub async fn authorized_object_ids(
    pool: &PgPool,
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
    pool: &PgPool,
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
    pool: &PgPool,
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
    const ROLE_CANDIDATES: &str = r#"SELECT id, tenant_id,
               row_number() OVER (ORDER BY name, id) AS ordinality
           FROM roles
           WHERE deleted_at IS NULL
             AND (NULLIF($5->>'tenant_id', '')::uuid IS NULL OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL OR name ILIKE ($5->>'q') OR description ILIKE ($5->>'q'))
             AND (NULLIF($5->>'id', '') IS NULL OR id::text ILIKE ($5->>'id'))"#;
    const POLICY_CANDIDATES: &str = r#"SELECT id, tenant_id,
               row_number() OVER (ORDER BY created_at DESC, id) AS ordinality
           FROM (
               SELECT id, tenant_id, created_at FROM direct_policies
               UNION ALL
               SELECT id, tenant_id, created_at FROM role_assignments
           ) policies
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL OR id::text ILIKE ($5->>'q'))
             AND (NULLIF($5->>'id', '') IS NULL OR id::text ILIKE ($5->>'id'))"#;
    const ENDPOINT_CANDIDATES: &str = r#"SELECT id, tenant_id,
               row_number() OVER (ORDER BY tenant_id NULLS FIRST, key, id) AS ordinality
           FROM api_endpoints
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL OR name ILIKE ($5->>'q') OR key ILIKE ($5->>'q'))
             AND (NULLIF($5->>'id', '') IS NULL OR id::text ILIKE ($5->>'id'))"#;
    let candidate_sql = match params.object_kind.as_str() {
        "role" => ROLE_CANDIDATES,
        "policy" => POLICY_CANDIDATES,
        "api_endpoint" => ENDPOINT_CANDIDATES,
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
    pool: &PgPool,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let id = search_pattern(params.id);
    let q = search_pattern(params.q);
    let external_id = crate::models::external_id::normalize_external_id(params.external_id);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = authorized_entity_order_by(params.entity_order, params.dir);

    let sql = r#"WITH RECURSIVE target_groups(id) AS (
                   SELECT $8::uuid WHERE $8::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $9::boolean
               ),
               grants AS (
                   SELECT * FROM subject_effective_grants($1)
               ),
               __CEILING_CTE__,
               caps AS (
                   SELECT a.id AS capability_id, aa.object_type
                   FROM actions a
                   JOIN action_applicability aa ON aa.action_id = a.id
                   WHERE a.name = $2 AND aa.object_kind = 'entity'
               ),
               candidates AS (
                   SELECT e.id, e.kind::text AS sub_kind, e.tenant_id, e.created_at, e.updated_at,
                          e.name, e.status::text AS status,
                          COALESCE((SELECT array_agg(gep.group_id)
                                    FROM group_entity_parents gep
                                    WHERE gep.entity_id = e.id), '{}'::uuid[]) AS parent_group_ids
                   FROM entities e
                   WHERE e.deleted_at IS NULL
                     AND (e.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = e.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL))
                     AND ($3::uuid IS NULL OR e.tenant_id = $3)
                     AND ($4::text IS NULL OR e.kind::text = $4 OR 'entity:' || e.kind::text = $4)
                     AND ($5::text IS NULL OR e.name ILIKE $5 OR e.attributes::text ILIKE $5)
                     AND ($6::uuid IS NULL OR e.profile_id = $6)
                     AND ($7::text IS NULL OR e.status::text = $7)
                     AND ($8::uuid IS NULL OR EXISTS (
                             SELECT 1 FROM group_entity_parents gep
                             WHERE gep.entity_id = e.id
                               AND gep.group_id IN (SELECT id FROM target_groups)))
                     AND ($13::jsonb IS NULL OR e.attributes @> $13::jsonb)
                     AND ($14::text IS NULL OR e.external_id = $14)
                     AND ($15::text IS NULL OR e.id::text ILIKE $15)
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = ANY(c.parent_group_ids)
                   UNION
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               candidate_ancestor_ids AS (
                   SELECT object_id, array_agg(ancestor_id) AS ancestors
                   FROM candidate_ancestors
                   GROUP BY object_id
               ),
               authorized AS (
                   SELECT c.id, c.created_at, c.updated_at, c.name, c.sub_kind, c.status
                   FROM candidates c
                   LEFT JOIN candidate_ancestor_ids ca ON ca.object_id = c.id
                   WHERE EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'allow' AND g.conditions = '{}'::jsonb
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'entity', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'deny'
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'entity', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND ($12::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling cl
                       WHERE (cl.tenant_id IS NULL OR cl.tenant_id = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = cl.action_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                         )
                         AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'entity', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   ))
               )
               SELECT id, COUNT(*) OVER() AS total
               FROM authorized
               ORDER BY __ORDER_BY__
               LIMIT $10 OFFSET $11"#
        .replace("__ORDER_BY__", order_by)
        .replace("__CEILING_CTE__", &ceiling_cte("$12"));

    let rows = sqlx::query(&sql)
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
        .bind(ceiling_credential_id)
        .bind(attributes_contains)
        .bind(external_id)
        .bind(id)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    rows_to_authorized_object_ids(rows)
}

#[derive(Debug, Clone, Copy)]
enum AuthorizedResourceProjection {
    Ids,
    Kinds,
}

async fn authorized_resource_ids(
    pool: &PgPool,
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
    pool: &PgPool,
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
    pool: &PgPool,
    subject_id: Uuid,
    tenant_id: Option<Uuid>,
    ceiling_credential_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    use sqlx::Row;

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
        .map(|row| row.try_get("kind").map_err(db_err))
        .collect()
}

async fn authorized_resource_rows(
    pool: &PgPool,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
    projection: AuthorizedResourceProjection,
) -> Result<Vec<sqlx::postgres::PgRow>, AppError> {
    let limit = match projection {
        AuthorizedResourceProjection::Ids => params.limit.clamp(1, 500),
        AuthorizedResourceProjection::Kinds => 500,
    };
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = authorized_resource_order_by(params.resource_order, params.dir);

    let select_clause = match projection {
        AuthorizedResourceProjection::Ids => format!(
            "SELECT id, COUNT(*) OVER() AS total
             FROM authorized
             ORDER BY {order_by}
             LIMIT $9 OFFSET $10"
        ),
        AuthorizedResourceProjection::Kinds => String::from(
            "SELECT DISTINCT sub_kind AS kind
             FROM authorized
             ORDER BY kind
             LIMIT $9 OFFSET $10",
        ),
    };
    let sql = r#"WITH RECURSIVE target_groups(id) AS (
                   SELECT $6::uuid WHERE $6::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $7::boolean
               ),
               grants AS (
                   SELECT * FROM subject_effective_grants($1)
               ),
               __CEILING_CTE__,
               caps AS (
                   SELECT a.id AS capability_id, aa.object_type
                   FROM actions a
                   JOIN action_applicability aa ON aa.action_id = a.id
                   WHERE a.name = $2 AND aa.object_kind = 'resource'
               ),
               candidates AS (
                   SELECT r.id, r.kind AS sub_kind, r.tenant_id, r.created_at, r.updated_at,
                          r.name,
                          COALESCE((SELECT array_agg(grp.group_id)
                                    FROM group_resource_parents grp
                                    WHERE grp.resource_id = r.id), '{}'::uuid[]) AS parent_group_ids
                   FROM resources r
                   WHERE r.deleted_at IS NULL
                     AND (r.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL))
                     AND ($3::uuid IS NULL OR r.tenant_id = $3)
                     AND ($4::text IS NULL OR r.kind = $4 OR 'resource:' || r.kind = $4)
                     AND ($5::text IS NULL OR r.name ILIKE $5 OR r.attributes::text ILIKE $5)
                     AND ($6::uuid IS NULL OR EXISTS (
                             SELECT 1 FROM group_resource_parents grp
                             WHERE grp.resource_id = r.id
                               AND grp.group_id IN (SELECT id FROM target_groups)))
                     AND ($8::jsonb IS NULL OR r.attributes @> $8::jsonb)
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = ANY(c.parent_group_ids)
                   UNION
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               candidate_ancestor_ids AS (
                   SELECT object_id, array_agg(ancestor_id) AS ancestors
                   FROM candidate_ancestors
                   GROUP BY object_id
               ),
               authorized AS (
                   SELECT c.id, c.sub_kind, c.created_at, c.updated_at, c.name
                   FROM candidates c
                   LEFT JOIN candidate_ancestor_ids ca ON ca.object_id = c.id
                   WHERE EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'allow' AND g.conditions = '{}'::jsonb
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'resource', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'deny'
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'resource', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND ($11::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling cl
                       WHERE (cl.tenant_id IS NULL OR cl.tenant_id = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = cl.action_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                         )
                         AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'resource', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   ))
               )
               __SELECT__"#
        .replace("__SELECT__", &select_clause)
        .replace("__CEILING_CTE__", &ceiling_cte("$11"));

    sqlx::query(&sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.object_type)
        .bind(q)
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(attributes_contains)
        .bind(limit)
        .bind(offset)
        .bind(ceiling_credential_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

async fn authorized_group_ids(
    pool: &PgPool,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let status = params.entity_status.map(|status| match status {
        crate::models::enums::EntityStatus::Active => "active".to_string(),
        crate::models::enums::EntityStatus::Inactive => "inactive".to_string(),
        crate::models::enums::EntityStatus::Suspended => "suspended".to_string(),
    });
    let order_by = authorized_group_order_by(params.group_order, params.dir);

    // Scope matching is delegated to the shared `grant_scope_matches` predicate
    // (the same logic the PDP's Rust path mirrors). For groups the relevant
    // scopes are platform/tenant/object_kind/object plus `group_child_kind`/
    // `group_descendant_kind`; the `group_*_objects` scope modes are
    // CHECK-constrained to entity/resource objects, so they never target a group.
    let sql = r#"WITH RECURSIVE target_groups(id) AS (
                   SELECT $6::uuid WHERE $6::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $7::boolean
               ),
               grants AS (
                   SELECT * FROM subject_effective_grants($1)
               ),
               __CEILING_CTE__,
               caps AS (
                   SELECT a.id AS capability_id, aa.object_type
                   FROM actions a
                   JOIN action_applicability aa ON aa.action_id = a.id
                   WHERE a.name = $2 AND aa.object_kind = 'group'
               ),
               candidates AS (
                   SELECT g.id, 'group'::text AS sub_kind, g.tenant_id, g.created_at, g.updated_at,
                          g.name, g.status::text AS status,
                          CASE WHEN gph.parent_id IS NULL THEN '{}'::uuid[]
                               ELSE ARRAY[gph.parent_id] END AS parent_group_ids
                   FROM groups g
                   LEFT JOIN group_hierarchy gph ON gph.child_id = g.id
                   WHERE g.deleted_at IS NULL
                     AND (g.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = g.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL))
                     AND ($3::uuid IS NULL OR g.tenant_id = $3)
                     AND ($4::text IS NULL OR g.group_type = $4)
                     AND ($5::text IS NULL OR g.name ILIKE $5 OR g.description ILIKE $5 OR g.attributes::text ILIKE $5)
                     AND ($8::text IS NULL OR g.status = $8)
                     AND ($6::uuid IS NULL OR gph.parent_id IN (SELECT id FROM target_groups))
                     AND ($12::jsonb IS NULL OR g.attributes @> $12::jsonb)
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = ANY(c.parent_group_ids)
                   UNION
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               candidate_ancestor_ids AS (
                   SELECT object_id, array_agg(ancestor_id) AS ancestors
                   FROM candidate_ancestors
                   GROUP BY object_id
               ),
               authorized AS (
                   SELECT c.id, c.created_at, c.updated_at, c.name, c.status
                   FROM candidates c
                   LEFT JOIN candidate_ancestor_ids ca ON ca.object_id = c.id
                   WHERE EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'allow' AND g.conditions = '{}'::jsonb
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'group:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'group', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'deny'
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'group:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'group', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND ($11::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling cl
                       WHERE (cl.tenant_id IS NULL OR cl.tenant_id = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = cl.action_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'group:' || c.sub_kind)
                         )
                         AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'group', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   ))
               )
               SELECT id, COUNT(*) OVER() AS total
               FROM authorized
               ORDER BY __ORDER_BY__
               LIMIT $9 OFFSET $10"#
        .replace("__ORDER_BY__", order_by)
        .replace("__CEILING_CTE__", &ceiling_cte("$11"));

    let rows = sqlx::query(&sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.group_type)
        .bind(q)
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .bind(ceiling_credential_id)
        .bind(attributes_contains)
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

pub async fn audit_logs(
    pool: &PgPool,
    params: crate::models::access::AuditQuery,
    allowed_tenant_ids: Option<Vec<Uuid>>,
) -> Result<AuditLogResponse, AppError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, AuditLogItem>(
        r#"SELECT id, actor_entity_id, tenant_id, target_kind, target_id, event, outcome, details, created_at
           FROM audit_logs
           WHERE ($1::uuid IS NULL OR actor_entity_id = $1)
             AND ($2::text IS NULL OR event = $2)
             AND ($3::text IS NULL OR outcome = $3)
             AND ($4::timestamptz IS NULL OR created_at >= $4)
             AND ($5::timestamptz IS NULL OR created_at < $5)
             AND ($6::uuid IS NULL OR tenant_id = $6)
             AND ($7::uuid[] IS NULL OR tenant_id = ANY($7))
             AND ($8::text IS NULL OR target_kind = $8)
             AND ($9::uuid IS NULL OR target_id = $9)
           ORDER BY created_at DESC
           LIMIT $10 OFFSET $11"#,
    )
    .bind(params.actor_entity_id)
    .bind(params.event.clone())
    .bind(params.outcome.clone())
    .bind(params.from)
    .bind(params.to)
    .bind(params.tenant_id)
    .bind(allowed_tenant_ids.as_deref())
    .bind(params.target_kind.clone())
    .bind(params.target_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM audit_logs
           WHERE ($1::uuid IS NULL OR actor_entity_id = $1)
             AND ($2::text IS NULL OR event = $2)
             AND ($3::text IS NULL OR outcome = $3)
             AND ($4::timestamptz IS NULL OR created_at >= $4)
             AND ($5::timestamptz IS NULL OR created_at < $5)
             AND ($6::uuid IS NULL OR tenant_id = $6)
             AND ($7::uuid[] IS NULL OR tenant_id = ANY($7))
             AND ($8::text IS NULL OR target_kind = $8)
             AND ($9::uuid IS NULL OR target_id = $9)"#,
    )
    .bind(params.actor_entity_id)
    .bind(params.event)
    .bind(params.outcome)
    .bind(params.from)
    .bind(params.to)
    .bind(params.tenant_id)
    .bind(allowed_tenant_ids.as_deref())
    .bind(params.target_kind)
    .bind(params.target_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(AuditLogResponse { items, total })
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
    pool: &PgPool,
    entity_id: Uuid,
    action_name: &str,
    object_kind: &str,
) -> Result<Vec<Uuid>, AppError> {
    let Some(action_id): Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
            .bind(action_name)
            .fetch_optional(pool)
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
    .bind(params.kind)
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
    pub(crate) parent_group_ids: Vec<Uuid>,
}

pub(crate) async fn load_authz_subject(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Option<AuthzSubjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzSubjectRecord>(
        r#"SELECT id, name, kind, tenant_id, status, attributes
           FROM entities
           WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_tenant(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<AuthzTenantRecord>, AppError> {
    sqlx::query_as::<_, AuthzTenantRecord>(
        r#"SELECT id, name, status, deleted_at, attributes
           FROM tenants
           WHERE id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_resource(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT r.id, r.kind, r.name, r.tenant_id, r.attributes,
                  COALESCE((SELECT array_agg(grp.group_id)
                            FROM group_resource_parents grp
                            WHERE grp.resource_id = r.id), '{}'::uuid[]) AS parent_group_ids
           FROM resources r
           WHERE r.id = $1 AND r.deleted_at IS NULL"#,
    )
    .bind(resource_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_entity_object(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.attributes,
                  COALESCE((SELECT array_agg(gep.group_id)
                            FROM group_entity_parents gep
                            WHERE gep.entity_id = e.id), '{}'::uuid[]) AS parent_group_ids
           FROM entities e
           WHERE e.id = $1 AND e.status <> 'inactive' AND e.deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_group_object(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    // The group hierarchy stays a tree (`PRIMARY KEY (child_id)`), so this is 0
    // or 1 parent — carried as an array only so every protected object presents
    // the same shape to the scope predicate.
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT g.id, 'group'::text AS kind, g.name, g.tenant_id, g.attributes,
                  CASE WHEN gh.parent_id IS NULL THEN '{}'::uuid[] ELSE ARRAY[gh.parent_id] END
                      AS parent_group_ids
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE g.id = $1 AND g.status <> 'inactive' AND g.deleted_at IS NULL"#,
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_credential_object(
    pool: &PgPool,
    credential_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT c.id, c.kind, c.identifier AS name, e.tenant_id,
                  c.metadata AS attributes, '{}'::uuid[] AS parent_group_ids
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.id = $1"#,
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

/// Recursive ancestors of every supplied group, de-duplicated. An object can be
/// in several groups in different subtrees, so the tree scopes must be evaluated
/// against the union of their ancestors, not one branch's.
pub(crate) async fn group_ancestor_ids(
    pool: &PgPool,
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    if group_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(
        r#"WITH RECURSIVE ancestors(id) AS (
               SELECT parent_id FROM group_hierarchy WHERE child_id = ANY($1::uuid[])
               UNION
               SELECT gh.parent_id
               FROM group_hierarchy gh
               JOIN ancestors a ON gh.child_id = a.id
           )
           SELECT DISTINCT id FROM ancestors"#,
    )
    .bind(group_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// Canonical grant expansion for a subject: the single flat list of effective
/// grants (direct policies and role-linked blocks), with the subject's group
/// membership resolved recursively. Each grant carries the permission block's
/// real scope, effect and conditions plus the assignment-level tenant boundary,
/// so a reader can decide access by matching tenant → block scope → action →
/// conditions and applying the effect (deny overrides allow).
pub async fn effective_grants_for_subject(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Vec<EffectiveGrant>, AppError> {
    use sqlx::Row;
    // Canonical grant expansion lives in the `subject_effective_grants` SQL
    // function, shared by this PDP path and every authorized
    // listing reader so scope/effect/conditions semantics cannot drift.
    let rows = sqlx::query(
        r#"SELECT assignment_id, block_id, role_id, role_name, via, tenant_boundary,
                  scope_kind, scope_ref, capability_id, effect, conditions
           FROM subject_effective_grants($1)"#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(|row| {
            let scope_kind_text: String = row.try_get("scope_kind").map_err(db_err)?;
            Ok(EffectiveGrant {
                assignment_id: row.try_get("assignment_id").map_err(db_err)?,
                block_id: row.try_get("block_id").map_err(db_err)?,
                role_id: row.try_get("role_id").map_err(db_err)?,
                role_name: row.try_get("role_name").map_err(db_err)?,
                via: row.try_get("via").map_err(db_err)?,
                tenant_boundary: row.try_get("tenant_boundary").map_err(db_err)?,
                scope_kind: parse_scope_kind_text(&scope_kind_text)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                capability_id: row.try_get("capability_id").map_err(db_err)?,
                effect: row.try_get("effect").map_err(db_err)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
            })
        })
        .collect()
}

/// Locks every root group's owning tenant row first, then the hierarchy
/// advisory lock, then every group in the closure rooted at `root_group_ids`
/// (each root plus every descendant subgroup, via a `group_hierarchy`
/// descent) `FOR UPDATE`. Object-group rows are locked before principal-group
/// rows, and each physical table is locked in stable UUID order. This matches
/// the canonical physical-group ordering used by mutations when a legacy UUID
/// exists in both tables. The member entity ids across that (now-locked)
/// closure are returned.
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
    tx: &mut Transaction<'_, Postgres>,
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
    tx: &mut Transaction<'_, Postgres>,
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
/// preparation needs the same ordering barrier as live mutations, and a UUID
/// present in both physical group tables must contribute both ownership rows.
async fn lock_group_tenant_rows(
    tx: &mut Transaction<'_, Postgres>,
    group_ids: &[Uuid],
) -> Result<(), AppError> {
    let tenant_ids: Vec<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM groups WHERE id = ANY($1::uuid[])")
            .bind(group_ids)
            .fetch_all(&mut **tx)
            .await
            .map_err(db_err)?;
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids).await
}

async fn lock_group_closures_after_tenant_rows(
    tx: &mut Transaction<'_, Postgres>,
    root_group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    // Hierarchy rows can be inserted or removed without an existing row lock
    // to wait on. Serialize closure enumeration with every hierarchy mutation
    // so a newly attached subtree cannot enter the graph between enumeration
    // and the locks below.
    lock_group_hierarchy(tx).await?;

    let mut closure: Vec<Uuid> = sqlx::query_scalar(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT id FROM UNNEST($1::uuid[]) AS root(id)
               UNION
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
           )
           SELECT id FROM target_groups"#,
    )
    .bind(root_group_ids)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)?;
    closure.sort_unstable();
    closure.dedup();

    // A legacy UUID may exist in both physical group tables. Every mutation
    // that can encounter both uses object -> principal ordering; taking only
    // the principal lock here could deadlock with such a mutation holding the
    // object row. Object-only roots still need this lock so their hierarchy
    // cannot be changed while the prepared closure is in use.
    sqlx::query("SELECT id FROM object_groups WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&closure)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;

    sqlx::query("SELECT id FROM principal_groups WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&closure)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;

    sqlx::query_scalar("SELECT DISTINCT entity_id FROM group_members WHERE group_id = ANY($1)")
        .bind(&closure)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)
}

pub(crate) async fn load_authz_role_object(
    pool: &PgPool,
    role_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT r.id, 'role'::text AS kind, r.name, r.tenant_id,
                  '{}'::jsonb AS attributes, '{}'::uuid[] AS parent_group_ids
           FROM roles r
           JOIN protected_object_ids registry
             ON registry.id = r.id
            AND registry.object_kind = 'role'
            AND registry.source_table = 'roles'
           WHERE r.id = $1 AND r.deleted_at IS NULL"#,
    )
    .bind(role_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_policy_object(
    pool: &PgPool,
    policy_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT registry.id, 'policy'::text AS kind, NULL::text AS name,
                  policy.tenant_id, '{}'::jsonb AS attributes,
                  '{}'::uuid[] AS parent_group_ids
           FROM protected_object_ids registry
           JOIN LATERAL (
               SELECT tenant_id
               FROM direct_policies
               WHERE registry.source_table = 'direct_policies' AND id = registry.id
               UNION ALL
               SELECT tenant_id
               FROM role_assignments
               WHERE registry.source_table = 'role_assignments' AND id = registry.id
           ) policy ON TRUE
           WHERE registry.id = $1 AND registry.object_kind = 'policy'"#,
    )
    .bind(policy_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(crate) async fn load_authz_api_endpoint_object(
    pool: &PgPool,
    endpoint_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT endpoint.id, 'api_endpoint'::text AS kind, endpoint.name,
                  endpoint.tenant_id, '{}'::jsonb AS attributes,
                  '{}'::uuid[] AS parent_group_ids
           FROM api_endpoints endpoint
           JOIN protected_object_ids registry
             ON registry.id = endpoint.id
            AND registry.object_kind = 'api_endpoint'
            AND registry.source_table = 'api_endpoints'
           WHERE endpoint.id = $1"#,
    )
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

/// Serializes recursive group-closure reads with hierarchy mutations. A
/// transaction-scoped advisory lock is used because an attach/detach may
/// create or delete the hierarchy row, leaving no row lock for a reader to
/// wait on.
pub async fn lock_group_hierarchy(tx: &mut Transaction<'_, Postgres>) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('atom:group-hierarchy', 0))")
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// [`lock_group_closures_and_collect_member_ids`], mapped straight to
/// `atom:v1:grants:*` cache keys — the form every locked group-subject
/// mutation call site actually wants.
pub async fn lock_group_closures_and_collect_grants_keys(
    tx: &mut Transaction<'_, Postgres>,
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
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
) -> Result<Vec<String>, AppError> {
    let role_tenant_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT tenant_id FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(&mut **tx)
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
        let tenant_locked: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_err)?;
        if tenant_locked.is_none() {
            return Err(AppError::not_found(format!(
                "role {role_id} tenant {tenant_id} not found"
            )));
        }
    }
    let locked: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM roles
           WHERE id = $1 AND tenant_id IS NOT DISTINCT FROM $2
           FOR UPDATE"#,
    )
    .bind(role_id)
    .bind(role_tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("role {role_id} not found")));
    }
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "roles", role_id).await?;
    let entity_subject_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT subject_id FROM role_assignments WHERE role_id = $1 AND subject_kind = 'entity'",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)?;
    let group_subject_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT subject_id FROM role_assignments WHERE role_id = $1 AND subject_kind = 'group'",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
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
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
    subject_group_id: Uuid,
) -> Result<Vec<String>, AppError> {
    lock_role(tx, role_id).await?;
    lock_group_closures_and_collect_grants_keys(tx, &[subject_group_id]).await
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
