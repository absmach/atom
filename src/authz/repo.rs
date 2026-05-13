use std::collections::{BTreeMap, HashMap};

use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::{
        access::{
            AccessItem, AccessQuery, AdminPageQuery, AuditLogItem, AuditLogResponse,
            CapabilitySource, CapabilitySummary, EffectiveCapabilitiesQuery,
            EffectiveCapabilitiesResponse, EffectiveCapability, EntityAccessResponse,
            EntitySummary, ExpiringCredentialItem, ExpiringCredentialsQuery,
            ExpiringCredentialsResponse, GrantSummary, GroupAccessItem, GroupAccessQuery,
            GroupAccessResponse, GroupInfo, OrphanPoliciesResponse, OrphanPolicyItem,
            ResourceAccessEntity, ResourceAccessItem, ResourceAccessQuery, ResourceAccessResponse,
            ResourceSummary, RoleHolderGroup, RoleHolderItem, RoleHoldersQuery,
            RoleHoldersResponse, RoleSummary, RoleWithCapabilities, UnprotectedResourceItem,
            UnprotectedResourcesQuery, UnprotectedResourcesResponse,
        },
        capability::{Capability, CreateCapability, ListCapabilities},
        entity::Entity,
        enums::{CredentialKind, Effect, GrantKind, SubjectKind},
        group::Group,
        policy::{CreatePolicyBinding, ListPolicies, PolicyBinding, PolicyList},
        resource::{CreateResource, ListResources, Resource, ResourceList, UpdateResource},
        role::{CreateRole, ListRoles, Role, RoleList, UpdateRole},
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
    sqlx::query_as::<_, Resource>(
        r#"INSERT INTO resources (id, kind, name, tenant_id, owner_id, attributes)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, kind, name, tenant_id, owner_id, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.kind)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.owner_id)
    .bind(attrs)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_resource(pool: &PgPool, id: Uuid) -> Result<Resource, AppError> {
    sqlx::query_as::<_, Resource>(
        "SELECT id, kind, name, tenant_id, owner_id, attributes, created_at, updated_at FROM resources WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_resources(
    pool: &PgPool,
    params: ListResources,
) -> Result<ResourceList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let kind = params.kind;
    let tenant_id = params.tenant_id;
    let q = search_pattern(params.q);

    let items = sqlx::query_as::<_, Resource>(
        r#"SELECT id, kind, name, tenant_id, owner_id, attributes, created_at, updated_at
           FROM resources
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR tenant_id = $2)
             AND ($3::text IS NULL OR name ILIKE $3 OR attributes::text ILIKE $3)
           ORDER BY created_at DESC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(kind.clone())
    .bind(tenant_id)
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM resources
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR tenant_id = $2)
             AND ($3::text IS NULL OR name ILIKE $3 OR attributes::text ILIKE $3)"#,
    )
    .bind(kind)
    .bind(tenant_id)
    .bind(q)
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
    sqlx::query_as::<_, Resource>(
        r#"UPDATE resources
           SET name       = COALESCE($2, name),
               attributes = COALESCE($3, attributes),
               updated_at = now()
           WHERE id = $1
           RETURNING id, kind, name, tenant_id, owner_id, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.attributes)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })
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

// ─── Roles ────────────────────────────────────────────────────────────────────

pub async fn create_role(pool: &PgPool, req: CreateRole) -> Result<Role, AppError> {
    let id = Uuid::new_v4();
    let scope_kind = req.scope_kind.unwrap_or_else(|| {
        if req.tenant_id.is_some() {
            "tenant".to_string()
        } else {
            "platform".to_string()
        }
    });
    let scope_ref = req
        .scope_ref
        .or_else(|| req.tenant_id.map(|tenant_id| tenant_id.to_string()));
    sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description, scope_kind, scope_ref)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, name, tenant_id, description, scope_kind, scope_ref, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .bind(scope_kind)
    .bind(scope_ref)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_role(pool: &PgPool, id: Uuid) -> Result<Role, AppError> {
    sqlx::query_as::<_, Role>(
        "SELECT id, name, tenant_id, description, scope_kind, scope_ref, created_at, updated_at FROM roles WHERE id = $1",
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

    let items = sqlx::query_as::<_, Role>(
        r#"SELECT id, name, tenant_id, description, scope_kind, scope_ref, created_at, updated_at FROM roles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR scope_kind = $2)
             AND ($3::text IS NULL OR scope_ref = $3)
             AND ($4::text IS NULL OR name ILIKE $4 OR description ILIKE $4)
           ORDER BY name LIMIT $5 OFFSET $6"#,
    )
    .bind(params.tenant_id)
    .bind(params.scope_kind.clone())
    .bind(params.scope_ref.clone())
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM roles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR scope_kind = $2)
             AND ($3::text IS NULL OR scope_ref = $3)
             AND ($4::text IS NULL OR name ILIKE $4 OR description ILIKE $4)"#,
    )
    .bind(params.tenant_id)
    .bind(params.scope_kind)
    .bind(params.scope_ref)
    .bind(q)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleList { items, total })
}

pub async fn update_role(pool: &PgPool, id: Uuid, req: UpdateRole) -> Result<Role, AppError> {
    sqlx::query_as::<_, Role>(
        r#"UPDATE roles
           SET name        = COALESCE($2, name),
               description = COALESCE($3, description),
               updated_at  = now()
           WHERE id = $1
           RETURNING id, name, tenant_id, description, scope_kind, scope_ref, created_at, updated_at"#,
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
    crate::guardrails::validate_role_capability(pool, role_id, cap_id).await?;
    sqlx::query(
        "INSERT INTO role_capabilities (role_id, capability_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(role_id)
    .bind(cap_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn remove_role_capability(
    pool: &PgPool,
    role_id: Uuid,
    cap_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM role_capabilities WHERE role_id = $1 AND capability_id = $2")
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
        r#"SELECT c.id, c.name, c.resource_kind, c.description, c.created_at, c.updated_at
           FROM capabilities c
           JOIN role_capabilities rc ON rc.capability_id = c.id
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
    sqlx::query_as::<_, Capability>(
        r#"INSERT INTO capabilities (id, name, resource_kind, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, resource_kind, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.resource_kind)
    .bind(req.description)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_capability(pool: &PgPool, id: Uuid) -> Result<Capability, AppError> {
    sqlx::query_as::<_, Capability>(
        "SELECT id, name, resource_kind, description, created_at, updated_at FROM capabilities WHERE id = $1",
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
        r#"SELECT id, name, resource_kind, description, created_at, updated_at FROM capabilities
           WHERE ($1::text IS NULL OR resource_kind = $1)
           ORDER BY name LIMIT $2 OFFSET $3"#,
    )
    .bind(&params.resource_kind)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM capabilities WHERE ($1::text IS NULL OR resource_kind = $1)",
    )
    .bind(&params.resource_kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(crate::models::capability::CapabilityList { items, total })
}

pub async fn update_capability(
    pool: &PgPool,
    id: Uuid,
    req: crate::models::capability::UpdateCapability,
) -> Result<Capability, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"UPDATE capabilities
           SET name          = COALESCE($2, name),
               resource_kind = COALESCE($3, resource_kind),
               description   = COALESCE($4, description),
               updated_at    = now()
           WHERE id = $1
           RETURNING id, name, resource_kind, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.resource_kind)
    .bind(req.description)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("capability {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn delete_capability(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM capabilities WHERE id = $1")
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
    let policy = sqlx::query_as::<_, PolicyBinding>(
        r#"INSERT INTO policy_bindings
             (id, tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING id, tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at"#,
    )
    .bind(id)
    .bind(req.tenant_id)
    .bind(req.subject_kind)
    .bind(req.subject_id)
    .bind(req.grant_kind)
    .bind(req.grant_id)
    .bind(req.scope_kind)
    .bind(req.scope_ref)
    .bind(req.effect)
    .bind(conditions)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

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
           FROM policy_bindings WHERE id = $1"#,
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
           FROM policy_bindings
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
        r#"SELECT COUNT(*) FROM policy_bindings
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
           FROM policy_bindings
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
           FROM policy_bindings
           WHERE grant_kind = 'role' AND grant_id = $1"#,
    )
    .bind(role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(PolicyList { items, total })
}

pub async fn delete_policy(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM policy_bindings WHERE id = $1")
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
             SELECT tenant_id FROM policy_bindings WHERE id = $1
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
        r#"SELECT id, kind, name, tenant_id, profile_id, profile_version_id,
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
             FROM policy_bindings pb
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $1
             UNION ALL
             SELECT pb.*, ('group:' || g.name)::text AS via
             FROM policy_bindings pb
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
                   SELECT 1 FROM role_capabilities rc
                   WHERE rc.role_id = b.grant_id AND rc.capability_id = $5
                 ))
               )
           )
           SELECT e.*,
                  COALESCE(jsonb_agg(jsonb_build_object(
                    'id', c.id,
                    'name', c.name,
                    'resource_kind', c.resource_kind
                  ) ORDER BY c.name) FILTER (WHERE c.id IS NOT NULL), '[]'::jsonb) AS capabilities
           FROM expanded e
           LEFT JOIN role_capabilities rc ON e.grant_kind = 'role' AND rc.role_id = e.grant_id
           LEFT JOIN capabilities c ON
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
             SELECT pb.* FROM policy_bindings pb
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $1
             UNION ALL
             SELECT pb.* FROM policy_bindings pb
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
                 SELECT 1 FROM role_capabilities rc
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
             FROM policy_bindings pb
             JOIN entities e ON pb.subject_kind = 'entity' AND e.id = pb.subject_id
             WHERE pb.scope_kind = 'platform'
                OR (pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource')
                OR (pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || $1)
                OR (pb.scope_kind = 'object' AND pb.scope_ref = $2)
             UNION ALL
             SELECT pb.*, e.id AS entity_id, e.name AS entity_name, e.kind AS entity_kind,
                    e.tenant_id AS entity_tenant_id, ('group:' || g.name)::text AS via
             FROM policy_bindings pb
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
                   SELECT 1 FROM role_capabilities rc
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
                    'name', cap.name,
                    'resource_kind', cap.resource_kind
                  ) ORDER BY cap.name) FILTER (WHERE cap.id IS NOT NULL), '[]'::jsonb) AS capabilities
           FROM filtered f
           LEFT JOIN role_capabilities rc ON f.grant_kind = 'role' AND rc.role_id = f.grant_id
           LEFT JOIN capabilities cap ON
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
           FROM policy_bindings pb
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
             FROM policy_bindings pb
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
                   SELECT 1 FROM role_capabilities rc
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
                    'name', c.name,
                    'resource_kind', c.resource_kind
                  ) ORDER BY c.name) FILTER (WHERE c.id IS NOT NULL), '[]'::jsonb) AS capabilities
           FROM expanded e
           LEFT JOIN role_capabilities rc ON e.grant_kind = 'role' AND rc.role_id = e.grant_id
           LEFT JOIN capabilities c ON
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
            resource_kind: cap.resource_kind,
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
           FROM policy_bindings pb
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
           FROM policy_bindings pb
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

pub async fn effective_capabilities(
    pool: &PgPool,
    entity_id: Uuid,
    params: EffectiveCapabilitiesQuery,
) -> Result<EffectiveCapabilitiesResponse, AppError> {
    use sqlx::Row;
    let entity = sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, tenant_id, profile_id, profile_version_id,
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
             FROM policy_bindings pb
             LEFT JOIN roles r ON pb.grant_kind = 'role' AND r.id = pb.grant_id
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $1
               AND ($2::uuid IS NULL OR r.tenant_id = $2)
             UNION ALL
             SELECT pb.*, ('group:' || g.name)::text AS via
             FROM policy_bindings pb
             JOIN group_members gm ON gm.group_id = pb.subject_id
             JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
             LEFT JOIN roles r ON pb.grant_kind = 'role' AND r.id = pb.grant_id
             WHERE pb.subject_kind = 'group' AND gm.entity_id = $1
               AND ($2::uuid IS NULL OR g.tenant_id = $2 OR r.tenant_id = $2)
           )
           SELECT c.id AS capability_id, c.name AS capability_name, c.resource_kind,
                  b.grant_kind, b.grant_id, role.name AS role_name, b.id AS policy_id,
                  b.scope_kind, b.scope_ref, b.effect, b.via
           FROM bindings b
           LEFT JOIN roles role ON b.grant_kind = 'role' AND role.id = b.grant_id
           LEFT JOIN role_capabilities rc ON b.grant_kind = 'role' AND rc.role_id = b.grant_id
           JOIN capabilities c ON
             (b.grant_kind = 'capability' AND c.id = b.grant_id)
             OR (b.grant_kind = 'role' AND c.id = rc.capability_id)
           WHERE ($3::text IS NULL OR c.resource_kind = $3 OR c.resource_kind IS NULL)
           ORDER BY c.name, b.created_at DESC"#,
    )
    .bind(entity_id)
    .bind(params.tenant_id)
    .bind(params.resource_kind)
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
                resource_kind: row.try_get("resource_kind").unwrap_or(None),
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
        r#"SELECT DISTINCT pb.scope_ref::uuid
           FROM policy_bindings pb
           WHERE (
               (pb.subject_kind = 'entity' AND pb.subject_id = $1)
               OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                   SELECT group_id FROM group_members WHERE entity_id = $1
               ))
           )
             AND pb.effect = 'allow'
             AND pb.scope_kind = 'tenant'
             AND pb.scope_ref IS NOT NULL
             AND (
               (pb.grant_kind = 'capability' AND pb.grant_id IN (
                   SELECT id FROM capabilities WHERE name = $2 AND resource_kind IS NULL
               ))
               OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                   SELECT rc.role_id FROM role_capabilities rc
                   JOIN capabilities c ON c.id = rc.capability_id
                   WHERE c.name = $2 AND c.resource_kind IS NULL
               ))
             )"#,
    )
    .bind(entity_id)
    .bind(capability_name)
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
             SELECT pb.*,
                    CASE
                      WHEN (pb.subject_kind = 'entity' AND e.id IS NULL)
                        OR (pb.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN (pb.grant_kind = 'capability' AND c.id IS NULL)
                        OR (pb.grant_kind = 'role' AND r.id IS NULL)
                      THEN 'grant_not_found'
                    END AS orphan_reason
             FROM policy_bindings pb
             LEFT JOIN entities e ON pb.subject_kind = 'entity' AND pb.subject_id = e.id
             LEFT JOIN groups g ON pb.subject_kind = 'group' AND pb.subject_id = g.id
             LEFT JOIN capabilities c ON pb.grant_kind = 'capability' AND pb.grant_id = c.id
             LEFT JOIN roles r ON pb.grant_kind = 'role' AND pb.grant_id = r.id
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
                      WHEN (pb.subject_kind = 'entity' AND e.id IS NULL)
                        OR (pb.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN (pb.grant_kind = 'capability' AND c.id IS NULL)
                        OR (pb.grant_kind = 'role' AND r.id IS NULL)
                      THEN 'grant_not_found'
                    END AS orphan_reason
             FROM policy_bindings pb
             LEFT JOIN entities e ON pb.subject_kind = 'entity' AND pb.subject_id = e.id
             LEFT JOIN groups g ON pb.subject_kind = 'group' AND pb.subject_id = g.id
             LEFT JOIN capabilities c ON pb.grant_kind = 'capability' AND pb.grant_id = c.id
             LEFT JOIN roles r ON pb.grant_kind = 'role' AND pb.grant_id = r.id
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
                subject_kind: row.try_get("subject_kind").map_err(db_err)?,
                subject_id: row.try_get("subject_id").map_err(db_err)?,
                grant_kind: row.try_get("grant_kind").map_err(db_err)?,
                grant_id: row.try_get("grant_id").map_err(db_err)?,
                scope_kind: row.try_get("scope_kind").map_err(db_err)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                effect: row.try_get("effect").map_err(db_err)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
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
        r#"SELECT id, kind, name, tenant_id, owner_id, attributes, created_at, updated_at
           FROM resources r
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR kind = $2)
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb
               WHERE pb.scope_kind = 'object' AND pb.scope_ref = r.id::text
             )
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb
               WHERE pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || r.kind
             )
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb
               WHERE pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource'
             )
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb WHERE pb.scope_kind = 'platform'
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
               SELECT 1 FROM policy_bindings pb
               WHERE pb.scope_kind = 'object' AND pb.scope_ref = r.id::text
             )
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb
               WHERE pb.scope_kind = 'object_type' AND pb.scope_ref = 'resource:' || r.kind
             )
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb
               WHERE pb.scope_kind = 'object_kind' AND pb.scope_ref = 'resource'
             )
             AND NOT EXISTS (
               SELECT 1 FROM policy_bindings pb WHERE pb.scope_kind = 'platform'
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
        Some(name) => sqlx::query_scalar("SELECT id FROM capabilities WHERE name = $1 LIMIT 1")
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
        "SELECT id, name, tenant_id, description, status, attributes, created_at, updated_at FROM groups WHERE id = $1",
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
        r#"SELECT pb.id, pb.tenant_id, pb.subject_kind, pb.subject_id, pb.grant_kind, pb.grant_id,
                  pb.scope_kind, pb.scope_ref, pb.effect, pb.conditions, pb.created_at
           FROM policy_bindings pb
           WHERE
             (pb.subject_kind = 'entity' AND pb.subject_id = $1)
             OR
             (pb.subject_kind = 'group' AND pb.subject_id IN (
               SELECT group_id FROM group_members WHERE entity_id = $1
             ))"#,
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
        "SELECT role_id, capability_id FROM role_capabilities WHERE role_id = ANY($1::uuid[])",
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

pub async fn find_capability_by_name(
    pool: &PgPool,
    name: &str,
    resource_kind: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM capabilities
           WHERE name = $1
             AND (resource_kind IS NULL OR resource_kind = $2)
           ORDER BY resource_kind NULLS LAST
           LIMIT 1"#,
    )
    .bind(name)
    .bind(resource_kind)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}
