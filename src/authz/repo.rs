use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::{
        capability::{Capability, CreateCapability, ListCapabilities},
        policy::{CreatePolicyBinding, ListPolicies, PolicyBinding, PolicyList},
        resource::{CreateResource, ListResources, Resource, ResourceList, UpdateResource},
        role::{CreateRole, ListRoles, Role, RoleList},
    },
};

// ─── Resources ────────────────────────────────────────────────────────────────

pub async fn create_resource(pool: &PgPool, req: CreateResource) -> Result<Resource, AppError> {
    let id = Uuid::new_v4();
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

pub async fn list_resources(pool: &PgPool, params: ListResources) -> Result<ResourceList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let kind = params.kind;
    let tenant_id = params.tenant_id;

    let items = sqlx::query_as::<_, Resource>(
        r#"SELECT id, kind, name, tenant_id, owner_id, attributes, created_at, updated_at
           FROM resources
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR tenant_id = $2)
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(kind.clone())
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM resources
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR tenant_id = $2)"#,
    )
    .bind(kind)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ResourceList { items, total })
}

pub async fn update_resource(pool: &PgPool, id: Uuid, req: UpdateResource) -> Result<Resource, AppError> {
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
    sqlx::query_as::<_, Role>(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, created_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_role(pool: &PgPool, id: Uuid) -> Result<Role, AppError> {
    sqlx::query_as::<_, Role>(
        "SELECT id, name, tenant_id, description, created_at FROM roles WHERE id = $1",
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

    let items = sqlx::query_as::<_, Role>(
        r#"SELECT id, name, tenant_id, description, created_at FROM roles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
           ORDER BY name LIMIT $2 OFFSET $3"#,
    )
    .bind(params.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM roles WHERE ($1::uuid IS NULL OR tenant_id = $1)"
    )
    .bind(params.tenant_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleList { items, total })
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

pub async fn add_role_capability(pool: &PgPool, role_id: Uuid, cap_id: Uuid) -> Result<(), AppError> {
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

pub async fn remove_role_capability(pool: &PgPool, role_id: Uuid, cap_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM role_capabilities WHERE role_id = $1 AND capability_id = $2",
    )
    .bind(role_id)
    .bind(cap_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn get_role_capabilities(pool: &PgPool, role_id: Uuid) -> Result<Vec<Capability>, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"SELECT c.id, c.name, c.resource_kind, c.description
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

pub async fn create_capability(pool: &PgPool, req: CreateCapability) -> Result<Capability, AppError> {
    let id = Uuid::new_v4();
    sqlx::query_as::<_, Capability>(
        r#"INSERT INTO capabilities (id, name, resource_kind, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, resource_kind, description"#,
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
        "SELECT id, name, resource_kind, description FROM capabilities WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("capability {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_capabilities(pool: &PgPool, params: ListCapabilities) -> Result<Vec<Capability>, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"SELECT id, name, resource_kind, description FROM capabilities
           WHERE ($1::text IS NULL OR resource_kind = $1 OR resource_kind IS NULL)
           ORDER BY name"#,
    )
    .bind(params.resource_kind)
    .fetch_all(pool)
    .await
    .map_err(db_err)
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

pub async fn create_policy(pool: &PgPool, req: CreatePolicyBinding) -> Result<PolicyBinding, AppError> {
    let id = Uuid::new_v4();
    let conditions = if req.conditions.is_null() {
        serde_json::json!({})
    } else {
        req.conditions
    };
    sqlx::query_as::<_, PolicyBinding>(
        r#"INSERT INTO policy_bindings
             (id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at"#,
    )
    .bind(id)
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
    .map_err(db_err)
}

pub async fn get_policy(pool: &PgPool, id: Uuid) -> Result<PolicyBinding, AppError> {
    sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at
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
    let subject_id = params.subject_id;
    let subject_kind = params.subject_kind;

    let items = sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at
           FROM policy_bindings
           WHERE ($1::uuid IS NULL OR subject_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(subject_id)
    .bind(subject_kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM policy_bindings
           WHERE ($1::uuid IS NULL OR subject_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)"#,
    )
    .bind(subject_id)
    .bind(subject_kind)
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

// ─── Engine helpers ───────────────────────────────────────────────────────────

pub async fn load_bindings_for_entity(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Vec<PolicyBinding>, AppError> {
    sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT pb.id, pb.subject_kind, pb.subject_id, pb.grant_kind, pb.grant_id,
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
    let rows =
        sqlx::query("SELECT role_id, capability_id FROM role_capabilities WHERE role_id = ANY($1::uuid[])")
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
