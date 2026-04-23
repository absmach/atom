use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::{
        entity::{CreateEntity, Entity, EntityList, ListEntities, Ownership},
        group::{CreateGroup, Group, GroupList, ListGroups},
        session::Session,
    },
};

// ─── Entities ────────────────────────────────────────────────────────────────

pub async fn create_entity(pool: &PgPool, req: CreateEntity) -> Result<Entity, AppError> {
    let id = Uuid::new_v4();
    let attrs = if req.attributes == Value::Null {
        serde_json::json!({})
    } else {
        req.attributes
    };
    sqlx::query_as::<_, Entity>(
        r#"INSERT INTO entities (id, kind, name, tenant_id, attributes)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, kind, name, tenant_id, status, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.kind)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(attrs)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_entity(pool: &PgPool, id: Uuid) -> Result<Entity, AppError> {
    sqlx::query_as::<_, Entity>(
        "SELECT id, kind, name, tenant_id, status, attributes, created_at, updated_at FROM entities WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_entities(pool: &PgPool, params: ListEntities) -> Result<EntityList, AppError> {
    let limit = params.limit.min(100).max(1);
    let offset = params.offset.max(0);
    let kind = params.kind;
    let tenant_id = params.tenant_id;
    let status = params.status;

    let items = sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, tenant_id, status, attributes, created_at, updated_at
           FROM entities
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR tenant_id = $2)
             AND ($3::text IS NULL OR status = $3)
           ORDER BY created_at DESC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(kind.clone())
    .bind(tenant_id)
    .bind(status.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM entities
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR tenant_id = $2)
             AND ($3::text IS NULL OR status = $3)"#,
    )
    .bind(kind)
    .bind(tenant_id)
    .bind(status)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub async fn update_entity(
    pool: &PgPool,
    id: Uuid,
    name: Option<String>,
    status: Option<String>,
    attributes: Option<Value>,
) -> Result<Entity, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"UPDATE entities
           SET name       = COALESCE($2, name),
               status     = COALESCE($3, status),
               attributes = COALESCE($4, attributes),
               updated_at = now()
           WHERE id = $1
           RETURNING id, kind, name, tenant_id, status, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(name)
    .bind(status)
    .bind(attributes)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn delete_entity(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("entity {id} not found")));
    }
    Ok(())
}

// ─── Sessions ────────────────────────────────────────────────────────────────

pub async fn create_session(
    pool: &PgPool,
    entity_id: Uuid,
    expiry_secs: u64,
) -> Result<Session, AppError> {
    let id = Uuid::new_v4();
    let expires_at: DateTime<Utc> = Utc::now() + Duration::seconds(expiry_secs as i64);

    sqlx::query_as::<_, Session>(
        r#"INSERT INTO sessions (id, entity_id, expires_at)
           VALUES ($1, $2, $3)
           RETURNING id, entity_id, expires_at, revoked_at, created_at"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_session(pool: &PgPool, id: Uuid) -> Result<Session, AppError> {
    sqlx::query_as::<_, Session>(
        "SELECT id, entity_id, expires_at, revoked_at, created_at FROM sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("session {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn revoke_session(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!(
            "session {id} not found or already revoked"
        )));
    }
    Ok(())
}

// ─── Groups ──────────────────────────────────────────────────────────────────

pub async fn create_group(pool: &PgPool, req: CreateGroup) -> Result<Group, AppError> {
    let id = Uuid::new_v4();
    sqlx::query_as::<_, Group>(
        r#"INSERT INTO groups (id, name, tenant_id, description)
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

pub async fn get_group(pool: &PgPool, id: Uuid) -> Result<Group, AppError> {
    sqlx::query_as::<_, Group>(
        "SELECT id, name, tenant_id, description, created_at, updated_at FROM groups WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("group {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_groups(pool: &PgPool, params: ListGroups) -> Result<GroupList, AppError> {
    let limit = params.limit.min(100).max(1);
    let offset = params.offset.max(0);

    let items = sqlx::query_as::<_, Group>(
        r#"SELECT id, name, tenant_id, description, created_at, updated_at
           FROM groups
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(params.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE ($1::uuid IS NULL OR tenant_id = $1)")
            .bind(params.tenant_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    Ok(GroupList { items, total })
}

pub async fn delete_group(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!("group {id} not found")));
    }
    Ok(())
}

pub async fn add_group_member(pool: &PgPool, group_id: Uuid, entity_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO group_members (group_id, entity_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(entity_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn remove_group_member(pool: &PgPool, group_id: Uuid, entity_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND entity_id = $2")
        .bind(group_id)
        .bind(entity_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub async fn list_group_members(pool: &PgPool, group_id: Uuid) -> Result<Vec<Entity>, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.status, e.attributes, e.created_at, e.updated_at
           FROM entities e
           JOIN group_members gm ON gm.entity_id = e.id
           WHERE gm.group_id = $1
           ORDER BY e.name"#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn get_entity_groups(pool: &PgPool, entity_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar("SELECT group_id FROM group_members WHERE entity_id = $1")
        .bind(entity_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

// ─── Ownerships ──────────────────────────────────────────────────────────────

pub async fn create_ownership(
    pool: &PgPool,
    owner_id: Uuid,
    owned_id: Uuid,
    relation: String,
) -> Result<Ownership, AppError> {
    sqlx::query_as::<_, Ownership>(
        r#"INSERT INTO ownerships (owner_id, owned_id, relation)
           VALUES ($1, $2, $3)
           ON CONFLICT (owner_id, owned_id) DO UPDATE SET relation = EXCLUDED.relation
           RETURNING owner_id, owned_id, relation, created_at"#,
    )
    .bind(owner_id)
    .bind(owned_id)
    .bind(relation)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn list_owned(pool: &PgPool, owner_id: Uuid) -> Result<Vec<Entity>, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.status, e.attributes, e.created_at, e.updated_at
           FROM entities e
           JOIN ownerships o ON o.owned_id = e.id
           WHERE o.owner_id = $1
           ORDER BY e.created_at DESC"#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn delete_ownership(pool: &PgPool, owner_id: Uuid, owned_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM ownerships WHERE owner_id = $1 AND owned_id = $2")
        .bind(owner_id)
        .bind(owned_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}
