use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::{
        entity::{CreateEntity, Entity, EntityList, ListEntities, Ownership, UpdateEntity},
        enums::EntityKind,
        group::{CreateGroup, Group, GroupList, ListGroups, UpdateGroup},
        session::Session,
    },
    schema,
};

// ─── Entities ────────────────────────────────────────────────────────────────

pub const AUTHENTICATED_USERS_GROUP_ID: Uuid = Uuid::from_u128(5);

pub async fn create_entity(pool: &PgPool, req: CreateEntity) -> Result<Entity, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = normalize_attributes(req.attributes);
    let (kind, profile_id, profile_version_id) = resolve_entity_profile(
        pool,
        req.kind,
        req.profile_id,
        req.profile_version_id,
        &attrs,
    )
    .await?;
    let is_human = kind == EntityKind::Human;

    let mut tx = pool.begin().await.map_err(db_err)?;
    let entity = sqlx::query_as::<_, Entity>(
        r#"INSERT INTO entities
           (id, kind, name, tenant_id, profile_id, profile_version_id, attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, kind, name, tenant_id, profile_id, profile_version_id,
                     status, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(kind)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(profile_id)
    .bind(profile_version_id)
    .bind(attrs)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    if is_human {
        add_authenticated_user_membership_in_tx(&mut tx, entity.id).await?;
    }

    tx.commit().await.map_err(db_err)?;
    Ok(entity)
}

pub async fn add_authenticated_user_membership_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO group_members (group_id, entity_id)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(AUTHENTICATED_USERS_GROUP_ID)
    .bind(entity_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn get_entity(pool: &PgPool, id: Uuid) -> Result<Entity, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, tenant_id, profile_id, profile_version_id,
                  status, attributes, created_at, updated_at
           FROM entities
           WHERE id = $1"#,
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
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let kind = params.kind;
    let profile_id = params.profile_id;
    let tenant_id = params.tenant_id;
    let status = params.status;
    let q = search_pattern(params.q);

    let items = sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, tenant_id, profile_id, profile_version_id,
                  status, attributes, created_at, updated_at
           FROM entities
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR profile_id = $2)
             AND ($3::uuid IS NULL OR tenant_id = $3)
             AND ($4::text IS NULL OR status = $4)
             AND ($5::text IS NULL OR name ILIKE $5 OR attributes::text ILIKE $5)
           ORDER BY created_at DESC
           LIMIT $6 OFFSET $7"#,
    )
    .bind(kind.clone())
    .bind(profile_id)
    .bind(tenant_id)
    .bind(status.clone())
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM entities
           WHERE ($1::text IS NULL OR kind = $1)
             AND ($2::uuid IS NULL OR profile_id = $2)
             AND ($3::uuid IS NULL OR tenant_id = $3)
             AND ($4::text IS NULL OR status = $4)
             AND ($5::text IS NULL OR name ILIKE $5 OR attributes::text ILIKE $5)"#,
    )
    .bind(kind)
    .bind(profile_id)
    .bind(tenant_id)
    .bind(status)
    .bind(q)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub async fn update_entity(pool: &PgPool, id: Uuid, req: UpdateEntity) -> Result<Entity, AppError> {
    let attributes = req.attributes.map(normalize_attributes);
    if let Some(attrs) = attributes.as_ref() {
        validate_existing_entity_attributes(pool, id, attrs).await?;
    }

    sqlx::query_as::<_, Entity>(
        r#"UPDATE entities
           SET name               = COALESCE($2, name),
               kind               = COALESCE($3, kind),
               tenant_id          = COALESCE($4, tenant_id),
               profile_id         = COALESCE($5, profile_id),
               profile_version_id = COALESCE($6, profile_version_id),
               status             = COALESCE($7, status),
               attributes         = COALESCE($8, attributes),
               updated_at         = now()
           WHERE id = $1
           RETURNING id, kind, name, tenant_id, profile_id, profile_version_id,
                     status, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.kind)
    .bind(req.tenant_id)
    .bind(req.profile_id)
    .bind(req.profile_version_id)
    .bind(req.status)
    .bind(attributes)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {id} not found")),
        other => AppError::Database(other),
    })
}

async fn resolve_entity_profile(
    pool: &PgPool,
    requested_kind: Option<EntityKind>,
    profile_id: Option<Uuid>,
    requested_profile_version_id: Option<Uuid>,
    attributes: &Value,
) -> Result<(EntityKind, Option<Uuid>, Option<Uuid>), AppError> {
    let Some(profile_id) = profile_id else {
        if requested_profile_version_id.is_some() {
            return Err(AppError::bad_request(
                "profile_version_id requires profile_id",
            ));
        }
        let kind = requested_kind
            .ok_or_else(|| AppError::bad_request("kind is required without profile_id"))?;
        return Ok((kind, None, None));
    };

    let profile = super::profile_repo::get_profile(pool, profile_id).await?;
    if profile.object_kind != "entity" {
        return Err(AppError::bad_request(format!(
            "profile {profile_id} is for object_kind '{}', not 'entity'",
            profile.object_kind
        )));
    }
    if profile.status != "active" {
        return Err(AppError::bad_request(format!(
            "profile {profile_id} is not active"
        )));
    }

    let kind = entity_kind_from_profile(&profile.kind)?;
    if let Some(requested_kind) = requested_kind {
        if requested_kind != kind {
            return Err(AppError::bad_request(format!(
                "profile kind '{}' conflicts with requested entity kind '{}'",
                profile.kind,
                entity_kind_as_str(&requested_kind)
            )));
        }
    }

    let version = match requested_profile_version_id {
        Some(version_id) => {
            let version = super::profile_repo::get_profile_version(pool, version_id).await?;
            if version.profile_id != profile_id {
                return Err(AppError::bad_request(format!(
                    "profile_version_id {version_id} does not belong to profile_id {profile_id}"
                )));
            }
            version
        }
        None => super::profile_repo::get_active_profile_version(pool, profile_id)
            .await?
            .ok_or_else(|| {
                AppError::bad_request(format!("profile {profile_id} has no active version"))
            })?,
    };

    schema::validate_json_schema(&version.json_schema, attributes)?;
    Ok((kind, Some(profile_id), Some(version.id)))
}

async fn validate_existing_entity_attributes(
    pool: &PgPool,
    id: Uuid,
    attributes: &Value,
) -> Result<(), AppError> {
    let schema = sqlx::query_scalar::<_, Value>(
        r#"SELECT pv.json_schema
           FROM entities e
           JOIN profile_versions pv ON pv.id = e.profile_version_id
           WHERE e.id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    if let Some(schema) = schema {
        schema::validate_json_schema(&schema, attributes)?;
    }
    Ok(())
}

fn normalize_attributes(attributes: Value) -> Value {
    if attributes == Value::Null {
        serde_json::json!({})
    } else {
        attributes
    }
}

fn entity_kind_from_profile(kind: &str) -> Result<EntityKind, AppError> {
    match kind {
        "human" => Ok(EntityKind::Human),
        "device" => Ok(EntityKind::Device),
        "service" => Ok(EntityKind::Service),
        "workload" => Ok(EntityKind::Workload),
        "application" => Ok(EntityKind::Application),
        other => Err(AppError::bad_request(format!(
            "profile kind '{other}' is not a valid entity kind"
        ))),
    }
}

fn entity_kind_as_str(kind: &EntityKind) -> &'static str {
    match kind {
        EntityKind::Human => "human",
        EntityKind::Device => "device",
        EntityKind::Service => "service",
        EntityKind::Workload => "workload",
        EntityKind::Application => "application",
    }
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
    let result =
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
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
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = normalize_attributes(req.attributes);
    sqlx::query_as::<_, Group>(
        r#"INSERT INTO groups (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, name, tenant_id, description,
                     NULL::uuid AS parent_id,
                     status, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.tenant_id)
    .bind(req.description)
    .bind(attrs)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub async fn get_group(pool: &PgPool, id: Uuid) -> Result<Group, AppError> {
    sqlx::query_as::<_, Group>(
        r#"SELECT g.id, g.name, g.tenant_id, g.description, gh.parent_id,
                  g.status, g.attributes, g.created_at, g.updated_at
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE g.id = $1"#,
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
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let status = params.status;
    let q = search_pattern(params.q);
    let parent_id = params.parent_id;

    let items = sqlx::query_as::<_, Group>(
        r#"SELECT g.id, g.name, g.tenant_id, g.description, gh.parent_id,
                  g.status, g.attributes, g.created_at, g.updated_at
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE ($1::uuid IS NULL OR g.tenant_id = $1)
             AND ($2::text IS NULL OR g.status = $2)
             AND ($3::text IS NULL OR g.name ILIKE $3 OR g.description ILIKE $3 OR g.attributes::text ILIKE $3)
             AND (($4::uuid IS NULL AND $5::boolean = FALSE)
                  OR ($5::boolean = TRUE AND gh.parent_id = $4))
           ORDER BY g.created_at DESC
           LIMIT $6 OFFSET $7"#,
    )
    .bind(params.tenant_id)
    .bind(status.clone())
    .bind(q.clone())
    .bind(parent_id)
    .bind(parent_id.is_some())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE ($1::uuid IS NULL OR g.tenant_id = $1)
             AND ($2::text IS NULL OR g.status = $2)
             AND ($3::text IS NULL OR g.name ILIKE $3 OR g.description ILIKE $3 OR g.attributes::text ILIKE $3)
             AND (($4::uuid IS NULL AND $5::boolean = FALSE)
                  OR ($5::boolean = TRUE AND gh.parent_id = $4))"#,
    )
    .bind(params.tenant_id)
    .bind(status)
    .bind(q)
    .bind(parent_id)
    .bind(parent_id.is_some())
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(GroupList { items, total })
}

pub async fn update_group(pool: &PgPool, id: Uuid, req: UpdateGroup) -> Result<Group, AppError> {
    let attributes = req.attributes.map(normalize_attributes);
    sqlx::query_as::<_, Group>(
        r#"UPDATE groups
           SET name        = COALESCE($2, name),
               description = COALESCE($3, description),
               status      = COALESCE($4, status),
               attributes  = COALESCE($5, attributes),
               updated_at  = now()
           WHERE id = $1
           RETURNING id, name, tenant_id, description,
                     (SELECT parent_id FROM group_hierarchy WHERE child_id = groups.id) AS parent_id,
                     status, attributes, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.description)
    .bind(req.status)
    .bind(attributes)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("group {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn set_group_parent(
    pool: &PgPool,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Group, AppError> {
    if child_id == parent_id {
        return Err(AppError::bad_request("group cannot be its own parent"));
    }

    use sqlx::Row;
    let child = sqlx::query("SELECT tenant_id FROM groups WHERE id = $1")
        .bind(child_id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found(format!("group {child_id} not found")),
            other => AppError::Database(other),
        })?;
    let parent = sqlx::query("SELECT tenant_id FROM groups WHERE id = $1")
        .bind(parent_id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                AppError::not_found(format!("parent group {parent_id} not found"))
            }
            other => AppError::Database(other),
        })?;
    let child_tenant_id: Option<Uuid> = child.try_get("tenant_id").unwrap_or(None);
    let parent_tenant_id: Option<Uuid> = parent.try_get("tenant_id").unwrap_or(None);
    if child_tenant_id != parent_tenant_id {
        return Err(AppError::bad_request(
            "parent and child groups must belong to the same tenant",
        ));
    }

    let creates_cycle: bool = sqlx::query_scalar(
        r#"WITH RECURSIVE ancestors(id) AS (
               SELECT parent_id FROM group_hierarchy WHERE child_id = $1
               UNION ALL
               SELECT gh.parent_id
               FROM group_hierarchy gh
               JOIN ancestors a ON gh.child_id = a.id
           )
           SELECT EXISTS (SELECT 1 FROM ancestors WHERE id = $2)"#,
    )
    .bind(parent_id)
    .bind(child_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    if creates_cycle {
        return Err(AppError::bad_request("group hierarchy cycle detected"));
    }

    sqlx::query(
        r#"INSERT INTO group_hierarchy (parent_id, child_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (child_id) DO UPDATE
           SET parent_id = EXCLUDED.parent_id,
               tenant_id = EXCLUDED.tenant_id,
               updated_at = now()"#,
    )
    .bind(parent_id)
    .bind(child_id)
    .bind(child_tenant_id)
    .execute(pool)
    .await
    .map_err(db_err)?;

    get_group(pool, child_id).await
}

pub async fn remove_group_parent(pool: &PgPool, child_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM group_hierarchy WHERE child_id = $1")
        .bind(child_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub async fn list_child_groups(
    pool: &PgPool,
    parent_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<GroupList, AppError> {
    list_groups(
        pool,
        ListGroups {
            q: None,
            tenant_id: None,
            parent_id: Some(parent_id),
            status: None,
            limit,
            offset,
        },
    )
    .await
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

pub async fn add_group_member(
    pool: &PgPool,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    crate::guardrails::validate_group_member(pool, group_id, entity_id).await?;
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

pub async fn remove_group_member(
    pool: &PgPool,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
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
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.profile_id, e.profile_version_id,
                  e.status, e.attributes, e.created_at, e.updated_at
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
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.profile_id, e.profile_version_id,
                  e.status, e.attributes, e.created_at, e.updated_at
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

pub async fn delete_ownership(
    pool: &PgPool,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM ownerships WHERE owner_id = $1 AND owned_id = $2")
        .bind(owner_id)
        .bind(owned_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}
