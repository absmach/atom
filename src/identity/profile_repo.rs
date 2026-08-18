use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::profile::{
        CreateProfile, CreateProfileVersion, ListProfiles, Profile, ProfileList, ProfileVersion,
        UpdateProfile, UpdateProfileVersion,
    },
};

pub async fn create_profile(pool: &PgPool, req: CreateProfile) -> Result<Profile, AppError> {
    create_profile_with_audit(pool, false, None, req).await
}

pub async fn create_profile_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateProfile,
) -> Result<Profile, AppError> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let profile = sqlx::query_as::<_, Profile>(
        r#"INSERT INTO profiles
           (id, tenant_id, object_kind, kind, key, display_name, description, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, 'active'))
           RETURNING id, tenant_id, object_kind, kind, key, display_name, description,
                     status, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.tenant_id)
    .bind(req.object_kind)
    .bind(req.kind)
    .bind(req.key)
    .bind(req.display_name)
    .bind(req.description)
    .bind(req.status)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: profile.tenant_id,
            target_kind: "profile",
            target_id: Some(profile.id),
            event: "profile.create",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(profile)
}

pub async fn get_profile(pool: &PgPool, id: Uuid) -> Result<Profile, AppError> {
    sqlx::query_as::<_, Profile>(
        r#"SELECT id, tenant_id, object_kind, kind, key, display_name, description,
                  status, created_at, updated_at
           FROM profiles
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("profile {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_profiles(pool: &PgPool, params: ListProfiles) -> Result<ProfileList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let tenant_id = params.tenant_id;
    let object_kind = params.object_kind;
    let kind = params.kind;
    let key = params.key;
    let status = params.status;

    let items = sqlx::query_as::<_, Profile>(
        r#"SELECT id, tenant_id, object_kind, kind, key, display_name, description,
                  status, created_at, updated_at
           FROM profiles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR object_kind = $2)
             AND ($3::text IS NULL OR kind = $3)
             AND ($4::text IS NULL OR key = $4)
             AND ($5::text IS NULL OR status = $5)
           ORDER BY object_kind, kind, key
           LIMIT $6 OFFSET $7"#,
    )
    .bind(tenant_id)
    .bind(object_kind.clone())
    .bind(kind.clone())
    .bind(key.clone())
    .bind(status.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM profiles
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR object_kind = $2)
             AND ($3::text IS NULL OR kind = $3)
             AND ($4::text IS NULL OR key = $4)
             AND ($5::text IS NULL OR status = $5)"#,
    )
    .bind(tenant_id)
    .bind(object_kind)
    .bind(kind)
    .bind(key)
    .bind(status)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ProfileList { items, total })
}

pub async fn update_profile(
    pool: &PgPool,
    id: Uuid,
    req: UpdateProfile,
) -> Result<Profile, AppError> {
    update_profile_with_audit(pool, false, None, id, req).await
}

pub async fn update_profile_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateProfile,
) -> Result<Profile, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let profile = sqlx::query_as::<_, Profile>(
        r#"UPDATE profiles
           SET display_name = COALESCE($2, display_name),
               description  = COALESCE($3, description),
               status       = COALESCE($4, status),
               updated_at   = now()
           WHERE id = $1
           RETURNING id, tenant_id, object_kind, kind, key, display_name, description,
                     status, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.display_name)
    .bind(req.description)
    .bind(req.status)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("profile {id} not found")),
        other => AppError::Database(other),
    })?;
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: profile.tenant_id,
            target_kind: "profile",
            target_id: Some(id),
            event: "profile.update",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(profile)
}

pub async fn create_profile_version(
    pool: &PgPool,
    profile_id: Uuid,
    req: CreateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    create_profile_version_with_audit(pool, false, None, None, profile_id, req).await
}

pub async fn create_profile_version_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    profile_id: Uuid,
    req: CreateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    let id = Uuid::new_v4();
    let json_schema = json_object_or_default(req.json_schema);
    let ui_schema = json_object_or_default(req.ui_schema);

    let mut tx = pool.begin().await.map_err(db_err)?;
    let version = sqlx::query_as::<_, ProfileVersion>(
        r#"INSERT INTO profile_versions
           (id, profile_id, version, json_schema, ui_schema, status)
           VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'active'))
           RETURNING id, profile_id, version, json_schema, ui_schema, status, created_at"#,
    )
    .bind(id)
    .bind(profile_id)
    .bind(req.version)
    .bind(json_schema)
    .bind(ui_schema)
    .bind(req.status)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "profile_version",
            target_id: Some(version.id),
            event: "profile_version.create",
        },
        &serde_json::json!({ "profile_id": profile_id }),
    )
    .await?;
    Ok(version)
}

pub async fn update_profile_version(
    pool: &PgPool,
    id: Uuid,
    req: UpdateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    update_profile_version_with_audit(pool, false, None, None, id, req).await
}

pub async fn update_profile_version_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    id: Uuid,
    req: UpdateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let version = sqlx::query_as::<_, ProfileVersion>(
        r#"UPDATE profile_versions
           SET json_schema = COALESCE($2, json_schema),
               ui_schema   = COALESCE($3, ui_schema),
               status      = COALESCE($4, status)
           WHERE id = $1
           RETURNING id, profile_id, version, json_schema, ui_schema, status, created_at"#,
    )
    .bind(id)
    .bind(req.json_schema)
    .bind(req.ui_schema)
    .bind(req.status)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("profile version {id} not found")),
        other => AppError::Database(other),
    })?;
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "profile_version",
            target_id: Some(id),
            event: "profile_version.update",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(version)
}

pub async fn get_profile_version(pool: &PgPool, id: Uuid) -> Result<ProfileVersion, AppError> {
    sqlx::query_as::<_, ProfileVersion>(
        r#"SELECT id, profile_id, version, json_schema, ui_schema, status, created_at
           FROM profile_versions
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("profile version {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn get_active_profile_version(
    pool: &PgPool,
    profile_id: Uuid,
) -> Result<Option<ProfileVersion>, AppError> {
    sqlx::query_as::<_, ProfileVersion>(
        r#"SELECT id, profile_id, version, json_schema, ui_schema, status, created_at
           FROM profile_versions
           WHERE profile_id = $1
             AND status = 'active'
           ORDER BY version DESC
           LIMIT 1"#,
    )
    .bind(profile_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub async fn list_profile_versions(
    pool: &PgPool,
    profile_id: Uuid,
) -> Result<Vec<ProfileVersion>, AppError> {
    sqlx::query_as::<_, ProfileVersion>(
        r#"SELECT id, profile_id, version, json_schema, ui_schema, status, created_at
           FROM profile_versions
           WHERE profile_id = $1
           ORDER BY version DESC"#,
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

fn json_object_or_default(value: Value) -> Value {
    if value.is_null() {
        serde_json::json!({})
    } else {
        value
    }
}
