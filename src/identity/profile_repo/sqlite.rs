//! Native sqlite storage for profiles and their versions.

use sqlx::{SqliteConnection as Connection, SqlitePool as Database};
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::profile::{
        CreateProfile, CreateProfileVersion, ListProfiles, Profile, ProfileList, ProfileVersion,
        UpdateProfile, UpdateProfileVersion,
    },
};

pub(super) async fn get_profile(pool: &Database, id: Uuid) -> Result<Profile, AppError> {
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

pub(super) async fn list_profiles(
    pool: &Database,
    params: ListProfiles,
) -> Result<ProfileList, AppError> {
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
           WHERE ($1 IS NULL OR tenant_id = $1)
             AND ($2 IS NULL OR object_kind = $2)
             AND ($3 IS NULL OR kind = $3)
             AND ($4 IS NULL OR key = $4)
             AND ($5 IS NULL OR status = $5)
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
           WHERE ($1 IS NULL OR tenant_id = $1)
             AND ($2 IS NULL OR object_kind = $2)
             AND ($3 IS NULL OR kind = $3)
             AND ($4 IS NULL OR key = $4)
             AND ($5 IS NULL OR status = $5)"#,
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

pub(super) async fn get_profile_version(
    pool: &Database,
    id: Uuid,
) -> Result<ProfileVersion, AppError> {
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

pub(super) async fn get_active_profile_version(
    pool: &Database,
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

pub(super) async fn list_profile_versions(
    pool: &Database,
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
pub(super) async fn insert_profile(
    conn: &mut Connection,
    id: Uuid,
    req: CreateProfile,
) -> Result<Profile, AppError> {
    sqlx::query_as::<_, Profile>(
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
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

pub(super) async fn update_profile(
    conn: &mut Connection,
    id: Uuid,
    req: UpdateProfile,
) -> Result<Profile, AppError> {
    sqlx::query_as::<_, Profile>(
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
    .fetch_one(conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("profile {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn insert_profile_version(
    conn: &mut Connection,
    id: Uuid,
    profile_id: Uuid,
    req: CreateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    sqlx::query_as::<_, ProfileVersion>(
        r#"INSERT INTO profile_versions
           (id, profile_id, version, json_schema, ui_schema, status)
           VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'active'))
           RETURNING id, profile_id, version, json_schema, ui_schema, status, created_at"#,
    )
    .bind(id)
    .bind(profile_id)
    .bind(req.version)
    .bind(req.json_schema.to_string())
    .bind(req.ui_schema.to_string())
    .bind(req.status)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

pub(super) async fn update_profile_version(
    conn: &mut Connection,
    id: Uuid,
    req: UpdateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    sqlx::query_as::<_, ProfileVersion>(
        r#"UPDATE profile_versions
           SET json_schema = COALESCE($2, json_schema),
               ui_schema   = COALESCE($3, ui_schema),
               status      = COALESCE($4, status)
           WHERE id = $1
           RETURNING id, profile_id, version, json_schema, ui_schema, status, created_at"#,
    )
    .bind(id)
    .bind(req.json_schema.map(|value| value.to_string()))
    .bind(req.ui_schema.map(|value| value.to_string()))
    .bind(req.status)
    .fetch_one(conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("profile version {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn profile_tenant_target(
    pool: &Database,
    id: Uuid,
) -> std::result::Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar("SELECT tenant_id FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

pub(super) async fn profile_version_tenant_target(
    pool: &Database,
    id: Uuid,
) -> std::result::Result<Option<(Uuid, Option<Uuid>)>, AppError> {
    sqlx::query_as(
        r#"SELECT version.profile_id, profile.tenant_id
           FROM profile_versions version
           JOIN profiles profile ON profile.id = version.profile_id
           WHERE version.id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}
