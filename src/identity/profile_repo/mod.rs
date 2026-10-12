//! Profile domain operations and shared mutation/event orchestration.
//! Native storage is private to each backend; writes borrow the caller transaction.

mod postgres;
mod sqlite;

use crate::db::Database;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::profile::{
        CreateProfile, CreateProfileVersion, ListProfiles, Profile, ProfileList, ProfileVersion,
        UpdateProfile, UpdateProfileVersion,
    },
};

pub async fn create_profile(pool: &Database, req: CreateProfile) -> Result<Profile, AppError> {
    create_profile_with_audit(pool, false, None, req).await
}

pub async fn create_profile_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateProfile,
) -> Result<Profile, AppError> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let profile = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => postgres::insert_profile(conn, id, req).await?,
        crate::db::DbTransaction::Sqlite(conn) => sqlite::insert_profile(conn, id, req).await?,
    };
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

pub async fn get_profile(pool: &Database, id: Uuid) -> Result<Profile, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_profile(pool, id).await,
        Database::Sqlite(db) => sqlite::get_profile(&db.pool, id).await,
    }
}

pub async fn list_profiles(pool: &Database, params: ListProfiles) -> Result<ProfileList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_profiles(pool, params).await,
        Database::Sqlite(db) => sqlite::list_profiles(&db.pool, params).await,
    }
}

pub async fn update_profile(
    pool: &Database,
    id: Uuid,
    req: UpdateProfile,
) -> Result<Profile, AppError> {
    update_profile_with_audit(pool, false, None, id, req).await
}

pub async fn update_profile_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateProfile,
) -> Result<Profile, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let profile = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => postgres::update_profile(conn, id, req).await?,
        crate::db::DbTransaction::Sqlite(conn) => sqlite::update_profile(conn, id, req).await?,
    };
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
    pool: &Database,
    profile_id: Uuid,
    req: CreateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    create_profile_version_with_audit(pool, false, None, None, profile_id, req).await
}

pub async fn create_profile_version_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    profile_id: Uuid,
    req: CreateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    let id = Uuid::new_v4();
    let req = CreateProfileVersion {
        json_schema: json_object_or_default(req.json_schema),
        ui_schema: json_object_or_default(req.ui_schema),
        ..req
    };

    let mut tx = pool.begin().await.map_err(db_err)?;
    let version = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => {
            postgres::insert_profile_version(conn, id, profile_id, req).await?
        }
        crate::db::DbTransaction::Sqlite(conn) => {
            sqlite::insert_profile_version(conn, id, profile_id, req).await?
        }
    };
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
    pool: &Database,
    id: Uuid,
    req: UpdateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    update_profile_version_with_audit(pool, false, None, None, id, req).await
}

pub async fn update_profile_version_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    id: Uuid,
    req: UpdateProfileVersion,
) -> Result<ProfileVersion, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let version = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => {
            postgres::update_profile_version(conn, id, req).await?
        }
        crate::db::DbTransaction::Sqlite(conn) => {
            sqlite::update_profile_version(conn, id, req).await?
        }
    };
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

pub async fn get_profile_version(pool: &Database, id: Uuid) -> Result<ProfileVersion, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_profile_version(pool, id).await,
        Database::Sqlite(db) => sqlite::get_profile_version(&db.pool, id).await,
    }
}

pub async fn get_active_profile_version(
    pool: &Database,
    profile_id: Uuid,
) -> Result<Option<ProfileVersion>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_active_profile_version(pool, profile_id).await,
        Database::Sqlite(db) => sqlite::get_active_profile_version(&db.pool, profile_id).await,
    }
}

pub async fn list_profile_versions(
    pool: &Database,
    profile_id: Uuid,
) -> Result<Vec<ProfileVersion>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_profile_versions(pool, profile_id).await,
        Database::Sqlite(db) => sqlite::list_profile_versions(&db.pool, profile_id).await,
    }
}

fn json_object_or_default(value: Value) -> Value {
    if value.is_null() {
        serde_json::json!({})
    } else {
        value
    }
}

pub(crate) async fn profile_tenant_target(
    pool: &Database,
    id: Uuid,
) -> std::result::Result<Option<Option<Uuid>>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::profile_tenant_target(pool, id).await,
        Database::Sqlite(db) => sqlite::profile_tenant_target(&db.pool, id).await,
    }
}

pub(crate) async fn profile_version_tenant_target(
    pool: &Database,
    id: Uuid,
) -> std::result::Result<Option<(Uuid, Option<Uuid>)>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::profile_version_tenant_target(pool, id).await,
        Database::Sqlite(db) => sqlite::profile_version_tenant_target(&db.pool, id).await,
    }
}
