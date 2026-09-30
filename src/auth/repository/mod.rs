//! Authentication state persistence. Verification, cache coordination and authorization gates remain shared.
mod postgres;
mod sqlite;
use super::{CredentialSnapshot, SessionEntityTenantSnapshot};
use crate::{
    db::Database,
    error::AppError,
    models::enums::{CredentialKind, CredentialStatus, EntityStatus, TenantStatus},
};
use chrono::Utc;
use uuid::Uuid;
pub(super) async fn load_session_entity_tenant(
    pool: &Database,
    session_id: Uuid,
    entity_id: Uuid,
) -> Result<SessionEntityTenantSnapshot, AppError> {
    let row = match pool {
        Database::Postgres(pool) => {
            postgres::load_session_entity_tenant(pool, session_id, entity_id).await
        }
        Database::Sqlite(db) => {
            sqlite::load_session_entity_tenant(&db.pool, session_id, entity_id).await
        }
    }
    .map_err(|error| match error {
        sqlx::Error::RowNotFound => AppError::unauthorized("session not found"),
        other => AppError::Database(other),
    })?;
    Ok(SessionEntityTenantSnapshot {
        session_entity_id: entity_id,
        revoked_at: row.revoked_at,
        expires_at: row
            .expires_at
            .map_err(|_| AppError::unauthorized("corrupt session"))?,
        entity_tenant_id: row.entity_tenant_id,
        entity_status: row
            .entity_status
            .map_err(|_| AppError::unauthorized("corrupt entity"))?,
        tenant_status: row.tenant_status,
    })
}
pub(super) async fn load_credential_row(
    pool: &Database,
    cred_id: Uuid,
) -> Result<CredentialSnapshot, AppError> {
    let row = match pool {
        Database::Postgres(pool) => postgres::load_credential_row(pool, cred_id).await,
        Database::Sqlite(db) => sqlite::load_credential_row(&db.pool, cred_id).await,
    }
    .map_err(|error| match error {
        sqlx::Error::RowNotFound => AppError::unauthorized("api key not found"),
        other => AppError::Database(other),
    })?;
    Ok(CredentialSnapshot {
        entity_id: row.entity_id.map_err(crate::error::db_err)?,
        tenant_id: row.tenant_id,
        secret_hash: row.secret_hash,
        secret_lookup_hash: row.secret_lookup_hash,
        status: row.status.map_err(crate::error::db_err)?,
        expires_at: row.expires_at,
        scoped: row.scoped,
        entity_status: row
            .entity_status
            .map_err(|_| AppError::unauthorized("corrupt entity"))?,
        tenant_status: row.tenant_status,
    })
}
pub(super) async fn actor_is_active(pool: &Database, entity_id: Uuid) -> Result<bool, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::actor_is_active(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::actor_is_active(&db.pool, entity_id).await,
    }
}
pub(super) async fn tenant_is_active(pool: &Database, tenant_id: Uuid) -> Result<bool, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::tenant_is_active(pool, tenant_id).await,
        Database::Sqlite(db) => sqlite::tenant_is_active(&db.pool, tenant_id).await,
    }
}
pub(super) async fn action_id_by_name(
    pool: &Database,
    name: &str,
) -> Result<Option<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::action_id_by_name(pool, name).await,
        Database::Sqlite(db) => sqlite::action_id_by_name(&db.pool, name).await,
    }
}
pub(super) async fn action_ids_by_name(
    pool: &Database,
    names: &[&str],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::action_ids_by_name(pool, names).await,
        Database::Sqlite(db) => sqlite::action_ids_by_name(&db.pool, names).await,
    }
}
pub(super) async fn upgrade_verifier(
    pool: &Database,
    cred_id: Uuid,
    digest: &[u8],
) -> Result<(), AppError> {
    match pool {
        Database::Postgres(pool) => postgres::upgrade_verifier(pool, cred_id, digest).await,
        Database::Sqlite(db) => sqlite::upgrade_verifier(&db.pool, cred_id, digest).await,
    }
}
pub(super) async fn touch_usage(pool: &Database, cred_id: Uuid) -> Result<(), AppError> {
    match pool {
        Database::Postgres(pool) => postgres::touch_usage(pool, cred_id).await,
        Database::Sqlite(db) => sqlite::touch_usage(&db.pool, cred_id).await,
    }
}

// Decode errors remain attached to required fields until shared authentication
// mapping classifies them. Optional legacy fields retain their old defaults.
pub(super) struct SessionRow {
    revoked_at: Option<chrono::DateTime<Utc>>,
    expires_at: Result<chrono::DateTime<Utc>, sqlx::Error>,
    entity_tenant_id: Option<Uuid>,
    entity_status: Result<EntityStatus, sqlx::Error>,
    tenant_status: Option<TenantStatus>,
}
pub(super) struct CredentialRow {
    entity_id: Result<Uuid, sqlx::Error>,
    tenant_id: Option<Uuid>,
    secret_hash: Option<String>,
    secret_lookup_hash: Option<Vec<u8>>,
    status: Result<CredentialStatus, sqlx::Error>,
    expires_at: Option<chrono::DateTime<Utc>>,
    scoped: bool,
    entity_status: Result<EntityStatus, sqlx::Error>,
    tenant_status: Option<TenantStatus>,
}
