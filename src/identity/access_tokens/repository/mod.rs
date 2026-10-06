//! Access-token storage operations. Secret generation, ceiling validation and ownership guards stay shared.
mod postgres;
mod sqlite;
use super::ListAccessTokens;
use crate::{
    db::{Database, DbTransaction},
    error::AppError,
    models::token::{AccessTokenPermission, AccessTokenSummary},
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub(super) struct NewToken {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub key_prefix: String,
    pub secret_hash: Option<String>,
    pub secret_lookup_hash: Option<Vec<u8>>,
    pub scoped: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Value,
}

pub(super) async fn insert_token(
    tx: &mut DbTransaction<'_>,
    input: NewToken,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::insert_token(conn, input).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_token(conn, input).await,
    }
}

pub(super) async fn lock_active_token(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<Option<(bool, Option<String>)>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::lock_active_token(conn, entity_id, cred_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::lock_active_token(conn, entity_id, cred_id).await,
    }
}

pub(super) async fn clear_ceiling(
    tx: &mut DbTransaction<'_>,
    cred_id: Uuid,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::clear_ceiling(conn, cred_id).await,
        DbTransaction::Sqlite(conn) => sqlite::clear_ceiling(conn, cred_id).await,
    }
}

pub(super) async fn action_ids(
    tx: &mut DbTransaction<'_>,
    names: &[String],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::action_ids(conn, names).await,
        DbTransaction::Sqlite(conn) => sqlite::action_ids(conn, names).await,
    }
}

pub(super) async fn insert_ceiling(
    tx: &mut DbTransaction<'_>,
    cred_id: Uuid,
    permission: &AccessTokenPermission,
    action_ids: &[Uuid],
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_ceiling(conn, cred_id, permission, action_ids).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_ceiling(conn, cred_id, permission, action_ids).await
        }
    }
}

pub(super) async fn lock_token_owner(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<Option<Option<String>>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_token_owner(conn, entity_id, cred_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_token_owner(conn, entity_id, cred_id).await,
    }
}

pub(super) async fn revoke(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::revoke(conn, entity_id, cred_id).await,
        DbTransaction::Sqlite(conn) => sqlite::revoke(conn, entity_id, cred_id).await,
    }
}

pub(super) async fn list_access_tokens(
    pool: &Database,
    entity_id: Uuid,
    params: ListAccessTokens,
) -> Result<(Vec<AccessTokenSummary>, i64), AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_access_tokens(pool, entity_id, params).await,
        Database::Sqlite(db) => sqlite::list_access_tokens(&db.pool, entity_id, params).await,
    }
}

pub(super) async fn access_token_owner(pool: &Database, cred_id: Uuid) -> Result<Uuid, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::access_token_owner(pool, cred_id).await,
        Database::Sqlite(db) => sqlite::access_token_owner(&db.pool, cred_id).await,
    }
}
