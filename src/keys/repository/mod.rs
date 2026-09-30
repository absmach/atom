//! Signing-key persistence. Key generation, encryption, loading and rotation policy remain shared.
mod postgres;
mod sqlite;
use super::{KeyStorageValues, SigningKeyStorageSummary};
use crate::{
    db::{Database, DbTransaction, IntoTarget, Target},
    error::AppError,
};
use chrono::{DateTime, Utc};

#[derive(sqlx::FromRow)]
pub(super) struct StoredKey {
    pub kid: String,
    pub public_key: String,
    pub private_key: Option<String>,
    pub private_key_ciphertext: Option<Vec<u8>>,
    pub private_key_nonce: Option<Vec<u8>>,
    pub private_key_key_id: Option<String>,
    pub private_key_encryption_alg: Option<String>,
    pub status: String,
}
#[derive(sqlx::FromRow)]
pub(super) struct KeyMetadata {
    pub kid: String,
    pub algorithm: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub has_plaintext: bool,
    pub has_ciphertext: bool,
    pub private_key_key_id: Option<String>,
}

pub(super) async fn active_keys<'e, E>(executor: E) -> Result<Vec<StoredKey>, AppError>
where
    E: IntoTarget<'e>,
{
    match executor.into_target() {
        Target::PoolPostgres(conn) => postgres::active_keys(conn).await,
        Target::ConnectionPostgres(conn) => postgres::active_keys(conn).await,
        Target::PoolSqlite(conn) => sqlite::active_keys(conn).await,
        Target::ConnectionSqlite(conn) => sqlite::active_keys(conn).await,
    }
}

pub(super) async fn insert_primary<'e, E>(
    executor: E,
    kid: &str,
    public_pem: &str,
    storage: KeyStorageValues,
) -> Result<(), AppError>
where
    E: IntoTarget<'e>,
{
    match executor.into_target() {
        Target::PoolPostgres(conn) => {
            postgres::insert_primary(conn, kid, public_pem, storage).await
        }
        Target::ConnectionPostgres(conn) => {
            postgres::insert_primary(conn, kid, public_pem, storage).await
        }
        Target::PoolSqlite(conn) => sqlite::insert_primary(conn, kid, public_pem, storage).await,
        Target::ConnectionSqlite(conn) => {
            sqlite::insert_primary(conn, kid, public_pem, storage).await
        }
    }
}

pub(super) async fn primary_count(pool: &Database) -> Result<i64, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::primary_count(pool).await,
        Database::Sqlite(db) => sqlite::primary_count(&db.pool).await,
    }
}

pub(super) async fn demote_active(tx: &mut DbTransaction<'_>) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::demote_active(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::demote_active(conn).await,
    }
}

pub(super) async fn legacy_keys(pool: &Database) -> Result<Vec<(String, String)>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::legacy_keys(pool).await,
        Database::Sqlite(db) => sqlite::legacy_keys(&db.pool).await,
    }
}

pub(super) async fn encrypt_legacy(
    pool: &Database,
    kid: &str,
    ciphertext: &[u8],
    nonce: &[u8],
    key_id: &str,
    algorithm: &str,
) -> Result<(), AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::encrypt_legacy(pool, kid, ciphertext, nonce, key_id, algorithm).await
        }
        Database::Sqlite(db) => {
            sqlite::encrypt_legacy(&db.pool, kid, ciphertext, nonce, key_id, algorithm).await
        }
    }
}

pub(super) async fn metadata(pool: &Database) -> Result<Vec<KeyMetadata>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::metadata(pool).await,
        Database::Sqlite(db) => sqlite::metadata(&db.pool).await,
    }
}

pub(super) async fn storage_summary(pool: &Database) -> Result<SigningKeyStorageSummary, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::storage_summary(pool).await,
        Database::Sqlite(db) => sqlite::storage_summary(&db.pool).await,
    }
}
