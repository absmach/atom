//! Native sqlite signing-key storage.
use super::{KeyMetadata, KeyStorageValues, SigningKeyStorageSummary, StoredKey};
use crate::error::{db_err, AppError};
use sqlx::{Sqlite as Driver, SqliteConnection as Connection, SqlitePool as Database};

pub(super) async fn active_keys<'e, E>(executor: E) -> Result<Vec<StoredKey>, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as(super::sql::ACTIVE_KEYS)
        .fetch_all(executor)
        .await
        .map_err(db_err)
}
pub(super) async fn insert_primary<'e, E>(
    executor: E,
    kid: &str,
    public_pem: &str,
    storage: KeyStorageValues,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query(super::sql::INSERT_PRIMARY)
        .bind(kid)
        .bind(public_pem)
        .bind(storage.plaintext)
        .bind(storage.ciphertext)
        .bind(storage.nonce)
        .bind(storage.key_id)
        .bind(storage.encryption_alg)
        .execute(executor)
        .await
        .map_err(db_err)?;
    Ok(())
}
pub(super) async fn primary_count(pool: &Database) -> Result<i64, AppError> {
    sqlx::query_scalar(super::sql::PRIMARY_COUNT)
        .fetch_one(pool)
        .await
        .map_err(db_err)
}
pub(super) async fn demote_active(conn: &mut Connection) -> Result<(), AppError> {
    sqlx::query(super::sql::RETIRE_STANDBY)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    sqlx::query(super::sql::DEMOTE_PRIMARY)
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}
pub(super) async fn legacy_keys(pool: &Database) -> Result<Vec<(String, String)>, AppError> {
    sqlx::query_as(super::sql::LEGACY_KEYS)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}
pub(super) async fn encrypt_legacy(
    pool: &Database,
    kid: &str,
    ciphertext: &[u8],
    nonce: &[u8],
    key_id: &str,
    algorithm: &str,
) -> Result<(), AppError> {
    sqlx::query(super::sql::ENCRYPT_LEGACY)
        .bind(kid)
        .bind(ciphertext)
        .bind(nonce)
        .bind(key_id)
        .bind(algorithm)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}
pub(super) async fn metadata(pool: &Database) -> Result<Vec<KeyMetadata>, AppError> {
    sqlx::query_as(super::sql::KEY_METADATA)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}
pub(super) async fn storage_summary(pool: &Database) -> Result<SigningKeyStorageSummary, AppError> {
    sqlx::query_as("SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE private_key_ciphertext IS NOT NULL) AS encrypted, COUNT(*) FILTER (WHERE private_key IS NOT NULL) AS plaintext FROM signing_keys")
        .fetch_one(pool).await.map_err(db_err)
}
