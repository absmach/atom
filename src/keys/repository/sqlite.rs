//! Native sqlite signing-key storage.
use super::{KeyMetadata, KeyStorageValues, SigningKeyStorageSummary, StoredKey};
use crate::error::{db_err, AppError};
use sqlx::{Sqlite as Driver, SqliteConnection as Connection, SqlitePool as Database};

pub(super) async fn active_keys<'e, E>(executor: E) -> Result<Vec<StoredKey>, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as("SELECT kid, public_key, private_key, private_key_ciphertext, private_key_nonce, private_key_key_id, private_key_encryption_alg, status
        FROM signing_keys WHERE status IN ('primary', 'standby') ORDER BY created_at DESC")
        .fetch_all(executor).await.map_err(db_err)
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
    sqlx::query("INSERT INTO signing_keys (kid, public_key, private_key, private_key_ciphertext, private_key_nonce, private_key_key_id, private_key_encryption_alg, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'primary')")
        .bind(kid).bind(public_pem).bind(storage.plaintext).bind(storage.ciphertext).bind(storage.nonce).bind(storage.key_id).bind(storage.encryption_alg)
        .execute(executor).await.map_err(db_err)?;
    Ok(())
}
pub(super) async fn primary_count(pool: &Database) -> Result<i64, AppError> {
    sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys WHERE status = 'primary'")
        .fetch_one(pool)
        .await
        .map_err(db_err)
}
pub(super) async fn demote_active(conn: &mut Connection) -> Result<(), AppError> {
    sqlx::query("UPDATE signing_keys SET status = 'retired' WHERE status = 'standby'")
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    sqlx::query("UPDATE signing_keys SET status = 'standby' WHERE status = 'primary'")
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}
pub(super) async fn legacy_keys(pool: &Database) -> Result<Vec<(String, String)>, AppError> {
    sqlx::query_as("SELECT kid, private_key FROM signing_keys WHERE private_key IS NOT NULL AND private_key_ciphertext IS NULL").fetch_all(pool).await.map_err(db_err)
}
pub(super) async fn encrypt_legacy(
    pool: &Database,
    kid: &str,
    ciphertext: &[u8],
    nonce: &[u8],
    key_id: &str,
    algorithm: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE signing_keys SET private_key = NULL, private_key_ciphertext = $2, private_key_nonce = $3, private_key_key_id = $4, private_key_encryption_alg = $5 WHERE kid = $1")
        .bind(kid).bind(ciphertext).bind(nonce).bind(key_id).bind(algorithm).execute(pool).await.map_err(db_err)?;
    Ok(())
}
pub(super) async fn metadata(pool: &Database) -> Result<Vec<KeyMetadata>, AppError> {
    sqlx::query_as("SELECT kid, algorithm, status, created_at, private_key IS NOT NULL AS has_plaintext, private_key_ciphertext IS NOT NULL AS has_ciphertext, private_key_key_id FROM signing_keys ORDER BY created_at DESC")
        .fetch_all(pool).await.map_err(db_err)
}
pub(super) async fn storage_summary(pool: &Database) -> Result<SigningKeyStorageSummary, AppError> {
    sqlx::query_as("SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE private_key_ciphertext IS NOT NULL) AS encrypted, COUNT(*) FILTER (WHERE private_key IS NOT NULL) AS plaintext FROM signing_keys")
        .fetch_one(pool).await.map_err(db_err)
}
