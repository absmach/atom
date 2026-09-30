//! PostgreSQL implementation of the file repository contract in [`super`].

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::{NewFileObject, QueuedBlob};
use crate::{
    error::{db_err, AppError},
    files::FileObject,
};

const COLUMNS: &str = "f.resource_id, f.tenant_id, f.storage_key, f.size_bytes, f.content_type, \
                       f.sha256, f.public, f.created_at, f.updated_at";

pub(super) async fn queue(
    pool: &PgPool,
    key: &str,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO blob_deletions (storage_key, tenant_id) VALUES ($1, $2)
         ON CONFLICT (storage_key) DO UPDATE SET queued_at = now()",
    )
    .bind(key)
    .bind(tenant_id)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(db_err)
}

pub(super) async fn unqueue(tx: &mut PgConnection, key: &str) -> Result<bool, AppError> {
    sqlx::query("DELETE FROM blob_deletions WHERE storage_key = $1")
        .bind(key)
        .execute(tx)
        .await
        .map(|done| done.rows_affected() == 1)
        .map_err(db_err)
}

pub(super) async fn insert(
    tx: &mut PgConnection,
    new: &NewFileObject<'_>,
) -> Result<FileObject, AppError> {
    sqlx::query_as::<_, FileObject>(&format!(
        "INSERT INTO file_objects AS f
             (resource_id, tenant_id, storage_key, size_bytes, content_type, sha256, public)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING {COLUMNS}"
    ))
    .bind(new.resource_id)
    .bind(new.tenant_id)
    .bind(new.storage_key)
    .bind(new.size_bytes)
    .bind(new.content_type)
    .bind(new.sha256)
    .bind(new.public)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn get(pool: &PgPool, resource_id: Uuid) -> Result<Option<FileObject>, AppError> {
    sqlx::query_as::<_, FileObject>(&format!(
        "SELECT {COLUMNS} FROM file_objects f
         JOIN resources r ON r.id = f.resource_id
         WHERE f.resource_id = $1 AND r.deleted_at IS NULL"
    ))
    .bind(resource_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn get_in_tx(
    tx: &mut PgConnection,
    resource_id: Uuid,
) -> Result<Option<FileObject>, AppError> {
    sqlx::query_as::<_, FileObject>(&format!(
        "SELECT {COLUMNS} FROM file_objects f WHERE f.resource_id = $1 FOR UPDATE"
    ))
    .bind(resource_id)
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn replace_blob(
    tx: &mut PgConnection,
    resource_id: Uuid,
    new: &NewFileObject<'_>,
) -> Result<FileObject, AppError> {
    sqlx::query_as::<_, FileObject>(&format!(
        "UPDATE file_objects AS f
         SET storage_key = $2, size_bytes = $3, content_type = $4, sha256 = $5,
             public = $6, updated_at = now()
         WHERE f.resource_id = $1
         RETURNING {COLUMNS}"
    ))
    .bind(resource_id)
    .bind(new.storage_key)
    .bind(new.size_bytes)
    .bind(new.content_type)
    .bind(new.sha256)
    .bind(new.public)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn tenant_usage(tx: &mut PgConnection, tenant_id: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM file_objects WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn claim_due(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<QueuedBlob>, AppError> {
    sqlx::query_as::<_, QueuedBlob>(
        "DELETE FROM blob_deletions
         WHERE storage_key IN (
                   SELECT storage_key FROM blob_deletions
                   WHERE queued_at <= $1 ORDER BY queued_at LIMIT $2
                   FOR UPDATE SKIP LOCKED
               )
         RETURNING storage_key, tenant_id, attempts",
    )
    .bind(cutoff)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn requeue(pool: &PgPool, blob: &QueuedBlob, error: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO blob_deletions (storage_key, tenant_id, attempts, last_error)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (storage_key) DO UPDATE
         SET attempts = excluded.attempts, last_error = excluded.last_error, queued_at = now()",
    )
    .bind(&blob.storage_key)
    .bind(blob.tenant_id)
    .bind(blob.attempts + 1)
    .bind(error)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(db_err)
}

pub(super) async fn referenced(pool: &PgPool, key: &str) -> Result<bool, AppError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM file_objects WHERE storage_key = $1)",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}
