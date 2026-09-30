//! Storage for file metadata and the blob deletion queue. Domain inputs and
//! results only; each backend owns its SQL in [`postgres`] and [`sqlite`]
//! (see `product-docs/development/database-backends/REPOSITORY-PATTERN.md`).

mod postgres;
mod sqlite;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::FileObject;
use crate::{
    db::{Database, DbTransaction},
    error::AppError,
};

/// The server-owned facts about a file's bytes, written with its resource.
pub(crate) struct NewFileObject<'a> {
    pub resource_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub storage_key: &'a str,
    pub size_bytes: i64,
    pub content_type: &'a str,
    pub sha256: &'a str,
    pub public: bool,
}

/// A key taken off the deletion queue by the worker.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct QueuedBlob {
    pub storage_key: String,
    pub tenant_id: Option<Uuid>,
    pub attempts: i32,
}

/// Queues `key` for deletion ahead of writing it, outside any transaction:
/// if the upload that writes it never commits, the queue still collects it.
pub(crate) async fn queue_upload(
    pool: &Database,
    key: &str,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    match pool {
        Database::Postgres(pg) => postgres::queue(pg, key, tenant_id).await,
        Database::Sqlite(db) => sqlite::queue(&db.pool, key, tenant_id).await,
    }
}

/// Takes `key` off the deletion queue, in the transaction that starts to refer
/// to it. `false` means the worker already claimed it -- the upload outlasted
/// the grace period and its bytes are being deleted -- so the caller must not
/// commit a reference to it.
pub(crate) async fn unqueue_in_tx(tx: &mut DbTransaction<'_>, key: &str) -> Result<bool, AppError> {
    match tx {
        DbTransaction::Postgres(pg) => postgres::unqueue(pg, key).await,
        DbTransaction::Sqlite(lite) => sqlite::unqueue(lite, key).await,
    }
}

pub(crate) async fn insert_in_tx(
    tx: &mut DbTransaction<'_>,
    new: &NewFileObject<'_>,
) -> Result<FileObject, AppError> {
    match tx {
        DbTransaction::Postgres(pg) => postgres::insert(pg, new).await,
        DbTransaction::Sqlite(lite) => sqlite::insert(lite, new).await,
    }
}

/// The file behind a live (not soft-deleted) resource.
pub(crate) async fn get(
    pool: &Database,
    resource_id: Uuid,
) -> Result<Option<FileObject>, AppError> {
    match pool {
        Database::Postgres(pg) => postgres::get(pg, resource_id).await,
        Database::Sqlite(db) => sqlite::get(&db.pool, resource_id).await,
    }
}

pub(crate) async fn get_in_tx(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
) -> Result<Option<FileObject>, AppError> {
    match tx {
        DbTransaction::Postgres(pg) => postgres::get_in_tx(pg, resource_id).await,
        DbTransaction::Sqlite(lite) => sqlite::get_in_tx(lite, resource_id).await,
    }
}

/// Points a file at new bytes. The replaced key is queued for deletion by the
/// table's trigger, in this transaction.
pub(crate) async fn replace_blob_in_tx(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    new: &NewFileObject<'_>,
) -> Result<FileObject, AppError> {
    match tx {
        DbTransaction::Postgres(pg) => postgres::replace_blob(pg, resource_id, new).await,
        DbTransaction::Sqlite(lite) => sqlite::replace_blob(lite, resource_id, new).await,
    }
}

/// Bytes a tenant keeps, soft-deleted files included (they stay stored until
/// purged). Called with the tenant row locked, so concurrent uploads are
/// counted in turn.
pub(crate) async fn tenant_usage_in_tx(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
) -> Result<i64, AppError> {
    match tx {
        DbTransaction::Postgres(pg) => postgres::tenant_usage(pg, tenant_id).await,
        DbTransaction::Sqlite(lite) => sqlite::tenant_usage(lite, tenant_id).await,
    }
}

/// Claims up to `limit` keys queued before `cutoff`, oldest first, by removing
/// them from the queue. Claiming before deleting is what makes the race with a
/// late upload safe: an upload commits only if its own unqueue removed the
/// row, so the bytes are either claimed here or referenced there, never both.
/// A worker that dies after claiming leaks those bytes rather than deleting
/// bytes a file refers to. PostgreSQL skips rows another replica is claiming.
pub(crate) async fn claim_due(
    pool: &Database,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<QueuedBlob>, AppError> {
    match pool {
        Database::Postgres(pg) => postgres::claim_due(pg, cutoff, limit).await,
        Database::Sqlite(db) => sqlite::claim_due(&db.pool, cutoff, limit).await,
    }
}

/// Puts a claimed key back after a failed deletion, for a later pass.
pub(crate) async fn requeue(
    pool: &Database,
    blob: &QueuedBlob,
    error: &str,
) -> Result<(), AppError> {
    let error: String = error.chars().take(1000).collect();
    match pool {
        Database::Postgres(pg) => postgres::requeue(pg, blob, &error).await,
        Database::Sqlite(db) => sqlite::requeue(&db.pool, blob, &error).await,
    }
}

/// True when a file row still refers to `key`: a claimed key is only deleted
/// when nothing does.
pub(crate) async fn referenced(pool: &Database, key: &str) -> Result<bool, AppError> {
    match pool {
        Database::Postgres(pg) => postgres::referenced(pg, key).await,
        Database::Sqlite(db) => sqlite::referenced(&db.pool, key).await,
    }
}
