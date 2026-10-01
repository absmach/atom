mod postgres;
mod sqlite;

use crate::db::Database;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{db::DbTransaction, error::AppError};

use super::BulkRevocationSelector;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertificateWindowCandidate {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub window_kind: String,
    pub window_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorityWindowCandidate {
    pub issuer_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub kind: String,
    pub expires_at: DateTime<Utc>,
    pub window_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BulkCandidate {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExpiryMetricRow {
    pub status: String,
    pub bucket: String,
    pub count: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorityMetricRow {
    pub kind: String,
    pub seconds: f64,
}

/// Select due certificate windows that do not already have a durable marker.
/// The stored PR-007 snapshot wins; pre-PR-007 rows fall back to their
/// referenced/effective profile, never to a process-wide renewal constant.
pub async fn due_certificate_windows(
    tx: &mut DbTransaction<'_>,
    now: DateTime<Utc>,
    expiry_warning_secs: u64,
    limit: i64,
) -> Result<Vec<CertificateWindowCandidate>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::due_certificate_windows(conn, now, expiry_warning_secs, limit).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::due_certificate_windows(conn, now, expiry_warning_secs, limit).await
        }
    }
}

pub async fn due_authority_windows(
    tx: &mut DbTransaction<'_>,
    now: DateTime<Utc>,
    warning_secs: u64,
    limit: i64,
) -> Result<Vec<AuthorityWindowCandidate>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::due_authority_windows(conn, now, warning_secs, limit).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::due_authority_windows(conn, now, warning_secs, limit).await
        }
    }
}

pub async fn claim_notification(
    tx: &mut DbTransaction<'_>,
    subject_kind: &str,
    subject_id: Uuid,
    window_kind: &str,
    window_at: DateTime<Utc>,
) -> Result<bool, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::claim_notification(conn, subject_kind, subject_id, window_kind, window_at)
                .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::claim_notification(conn, subject_kind, subject_id, window_kind, window_at).await
        }
    }
}

pub async fn expiry_metrics(
    tx: &mut DbTransaction<'_>,
    now: DateTime<Utc>,
) -> Result<Vec<ExpiryMetricRow>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::expiry_metrics(conn, now).await,
        DbTransaction::Sqlite(conn) => sqlite::expiry_metrics(conn, now).await,
    }
}

pub async fn authority_metrics(
    tx: &mut DbTransaction<'_>,
    now: DateTime<Utc>,
) -> Result<Vec<AuthorityMetricRow>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::authority_metrics(conn, now).await,
        DbTransaction::Sqlite(conn) => sqlite::authority_metrics(conn, now).await,
    }
}

pub async fn selector_tenant_id(
    pool: &Database,
    selector: BulkRevocationSelector,
) -> Result<Option<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::selector_tenant_id(pool, selector).await,
        Database::Sqlite(db) => sqlite::selector_tenant_id(&db.pool, selector).await,
    }
}

/// Database-clock cutoff used to freeze the membership of a paginated bulk
/// operation. Credential creation also uses the database clock, avoiding
/// process/DB clock skew at the page boundary.
pub async fn bulk_snapshot_at(pool: &Database) -> Result<DateTime<Utc>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::bulk_snapshot_at(pool).await,
        Database::Sqlite(db) => sqlite::bulk_snapshot_at(&db.pool).await,
    }
}

pub async fn bulk_candidates(
    pool: &Database,
    selector: BulkRevocationSelector,
    after: Option<Uuid>,
    snapshot_at: &DateTime<Utc>,
    limit: i64,
) -> Result<Vec<BulkCandidate>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::bulk_candidates(pool, selector, after, snapshot_at, limit).await
        }
        Database::Sqlite(db) => {
            sqlite::bulk_candidates(&db.pool, selector, after, snapshot_at, limit).await
        }
    }
}

pub(crate) async fn claim_sweep(tx: &mut DbTransaction<'_>) -> Result<bool, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::claim_sweep(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::claim_sweep(conn).await,
    }
}
