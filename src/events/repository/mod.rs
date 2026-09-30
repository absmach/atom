//! Outbox repository contract. Delivery policy stays in the events service.
mod postgres;
mod sqlite;
use super::DomainEventPayload;
use crate::{
    db::{Database, DbTransaction, IntoTarget, Target},
    error::AppError,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub(super) struct OutboxRow {
    pub id: Uuid,
    pub payload: serde_json::Value,
}

pub(super) async fn append<'e, E>(executor: E, payload: &DomainEventPayload) -> Result<(), AppError>
where
    E: IntoTarget<'e>,
{
    match executor.into_target() {
        Target::PoolPostgres(conn) => postgres::append(conn, payload).await,
        Target::ConnectionPostgres(conn) => postgres::append(conn, payload).await,
        Target::PoolSqlite(conn) => sqlite::append(conn, payload).await,
        Target::ConnectionSqlite(conn) => sqlite::append(conn, payload).await,
    }
}

pub(super) async fn claim_delivery(
    tx: &mut DbTransaction<'_>,
    batch_size: i64,
    max_attempts: i32,
) -> Result<Vec<OutboxRow>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::claim_delivery(conn, batch_size, max_attempts).await
        }
        DbTransaction::Sqlite(conn) => sqlite::claim_delivery(conn, batch_size, max_attempts).await,
    }
}

pub(super) async fn record_delivery_failure(
    tx: &mut DbTransaction<'_>,
    ids: &[Uuid],
    error: &str,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::record_delivery_failure(conn, ids, error).await,
        DbTransaction::Sqlite(conn) => sqlite::record_delivery_failure(conn, ids, error).await,
    }
}

pub(super) async fn mark_delivered(
    tx: &mut DbTransaction<'_>,
    ids: &[Uuid],
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::mark_delivered(conn, ids).await,
        DbTransaction::Sqlite(conn) => sqlite::mark_delivered(conn, ids).await,
    }
}

pub(super) async fn quarantine(
    tx: &mut DbTransaction<'_>,
    ids: &[Uuid],
    error: &str,
) -> Result<Vec<(Uuid, i32)>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::quarantine(conn, ids, error).await,
        DbTransaction::Sqlite(conn) => sqlite::quarantine(conn, ids, error).await,
    }
}

pub(super) async fn purge_batch(
    pool: &Database,
    cutoff: DateTime<Utc>,
    max_attempts: i32,
    batch_size: i64,
) -> Result<u64, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::purge_batch(pool, cutoff, max_attempts, batch_size).await
        }
        Database::Sqlite(db) => {
            sqlite::purge_batch(&db.pool, cutoff, max_attempts, batch_size).await
        }
    }
}
