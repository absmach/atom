//! Audit-log storage. Fire-and-forget policy and commit sequencing stay in audit.rs.
mod postgres;
mod sqlite;
use crate::{
    audit::AuditEvent,
    db::{Database, IntoTarget, Target},
    error::AppError,
};
use chrono::{DateTime, Utc};

pub(super) async fn append<'e, E>(executor: E, event: &AuditEvent<'_>) -> Result<(), AppError>
where
    E: IntoTarget<'e>,
{
    match executor.into_target() {
        Target::PoolPostgres(conn) => postgres::append(conn, event).await,
        Target::ConnectionPostgres(conn) => postgres::append(conn, event).await,
        Target::PoolSqlite(conn) => sqlite::append(conn, event).await,
        Target::ConnectionSqlite(conn) => sqlite::append(conn, event).await,
    }
}

pub(super) async fn purge_batch(
    pool: &Database,
    cutoff: DateTime<Utc>,
    batch_size: i64,
) -> Result<u64, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::purge_batch(pool, cutoff, batch_size).await,
        Database::Sqlite(db) => sqlite::purge_batch(&db.pool, cutoff, batch_size).await,
    }
}
