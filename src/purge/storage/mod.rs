mod postgres;
mod sqlite;
use super::*;
pub(super) async fn select_doomed(
    tx: &mut DbTransaction<'_>,
    table: &str,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::select_doomed(conn, table, cutoff, batch_size).await
        }
        DbTransaction::Sqlite(conn) => sqlite::select_doomed(conn, table, cutoff, batch_size).await,
    }
}
pub(super) async fn delete_by_ids(
    tx: &mut DbTransaction<'_>,
    table: &str,
    ids: &[Uuid],
) -> Result<i64, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::delete_by_ids(conn, table, ids).await,
        DbTransaction::Sqlite(conn) => sqlite::delete_by_ids(conn, table, ids).await,
    }
}
pub(super) async fn purge_roles(
    tx: &mut DbTransaction<'_>,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_roles(conn, cutoff, batch_size).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_roles(conn, cutoff, batch_size).await,
    }
}
pub(super) async fn claim_sweep(tx: &mut DbTransaction<'_>) -> Result<bool, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::claim_sweep(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::claim_sweep(conn).await,
    }
}
pub(super) async fn prepare_entity_purge(
    tx: &mut DbTransaction<'_>,
    ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::prepare_entity_purge(conn, ids).await,
        DbTransaction::Sqlite(conn) => sqlite::prepare_entity_purge(conn, ids).await,
    }
}
