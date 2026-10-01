mod postgres;
mod sqlite;
use crate::db::DbTransaction;
use uuid::Uuid;
pub(super) async fn ensure_initial_password(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    hash: &str,
) -> Result<bool, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::ensure_initial_password(conn, entity_id, hash).await
        }
        DbTransaction::Sqlite(conn) => sqlite::ensure_initial_password(conn, entity_id, hash).await,
    }
}
