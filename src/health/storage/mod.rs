mod postgres;
mod sqlite;
use crate::db::Database;
pub(super) async fn ping(pool: &Database) -> Result<(), sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::ping(pool).await,
        Database::Sqlite(db) => sqlite::ping(&db.pool).await,
    }
}
pub(super) async fn migration_count(pool: &Database) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::migration_count(pool).await,
        Database::Sqlite(db) => sqlite::migration_count(&db.pool).await,
    }
}
pub(super) async fn last_audit_cleanup(
    pool: &Database,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::last_audit_cleanup(pool).await,
        Database::Sqlite(db) => sqlite::last_audit_cleanup(&db.pool).await,
    }
}
