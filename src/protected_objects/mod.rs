mod postgres;
mod sqlite;

use crate::db::Database;
use crate::db::DbExecutor;
use anyhow::Result;
use uuid::Uuid;

use crate::error::AppError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProtectedObjectIdentity {
    pub id: Uuid,
    pub object_kind: String,
    pub source_table: String,
    pub tenant_id: Option<Uuid>,
    pub object_type: Option<String>,
    pub live: bool,
}

pub async fn lookup(
    pool: &Database,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::lookup(pool, id).await,
        Database::Sqlite(db) => sqlite::lookup(&db.pool, id).await,
    }
}

pub async fn lookup_on_connection(
    connection: &mut impl DbExecutor,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError> {
    match connection.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::lookup(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::lookup(conn, id).await,
    }
}
