//! Borrow an existing connection without acquiring another pool connection.
use super::{Database, DbConn, DbTransaction};
use sqlx::{PgConnection, PgPool, SqliteConnection, SqlitePool};

pub enum ConnectionRef<'a> {
    Postgres(&'a mut PgConnection),
    Sqlite(&'a mut SqliteConnection),
}

/// A connection-like handle a query can run on: an open transaction or a pooled
/// connection. Functions that must work inside either take
/// `&mut impl DbExecutor`.
pub trait DbExecutor {
    fn connection(&mut self) -> ConnectionRef<'_>;
}

impl DbExecutor for DbTransaction<'_> {
    fn connection(&mut self) -> ConnectionRef<'_> {
        match self {
            DbTransaction::Postgres(tx) => ConnectionRef::Postgres(tx),
            DbTransaction::Sqlite(tx) => ConnectionRef::Sqlite(tx),
        }
    }
}

impl DbExecutor for DbConn {
    fn connection(&mut self) -> ConnectionRef<'_> {
        match self {
            DbConn::Postgres(conn) => ConnectionRef::Postgres(conn),
            DbConn::Sqlite(conn) => ConnectionRef::Sqlite(conn),
        }
    }
}

impl<T: DbExecutor + ?Sized> DbExecutor for &mut T {
    fn connection(&mut self) -> ConnectionRef<'_> {
        (**self).connection()
    }
}

/// Where a query runs.
pub enum Target<'a> {
    PoolPostgres(&'a PgPool),
    ConnectionPostgres(&'a mut PgConnection),
    PoolSqlite(&'a SqlitePool),
    ConnectionSqlite(&'a mut SqliteConnection),
}

/// Anything a query can run against.
pub trait IntoTarget<'a> {
    fn into_target(self) -> Target<'a>;
}

impl<'a> IntoTarget<'a> for &'a Database {
    fn into_target(self) -> Target<'a> {
        match self {
            Database::Postgres(pool) => Target::PoolPostgres(pool),
            Database::Sqlite(db) => Target::PoolSqlite(&db.pool),
        }
    }
}

impl<'a, 'b: 'a> IntoTarget<'a> for &'a &'b Database {
    fn into_target(self) -> Target<'a> {
        (*self).into_target()
    }
}

impl<'a, E: DbExecutor + ?Sized> IntoTarget<'a> for &'a mut E {
    fn into_target(self) -> Target<'a> {
        match self.connection() {
            ConnectionRef::Postgres(conn) => Target::ConnectionPostgres(conn),
            ConnectionRef::Sqlite(conn) => Target::ConnectionSqlite(conn),
        }
    }
}

impl<'a> IntoTarget<'a> for &'a PgPool {
    fn into_target(self) -> Target<'a> {
        Target::PoolPostgres(self)
    }
}

impl<'a> IntoTarget<'a> for &'a mut PgConnection {
    fn into_target(self) -> Target<'a> {
        Target::ConnectionPostgres(self)
    }
}
