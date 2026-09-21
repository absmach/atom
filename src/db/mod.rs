use std::time::Duration;

use sqlx::{
    migrate::MigrateError,
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
    Acquire, PgConnection, PgPool, Postgres, Sqlite, Transaction,
};

use crate::config::DbPoolConfig;

mod arg;
mod query;
pub mod sqlite;
mod sqlite_functions;
pub mod translate;

pub use arg::{enum_text, Arg, ArgKind, DbArg, TextList, UuidList};
pub use query::{
    query, query_as, query_scalar, DbRow, DbScalar, ExecResult, IntoTarget, Query, QueryAs,
    QueryBuilder, QueryScalar, Row, Target,
};
pub use sqlite::SqliteDb;

/// Identifies which storage backend a [`Database`] is backed by. `DATABASE_URL`'s
/// scheme selects this at startup (see [`classify_url`]); every backend-specific
/// pool/transaction type stays behind the [`Database`]/[`DbTransaction`] façade so
/// domain and transport code never names a concrete SQLx backend type directly.
///
/// Both backends are first-class: PostgreSQL for multi-replica and high-write
/// deployments, SQLite for a single local process (see
/// `product-docs/development/database-backends/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Postgres,
    Sqlite,
}

impl DatabaseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseKind::Postgres => "postgres",
            DatabaseKind::Sqlite => "sqlite",
        }
    }
}

impl std::fmt::Display for DatabaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies a `DATABASE_URL` by scheme without connecting, so an unsupported
/// scheme fails startup before any pool/migration work rather than deep inside
/// connection setup.
pub fn classify_url(url: &str) -> anyhow::Result<DatabaseKind> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        Ok(DatabaseKind::Postgres)
    } else if url.starts_with("sqlite://") || url == "sqlite::memory:" {
        Ok(DatabaseKind::Sqlite)
    } else {
        anyhow::bail!(
            "unsupported DATABASE_URL scheme; expected postgres://, postgresql://, \
             sqlite://<path>, or sqlite::memory:"
        )
    }
}

pub fn pool_options(cfg: &DbPoolConfig) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .max_lifetime(Duration::from_secs(cfg.max_lifetime_secs))
}

pub async fn create_pool(url: &str, cfg: &DbPoolConfig) -> anyhow::Result<PgPool> {
    let connect_options: PgConnectOptions = url.parse::<PgConnectOptions>()?;
    let pool = tokio::time::timeout(
        Duration::from_secs(cfg.connect_timeout_secs),
        pool_options(cfg).connect_with(connect_options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("database connect timed out"))??;
    Ok(pool)
}

/// A sanitized, log-safe summary of where a [`Database`] is connected — host,
/// port, and database name, never credentials. Startup logging uses this
/// instead of the raw `DATABASE_URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseLocation {
    pub kind: DatabaseKind,
    pub host: String,
    pub port: Option<u16>,
    pub database: String,
}

impl std::fmt::Display for DatabaseLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.kind == DatabaseKind::Sqlite {
            return write!(f, "sqlite:{}", self.host);
        }
        match self.port {
            Some(port) => write!(
                f,
                "{}://{}:{}/{}",
                self.kind, self.host, port, self.database
            ),
            None => write!(f, "{}://{}/{}", self.kind, self.host, self.database),
        }
    }
}

/// Re-parses `url` for logging only — `Database` itself never retains the raw
/// URL string once connected, so this is the one place startup recovers a
/// display form of it.
pub fn location(url: &str) -> anyhow::Result<DatabaseLocation> {
    match classify_url(url)? {
        DatabaseKind::Postgres => {
            let opts: PgConnectOptions = url.parse()?;
            Ok(DatabaseLocation {
                kind: DatabaseKind::Postgres,
                host: opts.get_host().to_string(),
                port: Some(opts.get_port()),
                database: opts.get_database().unwrap_or_default().to_string(),
            })
        }
        DatabaseKind::Sqlite => {
            // Category only: a file path is not an operator-safe log field.
            let category = match sqlite::parse_location(url)? {
                sqlite::SqliteLocation::File(_) => "file",
                sqlite::SqliteLocation::Memory => "memory",
            };
            Ok(DatabaseLocation {
                kind: DatabaseKind::Sqlite,
                host: category.to_string(),
                port: None,
                database: String::new(),
            })
        }
    }
}

/// Backend-neutral database handle: owns the connection pool, dispatches
/// migrations, and mints transactions. Cheaply cloneable (the pool clones its
/// handle, not its connections), so it lives on [`crate::state::AppState`].
///
/// Domain and transport code should hold this (or [`DbTransaction`]) rather
/// than a concrete SQLx pool/connection type — see
/// `product-docs/development/database-backends/RFC.md`.
#[derive(Clone)]
pub enum Database {
    Postgres(PgPool),
    Sqlite(SqliteDb),
}

impl Database {
    /// Classifies `url`, then connects and returns the pool wrapped in this
    /// façade. Fails before any listener serves on an unsupported scheme or a
    /// connection/timeout error.
    pub async fn connect(url: &str, cfg: &DbPoolConfig) -> anyhow::Result<Self> {
        match classify_url(url)? {
            DatabaseKind::Postgres => Ok(Database::Postgres(create_pool(url, cfg).await?)),
            DatabaseKind::Sqlite => Ok(Database::Sqlite(sqlite::connect(url, cfg).await?)),
        }
    }

    pub fn kind(&self) -> DatabaseKind {
        match self {
            Database::Postgres(_) => DatabaseKind::Postgres,
            Database::Sqlite(_) => DatabaseKind::Sqlite,
        }
    }

    /// Applies the migration set belonging to this backend.
    pub async fn run_migrations(&self) -> Result<(), MigrateError> {
        match self {
            Database::Postgres(pool) => sqlx::migrate!("./migrations").run(pool).await,
            Database::Sqlite(db) => sqlx::migrate!("./migrations/sqlite").run(&db.pool).await,
        }
    }

    /// Opens a new top-level transaction. SQLite transactions begin
    /// `IMMEDIATE`, taking the single write reservation up front so a
    /// read-then-write transaction can never deadlock against another writer.
    /// Nested (savepoint) transactions are opened from an existing
    /// [`DbTransaction`] via [`DbTransaction::begin`].
    pub async fn begin(&self) -> Result<DbTransaction<'static>, sqlx::Error> {
        match self {
            Database::Postgres(pool) => Ok(DbTransaction::Postgres(pool.begin().await?)),
            Database::Sqlite(db) => Ok(DbTransaction::Sqlite(
                db.pool.begin_with("BEGIN IMMEDIATE").await?,
            )),
        }
    }

    /// A pooled connection outside any transaction, for read-only validation
    /// that must not open a write transaction.
    pub async fn acquire(&self) -> Result<DbConn, sqlx::Error> {
        match self {
            Database::Postgres(pool) => Ok(DbConn::Postgres(pool.acquire().await?)),
            Database::Sqlite(db) => Ok(DbConn::Sqlite(db.pool.acquire().await?)),
        }
    }

    /// Transitional accessor for storage code that has not yet moved onto
    /// `Database`/`DbTransaction`. Panics on a non-PostgreSQL database, which
    /// is why removing every remaining use is a hard requirement of adding a
    /// second backend.
    pub fn as_postgres(&self) -> &PgPool {
        match self {
            Database::Postgres(pool) => pool,
            Database::Sqlite(_) => panic!("as_postgres() called on a SQLite database"),
        }
    }
}

/// A pooled connection acquired outside a transaction.
pub enum DbConn {
    Postgres(PoolConnection<Postgres>),
    Sqlite(PoolConnection<Sqlite>),
}

impl From<PgPool> for Database {
    fn from(pool: PgPool) -> Self {
        Database::Postgres(pool)
    }
}

/// A backend-neutral open transaction. Wraps exactly one backend transaction
/// and forwards commit/rollback/nested-savepoint semantics to it.
///
/// `'c` is the borrow lifetime of the connection this transaction runs on:
/// `'static` for a top-level transaction opened from a pooled [`Database`], or
/// borrowed from the parent for a nested savepoint opened via [`Self::begin`].
pub enum DbTransaction<'c> {
    Postgres(Transaction<'c, Postgres>),
    Sqlite(Transaction<'c, Sqlite>),
}

impl<'c> DbTransaction<'c> {
    pub fn kind(&self) -> DatabaseKind {
        match self {
            DbTransaction::Postgres(_) => DatabaseKind::Postgres,
            DbTransaction::Sqlite(_) => DatabaseKind::Sqlite,
        }
    }

    /// Opens a nested savepoint transaction borrowing this one. PKI
    /// issuance's serial-collision retry uses this so a unique violation
    /// aborts only the inner savepoint, never the caller's outer transaction
    /// (see `certs::service`).
    pub async fn begin(&mut self) -> Result<DbTransaction<'_>, sqlx::Error> {
        match self {
            DbTransaction::Postgres(tx) => Ok(DbTransaction::Postgres(tx.begin().await?)),
            DbTransaction::Sqlite(tx) => Ok(DbTransaction::Sqlite(tx.begin().await?)),
        }
    }

    pub async fn commit(self) -> Result<(), sqlx::Error> {
        match self {
            DbTransaction::Postgres(tx) => tx.commit().await,
            DbTransaction::Sqlite(tx) => tx.commit().await,
        }
    }

    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        match self {
            DbTransaction::Postgres(tx) => tx.rollback().await,
            DbTransaction::Sqlite(tx) => tx.rollback().await,
        }
    }

    /// The handle to pass to a query's `execute`/`fetch_*`, whether this
    /// transaction is held by value or by `&mut` reference.
    pub fn exec(&mut self) -> &mut Self {
        self
    }

    /// Transitional accessor: the concrete Postgres connection this
    /// transaction runs on, for storage code that has not yet moved onto the
    /// query layer. Panics on SQLite; see [`Database::as_postgres`].
    pub fn as_postgres_mut(&mut self) -> &mut PgConnection {
        match self {
            DbTransaction::Postgres(tx) => tx,
            DbTransaction::Sqlite(_) => panic!("as_postgres_mut() called on a SQLite transaction"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_options_accept_configured_values() {
        let cfg = DbPoolConfig {
            max_connections: 12,
            min_connections: 2,
            acquire_timeout_secs: 3,
            connect_timeout_secs: 4,
            idle_timeout_secs: 5,
            max_lifetime_secs: 6,
        };

        let pool = pool_options(&cfg)
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("lazy pool");

        assert_eq!(pool.options().get_max_connections(), 12);
        assert_eq!(pool.options().get_min_connections(), 2);
    }

    #[test]
    fn classify_url_accepts_postgres_schemes() {
        assert_eq!(
            classify_url("postgres://u:p@host/db").unwrap(),
            DatabaseKind::Postgres
        );
        assert_eq!(
            classify_url("postgresql://u:p@host/db").unwrap(),
            DatabaseKind::Postgres
        );
    }

    #[test]
    fn classify_url_accepts_sqlite_and_rejects_unknown_schemes() {
        assert_eq!(
            classify_url("sqlite://local.db").unwrap(),
            DatabaseKind::Sqlite
        );
        assert_eq!(
            classify_url("sqlite::memory:").unwrap(),
            DatabaseKind::Sqlite
        );
        assert!(classify_url("mysql://u:p@host/db").is_err());
        assert!(classify_url("not a url").is_err());
    }

    #[test]
    fn location_never_exposes_credentials() {
        let loc = location("postgres://user:hunter2@db.internal:6543/atom").unwrap();
        assert_eq!(loc.host, "db.internal");
        assert_eq!(loc.port, Some(6543));
        assert_eq!(loc.database, "atom");
        let rendered = loc.to_string();
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("user"));
    }
}
