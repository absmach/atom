//! SQLite runtime policy: connection options, durability settings, pool sizing
//! and the single-owner lock. The behaviour here is the product contract in
//! `product-docs/development/database-backends/RFC.md` ("SQLite concurrency and
//! canonical behavior") — none of it is operator-selectable in this release.

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};

use crate::config::DbPoolConfig;

/// Busy timeout for a contended write lock. Beyond this a request fails closed
/// as "service unavailable" rather than waiting indefinitely.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// File-backed pools default to a small reader set; SQLite has one writer, so a
/// large pool only adds contention.
const DEFAULT_FILE_POOL: u32 = 5;

/// Where a `sqlite:` URL points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteLocation {
    File(PathBuf),
    Memory,
}

/// Parses the two supported forms: `sqlite://<path>` and `sqlite::memory:`.
pub fn parse_location(url: &str) -> anyhow::Result<SqliteLocation> {
    if url == "sqlite::memory:" || url == "sqlite://:memory:" {
        return Ok(SqliteLocation::Memory);
    }
    let Some(path) = url.strip_prefix("sqlite://") else {
        anyhow::bail!("unsupported SQLite DATABASE_URL; use sqlite://<path> or sqlite::memory:");
    };
    if path.is_empty() {
        anyhow::bail!("DATABASE_URL sqlite:// requires a database file path");
    }
    if path.contains('?') {
        anyhow::bail!(
            "DATABASE_URL sqlite:// does not accept query parameters; durability settings are fixed"
        );
    }
    Ok(SqliteLocation::File(PathBuf::from(path)))
}

/// Holds an exclusive advisory lock on a sibling file for the life of the
/// process, so two Atom processes cannot own one database. Network or shared
/// storage is unsupported even where the filesystem appears to honour this.
#[derive(Debug)]
pub struct SingleOwnerLock {
    _file: File,
}

impl SingleOwnerLock {
    pub fn acquire(db_path: &Path) -> anyhow::Result<Self> {
        let mut lock_path = db_path.as_os_str().to_owned();
        lock_path.push(".atom-lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| anyhow::anyhow!("cannot open SQLite lock file: {e}"))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                "another Atom process already owns this SQLite database; \
                 stop it or use a different file"
            ),
            Err(std::fs::TryLockError::Error(e)) => {
                anyhow::bail!("cannot lock SQLite database ownership file: {e}")
            }
        }
    }
}

/// A SQLite pool plus the ownership lock that must outlive it.
#[derive(Clone)]
pub struct SqliteDb {
    pub pool: SqlitePool,
    pub location: SqliteLocation,
    _lock: Option<Arc<SingleOwnerLock>>,
}

pub async fn connect(url: &str, cfg: &DbPoolConfig) -> anyhow::Result<SqliteDb> {
    let location = parse_location(url)?;

    let (options, lock, max_connections) = match &location {
        SqliteLocation::Memory => (
            SqliteConnectOptions::new()
                .in_memory(true)
                .shared_cache(false),
            None,
            1,
        ),
        SqliteLocation::File(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if !parent.is_dir() {
                    anyhow::bail!(
                        "SQLite database directory {} does not exist; create it first",
                        parent.display()
                    );
                }
            }
            let lock = SingleOwnerLock::acquire(path)?;
            (
                SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal),
                Some(Arc::new(lock)),
                file_pool_size(cfg),
            )
        }
    };

    let pool = open_pool(options, &location, max_connections, cfg).await?;

    Ok(SqliteDb {
        pool,
        location,
        _lock: lock,
    })
}

impl SqliteDb {
    /// A second pool over the same database with its own connection limit,
    /// sharing this handle's ownership lock. Tests use it to prove a code path
    /// never needs a second connection while it holds one.
    pub async fn with_max_connections(
        &self,
        max_connections: u32,
        cfg: &DbPoolConfig,
    ) -> anyhow::Result<SqliteDb> {
        let options = (*self.pool.connect_options()).clone();
        let pool = open_pool(options, &self.location, max_connections, cfg).await?;
        Ok(SqliteDb {
            pool,
            location: self.location.clone(),
            _lock: self._lock.clone(),
        })
    }
}

async fn open_pool(
    options: SqliteConnectOptions,
    location: &SqliteLocation,
    max_connections: u32,
    cfg: &DbPoolConfig,
) -> anyhow::Result<SqlitePool> {
    let options = options
        .foreign_keys(true)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(BUSY_TIMEOUT)
        .pragma("recursive_triggers", "ON");

    let mut pool_options = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .after_connect(|conn, _meta| Box::pin(super::sqlite_functions::register(conn)));
    if *location == SqliteLocation::Memory {
        // An in-memory database lives and dies with its only connection.
        pool_options = pool_options
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None);
    }

    tokio::time::timeout(
        Duration::from_secs(cfg.connect_timeout_secs),
        pool_options.connect_with(options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("database connect timed out"))?
    .map_err(Into::into)
}

/// The configured pool size when the operator set one, else the SQLite default.
fn file_pool_size(cfg: &DbPoolConfig) -> u32 {
    if std::env::var_os("ATOM_DB_MAX_CONNECTIONS").is_some() {
        cfg.max_connections.max(1)
    } else {
        DEFAULT_FILE_POOL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_supported_locations() {
        assert_eq!(
            parse_location("sqlite::memory:").unwrap(),
            SqliteLocation::Memory
        );
        assert_eq!(
            parse_location("sqlite:///var/lib/atom/atom.db").unwrap(),
            SqliteLocation::File(PathBuf::from("/var/lib/atom/atom.db"))
        );
        assert_eq!(
            parse_location("sqlite://data/atom.db").unwrap(),
            SqliteLocation::File(PathBuf::from("data/atom.db"))
        );
    }

    #[test]
    fn rejects_empty_paths_and_query_parameters() {
        assert!(parse_location("sqlite://").is_err());
        assert!(parse_location("sqlite://atom.db?mode=ro").is_err());
        assert!(parse_location("sqlite:atom.db").is_err());
    }

    #[tokio::test]
    async fn baseline_migration_applies_and_seeds_the_platform_rows() {
        let cfg = DbPoolConfig::default();
        let db = crate::db::Database::connect("sqlite::memory:", &cfg)
            .await
            .unwrap();
        db.run_migrations().await.unwrap();
        let admins: i64 =
            crate::db::query_scalar("SELECT count(*) FROM entities WHERE name = 'admin'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(admins, 1);
        let registered: i64 = crate::db::query_scalar("SELECT count(*) FROM protected_object_ids")
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(registered >= 3);
    }

    #[test]
    fn a_second_owner_of_the_same_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("atom-lock-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("atom.db");
        let first = SingleOwnerLock::acquire(&db).expect("first owner");
        let second = SingleOwnerLock::acquire(&db);
        assert!(second.is_err());
        drop(first);
        assert!(SingleOwnerLock::acquire(&db).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }
}
