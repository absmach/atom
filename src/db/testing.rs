//! Shared fixtures for database-backed tests, in-crate and integration alike.
//!
//! `ATOM_TEST_BACKEND=sqlite` runs the suites against SQLite; anything else
//! (the default) runs them against PostgreSQL at `DATABASE_URL`. The test
//! bodies are identical on both backends.

use tokio::sync::OnceCell;

use super::Database;
use crate::config::DbPoolConfig;

/// True when the suites are running against SQLite.
pub fn is_sqlite() -> bool {
    std::env::var("ATOM_TEST_BACKEND")
        .map(|v| v.eq_ignore_ascii_case("sqlite"))
        .unwrap_or(false)
}

static SQLITE: OnceCell<Database> = OnceCell::const_new();

fn sqlite_path() -> std::path::PathBuf {
    match std::env::var_os("ATOM_TEST_SQLITE_PATH") {
        Some(path) => path.into(),
        None => std::env::temp_dir().join(format!("atom-test-{}.db", std::process::id())),
    }
}

/// The URL of the shared test database for this process.
pub fn database_url() -> String {
    if is_sqlite() {
        format!("sqlite://{}", sqlite_path().display())
    } else {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests")
    }
}

fn pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 10,
        ..DbPoolConfig::default()
    }
}

/// Connects to the test database and applies all migrations.
///
/// PostgreSQL tests share one database that CI recreates per test binary.
/// SQLite tests share one fresh file per test process: a SQLite file admits
/// exactly one owning process, so the pool is created once and cloned.
pub async fn database() -> Database {
    init_logging();
    if is_sqlite() {
        return SQLITE
            .get_or_init(|| async {
                let path = sqlite_path();
                for suffix in ["", "-wal", "-shm", ".atom-lock"] {
                    let mut name = path.clone().into_os_string();
                    name.push(suffix);
                    let _ = std::fs::remove_file(name);
                }
                let db = Database::connect(&format!("sqlite://{}", path.display()), &pool_config())
                    .await
                    .expect("open SQLite test database");
                db.run_migrations().await.expect("apply SQLite migrations");
                db
            })
            .await
            .clone();
    }
    let db = Database::connect(&database_url(), &pool_config())
        .await
        .expect("connect to test database");
    db.run_migrations().await.expect("apply migrations");
    db
}

/// A handle over the shared test database capped at one connection, so a code
/// path that borrows a second connection while holding the first deadlocks
/// (and its test times out) instead of passing by luck.
pub async fn single_connection_database() -> Database {
    database()
        .await
        .with_max_connections(1, &pool_config())
        .await
        .expect("open single-connection test pool")
}

/// Routes `tracing` output to the test's stderr when `RUST_LOG` is set, so a
/// masked "database error" can be traced to its SQL failure.
fn init_logging() {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    }
}

/// Installs a `BEFORE INSERT` trigger on `table` that aborts every insert for
/// which `condition` (boolean SQL over `NEW.*`, portable across both backends)
/// holds, so a single write can be forced to fail.
///
/// PostgreSQL raises `check_violation`; SQLite aborts the statement from the
/// trigger, which is reported as the same class of failure. Triggers are global
/// to the database: callers drop them with [`drop_rejecting_trigger`] before
/// asserting, and scope `condition` to rows only their own test creates.
pub async fn install_rejecting_trigger(
    db: &Database,
    name: &str,
    table: &str,
    condition: &str,
    message: &str,
) {
    drop_rejecting_trigger(db, name, table).await;
    let statements = match db.kind() {
        super::DatabaseKind::Postgres => vec![
            format!(
                "CREATE OR REPLACE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $fn$
                 BEGIN
                   IF {condition} THEN
                     RAISE EXCEPTION '{message}' USING ERRCODE = '23514';
                   END IF;
                   RETURN NEW;
                 END;
                 $fn$"
            ),
            format!(
                "CREATE TRIGGER {name} BEFORE INSERT ON {table}
                 FOR EACH ROW EXECUTE FUNCTION {name}()"
            ),
        ],
        super::DatabaseKind::Sqlite => vec![format!(
            "CREATE TRIGGER {name} BEFORE INSERT ON {table}
             FOR EACH ROW WHEN ({condition})
             BEGIN
               SELECT RAISE(ABORT, '{message}');
             END"
        )],
    };
    for statement in statements {
        super::query(&statement)
            .execute(db)
            .await
            .unwrap_or_else(|e| panic!("install rejecting trigger {name}: {e}"));
    }
}

/// Removes a trigger created by [`install_rejecting_trigger`] (and its function
/// on PostgreSQL). Safe to call when it does not exist.
pub async fn drop_rejecting_trigger(db: &Database, name: &str, table: &str) {
    let statements = match db.kind() {
        super::DatabaseKind::Postgres => vec![
            format!("DROP TRIGGER IF EXISTS {name} ON {table}"),
            format!("DROP FUNCTION IF EXISTS {name}()"),
        ],
        super::DatabaseKind::Sqlite => vec![format!("DROP TRIGGER IF EXISTS {name}")],
    };
    for statement in statements {
        super::query(&statement)
            .execute(db)
            .await
            .unwrap_or_else(|e| panic!("drop rejecting trigger {name}: {e}"));
    }
}
