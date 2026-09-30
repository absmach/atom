//! Operational contract of the SQLite backend: durability settings, single
//! ownership, restart persistence, atomic rollback, contention behaviour and
//! backup/restore. Unlike the DB-gated suites these need no external service —
//! every test creates its own database file — so they run in the default
//! `cargo test`.

use std::path::{Path, PathBuf};

use atom::{
    config::DbPoolConfig,
    db::{query, query_scalar, Database, DatabaseKind},
    error::{db_err, AppError},
};
use uuid::Uuid;

fn temp_db_path() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("atom-sqlite-ops-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("atom.db")
}

fn cleanup(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn url(path: &Path) -> String {
    format!("sqlite://{}", path.display())
}

async fn open(path: &Path) -> Database {
    let db = Database::connect(&url(path), &DbPoolConfig::default())
        .await
        .expect("open sqlite database");
    db.run_migrations().await.expect("apply migrations");
    db
}

async fn pragma_int(db: &Database, name: &str) -> i64 {
    query_scalar::<i64>(&format!("SELECT * FROM pragma_{name}"))
        .fetch_one(db)
        .await
        .unwrap_or_else(|e| panic!("pragma {name}: {e}"))
}

#[tokio::test]
async fn connections_apply_the_fixed_durability_policy() {
    let path = temp_db_path();
    let db = open(&path).await;
    assert_eq!(db.kind(), DatabaseKind::Sqlite);

    let journal: String = query_scalar("SELECT journal_mode FROM pragma_journal_mode")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(journal.to_ascii_lowercase(), "wal");
    // 2 = FULL: fsync on every commit.
    assert_eq!(pragma_int(&db, "synchronous").await, 2);
    assert_eq!(pragma_int(&db, "foreign_keys").await, 1);
    assert_eq!(pragma_int(&db, "recursive_triggers").await, 1);
    assert_eq!(pragma_int(&db, "busy_timeout").await, 30_000);
    drop(db);
    cleanup(&path);
}

#[tokio::test]
async fn tables_indexes_and_views_use_only_sqlite_builtins() {
    // Other SQLite tooling (the sqlite3 shell, VACUUM INTO, backup agents) has no
    // atom_* functions. Constraints that called one would make a plain copy of
    // the database fail, so only triggers may depend on them.
    let path = temp_db_path();
    let db = open(&path).await;
    let offenders: Vec<String> = query_scalar(
        "SELECT name FROM sqlite_master
         WHERE type IN ('table', 'index', 'view') AND sql LIKE '%atom\\_%' ESCAPE '\\'",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert!(
        offenders.is_empty(),
        "custom SQL functions in {offenders:?}"
    );
    drop(db);
    cleanup(&path);
}

#[tokio::test]
async fn data_survives_a_restart() {
    let path = temp_db_path();
    let entity_id = Uuid::new_v4();
    {
        let db = open(&path).await;
        query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
            .bind(entity_id)
            .bind(format!("restart-{entity_id}"))
            .execute(&db)
            .await
            .expect("insert");
    }
    // Reopening applies migrations again: the baseline must be idempotent and
    // must not disturb existing rows.
    let db = open(&path).await;
    let name: String = query_scalar("SELECT name FROM entities WHERE id = $1")
        .bind(entity_id)
        .fetch_one(&db)
        .await
        .expect("row persisted");
    assert_eq!(name, format!("restart-{entity_id}"));
    drop(db);
    cleanup(&path);
}

#[tokio::test]
async fn a_second_process_cannot_own_the_same_database() {
    let path = temp_db_path();
    let first = open(&path).await;
    let second = Database::connect(&url(&path), &DbPoolConfig::default()).await;
    let err = second
        .err()
        .expect("second owner must be refused")
        .to_string();
    assert!(
        err.contains("already owns this SQLite database"),
        "unexpected refusal: {err}"
    );
    drop(first);
    // Ownership is released with the first handle.
    let reopened = open(&path).await;
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn a_rolled_back_transaction_leaves_no_trace() {
    let path = temp_db_path();
    let db = open(&path).await;
    let entity_id = Uuid::new_v4();
    let mut tx = db.begin().await.expect("begin");
    query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
        .bind(entity_id)
        .bind(format!("rollback-{entity_id}"))
        .execute(&mut tx)
        .await
        .expect("insert in tx");
    // The registry row is written by a trigger in the same transaction.
    let registered: i64 = query_scalar("SELECT COUNT(*) FROM protected_object_ids WHERE id = $1")
        .bind(entity_id)
        .fetch_one(&mut tx)
        .await
        .unwrap();
    assert_eq!(registered, 1);
    tx.rollback().await.expect("rollback");

    for table in ["entities", "protected_object_ids"] {
        let n: i64 = query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id = $1"))
            .bind(entity_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table} row survived a rollback");
    }
    drop(db);
    cleanup(&path);
}

#[tokio::test]
async fn a_failed_statement_aborts_the_whole_transaction_atomically() {
    let path = temp_db_path();
    let db = open(&path).await;
    let entity_id = Uuid::new_v4();
    let name = format!("atomic-{entity_id}");
    let mut tx = db.begin().await.expect("begin");
    query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
        .bind(entity_id)
        .bind(&name)
        .execute(&mut tx)
        .await
        .expect("first insert");
    // Same live name in the same (global) scope violates the unique index.
    let duplicate =
        query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
            .bind(Uuid::new_v4())
            .bind(&name)
            .execute(&mut tx)
            .await
            .expect_err("duplicate name must be rejected");
    assert!(atom::error::is_unique_violation(&duplicate));
    drop(tx);

    let n: i64 = query_scalar("SELECT COUNT(*) FROM entities WHERE name = $1")
        .bind(&name)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(n, 0, "dropping the transaction must discard its writes");
    drop(db);
    cleanup(&path);
}

#[tokio::test]
async fn invariant_triggers_reject_and_classify_as_check_violations() {
    let path = temp_db_path();
    let db = open(&path).await;
    let entity_id = Uuid::new_v4();
    query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'human', $2, 'active')")
        .bind(entity_id)
        .bind(format!("human-{entity_id}"))
        .execute(&db)
        .await
        .expect("insert human");
    let err = query(
        "INSERT INTO credentials (entity_id, kind, secret_hash) VALUES ($1, 'shared_key', 'x')",
    )
    .bind(entity_id)
    .execute(&db)
    .await
    .expect_err("shared_key on a human must be rejected by the trigger");
    assert!(atom::error::is_check_violation(&err), "got {err}");
    drop(db);
    cleanup(&path);
}

#[tokio::test]
async fn a_second_writer_waits_for_the_first_then_proceeds() {
    let path = temp_db_path();
    let db = open(&path).await;
    // A second pool over the same file with its own connection. SQLite admits
    // one writer: this one queues behind the transaction below (up to the 30s
    // busy timeout, after which the failure maps to "service unavailable" — see
    // `busy_errors_map_to_service_unavailable`).
    let other = db
        .with_max_connections(1, &DbPoolConfig::default())
        .await
        .expect("second pool");
    let mut writer = db.begin().await.expect("hold the write lock");
    query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
        .bind(Uuid::new_v4())
        .bind(format!("busy-{}", Uuid::new_v4()))
        .execute(&mut writer)
        .await
        .expect("write");

    // Shorten the wait for the test by racing the attempt against a deadline:
    // a blocked writer must still be waiting, not have failed or succeeded.
    let attempt = tokio::time::timeout(
        std::time::Duration::from_millis(400),
        query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
            .bind(Uuid::new_v4())
            .bind(format!("blocked-{}", Uuid::new_v4()))
            .execute(&other),
    )
    .await;
    assert!(attempt.is_err(), "a second writer must wait for the first");
    writer.rollback().await.expect("release");

    // Once released the same write succeeds.
    query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
        .bind(Uuid::new_v4())
        .bind(format!("after-{}", Uuid::new_v4()))
        .execute(&other)
        .await
        .expect("write after release");
    drop(other);
    drop(db);
    cleanup(&path);
}

#[test]
fn busy_errors_map_to_service_unavailable() {
    let busy = sqlx::Error::Database(Box::new(FakeDbError {
        code: "5",
        message: "database is locked",
    }));
    assert!(matches!(db_err(busy), AppError::ServiceUnavailable(_)));
    let locked = sqlx::Error::Database(Box::new(FakeDbError {
        code: "517",
        message: "database is locked",
    }));
    assert!(matches!(db_err(locked), AppError::ServiceUnavailable(_)));
    let other = sqlx::Error::Database(Box::new(FakeDbError {
        code: "1",
        message: "syntax error",
    }));
    assert!(matches!(db_err(other), AppError::Database(_)));
}

#[tokio::test]
async fn a_copied_database_file_restores_to_the_same_data() {
    let path = temp_db_path();
    let entity_id = Uuid::new_v4();
    {
        let db = open(&path).await;
        query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')")
            .bind(entity_id)
            .bind(format!("backup-{entity_id}"))
            .execute(&db)
            .await
            .expect("insert");
        // Fold the WAL into the main file so a plain file copy is a complete
        // backup (the documented procedure), then copy while owning the lock.
        query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&db)
            .await
            .expect("checkpoint");
        let backup = path.with_file_name("backup.db");
        std::fs::copy(&path, &backup).expect("copy database file");
        drop(db);
        let restored = open(&backup).await;
        let name: String = query_scalar("SELECT name FROM entities WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&restored)
            .await
            .expect("row present in the restored copy");
        assert_eq!(name, format!("backup-{entity_id}"));
        drop(restored);
    }
    cleanup(&path);
}

/// Minimal `DatabaseError` so error classification can be exercised without
/// provoking a real SQLite failure.
#[derive(Debug)]
struct FakeDbError {
    code: &'static str,
    message: &'static str,
}

impl std::fmt::Display for FakeDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FakeDbError {}

impl sqlx::error::DatabaseError for FakeDbError {
    fn message(&self) -> &str {
        self.message
    }
    fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
        Some(std::borrow::Cow::Borrowed(self.code))
    }
    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }
    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::Other
    }
}
