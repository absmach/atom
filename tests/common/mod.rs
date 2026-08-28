//! Shared test fixtures for DB-gated integration tests.
//!
//! These tests require a reachable Postgres at `DATABASE_URL` and are
//! `#[ignore]` by default in each test file. Run with:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test -- --ignored
//! ```
//!
//! Cache-invalidation tests additionally require a reachable Redis at
//! `ATOM_TEST_REDIS_URL`, following the same `#[ignore]` convention:
//!
//! ```bash
//! DATABASE_URL=postgres://... ATOM_TEST_REDIS_URL=redis://... cargo test -- --ignored
//! ```

#![allow(dead_code)]

pub mod pki;

use atom::{cache::CacheClient, config::CacheConfig};
use sqlx::PgPool;

/// Connect to the test database and run all migrations.
pub async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to test database");
    sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .expect("load migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    pool
}

/// Connect to the test Redis with `CacheConfig::default`'s production TTLs,
/// overriding only mode, namespace, and Redis URL. Deliberately *not*
/// shortened: every
/// invalidation-correctness test asserts immediately, with no sleep, so a
/// short TTL could only mask a missing invalidation as a pass.
///
/// Assumes Redis is flushed between test binaries (see the `run_one` helper
/// in `.github/workflows/rust.yml`) and explicitly initializes the resulting
/// empty namespace incarnation — entries keyed off fixed ids such as the
/// seeded admin's would otherwise outlive the database they describe.
pub async fn cache_client() -> CacheClient {
    let url = std::env::var("ATOM_TEST_REDIS_URL")
        .expect("ATOM_TEST_REDIS_URL must be set for cache-gated tests");
    let cfg = CacheConfig {
        mode: atom::config::CacheMode::Enabled,
        redis_url: url,
        namespace: "integration-tests".into(),
        initialize_namespace: true,
        ..CacheConfig::default()
    };
    CacheClient::connect(&cfg)
        .await
        .expect("connect to test redis")
}

/// Well-known seeded admin entity.
pub fn admin_id() -> uuid::Uuid {
    "00000000-0000-0000-0000-000000000001".parse().unwrap()
}

/// Well-known seeded admin role.
pub fn admin_role_id() -> uuid::Uuid {
    "00000000-0000-0000-0000-000000000002".parse().unwrap()
}
