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

/// Connect to the test Redis with short TTLs so invalidation-correctness
/// tests aren't waiting on production-sized windows, and a fresh v1
/// namespace-mate configuration otherwise identical to `CacheConfig::default`.
pub async fn cache_client() -> CacheClient {
    let url = std::env::var("ATOM_TEST_REDIS_URL")
        .expect("ATOM_TEST_REDIS_URL must be set for cache-gated tests");
    let cfg = CacheConfig {
        enabled: true,
        redis_url: url,
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
