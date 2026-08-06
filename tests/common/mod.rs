//! Shared test fixtures for DB-gated integration tests.
//!
//! These tests require a reachable Postgres at `DATABASE_URL` and are
//! `#[ignore]` by default in each test file. Run with:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test -- --ignored
//! ```

#![allow(dead_code)]

pub mod pki;

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

/// Well-known seeded admin entity.
pub fn admin_id() -> uuid::Uuid {
    "00000000-0000-0000-0000-000000000001".parse().unwrap()
}

/// Well-known seeded admin role.
pub fn admin_role_id() -> uuid::Uuid {
    "00000000-0000-0000-0000-000000000002".parse().unwrap()
}
