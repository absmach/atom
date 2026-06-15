//! Atom — identity and authorization service.
//!
//! Both the binary entry point (`src/main.rs`) and integration tests in
//! `tests/` consume this crate as a library. Module visibility mirrors the
//! historical `mod` layout from `main.rs`.

pub mod api_endpoints;
pub mod audit;
pub mod auth;
pub mod authz;
pub mod certs;
pub mod config;
pub mod db;
pub mod error;
pub mod graphql;
pub mod grpc;
pub mod guardrails;
pub mod health;
pub mod identity;
pub mod keys;
pub mod models;
pub mod rate_limit;
pub mod routes;
pub mod schema;
pub mod state;
pub mod tenants;
