//! Atom — identity and authorization service.
//!
//! Both the binary entry point (`src/main.rs`) and integration tests in
//! `tests/` consume this crate as a library. Module visibility mirrors the
//! historical `mod` layout from `main.rs`.

pub mod api_endpoints;
pub mod audit;
pub mod auth;
pub mod authz;
pub mod bootstrap;
pub mod broker_auth;
pub mod build_info;
pub mod callout;
pub mod certs;
pub mod config;
mod connection_limit;
pub mod crypto;
pub mod db;
pub mod error;
pub mod events;
pub mod graphql;
pub mod grpc;
pub mod guardrails;
pub mod health;
pub mod http_server;
pub mod identity;
pub mod keys;
pub mod mail;
pub mod managed_by;
pub mod metrics;
pub mod models;
pub mod purge;
pub mod rate_limit;
pub mod routes;
pub mod schema;
pub mod shutdown;
pub mod state;
pub mod tenants;
