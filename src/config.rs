use anyhow::{Context, Result};
use uuid::Uuid;

// 00000000-0000-0000-0000-000000000001
pub const ADMIN_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub listen_addr: String,
    pub jwt_expiry_secs: u64,
    /// UUID of the seeded admin entity. Defaults to the well-known seed UUID.
    pub admin_entity_id: Uuid,
    /// If set, the admin entity's password credential is created on first boot.
    pub admin_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?,
            listen_addr: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            jwt_expiry_secs: std::env::var("JWT_EXPIRY_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
            admin_entity_id: std::env::var("ADMIN_ENTITY_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(ADMIN_ENTITY_ID),
            admin_secret: std::env::var("ADMIN_SECRET").ok(),
        })
    }
}
