use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Response after creating an API key — secret shown once, never again
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub credential_id: Uuid,
    pub key: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub expires_at: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SharedKeyResponse {
    pub credential_id: Uuid,
    pub key: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSharedKey {
    pub expires_at: Option<DateTime<Utc>>,
    pub description: Option<String>,
    pub key: Option<String>,
}
