use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::enums::CredentialStatus;

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

/// Response after creating a personal access token — token shown once, never again.
#[derive(Debug, Serialize)]
pub struct PersonalAccessTokenResponse {
    pub credential_id: Uuid,
    pub token: String,
    pub name: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct PersonalAccessTokenSummary {
    pub credential_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub identifier: Option<String>,
    pub status: CredentialStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePersonalAccessToken {
    pub name: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
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
