use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

/// One allow-list entry of an access token's permission ceiling. Mirrors a
/// permission block's scope shape; v1 supports the directly-matchable scope modes.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessTokenPermission {
    pub actions: Vec<String>,
    pub scope_mode: String,
    pub tenant_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<Uuid>,
    pub conditions: Option<Value>,
}

/// Response after creating an access token — token shown once, never again.
#[derive(Debug, Serialize)]
pub struct AccessTokenResponse {
    pub credential_id: Uuid,
    pub token: String,
    pub name: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AccessTokenSummary {
    pub credential_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub identifier: Option<String>,
    pub status: CredentialStatus,
    /// True when the token is capped by a permission ceiling (self-service tokens);
    /// false for provisioned, full-authority API keys.
    pub scoped: bool,
    pub permissions: Vec<AccessTokenPermissionSummary>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A ceiling entry rendered for display in the token list.
#[derive(Debug, Serialize)]
pub struct AccessTokenPermissionSummary {
    pub actions: Vec<String>,
    pub scope_mode: String,
    pub tenant_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<Uuid>,
    pub conditions: Value,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccessToken {
    pub name: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub permissions: Vec<AccessTokenPermission>,
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
