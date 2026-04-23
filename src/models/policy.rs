use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PolicyBinding {
    pub id: Uuid,
    pub subject_kind: String,
    pub subject_id: Uuid,
    pub grant_kind: String,
    pub grant_id: Uuid,
    pub scope_kind: String,
    pub scope_ref: Option<String>,
    pub effect: String,
    pub conditions: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyBinding {
    pub subject_kind: String,
    pub subject_id: Uuid,
    pub grant_kind: String,
    pub grant_id: Uuid,
    pub scope_kind: String,
    /// For scope_kind='resource' this is a resource UUID.
    /// For scope_kind='resource_kind' this is the kind name.
    /// For scope_kind='all' this is ignored.
    pub scope_ref: Option<String>,
    #[serde(default = "default_effect")]
    pub effect: String,
    #[serde(default)]
    pub conditions: Value,
}

fn default_effect() -> String {
    "allow".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ListPolicies {
    pub subject_id: Option<Uuid>,
    pub subject_kind: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct PolicyList {
    pub items: Vec<PolicyBinding>,
    pub total: i64,
}

/// Request body for the authorization check endpoint
#[derive(Debug, Deserialize)]
pub struct AuthzRequest {
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    /// Optional extra ABAC context, merged into the evaluation context
    #[serde(default)]
    pub context: Value,
}

#[derive(Debug, Serialize)]
pub struct AuthzResponse {
    pub allowed: bool,
    pub reason: String,
}
