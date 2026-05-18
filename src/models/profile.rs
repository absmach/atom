use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Profile {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub object_kind: String,
    pub kind: String,
    pub key: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProfileVersion {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub version: i32,
    pub json_schema: Value,
    pub ui_schema: Value,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProfile {
    pub tenant_id: Option<Uuid>,
    pub object_kind: String,
    pub kind: String,
    pub key: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfile {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProfileVersion {
    pub version: i32,
    #[serde(default = "default_json_object")]
    pub json_schema: Value,
    #[serde(default = "default_json_object")]
    pub ui_schema: Value,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileVersion {
    pub json_schema: Option<Value>,
    pub ui_schema: Option<Value>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListProfiles {
    pub tenant_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub kind: Option<String>,
    pub key: Option<String>,
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct ProfileList {
    pub items: Vec<Profile>,
    pub total: i64,
}

fn default_json_object() -> Value {
    json!({})
}

fn default_limit() -> i64 {
    20
}
