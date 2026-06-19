use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Resource {
    pub id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub attributes: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateResource {
    pub id: Option<Uuid>,
    pub kind: String,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateResource {
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::models::alias::deserialize_alias_update"
    )]
    pub alias: Option<Option<String>>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListResources {
    pub q: Option<String>,
    pub kind: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub parent_group_id: Option<Uuid>,
    pub include_descendants: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct ResourceList {
    pub items: Vec<Resource>,
    pub total: i64,
}
