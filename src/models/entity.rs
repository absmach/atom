use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Entity {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub status: String,
    pub attributes: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEntity {
    pub kind: String,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEntity {
    pub name: Option<String>,
    pub status: Option<String>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListEntities {
    pub kind: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct EntityList {
    pub items: Vec<Entity>,
    pub total: i64,
}

// Ownership
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Ownership {
    pub owner_id: Uuid,
    pub owned_id: Uuid,
    pub relation: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOwnership {
    pub owned_id: Uuid,
    #[serde(default = "default_relation")]
    pub relation: String,
}

fn default_relation() -> String {
    "owner".to_string()
}
