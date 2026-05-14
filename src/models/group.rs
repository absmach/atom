use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::EntityStatus;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
    pub parent_id: Option<Uuid>,
    pub status: EntityStatus,
    pub attributes: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroup {
    pub id: Option<Uuid>,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroup {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<EntityStatus>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListGroups {
    pub q: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub status: Option<EntityStatus>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct GroupList {
    pub items: Vec<Group>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct AddMember {
    pub entity_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct SetGroupParent {
    pub parent_id: Uuid,
}
