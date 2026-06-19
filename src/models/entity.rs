use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::{EntityKind, EntityStatus};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Entity {
    pub id: Uuid,
    pub kind: EntityKind,
    pub name: String,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub status: EntityStatus,
    pub attributes: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEntity {
    pub id: Option<Uuid>,
    pub kind: Option<EntityKind>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub name: String,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEntity {
    pub name: Option<String>,
    pub kind: Option<EntityKind>,
    #[serde(
        default,
        deserialize_with = "crate::models::alias::deserialize_alias_update"
    )]
    pub alias: Option<Option<String>>,
    pub tenant_id: Option<Uuid>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub status: Option<EntityStatus>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListEntities {
    pub q: Option<String>,
    pub kind: Option<EntityKind>,
    pub profile_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub status: Option<EntityStatus>,
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
pub struct EntityList {
    pub items: Vec<Entity>,
    pub total: i64,
}

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
