use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::enums::DeletedFilter;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRole {
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleDerivedKind {
    Simple,
    Composite,
    Empty,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRole {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListRoles {
    pub tenant_id: Option<Uuid>,
    pub derived_kind: Option<String>,
    pub q: Option<String>,
    #[serde(default)]
    pub deleted: DeletedFilter,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct RoleList {
    pub items: Vec<Role>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct AddRoleCapability {
    pub capability_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RolePermissionBlock {
    pub id: Uuid,
    pub role_id: Uuid,
    pub applies_to: String,
    pub object_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRolePermissionBlock {
    pub applies_to: String,
    pub object_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub capability_ids: Vec<Uuid>,
}
