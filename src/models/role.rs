use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
    pub scope_kind: String,
    pub scope_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRole {
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
    pub scope_kind: Option<String>,
    pub scope_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRole {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListRoles {
    pub tenant_id: Option<Uuid>,
    pub scope_kind: Option<String>,
    pub scope_ref: Option<String>,
    pub q: Option<String>,
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
