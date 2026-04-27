use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::TenantStatus;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub route: Option<String>,
    pub status: TenantStatus,
    pub tags: Vec<String>,
    pub attributes: Value,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenant {
    pub name: String,
    pub route: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTenant {
    pub name: Option<String>,
    pub route: Option<String>,
    pub tags: Option<Vec<String>>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListTenants {
    pub name: Option<String>,
    pub route: Option<String>,
    pub status: Option<TenantStatus>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct TenantList {
    pub items: Vec<Tenant>,
    pub total: i64,
}
