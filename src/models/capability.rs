use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Capability {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    /// `Some("config")` when provisioned from the bootstrap YAML. The UI
    /// uses this to render the row read-only; the API rejects update/delete
    /// with 409 conflict.
    #[sqlx(default)]
    pub managed_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CapabilityApplicability {
    pub object_kind: String,
    pub object_type: Option<String>,
    #[sqlx(default)]
    pub managed_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CapabilityApplicabilityEntry {
    pub capability_id: Uuid,
    pub capability_name: String,
    pub description: Option<String>,
    pub object_kind: String,
    pub object_type: Option<String>,
    pub created_at: DateTime<Utc>,
    #[sqlx(default)]
    pub managed_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityApplicabilityInput {
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCapability {
    pub name: String,
    pub description: Option<String>,
    pub applicability: Option<Vec<CapabilityApplicabilityInput>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCapability {
    pub name: Option<String>,
    pub description: Option<String>,
    pub applicability: Option<Vec<CapabilityApplicabilityInput>>,
}

#[derive(Debug, Deserialize)]
pub struct ListCapabilities {
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct CapabilityList {
    pub items: Vec<Capability>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct CapabilityApplicabilityList {
    pub items: Vec<CapabilityApplicabilityEntry>,
    pub total: i64,
}
