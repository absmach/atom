use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::{DeletedFilter, InvitationState, SortDir, TenantOrderField, TenantStatus};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub alias: Option<String>,
    pub status: TenantStatus,
    pub tags: Vec<String>,
    pub attributes: Value,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    /// `Some("config")` when provisioned from the bootstrap YAML. The API
    /// rejects update/restore with 409 conflict; the UI renders the row
    /// read-only.
    #[sqlx(default)]
    pub managed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenant {
    pub id: Option<Uuid>,
    pub name: String,
    pub alias: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTenant {
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::models::alias::deserialize_alias_update"
    )]
    pub alias: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListTenants {
    pub id: Option<String>,
    pub q: Option<String>,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tags: Option<String>,
    pub status: Option<TenantStatus>,
    #[serde(default)]
    pub deleted: DeletedFilter,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub order: TenantOrderField,
    #[serde(default)]
    pub dir: SortDir,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct TenantList {
    pub items: Vec<Tenant>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TenantInvitation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub invitee_user_id: Option<Uuid>,
    pub invitee_name: Option<String>,
    pub invitee_email: Option<String>,
    pub invited_by: Uuid,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub rejected_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantInvitation {
    pub invitee_user_id: Option<Uuid>,
    pub invitee_email: Option<String>,
    pub role_id: Option<Uuid>,
    #[serde(default)]
    pub resend: bool,
    pub redirect_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListTenantInvitations {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub state: Option<InvitationState>,
}

#[derive(Debug, Serialize)]
pub struct TenantInvitationList {
    pub items: Vec<TenantInvitation>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct InvitationTokenRequest {
    pub token: String,
}
