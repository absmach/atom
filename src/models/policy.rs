use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::{Effect, GrantKind, ScopeKind, SubjectKind};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PolicyBinding {
    pub id: Uuid,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub grant_kind: GrantKind,
    pub grant_id: Uuid,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub effect: Effect,
    pub conditions: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyBinding {
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub grant_kind: GrantKind,
    pub grant_id: Uuid,
    pub scope_kind: ScopeKind,
    /// For scope_kind='resource' this is a resource UUID.
    /// For scope_kind='resource_kind' this is the kind name.
    /// For scope_kind='all' this is ignored.
    pub scope_ref: Option<String>,
    #[serde(default)]
    pub effect: Effect,
    #[serde(default)]
    pub conditions: Value,
}

#[derive(Debug, Deserialize)]
pub struct ListPolicies {
    pub subject_id: Option<Uuid>,
    pub subject_kind: Option<SubjectKind>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct PolicyList {
    pub items: Vec<PolicyBinding>,
    pub total: i64,
}

/// Authorization check request.
///
/// Two equivalent ways to identify the protected object:
/// - `resource_id`: legacy form. Resolves the object from the `resources` table
///   with kind = `resources.kind`. Backwards compatible.
/// - `object_kind` + `object_id`: explicit form. Currently supports
///   `object_kind = "resource"` (same as `resource_id`) and
///   `object_kind = "tenant"` (resolves from `tenants`, kind = `"tenant"`).
///
/// At least one form must be supplied. If both are supplied, the explicit
/// `object_kind`/`object_id` pair takes precedence.
#[derive(Debug, Deserialize)]
pub struct AuthzRequest {
    pub subject_id: Uuid,
    pub action: String,
    #[serde(default)]
    pub resource_id: Option<Uuid>,
    #[serde(default)]
    pub object_kind: Option<String>,
    #[serde(default)]
    pub object_id: Option<Uuid>,
    #[serde(default)]
    pub context: Value,
}

#[derive(Debug, Serialize)]
pub struct AuthzResponse {
    pub allowed: bool,
    pub reason: String,
}
