use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::{
    AuditOutcome, CredentialKind, CredentialStatus, Effect, EntityKind, EntityStatus, GrantKind,
    ScopeKind, SubjectKind,
};
use super::{policy::PolicyBinding, role::Role};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub id: Uuid,
    pub name: String,
    pub kind: EntityKind,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainSubject {
    pub id: Uuid,
    pub name: String,
    pub kind: EntityKind,
    pub status: EntityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    pub id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSummary {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSummary {
    pub kind: GrantKind,
    pub role: Option<RoleSummary>,
    pub capabilities: Vec<CapabilitySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessItem {
    pub resource: ResourceSummary,
    pub effect: Effect,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub policy_id: Uuid,
    pub grant: GrantSummary,
    pub conditions: Value,
    pub via: String,
}

#[derive(Debug, Serialize)]
pub struct EntityAccessResponse {
    pub entity_id: Uuid,
    pub entity_name: String,
    pub entity_kind: EntityKind,
    pub items: Vec<AccessItem>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct ResourceAccessEntity {
    pub id: Uuid,
    pub name: String,
    pub kind: EntityKind,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ResourceAccessItem {
    pub entity: ResourceAccessEntity,
    pub effect: Effect,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub policy_id: Uuid,
    pub grant: GrantSummary,
    pub conditions: Value,
    pub via: String,
}

#[derive(Debug, Serialize)]
pub struct ResourceAccessResponse {
    pub resource_id: Uuid,
    pub resource: ResourceSummary,
    pub items: Vec<ResourceAccessItem>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub member_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GroupAccessItem {
    pub resource: ResourceSummary,
    pub effect: Effect,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub policy_id: Uuid,
    pub grant: GrantSummary,
    pub conditions: Value,
}

#[derive(Debug, Serialize)]
pub struct GroupAccessResponse {
    pub group_id: Uuid,
    pub group: GroupInfo,
    pub items: Vec<GroupAccessItem>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplainCapability {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluatedBinding {
    /// The assignment that confers this grant (`direct_policies.id` /
    /// `role_assignments.id`) — identifies *which* assignment granted access.
    pub id: Uuid,
    /// The permission block backing the grant. Distinct from `id` because one
    /// shared block can back many assignments.
    pub block_id: Uuid,
    pub effect: Effect,
    pub grant_kind: GrantKind,
    pub grant_id: Uuid,
    pub role_name: Option<String>,
    pub role_path: Option<String>,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub conditions: Value,
    pub via: String,
    pub result: String,
    pub skip_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthzExplainResponse {
    pub allowed: bool,
    pub reason: String,
    pub subject: Option<ExplainSubject>,
    pub resource: Option<ResourceSummary>,
    pub capability: Option<ExplainCapability>,
    pub matched_binding: Option<EvaluatedBinding>,
    pub evaluated_bindings: Vec<EvaluatedBinding>,
}

#[derive(Debug, Deserialize)]
pub struct BulkAuthzRequest {
    pub subject_id: Uuid,
    pub resource_id: Uuid,
    pub actions: Vec<String>,
    #[serde(default)]
    pub context: Value,
}

#[derive(Debug, Serialize)]
pub struct BulkAuthzResponse {
    pub subject_id: Uuid,
    pub resource_id: Uuid,
    pub results: BTreeMap<String, BulkAuthzResult>,
}

#[derive(Debug, Serialize)]
pub struct BulkAuthzResult {
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizedObjectIdsQuery {
    pub subject_id: Uuid,
    pub action: String,
    pub object_kind: String,
    pub object_type: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub q: Option<String>,
    pub profile_id: Option<Uuid>,
    pub entity_status: Option<EntityStatus>,
    pub parent_group_id: Option<Uuid>,
    pub include_descendants: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthorizedObjectIdsResponse {
    pub ids: Vec<Uuid>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct AccessQuery {
    pub tenant_id: Option<Uuid>,
    pub resource_kind: Option<String>,
    pub action: Option<String>,
    pub effect: Option<Effect>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct ResourceAccessQuery {
    pub action: Option<String>,
    pub entity_kind: Option<EntityKind>,
    pub effect: Option<Effect>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct RoleHoldersQuery {
    pub tenant_id: Option<Uuid>,
    pub subject_kind: Option<SubjectKind>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct GroupAccessQuery {
    pub resource_kind: Option<String>,
    pub action: Option<String>,
    pub effect: Option<Effect>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct RoleWithCapabilities {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub description: Option<String>,
    pub capabilities: Vec<CapabilitySummary>,
}

#[derive(Debug, Serialize)]
pub struct RoleHolderGroup {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub member_count: i64,
}

#[derive(Debug, Serialize)]
pub struct RoleHolderItem {
    pub subject_kind: SubjectKind,
    pub entity: Option<EntitySummary>,
    pub group: Option<RoleHolderGroup>,
    pub policy_id: Uuid,
    pub effect: Effect,
    pub scope_kind: ScopeKind,
    pub scope_ref: Option<String>,
    pub conditions: Value,
}

#[derive(Debug, Serialize)]
pub struct RoleHoldersResponse {
    pub role: RoleWithCapabilities,
    pub items: Vec<RoleHolderItem>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct SubjectRoleAssignmentsQuery {
    pub tenant_id: Option<Uuid>,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub derived_kind: Option<String>,
    pub q: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubjectRoleAssignment {
    pub policy: PolicyBinding,
    pub role: Role,
}

#[derive(Debug, Serialize)]
pub struct SubjectRoleAssignmentList {
    pub items: Vec<SubjectRoleAssignment>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub event: Option<String>,
    pub outcome: Option<AuditOutcome>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditLogItem {
    pub id: Uuid,
    pub entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub event: String,
    pub outcome: AuditOutcome,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub items: Vec<AuditLogItem>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct AdminPageQuery {
    #[serde(default = "default_admin_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct UnprotectedResourcesQuery {
    pub tenant_id: Option<Uuid>,
    pub kind: Option<String>,
    #[serde(default = "default_admin_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct ExpiringCredentialsQuery {
    #[serde(default = "default_days")]
    pub days: i64,
    pub entity_id: Option<Uuid>,
    pub kind: Option<CredentialKind>,
    #[serde(default = "default_admin_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct OrphanPolicyItem {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub source_kind: String,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub role_id: Option<Uuid>,
    pub permission_block_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub orphan_reason: String,
}

#[derive(Debug, Serialize)]
pub struct OrphanPoliciesResponse {
    pub items: Vec<OrphanPolicyItem>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct UnprotectedResourceItem {
    pub id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UnprotectedResourcesResponse {
    pub items: Vec<UnprotectedResourceItem>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct ExpiringCredentialItem {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub entity_name: String,
    pub entity_kind: EntityKind,
    pub kind: CredentialKind,
    pub status: CredentialStatus,
    pub expires_at: DateTime<Utc>,
    pub days_remaining: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ExpiringCredentialsResponse {
    pub items: Vec<ExpiringCredentialItem>,
    pub total: i64,
}

fn default_limit() -> i64 {
    20
}

fn default_audit_limit() -> i64 {
    50
}

fn default_admin_limit() -> i64 {
    50
}

fn default_days() -> i64 {
    30
}
