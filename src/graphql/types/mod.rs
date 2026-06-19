use async_graphql::{Context, Enum, InputObject, MaybeUndefined, Object, Result, ID};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    authz::repo as authz_repo,
    identity::{repo as identity_repo, service as identity_service},
    models::{
        access as access_model, action_assignment_rule as action_assignment_rule_model,
        api_endpoint as api_endpoint_model, capability as capability_model, entity as entity_model,
        enums::{
            ActionAssignmentDecision, AuditOutcome, CredentialKind, CredentialStatus, Effect,
            EntityKind, EntityStatus, GrantKind, ObjectKind, ScopeKind, SubjectKind, TenantStatus,
        },
        group as group_model, policy as policy_model, profile as profile_model,
        resource as resource_model, role as role_model, session as session_model,
        tenant as tenant_model, token as token_model,
    },
    state::AppState,
};

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "EntityKind", rename_items = "snake_case")]
pub enum GqlEntityKind {
    Human,
    Device,
    Service,
    Workload,
    Application,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "EntityStatus", rename_items = "snake_case")]
pub enum GqlEntityStatus {
    Active,
    Inactive,
    Suspended,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "TenantStatus", rename_items = "snake_case")]
pub enum GqlTenantStatus {
    Active,
    Inactive,
    Frozen,
    Deleted,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "SubjectKind", rename_items = "snake_case")]
pub enum GqlSubjectKind {
    Entity,
    Group,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "GrantKind", rename_items = "snake_case")]
pub enum GqlGrantKind {
    Capability,
    Role,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "ScopeKind", rename_items = "snake_case")]
pub enum GqlScopeKind {
    Platform,
    Tenant,
    ObjectKind,
    ObjectType,
    Object,
    GroupObjectType,
    GroupTreeObjectType,
    GroupChildKind,
    GroupDescendantKind,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "Effect", rename_items = "snake_case")]
pub enum GqlEffect {
    Allow,
    Deny,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "ActionAssignmentRuleDecision", rename_items = "snake_case")]
pub enum GqlActionAssignmentRuleDecision {
    Allow,
    Deny,
    RequireOverride,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(
    name = "CreateActionAssignmentRuleDecision",
    rename_items = "snake_case"
)]
pub enum GqlCreateActionAssignmentRuleDecision {
    Allow,
    Deny,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "CredentialKind", rename_items = "snake_case")]
pub enum GqlCredentialKind {
    Password,
    ApiKey,
    Certificate,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "AuditOutcome", rename_items = "snake_case")]
pub enum GqlAuditOutcome {
    Allow,
    Deny,
    Error,
}

pub struct Profile(pub profile_model::Profile);

#[Object]
impl Profile {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn object_kind(&self) -> &str {
        &self.0.object_kind
    }

    async fn kind(&self) -> &str {
        &self.0.kind
    }

    async fn key(&self) -> &str {
        &self.0.key
    }

    async fn display_name(&self) -> &str {
        &self.0.display_name
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn status(&self) -> &str {
        &self.0.status
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct ProfileVersion(pub profile_model::ProfileVersion);

#[Object]
impl ProfileVersion {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn profile_id(&self) -> ID {
        id(self.0.profile_id)
    }

    async fn version(&self) -> i32 {
        self.0.version
    }

    async fn json_schema(&self) -> &Value {
        &self.0.json_schema
    }

    async fn ui_schema(&self) -> &Value {
        &self.0.ui_schema
    }

    async fn status(&self) -> &str {
        &self.0.status
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct Entity(pub entity_model::Entity);

#[Object]
impl Entity {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn kind(&self) -> GqlEntityKind {
        GqlEntityKind::from(&self.0.kind)
    }

    async fn profile_id(&self) -> Option<ID> {
        self.0.profile_id.map(id)
    }

    async fn profile_version_id(&self) -> Option<ID> {
        self.0.profile_version_id.map(id)
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn alias(&self) -> Option<&str> {
        self.0.alias.as_deref()
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn parent_group_id(&self, ctx: &Context<'_>) -> Result<Option<ID>> {
        let state = ctx.data::<AppState>()?;
        identity_repo::get_entity_parent_group(&state.pool, self.0.id)
            .await
            .map(|parent_id| parent_id.map(id))
            .map_err(|err| async_graphql::Error::new(err.to_string()))
    }

    async fn status(&self) -> GqlEntityStatus {
        GqlEntityStatus::from(&self.0.status)
    }

    async fn attributes(&self) -> &Value {
        &self.0.attributes
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct Session(pub session_model::Session);

#[Object]
impl Session {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn entity_id(&self) -> ID {
        id(self.0.entity_id)
    }

    async fn expires_at(&self) -> String {
        timestamp(self.0.expires_at)
    }

    async fn revoked_at(&self) -> Option<String> {
        self.0.revoked_at.map(timestamp)
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct SignupResponse(pub session_model::SignupResponse);

#[Object]
impl SignupResponse {
    async fn entity_id(&self) -> ID {
        id(self.0.entity_id)
    }

    async fn email(&self) -> &str {
        &self.0.email
    }

    async fn verification_required(&self) -> bool {
        self.0.verification_required
    }
}

pub struct LoginResponse(pub session_model::LoginResponse);

#[Object]
impl LoginResponse {
    async fn token(&self) -> &str {
        &self.0.token
    }

    async fn entity_id(&self) -> ID {
        id(self.0.entity_id)
    }

    async fn session_id(&self) -> ID {
        id(self.0.session_id)
    }

    async fn expires_at(&self) -> String {
        timestamp(self.0.expires_at)
    }

    async fn email_verified(&self) -> Option<bool> {
        self.0.email_verified
    }

    async fn verification_required(&self) -> bool {
        self.0.verification_required
    }
}

pub struct Tenant(pub tenant_model::Tenant);

#[Object]
impl Tenant {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn alias(&self) -> Option<&str> {
        self.0.alias.as_deref()
    }

    async fn status(&self) -> GqlTenantStatus {
        GqlTenantStatus::from(&self.0.status)
    }

    async fn tags(&self) -> &[String] {
        &self.0.tags
    }

    async fn attributes(&self) -> &Value {
        &self.0.attributes
    }

    async fn created_by(&self) -> Option<ID> {
        self.0.created_by.map(id)
    }

    async fn updated_by(&self) -> Option<ID> {
        self.0.updated_by.map(id)
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct TenantInvitation(pub tenant_model::TenantInvitation);

#[Object]
impl TenantInvitation {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> ID {
        id(self.0.tenant_id)
    }

    async fn invitee_user_id(&self) -> Option<ID> {
        self.0.invitee_user_id.map(id)
    }

    async fn invitee_email(&self) -> Option<&str> {
        self.0.invitee_email.as_deref()
    }

    async fn invited_by(&self) -> ID {
        id(self.0.invited_by)
    }

    async fn role_id(&self) -> Option<ID> {
        self.0.role_id.map(id)
    }

    async fn role_name(&self) -> Option<&str> {
        self.0.role_name.as_deref()
    }

    async fn accepted_at(&self) -> Option<String> {
        self.0.accepted_at.map(timestamp)
    }

    async fn rejected_at(&self) -> Option<String> {
        self.0.rejected_at.map(timestamp)
    }

    async fn revoked_at(&self) -> Option<String> {
        self.0.revoked_at.map(timestamp)
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct Resource(pub resource_model::Resource);

#[Object]
impl Resource {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn kind(&self) -> &str {
        &self.0.kind
    }

    async fn name(&self) -> Option<&str> {
        self.0.name.as_deref()
    }

    async fn alias(&self) -> Option<&str> {
        self.0.alias.as_deref()
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn owner_id(&self) -> Option<ID> {
        self.0.owner_id.map(id)
    }

    async fn parent_group_id(&self, ctx: &Context<'_>) -> Result<Option<ID>> {
        let state = ctx.data::<AppState>()?;
        authz_repo::get_resource_parent_group(&state.pool, self.0.id)
            .await
            .map(|parent_id| parent_id.map(id))
            .map_err(|err| async_graphql::Error::new(err.to_string()))
    }

    async fn attributes(&self) -> &Value {
        &self.0.attributes
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct ApiEndpoint(pub api_endpoint_model::ApiEndpoint);

#[Object]
impl ApiEndpoint {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn key(&self) -> &str {
        &self.0.key
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn method(&self) -> &str {
        &self.0.method
    }

    async fn path(&self) -> &str {
        &self.0.path
    }

    async fn operation_kind(&self) -> &str {
        &self.0.operation_kind
    }

    async fn graphql(&self) -> &str {
        &self.0.graphql
    }

    async fn auth_mode(&self) -> &str {
        &self.0.auth_mode
    }

    async fn service_entity_id(&self) -> Option<ID> {
        self.0.service_entity_id.map(id)
    }

    async fn variables_mapping(&self) -> &Value {
        &self.0.variables_mapping
    }

    async fn request_schema(&self) -> &Value {
        &self.0.request_schema
    }

    async fn response_mapping(&self) -> &Value {
        &self.0.response_mapping
    }

    async fn status(&self) -> &str {
        &self.0.status
    }

    async fn created_by(&self) -> Option<ID> {
        self.0.created_by.map(id)
    }

    async fn updated_by(&self) -> Option<ID> {
        self.0.updated_by.map(id)
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct ApiEndpointExecution(pub api_endpoint_model::ApiEndpointExecution);

#[Object]
impl ApiEndpointExecution {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn endpoint_id(&self) -> Option<ID> {
        self.0.endpoint_id.map(id)
    }

    async fn caller_entity_id(&self) -> Option<ID> {
        self.0.caller_entity_id.map(id)
    }

    async fn status(&self) -> &str {
        &self.0.status
    }

    async fn request_summary(&self) -> &Value {
        &self.0.request_summary
    }

    async fn response_summary(&self) -> &Value {
        &self.0.response_summary
    }

    async fn error(&self) -> Option<&str> {
        self.0.error.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct Group(pub group_model::Group);

#[Object]
impl Group {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn group_type(&self) -> &str {
        &self.0.group_type
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn parent_id(&self) -> Option<ID> {
        self.0.parent_id.map(id)
    }

    async fn status(&self) -> GqlEntityStatus {
        GqlEntityStatus::from(&self.0.status)
    }

    async fn attributes(&self) -> &Value {
        &self.0.attributes
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct Credential(pub CredentialData);

pub struct CredentialData {
    pub id: Uuid,
    pub entity_id: Option<Uuid>,
    pub kind: CredentialKind,
    pub identifier: Option<String>,
    pub status: CredentialStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[Object]
impl Credential {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn entity_id(&self) -> Option<ID> {
        self.0.entity_id.map(id)
    }

    async fn kind(&self) -> GqlCredentialKind {
        GqlCredentialKind::from(&self.0.kind)
    }

    async fn identifier(&self) -> Option<&str> {
        self.0.identifier.as_deref()
    }

    async fn status(&self) -> &'static str {
        credential_status_as_str(&self.0.status)
    }

    async fn expires_at(&self) -> Option<String> {
        self.0.expires_at.map(timestamp)
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct ApiKeyResponse(pub token_model::ApiKeyResponse);

#[Object]
impl ApiKeyResponse {
    async fn credential_id(&self) -> ID {
        id(self.0.credential_id)
    }

    async fn key(&self) -> &str {
        &self.0.key
    }

    async fn expires_at(&self) -> Option<String> {
        self.0.expires_at.map(timestamp)
    }
}

pub struct Ownership(pub entity_model::Ownership);

#[Object]
impl Ownership {
    async fn owner_id(&self) -> ID {
        id(self.0.owner_id)
    }

    async fn owned_id(&self) -> ID {
        id(self.0.owned_id)
    }

    async fn relation(&self) -> &str {
        &self.0.relation
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct Role(pub role_model::Role);

#[Object]
impl Role {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn derived_kind(&self, ctx: &Context<'_>) -> Result<String> {
        let state = ctx.data::<AppState>()?;
        let kind = authz_repo::role_derived_kind(&state.pool, self.0.id)
            .await
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;
        Ok(match kind {
            role_model::RoleDerivedKind::Simple => "simple".to_string(),
            role_model::RoleDerivedKind::Composite => "composite".to_string(),
            role_model::RoleDerivedKind::Empty => "empty".to_string(),
        })
    }

    async fn permission_blocks(&self, ctx: &Context<'_>) -> Result<Vec<PermissionBlock>> {
        let state = ctx.data::<AppState>()?;
        let blocks = authz_repo::list_permission_blocks_for_role(&state.pool, self.0.id)
            .await
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;
        Ok(blocks.into_iter().map(PermissionBlock::from).collect())
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct RolePermissionBlock(pub role_model::RolePermissionBlock);

#[Object]
impl RolePermissionBlock {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn role_id(&self) -> ID {
        id(self.0.role_id)
    }

    async fn applies_to(&self) -> &str {
        &self.0.applies_to
    }

    async fn object_id(&self) -> Option<ID> {
        self.0.object_id.map(id)
    }

    async fn object_kind(&self) -> Option<&str> {
        self.0.object_kind.as_deref()
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn group_id(&self) -> Option<ID> {
        self.0.group_id.map(id)
    }

    async fn actions(&self, ctx: &Context<'_>) -> Result<Vec<Action>> {
        let state = ctx.data::<AppState>()?;
        let actions = authz_repo::role_permission_block_capabilities(&state.pool, self.0.id)
            .await
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;
        Ok(actions.into_iter().map(Action::from).collect())
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
    }
}

impl From<role_model::RolePermissionBlock> for RolePermissionBlock {
    fn from(block: role_model::RolePermissionBlock) -> Self {
        Self(block)
    }
}

pub struct Capability(pub capability_model::Capability);

#[Object]
impl Capability {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn applicability(&self, ctx: &Context<'_>) -> Result<Vec<CapabilityApplicability>> {
        let state = ctx.data::<AppState>()?;
        let applicability = authz_repo::capability_applicability(&state.pool, self.0.id).await?;
        Ok(applicability
            .into_iter()
            .map(CapabilityApplicability)
            .collect())
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct Action(pub capability_model::Capability);

#[Object]
impl Action {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn name(&self) -> &str {
        &self.0.name
    }

    async fn applicability(&self, ctx: &Context<'_>) -> Result<Vec<ActionApplicability>> {
        let state = ctx.data::<AppState>()?;
        let applicability = authz_repo::capability_applicability(&state.pool, self.0.id).await?;
        Ok(applicability.into_iter().map(ActionApplicability).collect())
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> Option<String> {
        self.0.updated_at.map(timestamp)
    }
}

pub struct ActionApplicability(pub capability_model::CapabilityApplicability);

#[Object]
impl ActionApplicability {
    async fn object_kind(&self) -> &str {
        &self.0.object_kind
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }
}

pub struct ActionApplicabilityEntry(pub capability_model::CapabilityApplicabilityEntry);

#[Object]
impl ActionApplicabilityEntry {
    async fn id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.0.capability_id,
            self.0.object_kind,
            self.0.object_type.as_deref().unwrap_or("")
        )
    }

    async fn action_id(&self) -> ID {
        id(self.0.capability_id)
    }

    async fn action_name(&self) -> &str {
        &self.0.capability_name
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn object_kind(&self) -> &str {
        &self.0.object_kind
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct ActionAssignmentRule(pub action_assignment_rule_model::ActionAssignmentRule);

#[Object]
impl ActionAssignmentRule {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn entity_kind(&self) -> GqlEntityKind {
        GqlEntityKind::from(&self.0.entity_kind)
    }

    async fn action_name(&self) -> &str {
        &self.0.action_name
    }

    async fn object_kind(&self) -> &str {
        self.0.object_kind.as_str()
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }

    async fn decision(&self) -> GqlActionAssignmentRuleDecision {
        GqlActionAssignmentRuleDecision::from(self.0.decision)
    }

    async fn is_absolute(&self) -> bool {
        self.0.is_absolute
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct CapabilityApplicability(pub capability_model::CapabilityApplicability);

#[Object]
impl CapabilityApplicability {
    async fn object_kind(&self) -> &str {
        &self.0.object_kind
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }
}

pub struct CapabilityApplicabilityEntry(pub capability_model::CapabilityApplicabilityEntry);

#[Object]
impl CapabilityApplicabilityEntry {
    async fn id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.0.capability_id,
            self.0.object_kind,
            self.0.object_type.as_deref().unwrap_or("")
        )
    }

    async fn capability_id(&self) -> ID {
        id(self.0.capability_id)
    }

    async fn capability_name(&self) -> &str {
        &self.0.capability_name
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn object_kind(&self) -> &str {
        &self.0.object_kind
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

#[derive(Default)]
pub struct CapabilityApplicabilityList {
    pub items: Vec<CapabilityApplicabilityEntry>,
    pub total: i64,
}

#[Object]
impl CapabilityApplicabilityList {
    async fn items(&self) -> &[CapabilityApplicabilityEntry] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

pub struct PolicyBinding(pub PolicyBindingData);

pub struct PolicyBindingData {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
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

#[Object]
impl PolicyBinding {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn subject_kind(&self) -> GqlSubjectKind {
        GqlSubjectKind::from(&self.0.subject_kind)
    }

    async fn subject_id(&self) -> ID {
        id(self.0.subject_id)
    }

    async fn grant_kind(&self) -> GqlGrantKind {
        GqlGrantKind::from(&self.0.grant_kind)
    }

    async fn grant_id(&self) -> ID {
        id(self.0.grant_id)
    }

    async fn scope_kind(&self) -> GqlScopeKind {
        GqlScopeKind::from(&self.0.scope_kind)
    }

    async fn scope_ref(&self) -> Option<&str> {
        self.0.scope_ref.as_deref()
    }

    async fn effect(&self) -> GqlEffect {
        GqlEffect::from(&self.0.effect)
    }

    async fn conditions(&self) -> &Value {
        &self.0.conditions
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct PermissionBlock(pub policy_model::PermissionBlock);

#[Object]
impl PermissionBlock {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn scope_mode(&self) -> &str {
        &self.0.scope_mode
    }

    async fn object_kind(&self) -> Option<&str> {
        self.0.object_kind.as_deref()
    }

    async fn object_type(&self) -> Option<&str> {
        self.0.object_type.as_deref()
    }

    async fn object_id(&self) -> Option<ID> {
        self.0.object_id.map(id)
    }

    async fn group_id(&self) -> Option<ID> {
        self.0.group_id.map(id)
    }

    async fn effect(&self) -> GqlEffect {
        GqlEffect::from(&self.0.effect)
    }

    async fn conditions(&self) -> &Value {
        &self.0.conditions
    }

    async fn actions(&self, ctx: &Context<'_>) -> Result<Vec<Action>> {
        let state = ctx.data::<AppState>()?;
        let actions = authz_repo::permission_block_capabilities(&state.pool, self.0.id)
            .await
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;
        Ok(actions.into_iter().map(Action::from).collect())
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
    }
}

impl From<policy_model::PermissionBlock> for PermissionBlock {
    fn from(block: policy_model::PermissionBlock) -> Self {
        Self(block)
    }
}

pub struct RoleAssignment(pub policy_model::RoleAssignment);

#[Object]
impl RoleAssignment {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn subject_kind(&self) -> GqlSubjectKind {
        GqlSubjectKind::from(&self.0.subject_kind)
    }

    async fn subject_id(&self) -> ID {
        id(self.0.subject_id)
    }

    async fn role_id(&self) -> ID {
        id(self.0.role_id)
    }

    async fn role(&self, ctx: &Context<'_>) -> Result<Role> {
        let state = ctx.data::<AppState>()?;
        let role = authz_repo::get_role(&state.pool, self.0.role_id)
            .await
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;
        Ok(role.into())
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

impl From<policy_model::RoleAssignment> for RoleAssignment {
    fn from(assignment: policy_model::RoleAssignment) -> Self {
        Self(assignment)
    }
}

pub struct DirectPolicy(pub policy_model::DirectPolicy);

#[Object]
impl DirectPolicy {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn subject_kind(&self) -> GqlSubjectKind {
        GqlSubjectKind::from(&self.0.subject_kind)
    }

    async fn subject_id(&self) -> ID {
        id(self.0.subject_id)
    }

    async fn permission_block_id(&self) -> ID {
        id(self.0.permission_block_id)
    }

    async fn permission_block(&self, ctx: &Context<'_>) -> Result<PermissionBlock> {
        let state = ctx.data::<AppState>()?;
        let block = authz_repo::get_permission_block(&state.pool, self.0.permission_block_id)
            .await
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;
        Ok(block.into())
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

impl From<policy_model::DirectPolicy> for DirectPolicy {
    fn from(policy: policy_model::DirectPolicy) -> Self {
        Self(policy)
    }
}

pub struct AuthzResponse(pub crate::models::policy::AuthzResponse);

#[Object]
impl AuthzResponse {
    async fn allowed(&self) -> bool {
        self.0.allowed
    }

    async fn reason(&self) -> &str {
        &self.0.reason
    }

    async fn details(&self) -> Option<&Value> {
        self.0.details.as_ref()
    }
}

pub struct AuthzExplainResponse {
    pub allowed: bool,
    pub reason: String,
    pub subject: Option<Value>,
    pub resource: Option<Value>,
    pub capability: Option<Value>,
    pub matched_binding: Option<Value>,
    pub evaluated_bindings: Value,
}

#[Object]
impl AuthzExplainResponse {
    async fn allowed(&self) -> bool {
        self.allowed
    }

    async fn reason(&self) -> &str {
        &self.reason
    }

    async fn subject(&self) -> Option<&Value> {
        self.subject.as_ref()
    }

    async fn resource(&self) -> Option<&Value> {
        self.resource.as_ref()
    }

    async fn capability(&self) -> Option<&Value> {
        self.capability.as_ref()
    }

    async fn matched_binding(&self) -> Option<&Value> {
        self.matched_binding.as_ref()
    }

    async fn evaluated_bindings(&self) -> &Value {
        &self.evaluated_bindings
    }
}

pub struct AuditLog(pub access_model::AuditLogItem);

#[Object]
impl AuditLog {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn entity_id(&self) -> Option<ID> {
        self.0.entity_id.map(id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn event(&self) -> &str {
        &self.0.event
    }

    async fn outcome(&self) -> GqlAuditOutcome {
        GqlAuditOutcome::from(&self.0.outcome)
    }

    async fn details(&self) -> &Value {
        &self.0.details
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

pub struct OrphanPolicy(pub access_model::OrphanPolicyItem);

#[Object]
impl OrphanPolicy {
    async fn id(&self) -> ID {
        id(self.0.id)
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn source_kind(&self) -> &str {
        &self.0.source_kind
    }

    async fn subject_kind(&self) -> GqlSubjectKind {
        GqlSubjectKind::from(&self.0.subject_kind)
    }

    async fn subject_id(&self) -> ID {
        id(self.0.subject_id)
    }

    async fn role_id(&self) -> Option<ID> {
        self.0.role_id.map(id)
    }

    async fn permission_block_id(&self) -> Option<ID> {
        self.0.permission_block_id.map(id)
    }

    async fn orphan_reason(&self) -> &str {
        &self.0.orphan_reason
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }
}

impl From<access_model::OrphanPolicyItem> for OrphanPolicy {
    fn from(policy: access_model::OrphanPolicyItem) -> Self {
        Self(policy)
    }
}

#[derive(InputObject)]
pub struct LoginInput {
    pub identifier: String,
    pub secret: String,
    pub tenant_id: Option<ID>,
    pub tenant_alias: Option<String>,
    #[graphql(default = "password")]
    pub kind: String,
}

#[derive(InputObject)]
pub struct SignupInput {
    pub name: String,
    pub email: String,
    pub password: String,
    #[graphql(default)]
    pub attributes: async_graphql::Json<serde_json::Value>,
}

#[derive(InputObject)]
pub struct CreateProfileInput {
    pub tenant_id: Option<ID>,
    pub object_kind: String,
    pub kind: String,
    pub key: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: Option<String>,
}

#[derive(InputObject)]
pub struct CreateProfileVersionInput {
    pub version: i32,
    pub json_schema: Option<Value>,
    pub ui_schema: Option<Value>,
    pub status: Option<String>,
}

#[derive(InputObject)]
pub struct UpdateProfileInput {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
}

#[derive(InputObject)]
pub struct CreateEntityInput {
    pub id: Option<ID>,
    pub profile_id: Option<ID>,
    pub profile_version_id: Option<ID>,
    pub kind: Option<GqlEntityKind>,
    pub name: String,
    pub alias: Option<String>,
    pub tenant_id: Option<ID>,
    pub attributes: Value,
}

#[derive(InputObject)]
pub struct UpdateEntityInput {
    pub name: Option<String>,
    pub kind: Option<GqlEntityKind>,
    pub alias: MaybeUndefined<String>,
    pub tenant_id: Option<ID>,
    pub profile_id: Option<ID>,
    pub profile_version_id: Option<ID>,
    pub status: Option<GqlEntityStatus>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct CreateTenantInput {
    pub id: Option<ID>,
    pub name: String,
    pub alias: Option<String>,
    pub tags: Option<Vec<String>>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct UpdateTenantInput {
    pub name: Option<String>,
    pub alias: MaybeUndefined<String>,
    pub tags: Option<Vec<String>>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct CreateTenantInvitationInput {
    pub invitee_user_id: Option<ID>,
    pub invitee_email: Option<String>,
    pub role_id: Option<ID>,
    pub resend: Option<bool>,
    pub redirect_url: Option<String>,
}

#[derive(InputObject)]
pub struct InvitationTokenInput {
    pub token: String,
}

#[derive(InputObject)]
pub struct CreateResourceInput {
    pub id: Option<ID>,
    pub kind: String,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tenant_id: Option<ID>,
    pub owner_id: Option<ID>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct UpdateResourceInput {
    pub name: Option<String>,
    pub alias: MaybeUndefined<String>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct CreateApiEndpointInput {
    pub tenant_id: Option<ID>,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub method: String,
    pub path: String,
    pub operation_kind: String,
    pub graphql: String,
    pub auth_mode: Option<String>,
    pub service_entity_id: Option<ID>,
    pub variables_mapping: Option<Value>,
    pub request_schema: Option<Value>,
    pub response_mapping: Option<Value>,
    pub status: Option<String>,
}

#[derive(InputObject)]
pub struct UpdateApiEndpointInput {
    pub key: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub operation_kind: Option<String>,
    pub graphql: Option<String>,
    pub auth_mode: Option<String>,
    pub service_entity_id: Option<ID>,
    pub variables_mapping: Option<Value>,
    pub request_schema: Option<Value>,
    pub response_mapping: Option<Value>,
    pub status: Option<String>,
}

#[derive(InputObject)]
pub struct CreateGroupInput {
    pub id: Option<ID>,
    pub name: String,
    pub tenant_id: Option<ID>,
    pub group_type: Option<String>,
    pub description: Option<String>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct UpdateGroupInput {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<GqlEntityStatus>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct CreateApiKeyInput {
    pub expires_at: Option<String>,
    pub description: Option<String>,
}

#[derive(InputObject)]
pub struct CreateRoleInput {
    pub name: String,
    pub tenant_id: Option<ID>,
    pub description: Option<String>,
}

#[derive(InputObject)]
pub struct CreateRolePermissionBlockInput {
    pub applies_to: String,
    pub object_id: Option<ID>,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub tenant_id: Option<ID>,
    pub group_id: Option<ID>,
    pub capability_ids: Vec<ID>,
}

#[derive(InputObject)]
pub struct UpdateRoleInput {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(InputObject)]
pub struct CreateCapabilityInput {
    pub name: String,
    pub description: Option<String>,
    pub applicability: Option<Vec<CapabilityApplicabilityInput>>,
}

#[derive(InputObject)]
pub struct UpdateCapabilityInput {
    pub name: Option<String>,
    pub description: Option<String>,
    pub applicability: Option<Vec<CapabilityApplicabilityInput>>,
}

#[derive(InputObject)]
pub struct CapabilityApplicabilityInput {
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(InputObject)]
pub struct AddCapabilityApplicabilityInput {
    pub capability_id: ID,
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(InputObject)]
pub struct RemoveCapabilityApplicabilityInput {
    pub capability_id: ID,
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(InputObject)]
pub struct CreateActionInput {
    pub name: String,
    pub description: Option<String>,
    pub applicability: Option<Vec<ActionApplicabilityInput>>,
}

#[derive(InputObject)]
pub struct UpdateActionInput {
    pub name: Option<String>,
    pub description: Option<String>,
    pub applicability: Option<Vec<ActionApplicabilityInput>>,
}

#[derive(InputObject)]
pub struct ActionApplicabilityInput {
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(InputObject)]
pub struct AddActionApplicabilityInput {
    pub action_id: ID,
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(InputObject)]
pub struct RemoveActionApplicabilityInput {
    pub action_id: ID,
    pub object_kind: String,
    pub object_type: Option<String>,
}

#[derive(InputObject)]
pub struct CreateActionAssignmentRuleInput {
    pub tenant_id: Option<ID>,
    pub entity_kind: GqlEntityKind,
    pub action_name: String,
    pub object_kind: String,
    pub object_type: Option<String>,
    pub decision: GqlCreateActionAssignmentRuleDecision,
    pub is_absolute: Option<bool>,
}

#[derive(InputObject)]
pub struct CreatePolicyInput {
    pub tenant_id: Option<ID>,
    pub subject_kind: GqlSubjectKind,
    pub subject_id: ID,
    pub grant_kind: GqlGrantKind,
    pub grant_id: ID,
    pub scope_kind: GqlScopeKind,
    pub scope_ref: Option<String>,
    pub effect: Option<GqlEffect>,
    pub conditions: Option<Value>,
}

#[derive(InputObject)]
pub struct CreatePermissionBlockInput {
    pub tenant_id: Option<ID>,
    pub scope_mode: String,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<ID>,
    pub group_id: Option<ID>,
    pub effect: Option<GqlEffect>,
    pub conditions: Option<Value>,
    pub action_ids: Vec<ID>,
}

#[derive(InputObject)]
pub struct CreateRoleAssignmentInput {
    pub tenant_id: Option<ID>,
    pub subject_kind: GqlSubjectKind,
    pub subject_id: ID,
    pub role_id: ID,
}

#[derive(InputObject)]
pub struct CreateDirectPolicyInput {
    pub tenant_id: Option<ID>,
    pub subject_kind: GqlSubjectKind,
    pub subject_id: ID,
    pub permission_block_id: ID,
}

#[derive(InputObject)]
pub struct AuthzCheckInput {
    pub subject_id: ID,
    pub action: String,
    pub resource_id: Option<ID>,
    pub object_kind: Option<String>,
    pub object_id: Option<ID>,
    pub context: Option<Value>,
}

#[derive(Default)]
pub struct ProfileList {
    pub items: Vec<Profile>,
    pub total: i64,
}

#[Object]
impl ProfileList {
    async fn items(&self) -> &[Profile] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct EntityList {
    pub items: Vec<Entity>,
    pub total: i64,
}

#[Object]
impl EntityList {
    async fn items(&self) -> &[Entity] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct TenantList {
    pub items: Vec<Tenant>,
    pub total: i64,
}

#[Object]
impl TenantList {
    async fn items(&self) -> &[Tenant] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct TenantInvitationList {
    pub items: Vec<TenantInvitation>,
    pub total: i64,
}

#[Object]
impl TenantInvitationList {
    async fn items(&self) -> &[TenantInvitation] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct ResourceList {
    pub items: Vec<Resource>,
    pub total: i64,
}

#[Object]
impl ResourceList {
    async fn items(&self) -> &[Resource] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct ApiEndpointList {
    pub items: Vec<ApiEndpoint>,
    pub total: i64,
}

#[Object]
impl ApiEndpointList {
    async fn items(&self) -> &[ApiEndpoint] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct ApiEndpointExecutionList {
    pub items: Vec<ApiEndpointExecution>,
    pub total: i64,
}

#[Object]
impl ApiEndpointExecutionList {
    async fn items(&self) -> &[ApiEndpointExecution] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct GroupList {
    pub items: Vec<Group>,
    pub total: i64,
}

#[Object]
impl GroupList {
    async fn items(&self) -> &[Group] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct CredentialList {
    pub items: Vec<Credential>,
    pub total: i64,
}

#[derive(Default)]
pub struct RoleList {
    pub items: Vec<Role>,
    pub total: i64,
}

#[Object]
impl RoleList {
    async fn items(&self) -> &[Role] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct CapabilityList {
    pub items: Vec<Capability>,
    pub total: i64,
}

#[Object]
impl CapabilityList {
    async fn items(&self) -> &[Capability] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct ActionList {
    pub items: Vec<Action>,
    pub total: i64,
}

#[Object]
impl ActionList {
    async fn items(&self) -> &[Action] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct ActionApplicabilityList {
    pub items: Vec<ActionApplicabilityEntry>,
    pub total: i64,
}

#[Object]
impl ActionApplicabilityList {
    async fn items(&self) -> &[ActionApplicabilityEntry] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct ActionAssignmentRuleList {
    pub items: Vec<ActionAssignmentRule>,
    pub total: i64,
}

#[Object]
impl ActionAssignmentRuleList {
    async fn items(&self) -> &[ActionAssignmentRule] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct PolicyBindingList {
    pub items: Vec<PolicyBinding>,
    pub total: i64,
}

#[Object]
impl PolicyBindingList {
    async fn items(&self) -> &[PolicyBinding] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct PermissionBlockList {
    pub items: Vec<PermissionBlock>,
    pub total: i64,
}

#[Object]
impl PermissionBlockList {
    async fn items(&self) -> &[PermissionBlock] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct RoleAssignmentList {
    pub items: Vec<RoleAssignment>,
    pub total: i64,
}

#[Object]
impl RoleAssignmentList {
    async fn items(&self) -> &[RoleAssignment] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct DirectPolicyList {
    pub items: Vec<DirectPolicy>,
    pub total: i64,
}

#[Object]
impl DirectPolicyList {
    async fn items(&self) -> &[DirectPolicy] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

pub struct SubjectRoleAssignment(pub access_model::SubjectRoleAssignment);

#[Object]
impl SubjectRoleAssignment {
    async fn policy(&self) -> PolicyBinding {
        self.0.policy.clone().into()
    }

    async fn role(&self) -> Role {
        self.0.role.clone().into()
    }
}

impl From<access_model::SubjectRoleAssignment> for SubjectRoleAssignment {
    fn from(assignment: access_model::SubjectRoleAssignment) -> Self {
        Self(assignment)
    }
}

#[derive(Default)]
pub struct SubjectRoleAssignmentList {
    pub items: Vec<SubjectRoleAssignment>,
    pub total: i64,
}

#[Object]
impl SubjectRoleAssignmentList {
    async fn items(&self) -> &[SubjectRoleAssignment] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[derive(Default)]
pub struct AuthorizedObjectIdList {
    pub ids: Vec<ID>,
    pub total: i64,
}

#[derive(InputObject)]
pub struct AuthorizedObjectIdsInput {
    pub subject_id: ID,
    pub action: String,
    pub object_kind: String,
    pub object_type: Option<String>,
    pub tenant_id: Option<ID>,
    pub q: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[Object]
impl AuthorizedObjectIdList {
    async fn ids(&self) -> &[ID] {
        &self.ids
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

impl From<access_model::AuthorizedObjectIdsResponse> for AuthorizedObjectIdList {
    fn from(response: access_model::AuthorizedObjectIdsResponse) -> Self {
        Self {
            ids: response.ids.into_iter().map(id).collect(),
            total: response.total,
        }
    }
}

#[derive(Default)]
pub struct AuditLogList {
    pub items: Vec<AuditLog>,
    pub total: i64,
}

#[Object]
impl AuditLogList {
    async fn items(&self) -> &[AuditLog] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

#[Object]
impl CredentialList {
    async fn items(&self) -> &[Credential] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

impl From<profile_model::Profile> for Profile {
    fn from(profile: profile_model::Profile) -> Self {
        Profile(profile)
    }
}

impl From<profile_model::ProfileVersion> for ProfileVersion {
    fn from(version: profile_model::ProfileVersion) -> Self {
        ProfileVersion(version)
    }
}

impl From<entity_model::Entity> for Entity {
    fn from(entity: entity_model::Entity) -> Self {
        Entity(entity)
    }
}

impl From<session_model::Session> for Session {
    fn from(session: session_model::Session) -> Self {
        Session(session)
    }
}

impl From<session_model::SignupResponse> for SignupResponse {
    fn from(response: session_model::SignupResponse) -> Self {
        SignupResponse(response)
    }
}

impl From<session_model::LoginResponse> for LoginResponse {
    fn from(response: session_model::LoginResponse) -> Self {
        LoginResponse(response)
    }
}

impl From<tenant_model::Tenant> for Tenant {
    fn from(tenant: tenant_model::Tenant) -> Self {
        Tenant(tenant)
    }
}

impl From<tenant_model::TenantInvitation> for TenantInvitation {
    fn from(invitation: tenant_model::TenantInvitation) -> Self {
        TenantInvitation(invitation)
    }
}

impl From<resource_model::Resource> for Resource {
    fn from(resource: resource_model::Resource) -> Self {
        Resource(resource)
    }
}

impl From<api_endpoint_model::ApiEndpoint> for ApiEndpoint {
    fn from(endpoint: api_endpoint_model::ApiEndpoint) -> Self {
        ApiEndpoint(endpoint)
    }
}

impl From<api_endpoint_model::ApiEndpointExecution> for ApiEndpointExecution {
    fn from(execution: api_endpoint_model::ApiEndpointExecution) -> Self {
        ApiEndpointExecution(execution)
    }
}

impl From<group_model::Group> for Group {
    fn from(group: group_model::Group) -> Self {
        Group(group)
    }
}

impl From<identity_service::CredentialSummary> for Credential {
    fn from(credential: identity_service::CredentialSummary) -> Self {
        Credential(CredentialData {
            id: credential.id,
            entity_id: None,
            kind: credential.kind,
            identifier: credential.identifier,
            status: credential.status,
            expires_at: credential.expires_at,
            created_at: credential.created_at,
        })
    }
}

impl From<token_model::ApiKeyResponse> for ApiKeyResponse {
    fn from(response: token_model::ApiKeyResponse) -> Self {
        ApiKeyResponse(response)
    }
}

impl From<entity_model::Ownership> for Ownership {
    fn from(ownership: entity_model::Ownership) -> Self {
        Ownership(ownership)
    }
}

impl From<role_model::Role> for Role {
    fn from(role: role_model::Role) -> Self {
        Role(role)
    }
}

impl From<capability_model::Capability> for Capability {
    fn from(capability: capability_model::Capability) -> Self {
        Capability(capability)
    }
}

impl From<capability_model::Capability> for Action {
    fn from(action: capability_model::Capability) -> Self {
        Action(action)
    }
}

impl From<crate::models::policy::PolicyBinding> for PolicyBinding {
    fn from(policy: crate::models::policy::PolicyBinding) -> Self {
        PolicyBinding(PolicyBindingData {
            id: policy.id,
            tenant_id: policy.tenant_id,
            subject_kind: policy.subject_kind,
            subject_id: policy.subject_id,
            grant_kind: policy.grant_kind,
            grant_id: policy.grant_id,
            scope_kind: policy.scope_kind,
            scope_ref: policy.scope_ref,
            effect: policy.effect,
            conditions: policy.conditions,
            created_at: policy.created_at,
        })
    }
}

impl From<crate::models::policy::AuthzResponse> for AuthzResponse {
    fn from(response: crate::models::policy::AuthzResponse) -> Self {
        AuthzResponse(response)
    }
}

impl From<access_model::AuthzExplainResponse> for AuthzExplainResponse {
    fn from(response: access_model::AuthzExplainResponse) -> Self {
        AuthzExplainResponse {
            allowed: response.allowed,
            reason: response.reason,
            subject: response
                .subject
                .map(|value| serde_json::to_value(value).unwrap_or(serde_json::Value::Null)),
            resource: response
                .resource
                .map(|value| serde_json::to_value(value).unwrap_or(serde_json::Value::Null)),
            capability: response
                .capability
                .map(|value| serde_json::to_value(value).unwrap_or(serde_json::Value::Null)),
            matched_binding: response
                .matched_binding
                .map(|value| serde_json::to_value(value).unwrap_or(serde_json::Value::Null)),
            evaluated_bindings: serde_json::to_value(response.evaluated_bindings)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }
}

impl From<access_model::AuditLogItem> for AuditLog {
    fn from(log: access_model::AuditLogItem) -> Self {
        AuditLog(log)
    }
}

impl From<access_model::ExpiringCredentialItem> for Credential {
    fn from(credential: access_model::ExpiringCredentialItem) -> Self {
        Credential(CredentialData {
            id: credential.id,
            entity_id: Some(credential.entity_id),
            kind: credential.kind,
            identifier: None,
            status: credential.status,
            expires_at: Some(credential.expires_at),
            created_at: credential.created_at,
        })
    }
}

pub fn parse_id(value: ID, name: &str) -> async_graphql::Result<Uuid> {
    value
        .as_str()
        .parse()
        .map_err(|_| async_graphql::Error::new(format!("{name} must be a UUID")))
}

pub fn parse_optional_id(value: Option<ID>, name: &str) -> async_graphql::Result<Option<Uuid>> {
    value.map(|id| parse_id(id, name)).transpose()
}

pub fn parse_optional_timestamp(
    value: Option<String>,
    name: &str,
) -> async_graphql::Result<Option<DateTime<Utc>>> {
    value
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| async_graphql::Error::new(format!("{name} must be RFC3339")))
        })
        .transpose()
}

pub fn parse_optional_entity_kind(value: Option<GqlEntityKind>) -> Option<EntityKind> {
    value.map(EntityKind::from)
}

pub fn parse_optional_entity_status(value: Option<GqlEntityStatus>) -> Option<EntityStatus> {
    value.map(EntityStatus::from)
}

pub fn parse_optional_subject_kind(value: Option<GqlSubjectKind>) -> Option<SubjectKind> {
    value.map(SubjectKind::from)
}

pub fn parse_subject_kind(value: GqlSubjectKind) -> SubjectKind {
    SubjectKind::from(value)
}

pub fn parse_grant_kind(value: GqlGrantKind) -> GrantKind {
    GrantKind::from(value)
}

pub fn parse_effect_or_default(value: Option<GqlEffect>) -> Effect {
    value.map(Effect::from).unwrap_or_default()
}

pub fn parse_optional_action_assignment_decision(
    value: Option<GqlActionAssignmentRuleDecision>,
) -> Option<ActionAssignmentDecision> {
    value.map(ActionAssignmentDecision::from)
}

pub fn parse_optional_audit_outcome(value: Option<GqlAuditOutcome>) -> Option<AuditOutcome> {
    value.map(AuditOutcome::from)
}

pub fn parse_optional_credential_kind(value: Option<GqlCredentialKind>) -> Option<CredentialKind> {
    value.map(CredentialKind::from)
}

pub fn parse_scope_kind(value: GqlScopeKind) -> ScopeKind {
    ScopeKind::from(value)
}

pub fn parse_object_kind(value: String, name: &str) -> async_graphql::Result<ObjectKind> {
    match value.as_str() {
        "entity" => Ok(ObjectKind::Entity),
        "resource" => Ok(ObjectKind::Resource),
        "group" => Ok(ObjectKind::Group),
        "tenant" => Ok(ObjectKind::Tenant),
        "role" => Ok(ObjectKind::Role),
        "policy" => Ok(ObjectKind::Policy),
        "credential" => Ok(ObjectKind::Credential),
        "audit_log" => Ok(ObjectKind::AuditLog),
        "signing_key" => Ok(ObjectKind::SigningKey),
        _ => Err(async_graphql::Error::new(format!(
            "{name} must be a valid object kind"
        ))),
    }
}

pub fn parse_optional_tenant_status(value: Option<GqlTenantStatus>) -> Option<TenantStatus> {
    value.map(TenantStatus::from)
}

impl From<GqlEntityKind> for EntityKind {
    fn from(kind: GqlEntityKind) -> Self {
        match kind {
            GqlEntityKind::Human => EntityKind::Human,
            GqlEntityKind::Device => EntityKind::Device,
            GqlEntityKind::Service => EntityKind::Service,
            GqlEntityKind::Workload => EntityKind::Workload,
            GqlEntityKind::Application => EntityKind::Application,
        }
    }
}

impl From<&EntityKind> for GqlEntityKind {
    fn from(kind: &EntityKind) -> Self {
        match kind {
            EntityKind::Human => GqlEntityKind::Human,
            EntityKind::Device => GqlEntityKind::Device,
            EntityKind::Service => GqlEntityKind::Service,
            EntityKind::Workload => GqlEntityKind::Workload,
            EntityKind::Application => GqlEntityKind::Application,
        }
    }
}

impl From<GqlEntityStatus> for EntityStatus {
    fn from(status: GqlEntityStatus) -> Self {
        match status {
            GqlEntityStatus::Active => EntityStatus::Active,
            GqlEntityStatus::Inactive => EntityStatus::Inactive,
            GqlEntityStatus::Suspended => EntityStatus::Suspended,
        }
    }
}

impl From<&EntityStatus> for GqlEntityStatus {
    fn from(status: &EntityStatus) -> Self {
        match status {
            EntityStatus::Active => GqlEntityStatus::Active,
            EntityStatus::Inactive => GqlEntityStatus::Inactive,
            EntityStatus::Suspended => GqlEntityStatus::Suspended,
        }
    }
}

impl From<GqlTenantStatus> for TenantStatus {
    fn from(status: GqlTenantStatus) -> Self {
        match status {
            GqlTenantStatus::Active => TenantStatus::Active,
            GqlTenantStatus::Inactive => TenantStatus::Inactive,
            GqlTenantStatus::Frozen => TenantStatus::Frozen,
            GqlTenantStatus::Deleted => TenantStatus::Deleted,
        }
    }
}

impl From<&TenantStatus> for GqlTenantStatus {
    fn from(status: &TenantStatus) -> Self {
        match status {
            TenantStatus::Active => GqlTenantStatus::Active,
            TenantStatus::Inactive => GqlTenantStatus::Inactive,
            TenantStatus::Frozen => GqlTenantStatus::Frozen,
            TenantStatus::Deleted => GqlTenantStatus::Deleted,
        }
    }
}

impl From<GqlSubjectKind> for SubjectKind {
    fn from(kind: GqlSubjectKind) -> Self {
        match kind {
            GqlSubjectKind::Entity => SubjectKind::Entity,
            GqlSubjectKind::Group => SubjectKind::Group,
        }
    }
}

impl From<&SubjectKind> for GqlSubjectKind {
    fn from(kind: &SubjectKind) -> Self {
        match kind {
            SubjectKind::Entity => GqlSubjectKind::Entity,
            SubjectKind::Group => GqlSubjectKind::Group,
        }
    }
}

impl From<GqlGrantKind> for GrantKind {
    fn from(kind: GqlGrantKind) -> Self {
        match kind {
            GqlGrantKind::Capability => GrantKind::Capability,
            GqlGrantKind::Role => GrantKind::Role,
        }
    }
}

impl From<&GrantKind> for GqlGrantKind {
    fn from(kind: &GrantKind) -> Self {
        match kind {
            GrantKind::Capability => GqlGrantKind::Capability,
            GrantKind::Role => GqlGrantKind::Role,
        }
    }
}

impl From<GqlScopeKind> for ScopeKind {
    fn from(kind: GqlScopeKind) -> Self {
        match kind {
            GqlScopeKind::Platform => ScopeKind::Platform,
            GqlScopeKind::Tenant => ScopeKind::Tenant,
            GqlScopeKind::ObjectKind => ScopeKind::ObjectKind,
            GqlScopeKind::ObjectType => ScopeKind::ObjectType,
            GqlScopeKind::Object => ScopeKind::Object,
            GqlScopeKind::GroupObjectType => ScopeKind::GroupObjectType,
            GqlScopeKind::GroupTreeObjectType => ScopeKind::GroupTreeObjectType,
            GqlScopeKind::GroupChildKind => ScopeKind::GroupChildKind,
            GqlScopeKind::GroupDescendantKind => ScopeKind::GroupDescendantKind,
        }
    }
}

impl From<&ScopeKind> for GqlScopeKind {
    fn from(kind: &ScopeKind) -> Self {
        match kind {
            ScopeKind::Platform => GqlScopeKind::Platform,
            ScopeKind::Tenant => GqlScopeKind::Tenant,
            ScopeKind::ObjectKind => GqlScopeKind::ObjectKind,
            ScopeKind::ObjectType => GqlScopeKind::ObjectType,
            ScopeKind::Object => GqlScopeKind::Object,
            ScopeKind::GroupObjectType => GqlScopeKind::GroupObjectType,
            ScopeKind::GroupTreeObjectType => GqlScopeKind::GroupTreeObjectType,
            ScopeKind::GroupChildKind => GqlScopeKind::GroupChildKind,
            ScopeKind::GroupDescendantKind => GqlScopeKind::GroupDescendantKind,
        }
    }
}

impl From<GqlEffect> for Effect {
    fn from(effect: GqlEffect) -> Self {
        match effect {
            GqlEffect::Allow => Effect::Allow,
            GqlEffect::Deny => Effect::Deny,
        }
    }
}

impl From<&Effect> for GqlEffect {
    fn from(effect: &Effect) -> Self {
        match effect {
            Effect::Allow => GqlEffect::Allow,
            Effect::Deny => GqlEffect::Deny,
        }
    }
}

impl From<GqlActionAssignmentRuleDecision> for ActionAssignmentDecision {
    fn from(decision: GqlActionAssignmentRuleDecision) -> Self {
        match decision {
            GqlActionAssignmentRuleDecision::Allow => ActionAssignmentDecision::Allow,
            GqlActionAssignmentRuleDecision::Deny => ActionAssignmentDecision::Deny,
            GqlActionAssignmentRuleDecision::RequireOverride => {
                ActionAssignmentDecision::RequireOverride
            }
        }
    }
}

impl From<GqlCreateActionAssignmentRuleDecision> for ActionAssignmentDecision {
    fn from(decision: GqlCreateActionAssignmentRuleDecision) -> Self {
        match decision {
            GqlCreateActionAssignmentRuleDecision::Allow => ActionAssignmentDecision::Allow,
            GqlCreateActionAssignmentRuleDecision::Deny => ActionAssignmentDecision::Deny,
        }
    }
}

impl From<ActionAssignmentDecision> for GqlActionAssignmentRuleDecision {
    fn from(decision: ActionAssignmentDecision) -> Self {
        match decision {
            ActionAssignmentDecision::Allow => GqlActionAssignmentRuleDecision::Allow,
            ActionAssignmentDecision::Deny => GqlActionAssignmentRuleDecision::Deny,
            ActionAssignmentDecision::RequireOverride => {
                GqlActionAssignmentRuleDecision::RequireOverride
            }
        }
    }
}

impl From<GqlAuditOutcome> for AuditOutcome {
    fn from(outcome: GqlAuditOutcome) -> Self {
        match outcome {
            GqlAuditOutcome::Allow => AuditOutcome::Allow,
            GqlAuditOutcome::Deny => AuditOutcome::Deny,
            GqlAuditOutcome::Error => AuditOutcome::Error,
        }
    }
}

impl From<&AuditOutcome> for GqlAuditOutcome {
    fn from(outcome: &AuditOutcome) -> Self {
        match outcome {
            AuditOutcome::Allow => GqlAuditOutcome::Allow,
            AuditOutcome::Deny => GqlAuditOutcome::Deny,
            AuditOutcome::Error => GqlAuditOutcome::Error,
        }
    }
}

impl From<GqlCredentialKind> for CredentialKind {
    fn from(kind: GqlCredentialKind) -> Self {
        match kind {
            GqlCredentialKind::Password => CredentialKind::Password,
            GqlCredentialKind::ApiKey => CredentialKind::ApiKey,
            GqlCredentialKind::Certificate => CredentialKind::Certificate,
        }
    }
}

impl From<&CredentialKind> for GqlCredentialKind {
    fn from(kind: &CredentialKind) -> Self {
        match kind {
            CredentialKind::Password => GqlCredentialKind::Password,
            CredentialKind::ApiKey => GqlCredentialKind::ApiKey,
            CredentialKind::Certificate => GqlCredentialKind::Certificate,
        }
    }
}

fn credential_status_as_str(status: &CredentialStatus) -> &'static str {
    match status {
        CredentialStatus::Active => "active",
        CredentialStatus::Revoked => "revoked",
    }
}

fn id(value: Uuid) -> ID {
    ID(value.to_string())
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}
