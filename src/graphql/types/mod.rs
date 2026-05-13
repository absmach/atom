use async_graphql::{Enum, InputObject, Object, ID};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    identity::service as identity_service,
    models::{
        access as access_model, api_endpoint as api_endpoint_model, capability as capability_model,
        entity as entity_model,
        enums::{
            AuditOutcome, CredentialKind, CredentialStatus, Effect, EntityKind, EntityStatus,
            GrantKind, ScopeKind, SubjectKind, TenantStatus,
        },
        group as group_model, profile as profile_model, resource as resource_model,
        role as role_model, session as session_model, tenant as tenant_model, token as token_model,
    },
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
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "Effect", rename_items = "snake_case")]
pub enum GqlEffect {
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

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
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

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn route(&self) -> Option<&str> {
        self.0.route.as_deref()
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

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(id)
    }

    async fn owner_id(&self) -> Option<ID> {
        self.0.owner_id.map(id)
    }

    async fn attributes(&self) -> &Value {
        &self.0.attributes
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn scope_kind(&self) -> &str {
        &self.0.scope_kind
    }

    async fn scope_ref(&self) -> Option<&str> {
        self.0.scope_ref.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

    async fn resource_kind(&self) -> Option<&str> {
        self.0.resource_kind.as_deref()
    }

    async fn description(&self) -> Option<&str> {
        self.0.description.as_deref()
    }

    async fn created_at(&self) -> String {
        timestamp(self.0.created_at)
    }

    async fn updated_at(&self) -> String {
        timestamp(self.0.updated_at)
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

#[derive(InputObject)]
pub struct LoginInput {
    pub identifier: String,
    pub secret: String,
    pub tenant_id: Option<ID>,
    pub tenant_route: Option<String>,
    #[graphql(default = "password")]
    pub kind: String,
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
    pub tenant_id: Option<ID>,
    pub attributes: Value,
}

#[derive(InputObject)]
pub struct UpdateEntityInput {
    pub name: Option<String>,
    pub kind: Option<GqlEntityKind>,
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
    pub route: Option<String>,
    pub tags: Option<Vec<String>>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct UpdateTenantInput {
    pub name: Option<String>,
    pub route: Option<String>,
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
    pub tenant_id: Option<ID>,
    pub owner_id: Option<ID>,
    pub attributes: Option<Value>,
}

#[derive(InputObject)]
pub struct UpdateResourceInput {
    pub name: Option<String>,
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
    pub scope_kind: Option<String>,
    pub scope_ref: Option<String>,
}

#[derive(InputObject)]
pub struct UpdateRoleInput {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(InputObject)]
pub struct CreateCapabilityInput {
    pub name: String,
    pub resource_kind: Option<String>,
    pub description: Option<String>,
}

#[derive(InputObject)]
pub struct UpdateCapabilityInput {
    pub name: Option<String>,
    pub resource_kind: Option<String>,
    pub description: Option<String>,
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

impl From<access_model::OrphanPolicyItem> for PolicyBinding {
    fn from(policy: access_model::OrphanPolicyItem) -> Self {
        PolicyBinding(PolicyBindingData {
            id: policy.id,
            tenant_id: None,
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
                .map(|value| serde_json::to_value(value).expect("subject serializes")),
            resource: response
                .resource
                .map(|value| serde_json::to_value(value).expect("resource serializes")),
            capability: response
                .capability
                .map(|value| serde_json::to_value(value).expect("capability serializes")),
            matched_binding: response
                .matched_binding
                .map(|value| serde_json::to_value(value).expect("binding serializes")),
            evaluated_bindings: serde_json::to_value(response.evaluated_bindings)
                .expect("bindings serialize"),
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

pub fn parse_optional_audit_outcome(value: Option<GqlAuditOutcome>) -> Option<AuditOutcome> {
    value.map(AuditOutcome::from)
}

pub fn parse_optional_credential_kind(value: Option<GqlCredentialKind>) -> Option<CredentialKind> {
    value.map(CredentialKind::from)
}

pub fn parse_scope_kind(value: GqlScopeKind) -> ScopeKind {
    ScopeKind::from(value)
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
