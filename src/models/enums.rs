use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntityKind {
    Human,
    Device,
    Service,
    Workload,
    Application,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EntityStatus {
    #[default]
    Active,
    Inactive,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    ApiKey,
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SubjectKind {
    Entity,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GrantKind {
    Capability,
    Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Top of the scope hierarchy. Matches every protected object and inherits
    /// into every tenant for the same capability (full inheritance lands in M4).
    Platform,
    /// Inheritance into objects whose `tenant_id` matches `scope_ref`. The PDP
    /// stub treats this as no-match until M3/M4 ship.
    Tenant,
    /// Matches every object whose coarse object kind equals `scope_ref`.
    ObjectKind,
    /// Matches every object whose namespaced sub-kind equals `scope_ref` (e.g.
    /// `resource:channel` or `entity:device`).
    ObjectType,
    /// Matches a single object whose UUID (as text) equals `scope_ref`.
    Object,
    /// Matches objects of a namespaced type whose direct parent group equals
    /// the UUID embedded in `scope_ref`.
    GroupObjectType,
    /// Matches objects of a namespaced type whose direct parent group is the
    /// UUID embedded in `scope_ref`, or any descendant of that group.
    GroupTreeObjectType,
    /// Matches direct child groups of the group UUID embedded in `scope_ref`.
    GroupChildKind,
    /// Matches descendant groups of the group UUID embedded in `scope_ref`.
    GroupDescendantKind,
}

/// Canonical set of protected object kinds. Used for `object_kind` columns in
/// policy scopes, guardrail rules, and authorization checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Entity,
    Resource,
    Group,
    Tenant,
    Role,
    Policy,
    Credential,
    AuditLog,
    SigningKey,
}

impl ObjectKind {
    /// Canonical string form (matches the DB CHECK constraint and the API
    /// contract). `AuditLog` serialises as `audit_log`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectKind::Entity => "entity",
            ObjectKind::Resource => "resource",
            ObjectKind::Group => "group",
            ObjectKind::Tenant => "tenant",
            ObjectKind::Role => "role",
            ObjectKind::Policy => "policy",
            ObjectKind::Credential => "credential",
            ObjectKind::AuditLog => "audit_log",
            ObjectKind::SigningKey => "signing_key",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ActionAssignmentDecision {
    Allow,
    Deny,
    RequireOverride,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Allow,
    Deny,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    #[default]
    Active,
    Inactive,
    Frozen,
    Deleted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletedFilter {
    #[default]
    Live,
    Deleted,
    All,
}

impl DeletedFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            DeletedFilter::Live => "live",
            DeletedFilter::Deleted => "deleted",
            DeletedFilter::All => "all",
        }
    }
}
