use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::{Effect, GrantKind, ScopeKind, SubjectKind};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PolicyBinding {
    pub id: Uuid,
    /// Tenant that owns the policy binding. `None` means platform/global policy.
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PermissionBlock {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub scope_mode: String,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub effect: Effect,
    pub conditions: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePermissionBlock {
    pub tenant_id: Option<Uuid>,
    pub scope_mode: String,
    pub object_kind: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub effect: Effect,
    pub conditions: Value,
    pub action_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListPermissionBlocks {
    pub tenant_id: Option<Uuid>,
    pub scope_mode: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct PermissionBlockList {
    pub items: Vec<PermissionBlock>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub role_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRoleAssignment {
    pub tenant_id: Option<Uuid>,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListRoleAssignments {
    pub tenant_id: Option<Uuid>,
    pub subject_kind: Option<SubjectKind>,
    pub subject_id: Option<Uuid>,
    pub role_id: Option<Uuid>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct RoleAssignmentList {
    pub items: Vec<RoleAssignment>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DirectPolicy {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub permission_block_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDirectPolicy {
    pub tenant_id: Option<Uuid>,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub permission_block_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListDirectPolicies {
    pub tenant_id: Option<Uuid>,
    pub subject_kind: Option<SubjectKind>,
    pub subject_id: Option<Uuid>,
    pub permission_block_id: Option<Uuid>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct DirectPolicyList {
    pub items: Vec<DirectPolicy>,
    pub total: i64,
}

/// Request to create a policy binding.
///
/// Deserialization accepts the canonical scope vocabulary
/// (`platform` / `tenant` / `object_kind` / `object_type` / `object` and the
/// group-scope kinds).
#[derive(Debug, Deserialize)]
pub struct CreatePolicyBinding {
    /// Tenant that owns the binding. `None` means platform/global policy.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub grant_kind: GrantKind,
    pub grant_id: Uuid,
    pub scope_kind: ScopeKind,
    /// Interpretation depends on `scope_kind`:
    /// - `platform`: ignored.
    /// - `tenant`: tenant UUID as text.
    /// - `object_kind`: coarse kind name (e.g., `resource`, `entity`, `tenant`).
    /// - `object_type`: namespaced sub-kind (e.g., `resource:channel`, `entity:device`).
    /// - `object`: object UUID as text.
    /// - `group_object_type`: `<group UUID>:<kind>:<sub-kind>`.
    /// - `group_tree_object_type`: `<group UUID>:<kind>:<sub-kind>`.
    /// - `group_child_kind`: `<group UUID>:group`.
    /// - `group_descendant_kind`: `<group UUID>:group`.
    #[serde(default)]
    pub scope_ref: Option<String>,
    #[serde(default)]
    pub effect: Effect,
    #[serde(default)]
    pub conditions: Value,
}

impl CreatePolicyBinding {
    /// Validate scope_kind/scope_ref consistency. Returns a human-readable
    /// error suitable for an HTTP 400 body.
    pub fn validate(&self) -> Result<(), String> {
        match self.scope_kind {
            ScopeKind::Platform => Ok(()),
            ScopeKind::Tenant => match &self.scope_ref {
                Some(r) => r
                    .parse::<Uuid>()
                    .map(|_| ())
                    .map_err(|_| format!("tenant scope_ref must be a UUID, got '{r}'")),
                None => Err("tenant scope requires scope_ref (tenant UUID)".to_string()),
            },
            ScopeKind::ObjectKind => match &self.scope_ref {
                Some(_) => Ok(()),
                None => Err("object_kind scope requires scope_ref (kind name)".to_string()),
            },
            ScopeKind::ObjectType => match &self.scope_ref {
                Some(r) if r.contains(':') => Ok(()),
                Some(r) => Err(format!(
                    "object_type scope_ref must be namespaced as '<kind>:<sub-kind>' (e.g., 'resource:channel'), got '{r}'"
                )),
                None => Err("object_type scope requires scope_ref".to_string()),
            },
            ScopeKind::Object => match &self.scope_ref {
                Some(_) => Ok(()),
                None => Err("object scope requires scope_ref (object UUID)".to_string()),
            },
            ScopeKind::GroupObjectType | ScopeKind::GroupTreeObjectType => match &self.scope_ref {
                Some(r) => validate_group_object_type_scope_ref(r),
                None => Err("group object type scope requires scope_ref".to_string()),
            },
            ScopeKind::GroupChildKind | ScopeKind::GroupDescendantKind => match &self.scope_ref {
                Some(r) => validate_group_kind_scope_ref(r),
                None => Err("group kind scope requires scope_ref".to_string()),
            },
        }
    }
}

fn validate_group_object_type_scope_ref(scope_ref: &str) -> Result<(), String> {
    let (group_id, object_type) = scope_ref.split_once(':').ok_or_else(|| {
        format!(
            "group object type scope_ref must be '<group UUID>:<kind>:<sub-kind>', got '{scope_ref}'"
        )
    })?;
    group_id
        .parse::<Uuid>()
        .map_err(|_| format!("group object type scope_ref has invalid group UUID '{group_id}'"))?;
    if object_type.split_once(':').is_some() {
        Ok(())
    } else {
        Err(format!(
            "group object type scope_ref must include a namespaced object type, got '{scope_ref}'"
        ))
    }
}

fn validate_group_kind_scope_ref(scope_ref: &str) -> Result<(), String> {
    let (group_id, kind) = scope_ref.split_once(':').ok_or_else(|| {
        format!("group kind scope_ref must be '<group UUID>:group', got '{scope_ref}'")
    })?;
    group_id
        .parse::<Uuid>()
        .map_err(|_| format!("group kind scope_ref has invalid group UUID '{group_id}'"))?;
    if kind == "group" {
        Ok(())
    } else {
        Err(format!(
            "group kind scope_ref must end with ':group', got '{scope_ref}'"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(body: serde_json::Value) -> Result<CreatePolicyBinding, serde_json::Error> {
        serde_json::from_value(body)
    }

    fn template(scope_kind: &str, scope_ref: Option<&str>) -> serde_json::Value {
        let mut v = json!({
            "subject_kind": "entity",
            "subject_id": "11111111-1111-1111-1111-111111111111",
            "grant_kind": "capability",
            "grant_id": "22222222-2222-2222-2222-222222222222",
            "scope_kind": scope_kind,
        });
        if let Some(r) = scope_ref {
            v.as_object_mut()
                .unwrap()
                .insert("scope_ref".into(), json!(r));
        }
        v
    }

    #[test]
    fn canonical_scope_kinds_deserialise() {
        let platform = parse(template("platform", None)).expect("parse");
        assert_eq!(platform.scope_kind, ScopeKind::Platform);
        assert_eq!(platform.scope_ref, None);

        let object_type = parse(template("object_type", Some("resource:channel"))).expect("parse");
        assert_eq!(object_type.scope_kind, ScopeKind::ObjectType);
        assert_eq!(object_type.scope_ref.as_deref(), Some("resource:channel"));
    }

    #[test]
    fn unknown_scope_kind_fails() {
        let err = parse(template("nonsense", None)).unwrap_err().to_string();
        assert!(err.contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn validate_object_type_rejects_bare_value() {
        let req = CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind: GrantKind::Capability,
            grant_id: Uuid::new_v4(),
            scope_kind: ScopeKind::ObjectType,
            scope_ref: Some("channel".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("namespaced"), "got: {err}");
    }

    #[test]
    fn validate_object_type_accepts_namespaced() {
        let req = CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind: GrantKind::Capability,
            grant_id: Uuid::new_v4(),
            scope_kind: ScopeKind::ObjectType,
            scope_ref: Some("resource:channel".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_tenant_requires_uuid_scope_ref() {
        let bad = CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind: GrantKind::Capability,
            grant_id: Uuid::new_v4(),
            scope_kind: ScopeKind::Tenant,
            scope_ref: Some("not-a-uuid".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        };
        assert!(bad.validate().is_err());

        let good = CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind: GrantKind::Capability,
            grant_id: Uuid::new_v4(),
            scope_kind: ScopeKind::Tenant,
            scope_ref: Some(Uuid::new_v4().to_string()),
            effect: Effect::Allow,
            conditions: json!({}),
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn validate_object_requires_scope_ref() {
        let req = CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind: GrantKind::Capability,
            grant_id: Uuid::new_v4(),
            scope_kind: ScopeKind::Object,
            scope_ref: None,
            effect: Effect::Allow,
            conditions: json!({}),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_platform_ignores_scope_ref() {
        let req = CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind: GrantKind::Capability,
            grant_id: Uuid::new_v4(),
            scope_kind: ScopeKind::Platform,
            scope_ref: None,
            effect: Effect::Allow,
            conditions: json!({}),
        };
        assert!(req.validate().is_ok());
    }
}

/// Authorization check request.
///
/// Two equivalent ways to identify the protected object:
/// - `resource_id`: legacy form. Resolves the object from the `resources` table
///   with kind = `resources.kind`. Backwards compatible.
/// - `object_kind` + `object_id`: explicit form. Currently supports
///   `object_kind = "resource"` (same as `resource_id`) and
///   `object_kind = "tenant"` (resolves from `tenants`, kind = `"tenant"`).
/// - `object_kind = "platform"`: global platform object. Does not use
///   `object_id`.
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
    /// Structured detail for explainability and audit. Populated for denials
    /// caused by tenant lifecycle state (M3) and reserved for future
    /// structured-reason additions. Omitted from JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl AuthzResponse {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: "allowed".to_string(),
            details: None,
        }
    }

    pub fn deny<S: Into<String>>(reason: S) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            details: None,
        }
    }

    pub fn deny_with_details<S: Into<String>>(reason: S, details: Value) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            details: Some(details),
        }
    }
}
