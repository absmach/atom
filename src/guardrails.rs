//! Assignment guardrails: the rules that decide whether a grant may be
//! created at all, independently of who is asking.
//!
//! Every entry point takes `&mut impl DbExecutor` rather than `&Database`. Callers
//! run these validations under the row locks their mutation already holds, so
//! the reads must go through *that* transaction: a second pooled connection
//! neither sees the transaction's uncommitted state nor respects its locks,
//! and acquiring one while holding a transaction risks exhausting the pool
//! (every request holding one connection and waiting for a second).

mod storage;

use crate::db::DbExecutor;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::{
        enums::{ActionAssignmentDecision as GuardrailDecision, GrantKind, ScopeKind, SubjectKind},
        policy::{CreateDirectPolicy, CreatePolicyBinding},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub entity_kind: String,
    pub capability_name: String,
    pub object_kind: String,
    pub object_type: Option<String>,
    pub tenant_id: Option<Uuid>,
}

pub fn decide(assignments: &[Assignment], rules: &[Rule]) -> Result<(), String> {
    for assignment in assignments {
        let decision = rules
            .iter()
            .filter(|rule| rule.matches(assignment))
            .max_by_key(|rule| rule.precedence())
            .map(|rule| rule.decision)
            .unwrap_or(GuardrailDecision::Allow);

        match decision {
            GuardrailDecision::Allow => {}
            GuardrailDecision::Deny => {
                return Err(format!(
                    "guardrail rejected {} receiving {} on {}{}",
                    assignment.entity_kind,
                    assignment.capability_name,
                    assignment.object_kind,
                    assignment
                        .object_type
                        .as_ref()
                        .map(|object_type| format!(":{object_type}"))
                        .unwrap_or_default()
                ));
            }
            GuardrailDecision::RequireOverride => {
                return Err(format!(
                    "guardrail requires override for {} receiving {}",
                    assignment.entity_kind, assignment.capability_name
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub tenant_id: Option<Uuid>,
    pub entity_kind: String,
    pub capability_name: String,
    pub object_kind: String,
    pub object_type: Option<String>,
    pub decision: GuardrailDecision,
    pub is_absolute: bool,
}

impl Rule {
    fn matches(&self, assignment: &Assignment) -> bool {
        self.entity_kind == assignment.entity_kind
            && self.capability_name == assignment.capability_name
            && self.object_kind == assignment.object_kind
            && self
                .object_type
                .as_ref()
                .map(|object_type| assignment.object_type.as_ref() == Some(object_type))
                .unwrap_or(true)
            && (self.tenant_id.is_none() || self.tenant_id == assignment.tenant_id)
    }

    fn precedence(&self) -> i32 {
        match (self.is_absolute, self.tenant_id.is_some(), self.decision) {
            (true, _, GuardrailDecision::Deny) => 50,
            (true, _, GuardrailDecision::RequireOverride) => 45,
            (_, true, GuardrailDecision::Deny) => 40,
            (_, true, GuardrailDecision::RequireOverride) => 35,
            (_, true, GuardrailDecision::Allow) => 30,
            (_, false, GuardrailDecision::Deny) => 20,
            (_, false, GuardrailDecision::RequireOverride) => 15,
            (_, false, GuardrailDecision::Allow) => 10,
        }
    }
}

pub async fn validate_policy(
    conn: &mut impl DbExecutor,
    req: &CreatePolicyBinding,
) -> Result<(), AppError> {
    let assignments = assignments_for_policy(&mut *conn, req).await?;
    validate_assignments(&mut *conn, &assignments).await
}

pub async fn validate_role_capability(
    conn: &mut impl DbExecutor,
    role_id: Uuid,
    capability_id: Uuid,
) -> Result<(), AppError> {
    let capability_names = storage::capability_names(&mut *conn, &[capability_id]).await?;
    let rows = storage::role_recipients(conn, role_id).await?;

    let mut assignments = Vec::new();
    for row in rows {
        let entity_kind: String = row.entity_kind;
        let tenant_id: Option<Uuid> = row.tenant_id;
        let scope_kind: ScopeKind = row.scope_kind;
        let scope_ref: Option<String> = row.scope_ref;
        let (object_kind, object_type) = scope_to_object(scope_kind, scope_ref.as_deref());
        assignments.extend(capability_names.iter().map(|capability_name| Assignment {
            entity_kind: entity_kind.clone(),
            capability_name: capability_name.clone(),
            object_kind: object_kind.clone(),
            object_type: object_type.clone(),
            tenant_id,
        }));
    }

    validate_assignments(&mut *conn, &assignments).await
}

pub async fn validate_role_assignment(
    conn: &mut impl DbExecutor,
    tenant_id: Option<Uuid>,
    subject_kind: SubjectKind,
    subject_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    let entity_kinds = storage::subject_entity_kinds(&mut *conn, subject_kind, subject_id).await?;
    if entity_kinds.is_empty() {
        return Ok(());
    }

    let role_capabilities = storage::role_permission_assignments(&mut *conn, &[role_id]).await?;
    let assignments = entity_kinds
        .into_iter()
        .flat_map(|entity_kind| {
            role_capabilities.iter().map(move |role_cap| Assignment {
                entity_kind: entity_kind.clone(),
                capability_name: role_cap.capability_name.clone(),
                object_kind: role_cap.object_kind.clone(),
                object_type: role_cap.object_type.clone(),
                tenant_id,
            })
        })
        .collect::<Vec<_>>();

    validate_assignments(&mut *conn, &assignments).await
}

/// Validate a role assignment using the caller's existing connection.
///
/// Transactional mutation paths must use this variant so validation cannot
/// wait for a second pool connection while the transaction holds the first.
pub async fn validate_role_assignment_on_connection(
    conn: &mut impl DbExecutor,
    tenant_id: Option<Uuid>,
    subject_kind: SubjectKind,
    subject_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    let entity_kinds = storage::subject_entity_kinds(&mut *conn, subject_kind, subject_id).await?;
    if entity_kinds.is_empty() {
        return Ok(());
    }

    let role_capabilities = storage::role_permission_assignments(&mut *conn, &[role_id]).await?;
    let assignments = entity_kinds
        .into_iter()
        .flat_map(|entity_kind| {
            role_capabilities.iter().map(move |role_cap| Assignment {
                entity_kind: entity_kind.clone(),
                capability_name: role_cap.capability_name.clone(),
                object_kind: role_cap.object_kind.clone(),
                object_type: role_cap.object_type.clone(),
                tenant_id,
            })
        })
        .collect::<Vec<_>>();

    validate_assignments(&mut *conn, &assignments).await
}

pub async fn validate_composite_role_assignment_plan(
    conn: &mut impl DbExecutor,
    entity_ids: &[Uuid],
    child_role_ids: &[Uuid],
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    if entity_ids.is_empty() || child_role_ids.is_empty() {
        return Ok(());
    }

    let mut unique_entity_ids = entity_ids.to_vec();
    unique_entity_ids.sort_unstable();
    unique_entity_ids.dedup();
    let mut unique_child_role_ids = child_role_ids.to_vec();
    unique_child_role_ids.sort_unstable();
    unique_child_role_ids.dedup();

    let entity_kinds = storage::entity_kinds(conn, &unique_entity_ids).await?;
    if entity_kinds.len() != unique_entity_ids.len() {
        return Err(AppError::bad_request("invalid member reference"));
    }

    let role_capabilities =
        storage::role_permission_assignments(&mut *conn, &unique_child_role_ids).await?;
    let assignments = entity_kinds
        .into_iter()
        .flat_map(|entity_kind| {
            role_capabilities.iter().map(move |role_cap| Assignment {
                entity_kind: entity_kind.clone(),
                capability_name: role_cap.capability_name.clone(),
                object_kind: role_cap.object_kind.clone(),
                object_type: role_cap.object_type.clone(),
                tenant_id,
            })
        })
        .collect::<Vec<_>>();

    validate_assignments(&mut *conn, &assignments).await
}

pub async fn validate_role_assignment_plan(
    conn: &mut impl DbExecutor,
    entity_ids: &[Uuid],
    capability_ids: &[Uuid],
    tenant_id: Option<Uuid>,
    scope_kind: ScopeKind,
    scope_ref: Option<&str>,
) -> Result<(), AppError> {
    if entity_ids.is_empty() || capability_ids.is_empty() {
        return Ok(());
    }

    let mut unique_entity_ids = entity_ids.to_vec();
    unique_entity_ids.sort_unstable();
    unique_entity_ids.dedup();
    let mut unique_capability_ids = capability_ids.to_vec();
    unique_capability_ids.sort_unstable();
    unique_capability_ids.dedup();

    let entity_kinds = storage::entity_kinds(conn, &unique_entity_ids).await?;
    if entity_kinds.len() != unique_entity_ids.len() {
        return Err(AppError::bad_request("invalid member reference"));
    }

    let capability_names = storage::capability_names(&mut *conn, &unique_capability_ids).await?;
    if capability_names.len() != unique_capability_ids.len() {
        return Err(AppError::bad_request("invalid capability reference"));
    }

    let (object_kind, object_type) = scope_to_object(scope_kind, scope_ref);
    let assignments = entity_kinds
        .into_iter()
        .flat_map(|entity_kind| {
            let object_kind = object_kind.clone();
            let object_type = object_type.clone();
            capability_names
                .iter()
                .map(move |capability_name| Assignment {
                    entity_kind: entity_kind.clone(),
                    capability_name: capability_name.clone(),
                    object_kind: object_kind.clone(),
                    object_type: object_type.clone(),
                    tenant_id,
                })
        })
        .collect::<Vec<_>>();

    validate_assignments(&mut *conn, &assignments).await
}

/// Takes the caller's connection rather than the pool: every caller runs this
/// mid-transaction, and reaching back into the pool for a second connection
/// while holding one deadlocks a saturated pool (and hangs outright at
/// `max_connections = 1`).
pub async fn validate_group_member(
    conn: &mut impl DbExecutor,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    let entity_kind: String = storage::entity_kind(conn, entity_id).await?;

    let rows = storage::inherited_group_grants(conn, group_id).await?;

    let mut assignments = Vec::new();
    for row in rows {
        let tenant_id: Option<Uuid> = row.tenant_id;
        let grant_kind: GrantKind = row.grant_kind;
        let grant_id: Uuid = row.grant_id;
        let scope_kind: ScopeKind = row.scope_kind;
        let scope_ref: Option<String> = row.scope_ref;
        let capability_names = match grant_kind {
            GrantKind::Capability => storage::capability_names(&mut *conn, &[grant_id]).await?,
            GrantKind::Role => storage::role_capability_names(&mut *conn, grant_id).await?,
        };
        let (object_kind, object_type) = scope_to_object(scope_kind, scope_ref.as_deref());
        assignments.extend(
            capability_names
                .into_iter()
                .map(|capability_name| Assignment {
                    entity_kind: entity_kind.clone(),
                    capability_name,
                    object_kind: object_kind.clone(),
                    object_type: object_type.clone(),
                    tenant_id,
                }),
        );
    }

    validate_assignments(&mut *conn, &assignments).await
}

pub async fn validate_direct_policy(
    conn: &mut impl DbExecutor,
    req: &CreateDirectPolicy,
) -> Result<(), AppError> {
    let entity_kinds =
        storage::subject_entity_kinds(&mut *conn, req.subject_kind.clone(), req.subject_id).await?;
    let permission_blocks =
        storage::permission_block_assignments(&mut *conn, &[req.permission_block_id]).await?;
    let assignments = entity_kinds
        .into_iter()
        .flat_map(|entity_kind| {
            permission_blocks.iter().map(move |block| Assignment {
                entity_kind: entity_kind.clone(),
                capability_name: block.capability_name.clone(),
                object_kind: block.object_kind.clone(),
                object_type: block.object_type.clone(),
                tenant_id: req.tenant_id,
            })
        })
        .collect::<Vec<_>>();

    validate_assignments(&mut *conn, &assignments).await
}

/// Takes the caller's connection, not the pool — see [`validate_group_member`].
pub async fn validate_role_permission_block_links(
    conn: &mut impl DbExecutor,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<(), AppError> {
    if permission_block_ids.is_empty() {
        return Ok(());
    }

    let rows = storage::assignment_recipients(conn, role_id).await?;

    let permission_blocks =
        storage::permission_block_assignments(&mut *conn, permission_block_ids).await?;
    let mut assignments = Vec::new();
    for row in rows {
        let tenant_id: Option<Uuid> = row.tenant_id;
        let entity_kind: String = row.entity_kind;
        assignments.extend(permission_blocks.iter().map(|block| Assignment {
            entity_kind: entity_kind.clone(),
            capability_name: block.capability_name.clone(),
            object_kind: block.object_kind.clone(),
            object_type: block.object_type.clone(),
            tenant_id,
        }));
    }

    validate_assignments(&mut *conn, &assignments).await
}

async fn assignments_for_policy(
    conn: &mut impl DbExecutor,
    req: &CreatePolicyBinding,
) -> Result<Vec<Assignment>, AppError> {
    let entity_kinds =
        storage::subject_entity_kinds(&mut *conn, req.subject_kind.clone(), req.subject_id).await?;
    let capability_names = match req.grant_kind {
        GrantKind::Capability => storage::capability_names(&mut *conn, &[req.grant_id]).await?,
        GrantKind::Role => storage::role_capability_names(&mut *conn, req.grant_id).await?,
    };
    let (object_kind, object_type) =
        scope_to_object(req.scope_kind.clone(), req.scope_ref.as_deref());

    Ok(entity_kinds
        .into_iter()
        .flat_map(|entity_kind| {
            let object_kind = object_kind.clone();
            let object_type = object_type.clone();
            capability_names
                .iter()
                .map(move |capability_name| Assignment {
                    entity_kind: entity_kind.clone(),
                    capability_name: capability_name.clone(),
                    object_kind: object_kind.clone(),
                    object_type: object_type.clone(),
                    tenant_id: req.tenant_id,
                })
        })
        .collect())
}

async fn validate_assignments(
    conn: &mut impl DbExecutor,
    assignments: &[Assignment],
) -> Result<(), AppError> {
    if assignments.is_empty() {
        return Ok(());
    }
    let rules = storage::load_rules(&mut *conn).await?;
    decide(assignments, &rules).map_err(AppError::bad_request)
}

#[derive(Debug, Clone)]
struct RoleCapabilityAssignment {
    capability_name: String,
    object_kind: String,
    object_type: Option<String>,
}

fn scope_to_object(scope_kind: ScopeKind, scope_ref: Option<&str>) -> (String, Option<String>) {
    match scope_kind {
        ScopeKind::Platform => ("platform".to_string(), None),
        ScopeKind::Tenant => ("tenant".to_string(), None),
        ScopeKind::ObjectKind => (scope_ref.unwrap_or("unknown").to_string(), None),
        ScopeKind::ObjectType => scope_ref
            .and_then(|value| value.split_once(':').map(|(kind, _)| (kind, value)))
            .map(|(kind, value)| (kind.to_string(), Some(value.to_string())))
            .unwrap_or_else(|| ("unknown".to_string(), None)),
        ScopeKind::Object => ("object".to_string(), None),
        ScopeKind::GroupObjectType | ScopeKind::GroupTreeObjectType => scope_ref
            .and_then(|value| value.split_once(':').map(|(_, object_type)| object_type))
            .and_then(|object_type| {
                object_type
                    .split_once(':')
                    .map(|(kind, _)| (kind.to_string(), Some(object_type.to_string())))
            })
            .unwrap_or_else(|| ("unknown".to_string(), None)),
        ScopeKind::GroupChildKind | ScopeKind::GroupDescendantKind => ("group".to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(kind: &str, capability: &str) -> Assignment {
        Assignment {
            entity_kind: kind.into(),
            capability_name: capability.into(),
            object_kind: "resource".into(),
            object_type: Some("resource:channel".into()),
            tenant_id: None,
        }
    }

    #[test]
    fn absolute_deny_wins_over_allow() {
        let rules = vec![
            Rule {
                tenant_id: None,
                entity_kind: "device".into(),
                capability_name: "manage".into(),
                object_kind: "resource".into(),
                object_type: None,
                decision: GuardrailDecision::Allow,
                is_absolute: false,
            },
            Rule {
                tenant_id: None,
                entity_kind: "device".into(),
                capability_name: "manage".into(),
                object_kind: "resource".into(),
                object_type: None,
                decision: GuardrailDecision::Deny,
                is_absolute: true,
            },
        ];
        assert!(decide(&[assignment("device", "manage")], &rules).is_err());
    }

    #[test]
    fn unmatched_assignment_allows_by_default() {
        assert!(decide(&[assignment("service", "publish")], &[]).is_ok());
    }

    #[test]
    fn matching_object_type_allow_passes() {
        let rules = vec![Rule {
            tenant_id: None,
            entity_kind: "device".into(),
            capability_name: "publish".into(),
            object_kind: "resource".into(),
            object_type: Some("resource:channel".into()),
            decision: GuardrailDecision::Allow,
            is_absolute: false,
        }];
        assert!(decide(&[assignment("device", "publish")], &rules).is_ok());
    }
}

#[derive(sqlx::FromRow)]
struct RoleRecipients {
    entity_kind: String,
    tenant_id: Option<Uuid>,
    scope_kind: ScopeKind,
    scope_ref: Option<String>,
}

#[derive(sqlx::FromRow)]
struct InheritedGroupGrants {
    tenant_id: Option<Uuid>,
    grant_kind: GrantKind,
    grant_id: Uuid,
    scope_kind: ScopeKind,
    scope_ref: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AssignmentRecipients {
    tenant_id: Option<Uuid>,
    entity_kind: String,
}
