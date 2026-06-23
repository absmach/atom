use sqlx::PgPool;
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

pub async fn validate_policy(pool: &PgPool, req: &CreatePolicyBinding) -> Result<(), AppError> {
    let assignments = assignments_for_policy(pool, req).await?;
    validate_assignments(pool, &assignments).await
}

pub async fn validate_role_capability(
    pool: &PgPool,
    role_id: Uuid,
    capability_id: Uuid,
) -> Result<(), AppError> {
    let capability_names = capability_names(pool, &[capability_id]).await?;
    let rows = sqlx::query(
        r#"WITH RECURSIVE assigned_groups(edge_id, group_id) AS (
               SELECT pb.id, pb.subject_id
               FROM effective_access_edges() pb
               WHERE pb.grant_kind = 'role' AND pb.grant_id = $1 AND pb.subject_kind = 'group'
               UNION
               SELECT ag.edge_id, gh.child_id
               FROM group_hierarchy gh
               JOIN assigned_groups ag ON gh.parent_id = ag.group_id
           )
           SELECT e.kind AS entity_kind, pb.tenant_id, pb.scope_kind, pb.scope_ref
           FROM effective_access_edges() pb
           JOIN entities e ON pb.subject_kind = 'entity' AND e.id = pb.subject_id
           WHERE pb.grant_kind = 'role' AND pb.grant_id = $1
           UNION ALL
           SELECT e.kind AS entity_kind, pb.tenant_id, pb.scope_kind, pb.scope_ref
           FROM assigned_groups ag
           JOIN effective_access_edges() pb ON pb.id = ag.edge_id
           JOIN group_members gm ON gm.group_id = ag.group_id
           JOIN entities e ON e.id = gm.entity_id"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut assignments = Vec::new();
    for row in rows {
        use sqlx::Row;
        let entity_kind: String = row.try_get("entity_kind").map_err(db_err)?;
        let tenant_id: Option<Uuid> = row.try_get("tenant_id").map_err(db_err)?;
        let scope_kind: ScopeKind = row.try_get("scope_kind").map_err(db_err)?;
        let scope_ref: Option<String> = row.try_get("scope_ref").map_err(db_err)?;
        let (object_kind, object_type) = scope_to_object(scope_kind, scope_ref.as_deref());
        assignments.extend(capability_names.iter().map(|capability_name| Assignment {
            entity_kind: entity_kind.clone(),
            capability_name: capability_name.clone(),
            object_kind: object_kind.clone(),
            object_type: object_type.clone(),
            tenant_id,
        }));
    }

    validate_assignments(pool, &assignments).await
}

pub async fn validate_role_assignment(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    subject_kind: SubjectKind,
    subject_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    let entity_kinds = subject_entity_kinds(pool, subject_kind, subject_id).await?;
    if entity_kinds.is_empty() {
        return Ok(());
    }

    let role_capabilities = role_permission_assignments(pool, &[role_id]).await?;
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

    validate_assignments(pool, &assignments).await
}

pub async fn validate_composite_role_assignment_plan(
    pool: &PgPool,
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

    let entity_kinds =
        sqlx::query_scalar::<_, String>("SELECT kind FROM entities WHERE id = ANY($1::uuid[])")
            .bind(&unique_entity_ids)
            .fetch_all(pool)
            .await
            .map_err(db_err)?;
    if entity_kinds.len() != unique_entity_ids.len() {
        return Err(AppError::bad_request("invalid member reference"));
    }

    let role_capabilities = role_permission_assignments(pool, &unique_child_role_ids).await?;
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

    validate_assignments(pool, &assignments).await
}

pub async fn validate_role_assignment_plan(
    pool: &PgPool,
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

    let entity_kinds =
        sqlx::query_scalar::<_, String>("SELECT kind FROM entities WHERE id = ANY($1::uuid[])")
            .bind(&unique_entity_ids)
            .fetch_all(pool)
            .await
            .map_err(db_err)?;
    if entity_kinds.len() != unique_entity_ids.len() {
        return Err(AppError::bad_request("invalid member reference"));
    }

    let capability_names = capability_names(pool, &unique_capability_ids).await?;
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

    validate_assignments(pool, &assignments).await
}

pub async fn validate_group_member(
    pool: &PgPool,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    use sqlx::Row;

    let entity_kind: String = sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
        .bind(entity_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    let rows = sqlx::query(
        r#"WITH RECURSIVE policy_groups(group_id) AS (
               SELECT $1::uuid
               UNION ALL
               SELECT gh.parent_id
               FROM group_hierarchy gh
               JOIN policy_groups pg ON pg.group_id = gh.child_id
           )
           SELECT pb.tenant_id, pb.grant_kind, pb.grant_id, pb.scope_kind, pb.scope_ref
           FROM effective_access_edges() pb
           WHERE pb.subject_kind = 'group'
             AND pb.subject_id IN (SELECT group_id FROM policy_groups)"#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut assignments = Vec::new();
    for row in rows {
        let tenant_id: Option<Uuid> = row.try_get("tenant_id").map_err(db_err)?;
        let grant_kind: GrantKind = row.try_get("grant_kind").map_err(db_err)?;
        let grant_id: Uuid = row.try_get("grant_id").map_err(db_err)?;
        let scope_kind: ScopeKind = row.try_get("scope_kind").map_err(db_err)?;
        let scope_ref: Option<String> = row.try_get("scope_ref").map_err(db_err)?;
        let capability_names = match grant_kind {
            GrantKind::Capability => capability_names(pool, &[grant_id]).await?,
            GrantKind::Role => role_capability_names(pool, grant_id).await?,
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

    validate_assignments(pool, &assignments).await
}

pub async fn validate_direct_policy(
    pool: &PgPool,
    req: &CreateDirectPolicy,
) -> Result<(), AppError> {
    let entity_kinds = subject_entity_kinds(pool, req.subject_kind.clone(), req.subject_id).await?;
    let permission_blocks = permission_block_assignments(pool, &[req.permission_block_id]).await?;
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

    validate_assignments(pool, &assignments).await
}

pub async fn validate_role_permission_block_links(
    pool: &PgPool,
    role_id: Uuid,
    permission_block_ids: &[Uuid],
) -> Result<(), AppError> {
    if permission_block_ids.is_empty() {
        return Ok(());
    }

    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT ra.tenant_id, e.kind AS entity_kind
           FROM role_assignments ra
           JOIN entities e ON ra.subject_kind = 'entity' AND e.id = ra.subject_id
           WHERE ra.role_id = $1
           UNION ALL
           SELECT ra.tenant_id, e.kind AS entity_kind
           FROM role_assignments ra
           JOIN group_members gm ON ra.subject_kind = 'group' AND gm.group_id = ra.subject_id
           JOIN entities e ON e.id = gm.entity_id
           WHERE ra.role_id = $1"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let permission_blocks = permission_block_assignments(pool, permission_block_ids).await?;
    let mut assignments = Vec::new();
    for row in rows {
        let tenant_id: Option<Uuid> = row.try_get("tenant_id").map_err(db_err)?;
        let entity_kind: String = row.try_get("entity_kind").map_err(db_err)?;
        assignments.extend(permission_blocks.iter().map(|block| Assignment {
            entity_kind: entity_kind.clone(),
            capability_name: block.capability_name.clone(),
            object_kind: block.object_kind.clone(),
            object_type: block.object_type.clone(),
            tenant_id,
        }));
    }

    validate_assignments(pool, &assignments).await
}

async fn assignments_for_policy(
    pool: &PgPool,
    req: &CreatePolicyBinding,
) -> Result<Vec<Assignment>, AppError> {
    let entity_kinds = subject_entity_kinds(pool, req.subject_kind.clone(), req.subject_id).await?;
    let capability_names = match req.grant_kind {
        GrantKind::Capability => capability_names(pool, &[req.grant_id]).await?,
        GrantKind::Role => role_capability_names(pool, req.grant_id).await?,
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

async fn validate_assignments(pool: &PgPool, assignments: &[Assignment]) -> Result<(), AppError> {
    if assignments.is_empty() {
        return Ok(());
    }
    let rules = load_rules(pool).await?;
    decide(assignments, &rules).map_err(AppError::bad_request)
}

async fn load_rules(pool: &PgPool) -> Result<Vec<Rule>, AppError> {
    use sqlx::Row;
    sqlx::query(
        r#"SELECT tenant_id, entity_kind, action_name AS capability_name, object_kind, object_type, decision, is_absolute
           FROM action_assignment_rules"#,
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(|row| {
        Ok(Rule {
            tenant_id: row.try_get("tenant_id").map_err(db_err)?,
            entity_kind: row.try_get("entity_kind").map_err(db_err)?,
            capability_name: row.try_get("capability_name").map_err(db_err)?,
            object_kind: row.try_get("object_kind").map_err(db_err)?,
            object_type: row.try_get("object_type").map_err(db_err)?,
            decision: row.try_get("decision").map_err(db_err)?,
            is_absolute: row.try_get("is_absolute").map_err(db_err)?,
        })
    })
    .collect()
}

async fn subject_entity_kinds(
    pool: &PgPool,
    subject_kind: SubjectKind,
    subject_id: Uuid,
) -> Result<Vec<String>, AppError> {
    match subject_kind {
        SubjectKind::Entity => sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
            .bind(subject_id)
            .fetch_all(pool)
            .await
            .map_err(db_err),
        SubjectKind::Group => sqlx::query_scalar(
            r#"WITH RECURSIVE subject_groups(group_id) AS (
                   SELECT $1::uuid
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN subject_groups sg ON sg.group_id = gh.parent_id
               )
               SELECT DISTINCT e.kind
               FROM group_members gm
               JOIN entities e ON e.id = gm.entity_id
               WHERE gm.group_id IN (SELECT group_id FROM subject_groups)"#,
        )
        .bind(subject_id)
        .fetch_all(pool)
        .await
        .map_err(db_err),
    }
}

async fn capability_names(pool: &PgPool, ids: &[Uuid]) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar("SELECT name FROM actions WHERE id = ANY($1::uuid[])")
        .bind(ids)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

async fn role_capability_names(pool: &PgPool, role_id: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        r#"SELECT DISTINCT c.name
           FROM (SELECT $1::uuid AS role_id) roles
           JOIN effective_role_actions() rc ON rc.role_id = roles.role_id
           JOIN actions c ON c.id = rc.capability_id"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

#[derive(Debug, Clone)]
struct RoleCapabilityAssignment {
    capability_name: String,
    object_kind: String,
    object_type: Option<String>,
}

async fn role_permission_assignments(
    pool: &PgPool,
    role_ids: &[Uuid],
) -> Result<Vec<RoleCapabilityAssignment>, AppError> {
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }

    use sqlx::Row;
    sqlx::query(
        r#"SELECT a.name AS capability_name,
                  CASE
                    WHEN pb.scope_mode = 'platform' THEN 'platform'
                    WHEN pb.scope_mode = 'tenant' THEN 'tenant'
                    WHEN pb.scope_mode IN ('object_kind', 'object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_kind
                    WHEN pb.scope_mode IN ('group', 'group_child_groups', 'group_descendant_groups') THEN 'group'
                    WHEN pb.scope_mode = 'object' THEN COALESCE(
                      target_resource.object_kind,
                      target_entity.object_kind,
                      target_group.object_kind,
                      target_tenant.object_kind,
                      'object'
                    )
                    ELSE 'unknown'
                  END AS object_kind,
                  CASE
                    WHEN pb.scope_mode IN ('object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_type
                    WHEN pb.scope_mode = 'object' THEN COALESCE(
                      target_resource.object_type,
                      target_entity.object_type
                    )
                    ELSE NULL
                  END AS object_type
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
           JOIN actions a ON a.id = pba.action_id
           LEFT JOIN LATERAL (
             SELECT 'resource'::text AS object_kind, 'resource:' || kind::text AS object_type
             FROM resources
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_resource ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'entity'::text AS object_kind, 'entity:' || kind::text AS object_type
             FROM entities
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_entity ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'group'::text AS object_kind
             FROM object_groups
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_group ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'tenant'::text AS object_kind
             FROM tenants
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_tenant ON TRUE
           WHERE rpb.role_id = ANY($1::uuid[])"#,
    )
    .bind(role_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(|row| {
        Ok(RoleCapabilityAssignment {
            capability_name: row.try_get("capability_name").map_err(db_err)?,
            object_kind: row.try_get("object_kind").map_err(db_err)?,
            object_type: row.try_get("object_type").map_err(db_err)?,
        })
    })
    .collect()
}

async fn permission_block_assignments(
    pool: &PgPool,
    permission_block_ids: &[Uuid],
) -> Result<Vec<RoleCapabilityAssignment>, AppError> {
    if permission_block_ids.is_empty() {
        return Ok(Vec::new());
    }

    use sqlx::Row;
    sqlx::query(
        r#"SELECT a.name AS capability_name,
                  CASE
                    WHEN pb.scope_mode = 'platform' THEN 'platform'
                    WHEN pb.scope_mode = 'tenant' THEN 'tenant'
                    WHEN pb.scope_mode IN ('object_kind', 'object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_kind
                    WHEN pb.scope_mode IN ('group', 'group_child_groups', 'group_descendant_groups') THEN 'group'
                    WHEN pb.scope_mode = 'object' THEN COALESCE(
                      target_resource.object_kind,
                      target_entity.object_kind,
                      target_group.object_kind,
                      target_tenant.object_kind,
                      'object'
                    )
                    ELSE 'unknown'
                  END AS object_kind,
                  CASE
                    WHEN pb.scope_mode IN ('object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_type
                    WHEN pb.scope_mode = 'object' THEN COALESCE(
                      target_resource.object_type,
                      target_entity.object_type
                    )
                    ELSE NULL
                  END AS object_type
           FROM permission_blocks pb
           JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
           JOIN actions a ON a.id = pba.action_id
           LEFT JOIN LATERAL (
             SELECT 'resource'::text AS object_kind, 'resource:' || kind::text AS object_type
             FROM resources
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_resource ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'entity'::text AS object_kind, 'entity:' || kind::text AS object_type
             FROM entities
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_entity ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'group'::text AS object_kind
             FROM object_groups
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_group ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'tenant'::text AS object_kind
             FROM tenants
             WHERE id = pb.object_id AND pb.scope_mode = 'object'
           ) target_tenant ON TRUE
           WHERE pb.id = ANY($1::uuid[])"#,
    )
    .bind(permission_block_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(|row| {
        Ok(RoleCapabilityAssignment {
            capability_name: row.try_get("capability_name").map_err(db_err)?,
            object_kind: row.try_get("object_kind").map_err(db_err)?,
            object_type: row.try_get("object_type").map_err(db_err)?,
        })
    })
    .collect()
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
