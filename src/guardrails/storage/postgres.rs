use super::*;
use sqlx::Row;
pub(super) async fn load_rules(conn: &mut sqlx::PgConnection) -> Result<Vec<Rule>, AppError> {
    sqlx::query(
        r#"SELECT tenant_id, entity_kind, action_name AS capability_name, object_kind, object_type, decision, is_absolute
           FROM action_assignment_rules"#,
    )
    .fetch_all(&mut *conn)
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
pub(super) async fn subject_entity_kinds(
    conn: &mut sqlx::PgConnection,
    subject_kind: SubjectKind,
    subject_id: Uuid,
) -> Result<Vec<String>, AppError> {
    match subject_kind {
        SubjectKind::Entity => sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
            .bind(subject_id)
            .fetch_all(&mut *conn)
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
        .fetch_all(&mut *conn)
        .await
        .map_err(db_err),
    }
}
pub(super) async fn capability_names(
    conn: &mut sqlx::PgConnection,
    ids: &[Uuid],
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar("SELECT name FROM actions WHERE id = ANY($1::uuid[])")
        .bind(ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_err)
}
pub(super) async fn role_capability_names(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        r#"SELECT DISTINCT c.name
           FROM (SELECT $1::uuid AS role_id) roles
           JOIN effective_role_actions() rc ON rc.role_id = roles.role_id
           JOIN actions c ON c.id = rc.capability_id"#,
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}
pub(super) async fn role_permission_assignments(
    conn: &mut sqlx::PgConnection,
    role_ids: &[Uuid],
) -> Result<Vec<RoleCapabilityAssignment>, AppError> {
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query(
        r#"SELECT a.name AS capability_name,
                  CASE
                    WHEN pb.scope_mode = 'platform' THEN 'platform'
                    WHEN pb.scope_mode = 'tenant' THEN 'tenant'
                    WHEN pb.scope_mode IN ('object_kind', 'object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_kind
                    WHEN pb.scope_mode IN ('group', 'group_child_groups', 'group_descendant_groups') THEN 'group'
                    WHEN pb.scope_mode = 'object' THEN COALESCE(target_registry.object_kind, 'object')
                    ELSE 'unknown'
                  END AS object_kind,
                  CASE
                    WHEN pb.scope_mode IN ('object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_type
                    WHEN pb.scope_mode = 'object' THEN COALESCE(target_resource.object_type, target_entity.object_type)
                    ELSE NULL
                  END AS object_type
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
           JOIN actions a ON a.id = pba.action_id
           LEFT JOIN protected_object_ids target_registry
             ON target_registry.id = pb.object_id AND pb.scope_mode = 'object'
           LEFT JOIN LATERAL (
             SELECT 'resource:' || kind::text AS object_type
             FROM resources
             WHERE id = pb.object_id AND target_registry.source_table = 'resources'
           ) target_resource ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'entity:' || kind::text AS object_type
             FROM entities
             WHERE id = pb.object_id AND target_registry.source_table = 'entities'
           ) target_entity ON TRUE
           WHERE rpb.role_id = ANY($1::uuid[])"#,
    )
    .bind(role_ids)
    .fetch_all(&mut *conn)
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
pub(super) async fn permission_block_assignments(
    conn: &mut sqlx::PgConnection,
    permission_block_ids: &[Uuid],
) -> Result<Vec<RoleCapabilityAssignment>, AppError> {
    if permission_block_ids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query(
        r#"SELECT a.name AS capability_name,
                  CASE
                    WHEN pb.scope_mode = 'platform' THEN 'platform'
                    WHEN pb.scope_mode = 'tenant' THEN 'tenant'
                    WHEN pb.scope_mode IN ('object_kind', 'object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_kind
                    WHEN pb.scope_mode IN ('group', 'group_child_groups', 'group_descendant_groups') THEN 'group'
                    WHEN pb.scope_mode = 'object' THEN COALESCE(target_registry.object_kind, 'object')
                    ELSE 'unknown'
                  END AS object_kind,
                  CASE
                    WHEN pb.scope_mode IN ('object_type', 'group_direct_objects', 'group_descendant_objects') THEN pb.object_type
                    WHEN pb.scope_mode = 'object' THEN COALESCE(target_resource.object_type, target_entity.object_type)
                    ELSE NULL
                  END AS object_type
           FROM permission_blocks pb
           JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
           JOIN actions a ON a.id = pba.action_id
           LEFT JOIN protected_object_ids target_registry
             ON target_registry.id = pb.object_id AND pb.scope_mode = 'object'
           LEFT JOIN LATERAL (
             SELECT 'resource:' || kind::text AS object_type
             FROM resources
             WHERE id = pb.object_id AND target_registry.source_table = 'resources'
           ) target_resource ON TRUE
           LEFT JOIN LATERAL (
             SELECT 'entity:' || kind::text AS object_type
             FROM entities
             WHERE id = pb.object_id AND target_registry.source_table = 'entities'
           ) target_entity ON TRUE
           WHERE pb.id = ANY($1::uuid[])"#,
    )
    .bind(permission_block_ids)
    .fetch_all(&mut *conn)
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
pub(super) async fn role_recipients(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Vec<RoleRecipients>, AppError> {
    sqlx::query_as::<_, RoleRecipients>(
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
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}
pub(super) async fn inherited_group_grants(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> Result<Vec<InheritedGroupGrants>, AppError> {
    sqlx::query_as::<_, InheritedGroupGrants>(
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
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}
pub(super) async fn assignment_recipients(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Vec<AssignmentRecipients>, AppError> {
    sqlx::query_as::<_, AssignmentRecipients>(
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
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}
pub(super) async fn entity_kinds(
    conn: &mut sqlx::PgConnection,
    ids: &[Uuid],
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar("SELECT kind FROM entities WHERE id = ANY($1::uuid[])")
        .bind(ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_err)
}
pub(super) async fn entity_kind(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)
}
