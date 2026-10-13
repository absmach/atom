use super::*;

pub(super) async fn stamp_direct_policy(
    conn: &mut sqlx::PgConnection,
    policy_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE direct_policies SET managed_by = $2 WHERE id = $1")
        .bind(policy_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn direct_policy(
    conn: &mut sqlx::PgConnection,
    policy_id: Uuid,
) -> Result<DirectPolicyState, sqlx::Error> {
    sqlx::query_as::<_, DirectPolicyState>(
        r#"SELECT tenant_id, subject_kind, subject_id, permission_block_id
           FROM direct_policies
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(policy_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn insert_direct_policy(
    conn: &mut sqlx::PgConnection,
    policy_id: Uuid,
    policy_tenant_id: Option<Uuid>,
    policy_subject_kind: &SubjectKind,
    policy_subject_id: Uuid,
    policy_permission_block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"INSERT INTO direct_policies (id, tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#).bind(policy_id).bind(policy_tenant_id).bind(policy_subject_kind).bind(policy_subject_id).bind(policy_permission_block_id).execute(&mut *conn).await.map(|result| result.rows_affected())
}

pub(super) async fn stamp_assignment_rule(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE action_assignment_rules SET managed_by = $2 WHERE id = $1")
        .bind(id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn assignment_rule(
    conn: &mut sqlx::PgConnection,
    normalized_tenant_id: Option<Uuid>,
    normalized_entity_kind: &EntityKind,
    normalized_action_name: &str,
    normalized_object_kind: ObjectKind,
    normalized_object_type: &Option<String>,
) -> Result<Option<AssignmentRuleState>, sqlx::Error> {
    sqlx::query_as::<_, AssignmentRuleState>(
        r#"SELECT id, tenant_id, entity_kind, action_name, object_kind,
                  object_type, decision, is_absolute
           FROM action_assignment_rules
           WHERE tenant_id IS NOT DISTINCT FROM $1
             AND entity_kind = $2
             AND action_name = $3
             AND object_kind = $4
             AND object_type IS NOT DISTINCT FROM $5
           FOR UPDATE"#,
    )
    .bind(normalized_tenant_id)
    .bind(normalized_entity_kind)
    .bind(normalized_action_name)
    .bind(normalized_object_kind)
    .bind(normalized_object_type)
    .fetch_optional(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_assignment_rule(
    conn: &mut sqlx::PgConnection,
    normalized_tenant_id: Option<Uuid>,
    normalized_entity_kind: &EntityKind,
    normalized_action_name: &str,
    normalized_object_kind: ObjectKind,
    normalized_object_type: &Option<String>,
    normalized_decision: ActionAssignmentDecision,
    normalized_is_absolute: bool,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO action_assignment_rules
               (tenant_id, entity_kind, action_name, object_kind, object_type,
                decision, is_absolute, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(normalized_tenant_id)
    .bind(normalized_entity_kind)
    .bind(normalized_action_name)
    .bind(normalized_object_kind)
    .bind(normalized_object_type)
    .bind(normalized_decision)
    .bind(normalized_is_absolute)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn stamp_applicability(
    conn: &mut sqlx::PgConnection,
    action_id: Uuid,
    app_object_kind_as_str__: &str,
    app_object_type: &Option<String>,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE action_applicability
              SET managed_by = $4
            WHERE action_id = $1
              AND object_kind = $2
              AND object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(action_id)
    .bind(app_object_kind_as_str__)
    .bind(app_object_type)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_applicability(
    conn: &mut sqlx::PgConnection,
    action_id: Uuid,
    app_object_kind_as_str__: &str,
    app_object_type: &Option<String>,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO action_applicability (action_id, object_kind, object_type, managed_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(action_id)
    .bind(app_object_kind_as_str__)
    .bind(app_object_type)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn final_action_applicability(
    conn: &mut sqlx::PgConnection,
    action_id: Uuid,
) -> Result<Vec<ApplicabilityState>, sqlx::Error> {
    sqlx::query_as::<_, ApplicabilityState>(
        "SELECT object_kind, object_type FROM action_applicability WHERE action_id = $1",
    )
    .bind(action_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn action_applicability(
    conn: &mut sqlx::PgConnection,
    action_id: Uuid,
) -> Result<Vec<ApplicabilityState>, sqlx::Error> {
    sqlx::query_as::<_, ApplicabilityState>(
        r#"SELECT object_kind, object_type
           FROM action_applicability
           WHERE action_id = $1
           ORDER BY object_kind, object_type
           FOR UPDATE"#,
    )
    .bind(action_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn stamp_action(
    conn: &mut sqlx::PgConnection,
    action_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE actions SET managed_by = $2 WHERE id = $1")
        .bind(action_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn action(
    conn: &mut sqlx::PgConnection,
    name: &str,
) -> Result<ActionState, sqlx::Error> {
    sqlx::query_as::<_, ActionState>(
        "SELECT id, description FROM actions WHERE name = $1 FOR UPDATE",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn insert_action(
    conn: &mut sqlx::PgConnection,
    name: &str,
    capability_description: &Option<String>,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO actions (name, description, managed_by)
           VALUES ($1, $2, $3)
           ON CONFLICT (name) DO NOTHING"#,
    )
    .bind(name)
    .bind(capability_description)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn stamp_role_assignment(
    conn: &mut sqlx::PgConnection,
    assignment_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE role_assignments SET managed_by = $2 WHERE id = $1")
        .bind(assignment_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn role_assignment(
    conn: &mut sqlx::PgConnection,
    assignment_id: Uuid,
) -> Result<RoleAssignmentState, sqlx::Error> {
    sqlx::query_as::<_, RoleAssignmentState>(
        r#"SELECT tenant_id, subject_kind, subject_id, role_id
           FROM role_assignments
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(assignment_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn insert_role_assignment(
    conn: &mut sqlx::PgConnection,
    assignment_id: Uuid,
    assignment_tenant_id: Option<Uuid>,
    assignment_subject_kind: &SubjectKind,
    assignment_subject_id: Uuid,
    assignment_role_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_assignments (id, tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(assignment_id)
    .bind(assignment_tenant_id)
    .bind(assignment_subject_kind)
    .bind(assignment_subject_id)
    .bind(assignment_role_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn stamp_role(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE roles SET managed_by = $2 WHERE id = $1")
        .bind(role_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn link_role_block(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
    block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn block_tenant(
    conn: &mut sqlx::PgConnection,
    block_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM permission_blocks WHERE id = $1 FOR UPDATE",
    )
    .bind(block_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn persisted_role_tenant(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(role_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn role_blocks(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>("SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1 ORDER BY permission_block_id").bind(role_id).fetch_all(&mut *conn).await
}

pub(super) async fn role_matches(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
    role_name: &str,
    role_tenant_id: Option<Uuid>,
    role_description: &Option<String>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
                   SELECT 1 FROM roles
                   WHERE id = $1 AND name = $2
                     AND tenant_id IS NOT DISTINCT FROM $3
                     AND description IS NOT DISTINCT FROM $4
                     AND deleted_at IS NULL
               )"#,
    )
    .bind(role_id)
    .bind(role_name)
    .bind(role_tenant_id)
    .bind(role_description)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn insert_role(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
    role_name: &str,
    role_tenant_id: Option<Uuid>,
    role_description: &Option<String>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(role_id)
    .bind(role_name)
    .bind(role_tenant_id)
    .bind(role_description)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn role_tenant(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn stamp_permission_block(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE permission_blocks SET managed_by = $2 WHERE id = $1")
        .bind(block_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn link_block_action(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
    action_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
    )
    .bind(block_id)
    .bind(action_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn stored_block_actions(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>("SELECT action_id FROM permission_block_actions WHERE permission_block_id = $1 ORDER BY action_id").bind(block_id).fetch_all(&mut *conn).await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn permission_block_matches(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
    scope_tenant_id: Option<Uuid>,
    scope_mode_as_str__: &str,
    scope_object_kind: &Option<String>,
    scope_object_type: &Option<String>,
    scope_object_id: Option<Uuid>,
    scope_group_id: Option<Uuid>,
    block_effect: &Effect,
    conditions: &Value,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
                 SELECT 1 FROM permission_blocks
                 WHERE id = $1
                   AND tenant_id IS NOT DISTINCT FROM $2
                   AND scope_mode = $3
                   AND object_kind IS NOT DISTINCT FROM $4
                   AND object_type IS NOT DISTINCT FROM $5
                   AND object_id IS NOT DISTINCT FROM $6
                   AND group_id IS NOT DISTINCT FROM $7
                   AND effect = $8 AND conditions = $9
                 FOR UPDATE
               )"#,
    )
    .bind(block_id)
    .bind(scope_tenant_id)
    .bind(scope_mode_as_str__)
    .bind(scope_object_kind)
    .bind(scope_object_type)
    .bind(scope_object_id)
    .bind(scope_group_id)
    .bind(block_effect)
    .bind(conditions)
    .fetch_one(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_permission_block(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
    scope_tenant_id: Option<Uuid>,
    scope_mode_as_str__: &str,
    scope_object_kind: &Option<String>,
    scope_object_type: &Option<String>,
    scope_object_id: Option<Uuid>,
    scope_group_id: Option<Uuid>,
    block_effect: &Effect,
    conditions: &Value,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"INSERT INTO permission_blocks
             (id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO NOTHING"#).bind(block_id).bind(scope_tenant_id).bind(scope_mode_as_str__).bind(scope_object_kind).bind(scope_object_type).bind(scope_object_id).bind(scope_group_id).bind(block_effect).bind(conditions).execute(&mut *conn).await.map(|result| result.rows_affected())
}

pub(super) async fn block_actions(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>("SELECT action_id FROM permission_block_actions WHERE permission_block_id = $1 ORDER BY action_id").bind(block_id).fetch_all(&mut *conn).await
}

pub(super) async fn permission_block(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
) -> Result<Option<PermissionBlockState>, sqlx::Error> {
    sqlx::query_as::<_, PermissionBlockState>(
        r#"SELECT tenant_id, scope_mode, object_kind, object_type, object_id,
                  group_id, effect, conditions
           FROM permission_blocks
           WHERE id = $1"#,
    )
    .bind(block_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn action_id(
    conn: &mut sqlx::PgConnection,
    action_name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM actions WHERE name = $1")
        .bind(action_name)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn hierarchy_has_cycle(
    conn: &mut sqlx::PgConnection,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"WITH RECURSIVE ancestors(id) AS (
               SELECT $1::uuid
               UNION
               SELECT hierarchy.parent_id
               FROM object_group_hierarchy hierarchy
               JOIN ancestors ON hierarchy.child_id = ancestors.id
           )
           SELECT EXISTS (SELECT 1 FROM ancestors WHERE id = $2)"#,
    )
    .bind(parent_id)
    .bind(child_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn lock_parent_groups(
    conn: &mut sqlx::PgConnection,
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id FROM object_groups
           WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL
           ORDER BY id FOR UPDATE"#,
    )
    .bind(group_ids)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn parent_relation(
    conn: &mut sqlx::PgConnection,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Option<ParentRelation>, sqlx::Error> {
    sqlx::query_as::<_, ParentRelation>(
        r#"SELECT child.tenant_id AS child_tenant_id,
                  parent.tenant_id AS parent_tenant_id,
                  hierarchy.tenant_id AS hierarchy_tenant_id
           FROM object_group_hierarchy hierarchy
           JOIN object_groups child
             ON child.id = hierarchy.child_id AND child.deleted_at IS NULL
           JOIN object_groups parent
             ON parent.id = hierarchy.parent_id AND parent.deleted_at IS NULL
           WHERE hierarchy.child_id = $1 AND hierarchy.parent_id = $2"#,
    )
    .bind(child_id)
    .bind(parent_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn stamp_object_group(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE object_groups SET managed_by = $2 WHERE id = $1")
        .bind(group_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn object_group_parent(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT parent_id FROM object_group_hierarchy WHERE child_id = $1",
    )
    .bind(group_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn object_group_resources(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT resource_id FROM object_group_resources WHERE group_id = $1 ORDER BY resource_id",
    )
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn object_group_entities(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT entity_id FROM object_group_entities WHERE group_id = $1 ORDER BY entity_id",
    )
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn object_group_matches(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT name = $2
                  AND tenant_id IS NOT DISTINCT FROM $3
                  AND description IS NOT DISTINCT FROM $4
                  AND attributes = $5
                  AND status = 'active'
                  AND deleted_at IS NULL
           FROM object_groups
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(group_id)
    .bind(group_name)
    .bind(group_tenant_id)
    .bind(group_description)
    .bind(attributes)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn insert_object_group(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO object_groups
               (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(group_id)
    .bind(group_name)
    .bind(group_tenant_id)
    .bind(group_description)
    .bind(attributes)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn object_resource_tenants(
    conn: &mut sqlx::PgConnection,
    resource_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM resources WHERE id = ANY($1::uuid[])",
    )
    .bind(resource_ids)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn object_entity_tenants(
    conn: &mut sqlx::PgConnection,
    entity_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM entities WHERE id = ANY($1::uuid[])",
    )
    .bind(entity_ids)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn object_group_tenants(
    conn: &mut sqlx::PgConnection,
    group_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM groups WHERE id = ANY($1::uuid[])")
        .bind(group_ids)
        .fetch_all(&mut *conn)
        .await
}

pub(super) async fn stamp_resource(
    conn: &mut sqlx::PgConnection,
    resource_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE resources SET managed_by = $2 WHERE id = $1")
        .bind(resource_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn resource_matches(
    conn: &mut sqlx::PgConnection,
    resource_id: Uuid,
    resource_kind: &str,
    resource_name: &Option<String>,
    alias: &Option<String>,
    resource_tenant_id: Option<Uuid>,
    resource_owner_id: Option<Uuid>,
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT kind = $2
                  AND name IS NOT DISTINCT FROM $3
                  AND alias IS NOT DISTINCT FROM $4
                  AND tenant_id IS NOT DISTINCT FROM $5
                  AND owner_id IS NOT DISTINCT FROM $6
                  AND attributes = $7
                  AND deleted_at IS NULL
           FROM resources
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(resource_id)
    .bind(resource_kind)
    .bind(resource_name)
    .bind(alias)
    .bind(resource_tenant_id)
    .bind(resource_owner_id)
    .bind(attributes)
    .fetch_optional(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_resource(
    conn: &mut sqlx::PgConnection,
    resource_id: Uuid,
    resource_kind: &str,
    resource_name: &Option<String>,
    alias: &Option<String>,
    resource_tenant_id: Option<Uuid>,
    resource_owner_id: Option<Uuid>,
    attributes: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO resources
               (id, kind, name, alias, tenant_id, owner_id, attributes, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(resource_id)
    .bind(resource_kind)
    .bind(resource_name)
    .bind(alias)
    .bind(resource_tenant_id)
    .bind(resource_owner_id)
    .bind(attributes)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn resource_tenant(
    conn: &mut sqlx::PgConnection,
    resource_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM resources WHERE id = $1")
        .bind(resource_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn member_entity_tenants(
    conn: &mut sqlx::PgConnection,
    group_members: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM entities WHERE id = ANY($1::uuid[])",
    )
    .bind(group_members)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn principal_group_tenants(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM principal_groups WHERE id = $1")
        .bind(group_id)
        .fetch_all(&mut *conn)
        .await
}

pub(super) async fn stamp_group(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE principal_groups SET managed_by = $2 WHERE id = $1")
        .bind(group_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn group_members(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT entity_id FROM principal_group_members WHERE group_id = $1 ORDER BY entity_id",
    )
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn group_matches(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT name = $2
                  AND tenant_id IS NOT DISTINCT FROM $3
                  AND description IS NOT DISTINCT FROM $4
                  AND attributes = $5
                  AND status = 'active'
                  AND deleted_at IS NULL
           FROM principal_groups
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(group_id)
    .bind(group_name)
    .bind(group_tenant_id)
    .bind(group_description)
    .bind(attributes)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn insert_group(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO principal_groups (id, name, tenant_id, description, attributes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(group_id)
    .bind(group_name)
    .bind(group_tenant_id)
    .bind(group_description)
    .bind(attributes)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn stamp_access_token(
    conn: &mut sqlx::PgConnection,
    cred_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE credentials SET managed_by = $2 WHERE id = $1")
        .bind(cred_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn access_token_state(
    conn: &mut sqlx::PgConnection,
    cred_id: Uuid,
) -> Result<AccessTokenState, sqlx::Error> {
    sqlx::query_as::<_, AccessTokenState>(
        r#"SELECT entity_id, kind, status, identifier, secret_hash,
                  secret_lookup_hash, scoped, expires_at IS NULL AS no_expiry,
                  metadata
           FROM credentials
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(cred_id)
    .fetch_one(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_access_token(
    conn: &mut sqlx::PgConnection,
    cred_id: Uuid,
    entity_id: Uuid,
    credential_kind: CredentialKind,
    identifier: &str,
    secret_hash: Option<String>,
    secret_lookup_hash: Option<Vec<u8>>,
    metadata: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO credentials
             (id, entity_id, kind, identifier, secret_hash, secret_lookup_hash,
              scoped, expires_at, metadata, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, false, NULL, $7, $8)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(credential_kind)
    .bind(identifier)
    .bind(secret_hash)
    .bind(secret_lookup_hash)
    .bind(metadata)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn stamp_credential(
    conn: &mut sqlx::PgConnection,
    credential_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE credentials SET managed_by = $2 WHERE id = $1")
        .bind(credential_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn shared_key_credentials(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    credential_kind: CredentialKind,
) -> Result<Vec<SharedKeyState>, sqlx::Error> {
    sqlx::query_as::<_, SharedKeyState>("SELECT id, secret_hash, secret_lookup_hash, metadata, scoped, expires_at FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active' FOR UPDATE").bind(entity_id).bind(credential_kind).fetch_all(&mut *conn).await
}

pub(super) async fn password_credentials(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    credential_kind: CredentialKind,
) -> Result<Vec<PasswordState>, sqlx::Error> {
    sqlx::query_as::<_, PasswordState>("SELECT id, secret_hash, metadata, scoped, expires_at FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active' FOR UPDATE").bind(entity_id).bind(credential_kind).fetch_all(&mut *conn).await
}

pub(super) async fn stamp_entity(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE entities SET managed_by = $2 WHERE id = $1")
        .bind(entity_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn entity_state(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    entity_kind: &EntityKind,
    entity_name: &str,
    alias: &Option<String>,
    entity_tenant_id: Option<Uuid>,
    entity_status: &EntityStatus,
    attributes: &Value,
) -> Result<Option<EntityState>, sqlx::Error> {
    sqlx::query_as::<_, EntityState>(
        r#"SELECT kind, attributes,
                  kind = $2
                  AND name = $3
                  AND alias IS NOT DISTINCT FROM $4
                  AND tenant_id IS NOT DISTINCT FROM $5
                  AND status = $6
                  AND attributes = $7
                  AND deleted_at IS NULL AS matches
           FROM entities
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(entity_id)
    .bind(entity_kind)
    .bind(entity_name)
    .bind(alias)
    .bind(entity_tenant_id)
    .bind(entity_status)
    .bind(attributes)
    .fetch_optional(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_entity(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    entity_kind: &EntityKind,
    entity_name: &str,
    alias: &Option<String>,
    entity_tenant_id: Option<Uuid>,
    entity_status: &EntityStatus,
    attributes: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, alias, tenant_id, status, attributes, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(entity_id)
    .bind(entity_kind)
    .bind(entity_name)
    .bind(alias)
    .bind(entity_tenant_id)
    .bind(entity_status)
    .bind(attributes)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn entity_tenant(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM entities WHERE id = $1")
        .bind(entity_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn stamp_tenant(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("UPDATE tenants SET managed_by = $2 WHERE id = $1")
        .bind(tenant_id)
        .bind(managed_by_config)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn tenant_matches(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    tenant_name: &str,
    alias: &Option<String>,
    tenant_status: &TenantStatus,
    tenant_tags: &[String],
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT name = $2
                  AND alias IS NOT DISTINCT FROM $3
                  AND status = $4
                  AND tags = $5
                  AND attributes = $6
                  AND deleted_at IS NULL
           FROM tenants
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .bind(tenant_name)
    .bind(alias)
    .bind(tenant_status)
    .bind(tenant_tags)
    .bind(attributes)
    .fetch_optional(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_tenant(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    tenant_name: &str,
    alias: &Option<String>,
    tenant_status: &TenantStatus,
    tenant_tags: &[String],
    attributes: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO tenants (id, name, alias, status, tags, attributes, managed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(tenant_id)
    .bind(tenant_name)
    .bind(alias)
    .bind(tenant_status)
    .bind(tenant_tags)
    .bind(attributes)
    .bind(managed_by_config)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn purge_orphan_admin_block(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"DELETE FROM permission_blocks pb
                   WHERE pb.id = $1
                     AND NOT EXISTS (
                         SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id
                     )"#,
    )
    .bind(block_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn unlink_admin_block(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
    block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM role_permission_blocks WHERE role_id = $1 AND permission_block_id = $2",
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn link_admin_block(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
    replacement_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)"#,
    )
    .bind(role_id)
    .bind(replacement_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn link_admin_actions(
    conn: &mut sqlx::PgConnection,
    replacement_id: Uuid,
    desired_capabilities: &[String],
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               SELECT $1, id FROM actions WHERE name = ANY($2::text[])"#,
    )
    .bind(replacement_id)
    .bind(desired_capabilities)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_admin_block(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO permission_blocks
                  (tenant_id, scope_mode, effect, conditions, managed_by)
               VALUES ($1, 'tenant', 'allow', '{}'::jsonb, 'system:tenant-admin')
               RETURNING id"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn block_action_names(
    conn: &mut sqlx::PgConnection,
    block_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT a.name
                   FROM permission_block_actions pba
                   JOIN actions a ON a.id = pba.action_id
                   WHERE pba.permission_block_id = $1
                   ORDER BY a.name"#,
    )
    .bind(block_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn admin_block(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT pb.id
               FROM role_permission_blocks rpb
               JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
               WHERE rpb.role_id = $1
                 AND pb.managed_by = 'system:tenant-admin'
               ORDER BY pb.id
               LIMIT 1"#,
    )
    .bind(role_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn admin_roles(
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<AdminRoleState>, sqlx::Error> {
    sqlx::query_as::<_, AdminRoleState>(
        r#"SELECT id, tenant_id
           FROM roles
           WHERE managed_by = 'system:tenant-admin' AND deleted_at IS NULL
           ORDER BY id"#,
    )
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn insert_default_actions(
    conn: &mut sqlx::PgConnection,
    capabilities: &[String],
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO tenant_admin_default_actions (action_id)
           SELECT id FROM actions WHERE name = ANY($1::text[])"#,
    )
    .bind(capabilities)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn clear_default_actions(
    conn: &mut sqlx::PgConnection,
) -> Result<u64, sqlx::Error> {
    sqlx::query("DELETE FROM tenant_admin_default_actions")
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn missing_default_actions(
    conn: &mut sqlx::PgConnection,
    capabilities: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT requested.name
           FROM unnest($1::text[]) AS requested(name)
           WHERE NOT EXISTS (SELECT 1 FROM actions WHERE actions.name = requested.name)
           ORDER BY requested.name"#,
    )
    .bind(capabilities)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn entity_ids(conn: &mut sqlx::PgConnection) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM entities")
        .fetch_all(&mut *conn)
        .await
}

pub(super) async fn lock_configuration_tables(
    conn: &mut sqlx::PgConnection,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"LOCK TABLE
               tenants, entities, entity_emails, credentials, resources,
               principal_groups, principal_group_hierarchy, principal_group_members,
               object_groups, object_group_hierarchy, object_group_entities,
               object_group_resources, actions, action_applicability,
               action_assignment_rules, permission_blocks, permission_block_actions,
               roles, role_permission_blocks, role_assignments, direct_policies,
               protected_object_ids, tenant_admin_default_actions
           IN EXCLUSIVE MODE"#,
    )
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn lock_bootstrap(
    conn: &mut sqlx::PgConnection,
    lock_key: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}
