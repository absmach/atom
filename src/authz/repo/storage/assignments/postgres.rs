use super::*;
use sqlx::Row;

pub(super) async fn read_live_subject_tenant_id(
    conn: &mut sqlx::PgConnection,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let subject_tenant_id: Option<Option<Uuid>> = match subject_kind {
        SubjectKind::Entity => sqlx::query_scalar(
            r#"SELECT tenant_id FROM entities
                   WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
        )
        .bind(subject_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?,
        SubjectKind::Group => sqlx::query_scalar(
            r#"SELECT tenant_id FROM principal_groups
                   WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
        )
        .bind(subject_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?,
    };
    let Some(subject_tenant_id) = subject_tenant_id else {
        return Err(AppError::bad_request(
            "assignment references a deleted, disabled, or unknown subject",
        ));
    };
    Ok(subject_tenant_id)
}

pub(super) async fn lock_live_subject_row(
    conn: &mut sqlx::PgConnection,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let table = match subject_kind {
        SubjectKind::Entity => "entities",
        SubjectKind::Group => "principal_groups",
    };
    let sql = format!(
        r#"SELECT id FROM {table}
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status = 'active'
             AND deleted_at IS NULL
           FOR UPDATE"#
    );
    let locked: Option<Uuid> = sqlx::query_scalar(&sql)
        .bind(subject_id)
        .bind(expected_tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::bad_request(
            "assignment subject changed during validation",
        ));
    }
    Ok(())
}

pub(super) async fn sync_tenant_membership_for_policy(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
           SELECT $1, $2, 'active'
           WHERE EXISTS (
               SELECT 1 FROM entities
               WHERE id = $2
                 AND kind = 'human'
                 AND status = 'active'
                 AND deleted_at IS NULL
           )
           ON CONFLICT (tenant_id, entity_id)
           DO UPDATE SET status = 'active'"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;

    Ok(())
}

pub(super) async fn get_policy(pool: &sqlx::PgPool, id: Uuid) -> Result<PolicyBinding, AppError> {
    sqlx::query_as::<_, PolicyBinding>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions, created_at
           FROM effective_access_edges() WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("policy {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn list_role_assignments(
    pool: &sqlx::PgPool,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, RoleAssignment>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at, managed_by
           FROM role_assignments
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR role_id = $4)
             AND EXISTS (SELECT 1 FROM roles r WHERE r.id = role_assignments.role_id AND r.deleted_at IS NULL)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = role_assignments.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = role_assignments.subject_id AND sg.deleted_at IS NULL))
             )
           ORDER BY created_at DESC
           LIMIT $5 OFFSET $6"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind.clone())
    .bind(params.subject_id)
    .bind(params.role_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM role_assignments
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR role_id = $4)
             AND EXISTS (SELECT 1 FROM roles r WHERE r.id = role_assignments.role_id AND r.deleted_at IS NULL)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = role_assignments.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = role_assignments.subject_id AND sg.deleted_at IS NULL))
             )"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind)
    .bind(params.subject_id)
    .bind(params.role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleAssignmentList { items, total })
}

pub(super) async fn get_role_assignment(
    pool: &sqlx::PgPool,
    id: Uuid,
) -> Result<RoleAssignment, AppError> {
    sqlx::query_as::<_, RoleAssignment>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at
           FROM role_assignments
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("role assignment {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn get_direct_policy(
    pool: &sqlx::PgPool,
    id: Uuid,
) -> Result<DirectPolicy, AppError> {
    sqlx::query_as::<_, DirectPolicy>(
        r#"SELECT id, tenant_id, subject_kind, subject_id, permission_block_id, created_at
           FROM direct_policies
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("direct policy {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn subject_role_assignments(
    pool: &sqlx::PgPool,
    params: SubjectRoleAssignmentsQuery,
) -> Result<SubjectRoleAssignmentList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let q = params.q;
    let derived_kind = params.derived_kind;
    let rows = sqlx::query(
        r#"SELECT
             pb.id AS policy_id,
             pb.tenant_id AS policy_tenant_id,
             pb.subject_kind,
             pb.subject_id,
             pb.grant_kind,
             pb.grant_id,
             pb.scope_kind AS policy_scope_kind,
             pb.scope_ref AS policy_scope_ref,
             pb.effect,
             pb.conditions,
             pb.created_at AS policy_created_at,
             r.id AS role_id,
             r.name AS role_name,
             r.tenant_id AS role_tenant_id,
             r.description AS role_description,
             r.created_at AS role_created_at,
             r.updated_at AS role_updated_at
           FROM effective_access_edges() pb
           JOIN roles r ON pb.grant_kind = 'role' AND pb.grant_id = r.id
           WHERE ($1::uuid IS NULL OR pb.tenant_id = $1)
             AND pb.subject_kind = $2
             AND pb.subject_id = $3
             AND ($4::text IS NULL OR r.name ILIKE $4 OR r.description ILIKE $4)
             AND (
               $5::text IS NULL
               OR ($5 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
               OR ($5 = 'composite' AND FALSE)
               OR ($5 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
             )
           ORDER BY pb.created_at DESC
           LIMIT $6 OFFSET $7"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind.clone())
    .bind(params.subject_id)
    .bind(q.clone())
    .bind(derived_kind.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let items = rows
        .into_iter()
        .map(|row| {
            Ok(SubjectRoleAssignment {
                policy: PolicyBinding {
                    id: row.try_get("policy_id").map_err(db_err)?,
                    tenant_id: row.try_get("policy_tenant_id").map_err(db_err)?,
                    subject_kind: row.try_get("subject_kind").map_err(db_err)?,
                    subject_id: row.try_get("subject_id").map_err(db_err)?,
                    grant_kind: row.try_get("grant_kind").map_err(db_err)?,
                    grant_id: row.try_get("grant_id").map_err(db_err)?,
                    scope_kind: row.try_get("policy_scope_kind").map_err(db_err)?,
                    scope_ref: row.try_get("policy_scope_ref").map_err(db_err)?,
                    effect: row.try_get("effect").map_err(db_err)?,
                    conditions: row.try_get("conditions").map_err(db_err)?,
                    created_at: row.try_get("policy_created_at").map_err(db_err)?,
                },
                role: Role {
                    id: row.try_get("role_id").map_err(db_err)?,
                    name: row.try_get("role_name").map_err(db_err)?,
                    tenant_id: row.try_get("role_tenant_id").map_err(db_err)?,
                    description: row.try_get("role_description").map_err(db_err)?,
                    deleted_at: None,
                    deleted_by: None,
                    created_at: row.try_get("role_created_at").map_err(db_err)?,
                    updated_at: row.try_get("role_updated_at").map_err(db_err)?,
                    // Explain view; only surfaces role identity, not lifecycle
                    // metadata. Leave managed_by unset — the UI reads it via
                    // list_roles / get_role, not this SELECT.
                    managed_by: None,
                },
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM effective_access_edges() pb
           JOIN roles r ON pb.grant_kind = 'role' AND pb.grant_id = r.id
           WHERE ($1::uuid IS NULL OR pb.tenant_id = $1)
             AND pb.subject_kind = $2
             AND pb.subject_id = $3
             AND ($4::text IS NULL OR r.name ILIKE $4 OR r.description ILIKE $4)
             AND (
               $5::text IS NULL
               OR ($5 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
               OR ($5 = 'composite' AND FALSE)
               OR ($5 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = r.id
                  ))
             )"#,
    )
    .bind(params.tenant_id)
    .bind(params.subject_kind)
    .bind(params.subject_id)
    .bind(q)
    .bind(derived_kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(SubjectRoleAssignmentList { items, total })
}

/// Resolves the object's own object groups and every ancestor of those
/// groups, carrying `(object_kind, object_type)` in the shape a permission
/// block records it, so a block's declared scope can be compared the way the
/// PDP compares it (`grant_scope_matches`, migration 001).
///
/// Anchored at the object and walks *upward*, so cost is bounded by tree
/// depth, not block count. The membership joins return every matching row —
/// an object in several groups must produce a match for each.
const DIRECT_POLICY_OBJECT_CTE: &str = r#"WITH RECURSIVE object_parent_groups(group_id, object_kind, object_type) AS (
             SELECT oge.group_id, 'entity'::text, 'entity:' || e.kind
             FROM object_group_entities oge
             JOIN entities e ON e.id = oge.entity_id
             WHERE oge.entity_id = $5::uuid AND e.deleted_at IS NULL
             UNION ALL
             SELECT ogr.group_id, 'resource'::text, 'resource:' || r.kind
             FROM object_group_resources ogr
             JOIN resources r ON r.id = ogr.resource_id
             WHERE ogr.resource_id = $5::uuid AND r.deleted_at IS NULL
             UNION ALL
             SELECT ogh.parent_id, 'group'::text, 'group:object'
             FROM object_group_hierarchy ogh
             JOIN object_groups og ON og.id = ogh.child_id
             WHERE ogh.child_id = $5::uuid AND og.deleted_at IS NULL
           ),
           object_ancestor_groups(group_id, object_kind, object_type) AS (
             SELECT ogh.parent_id, opg.object_kind, opg.object_type
             FROM object_parent_groups opg
             JOIN object_group_hierarchy ogh ON ogh.child_id = opg.group_id
             UNION ALL
             SELECT ogh.parent_id, oag.object_kind, oag.object_type
             FROM object_ancestor_groups oag
             JOIN object_group_hierarchy ogh ON ogh.child_id = oag.group_id
           )"#;

/// The reverse-lookup predicate: does this policy's permission block name the
/// object in `$5`, narrowed by the optional `$6` / `$7` co-filters?
///
/// Only scope modes that name a specific object, or a group object directly /
/// through a group hierarchy, are considered. A `group_descendant_objects` block
/// matches through *strict* ancestors of the object's own group, mirroring the
/// PDP: an object directly in the block's group is the `group_direct_objects`
/// case, not the descendant case.
const DIRECT_POLICY_OBJECT_PREDICATE: &str = r#"($5::uuid IS NULL OR EXISTS (
               SELECT 1 FROM permission_blocks pb
               WHERE pb.id = direct_policies.permission_block_id
                 AND ($6::text IS NULL OR pb.object_kind IS NULL OR pb.object_kind = $6)
                 AND ($7::text IS NULL OR pb.object_type IS NULL OR pb.object_type = $7)
                 AND (
                   (pb.scope_mode = 'object' AND pb.object_id = $5)
                   OR (pb.scope_mode = 'group'
                       AND pb.group_id = $5
                       AND ($6::text IS NULL OR $6 = 'group')
                       AND ($7::text IS NULL OR $7 = 'group:object')
                       AND EXISTS (
                         SELECT 1 FROM object_groups og
                         WHERE og.id = $5
                           AND og.deleted_at IS NULL))
                   OR (pb.scope_mode = 'group_direct_objects' AND EXISTS (
                         SELECT 1 FROM object_parent_groups opg
                         WHERE opg.group_id = pb.group_id
                           AND opg.object_kind = pb.object_kind
                           AND opg.object_type = pb.object_type))
                   OR (pb.scope_mode = 'group_descendant_objects' AND EXISTS (
                         SELECT 1 FROM object_ancestor_groups oag
                         WHERE oag.group_id = pb.group_id
                           AND oag.object_kind = pb.object_kind
                           AND oag.object_type = pb.object_type))
                   OR (pb.scope_mode = 'group_child_groups'
                       AND ($6::text IS NULL OR $6 = 'group')
                       AND ($7::text IS NULL OR $7 = 'group:object')
                       AND EXISTS (
                         SELECT 1 FROM object_parent_groups opg
                         WHERE opg.group_id = pb.group_id
                           AND opg.object_kind = 'group'))
                   OR (pb.scope_mode = 'group_descendant_groups'
                       AND ($6::text IS NULL OR $6 = 'group')
                       AND ($7::text IS NULL OR $7 = 'group:object')
                       AND (
                         EXISTS (
                           SELECT 1 FROM object_parent_groups opg
                           WHERE opg.group_id = pb.group_id
                             AND opg.object_kind = 'group')
                         OR EXISTS (
                           SELECT 1 FROM object_ancestor_groups oag
                           WHERE oag.group_id = pb.group_id
                             AND oag.object_kind = 'group')))
                 )
             ))"#;

pub(super) async fn list_direct_policies(
    pool: &sqlx::PgPool,
    params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let object_type = params.object_type.clone();
    let items_sql = format!(
        r#"{DIRECT_POLICY_OBJECT_CTE}
           SELECT id, tenant_id, subject_kind, subject_id, permission_block_id, created_at, managed_by
           FROM direct_policies
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR permission_block_id = $4)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = direct_policies.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = direct_policies.subject_id AND sg.deleted_at IS NULL))
             )
             AND {DIRECT_POLICY_OBJECT_PREDICATE}
           ORDER BY created_at DESC
           LIMIT $8 OFFSET $9"#
    );
    let items = sqlx::query_as::<_, DirectPolicy>(&items_sql)
        .bind(params.tenant_id)
        .bind(params.subject_kind.clone())
        .bind(params.subject_id)
        .bind(params.permission_block_id)
        .bind(params.object_id)
        .bind(params.object_kind)
        .bind(&object_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    let total_sql = format!(
        r#"{DIRECT_POLICY_OBJECT_CTE}
           SELECT COUNT(*)
           FROM direct_policies
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR subject_kind = $2)
             AND ($3::uuid IS NULL OR subject_id = $3)
             AND ($4::uuid IS NULL OR permission_block_id = $4)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = direct_policies.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = direct_policies.subject_id AND sg.deleted_at IS NULL))
             )
             AND {DIRECT_POLICY_OBJECT_PREDICATE}"#
    );
    let total = sqlx::query_scalar(&total_sql)
        .bind(params.tenant_id)
        .bind(params.subject_kind)
        .bind(params.subject_id)
        .bind(params.permission_block_id)
        .bind(params.object_id)
        .bind(params.object_kind)
        .bind(&object_type)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    Ok(DirectPolicyList { items, total })
}

pub(super) async fn insert_entity_role_assignment(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Option<Uuid>,
    member_id: &Uuid,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_assignments
                 (tenant_id, subject_kind, subject_id, role_id)
               VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(member_id)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_policy_role_assignment(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    grant_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_assignments
                     (id, tenant_id, subject_kind, subject_id, role_id)
                   VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(grant_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_policy_direct_assignment(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    permission_block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO direct_policies
                     (id, tenant_id, subject_kind, subject_id, permission_block_id)
                   VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(permission_block_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_role_assignment(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    role_id: &Uuid,
) -> Result<RoleAssignment, sqlx::Error> {
    sqlx::query_as(
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, $2, $3, $4)
           RETURNING id, tenant_id, subject_kind, subject_id, role_id, created_at"#,
    )
    .bind(tenant_id)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(role_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn insert_missing_role_assignment(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    role_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           SELECT $1, $2, $3, $4
           WHERE NOT EXISTS (
               SELECT 1 FROM role_assignments
               WHERE tenant_id IS NOT DISTINCT FROM $1
                 AND subject_kind = $2
                 AND subject_id = $3
                 AND role_id = $4
           )"#,
    )
    .bind(tenant_id)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(role_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn role_assignment_tenant_optional(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM role_assignments WHERE id = $1"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn remove_role_assignment(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM role_assignments WHERE id = $1"#)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn insert_direct_policy(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    permission_block_id: &Uuid,
) -> Result<DirectPolicy, sqlx::Error> {
    sqlx::query_as(
        r#"INSERT INTO direct_policies
             (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, $2, $3, $4)
           RETURNING id, tenant_id, subject_kind, subject_id, permission_block_id, created_at"#,
    )
    .bind(tenant_id)
    .bind(subject_kind)
    .bind(subject_id)
    .bind(permission_block_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn direct_policy_tenant_optional(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM direct_policies WHERE id = $1"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn remove_direct_policy_optional(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(r#"DELETE FROM direct_policies WHERE id = $1 RETURNING permission_block_id"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn live_entity_tenant_optional(
    conn: &mut sqlx::PgConnection,
    subject_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM entities WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(subject_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn active_membership(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Uuid,
    subject_id: &Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
                         SELECT 1 FROM tenant_memberships
                         WHERE tenant_id = $1 AND entity_id = $2 AND status = 'active'
                       )"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn live_principal_group_tenant_optional(
    conn: &mut sqlx::PgConnection,
    subject_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT tenant_id FROM principal_groups WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(subject_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn remove_direct_policy(
    conn: &mut sqlx::PgConnection,
    id: &Uuid,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(r#"DELETE FROM direct_policies WHERE id = $1 RETURNING permission_block_id"#)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
}

pub(super) async fn role_entity_subjects(
    conn: &mut sqlx::PgConnection,
    role_id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT subject_id FROM role_assignments WHERE role_id = $1 AND subject_kind = 'entity'"#,
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn role_group_subjects(
    conn: &mut sqlx::PgConnection,
    role_id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT subject_id FROM role_assignments WHERE role_id = $1 AND subject_kind = 'group'"#,
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await
}
