use super::*;
use sqlx::Row;

pub(super) async fn delete_orphaned_blocks(
    conn: &mut sqlx::SqliteConnection,
    block_ids: &[Uuid],
) -> Result<(), AppError> {
    if block_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"DELETE FROM permission_blocks AS pb WHERE pb.id IN (SELECT unhex(value) FROM json_each($1))
             AND pb.managed_by IS DISTINCT FROM 'config'
             AND NOT EXISTS (
                 SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id
             )
             AND NOT EXISTS (
                 SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id
             )"#,
    )
    .bind(crate::db::native::uuid_array_json(block_ids))
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn role_block_ids(
    conn: &mut sqlx::SqliteConnection,
    role_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1"#,
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn list_role_permission_blocks(
    pool: &sqlx::SqlitePool,
    role_id: Uuid,
) -> Result<Vec<RolePermissionBlock>, AppError> {
    sqlx::query_as::<_, RolePermissionBlock>(
        r#"SELECT pb.id,
                  rpb.role_id,
                  CASE
                    WHEN pb.scope_mode = 'group_direct_objects' THEN 'object_group_type'
                    WHEN pb.scope_mode = 'group_descendant_objects' THEN 'object_group_tree_type'
                    WHEN pb.scope_mode = 'group_child_groups' THEN 'object_group_child_kind'
                    WHEN pb.scope_mode = 'group_descendant_groups' THEN 'object_group_descendant_kind'
                    ELSE pb.scope_mode
                  END AS applies_to,
                  pb.object_id,
                  pb.object_kind,
                  pb.object_type,
                  pb.tenant_id,
                  pb.group_id,
                  pb.created_at,
                  pb.updated_at
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE rpb.role_id = $1
           ORDER BY pb.created_at, pb.id"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn list_permission_blocks_for_role(
    pool: &sqlx::SqlitePool,
    role_id: Uuid,
) -> Result<Vec<PermissionBlock>, AppError> {
    sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT pb.id,
                  pb.tenant_id,
                  pb.scope_mode,
                  pb.object_kind,
                  pb.object_type,
                  pb.object_id,
                  pb.group_id,
                  pb.effect,
                  pb.conditions,
                  pb.created_at,
                  pb.updated_at
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE rpb.role_id = $1
           ORDER BY pb.created_at, pb.id"#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn role_permission_block_capabilities(
    pool: &sqlx::SqlitePool,
    block_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"SELECT c.id, c.name, c.description, c.created_at, c.updated_at
           FROM actions c
           JOIN permission_block_actions pba ON pba.action_id = c.id
           WHERE pba.permission_block_id = $1
           ORDER BY c.name"#,
    )
    .bind(block_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn fetch_permission_block<'e, E: sqlx::Executor<'e, Database = sqlx::Sqlite>>(
    executor: E,
    id: Uuid,
) -> Result<PermissionBlock, AppError> {
    sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id,
                  effect, conditions, created_at, updated_at
           FROM permission_blocks
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(executor)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("permission block {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn list_permission_blocks(
    pool: &sqlx::SqlitePool,
    params: ListPermissionBlocks,
) -> Result<PermissionBlockList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, PermissionBlock>(
        r#"SELECT id, tenant_id, scope_mode, object_kind, object_type, object_id, group_id,
                  effect, conditions, created_at, updated_at, managed_by
           FROM permission_blocks
           WHERE ($1 IS NULL OR tenant_id = $1)
             AND ($2 IS NULL OR scope_mode = $2)
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(params.tenant_id)
    .bind(params.scope_mode.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM permission_blocks
           WHERE ($1 IS NULL OR tenant_id = $1)
             AND ($2 IS NULL OR scope_mode = $2)"#,
    )
    .bind(params.tenant_id)
    .bind(params.scope_mode)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(PermissionBlockList { items, total })
}

pub(super) async fn copy_role_permission_blocks(
    conn: &mut sqlx::SqliteConnection,
    target_role_id: Uuid,
    source_role_id: Uuid,
) -> Result<(), AppError> {
    let rows = sqlx::query(
        r#"SELECT pb.id, pb.tenant_id, pb.scope_mode, pb.object_kind, pb.object_type,
                  pb.object_id, pb.group_id, pb.effect, pb.conditions
           FROM role_permission_blocks rpb
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           JOIN roles r ON r.id = rpb.role_id AND r.deleted_at IS NULL
           WHERE rpb.role_id = $1"#,
    )
    .bind(source_role_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;

    for row in rows {
        let source_block_id: Uuid = row.try_get("id").map_err(db_err)?;
        let copied_block_id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO permission_blocks
                 (tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id"#,
        )
        .bind(row.try_get::<Option<Uuid>, _>("tenant_id").map_err(db_err)?)
        .bind(row.try_get::<String, _>("scope_mode").map_err(db_err)?)
        .bind(row.try_get::<Option<String>, _>("object_kind").map_err(db_err)?)
        .bind(row.try_get::<Option<String>, _>("object_type").map_err(db_err)?)
        .bind(row.try_get::<Option<Uuid>, _>("object_id").map_err(db_err)?)
        .bind(row.try_get::<Option<Uuid>, _>("group_id").map_err(db_err)?)
        .bind(row.try_get::<String, _>("effect").map_err(db_err)?)
        .bind(row.try_get::<Value, _>("conditions").map_err(db_err)?)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?;
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               SELECT $1, action_id
               FROM permission_block_actions
               WHERE permission_block_id = $2"#,
        )
        .bind(copied_block_id)
        .bind(source_block_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        sqlx::query(
            r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)"#,
        )
        .bind(target_role_id)
        .bind(copied_block_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    }

    Ok(())
}

pub(super) async fn purge_authz_references_for_ids(
    conn: &mut sqlx::SqliteConnection,
    ids: &[Uuid],
) -> Result<(), AppError> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query(r#"DELETE FROM permission_blocks WHERE object_id IN (SELECT unhex(value) FROM json_each($1))"#)
        .bind(crate::db::native::uuid_array_json(ids))
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    sqlx::query(r#"DELETE FROM direct_policies WHERE subject_id IN (SELECT unhex(value) FROM json_each($1))"#)
        .bind(crate::db::native::uuid_array_json(ids))
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    sqlx::query(r#"DELETE FROM role_assignments WHERE subject_id IN (SELECT unhex(value) FROM json_each($1))"#)
        .bind(crate::db::native::uuid_array_json(ids))
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub(super) async fn count_tenant_blocks(
    conn: &mut sqlx::SqliteConnection,
    unique_block_ids: &[Uuid],
    role_tenant_id: &Option<Uuid>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT COUNT(*)
               FROM permission_blocks
               WHERE id IN (SELECT unhex(value) FROM json_each($1))
                 AND tenant_id IS NOT DISTINCT FROM $2"#,
    )
    .bind(crate::db::native::uuid_array_json(unique_block_ids))
    .bind(role_tenant_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn link_role_block(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
    permission_block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
    )
    .bind(role_id)
    .bind(permission_block_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_allow_block(
    conn: &mut sqlx::SqliteConnection,
    scope_mode: &str,
    tenant_id: &Option<Uuid>,
    object_kind: &Option<&str>,
    object_type: &Option<&str>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(r#"INSERT INTO permission_blocks
             (scope_mode, tenant_id, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, 'allow', '{}')
           RETURNING id"#).bind(scope_mode).bind(tenant_id).bind(object_kind).bind(object_type).bind(object_id).bind(group_id).fetch_one(&mut *conn).await
}

pub(super) async fn link_block_action(
    conn: &mut sqlx::SqliteConnection,
    block_id: &Uuid,
    capability_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
    )
    .bind(block_id)
    .bind(capability_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn unlink_role_blocks(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
    block_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM role_permission_blocks WHERE role_id = $1 AND permission_block_id IN (SELECT unhex(value) FROM json_each($2))"#).bind(role_id).bind(crate::db::native::uuid_array_json(block_ids)).execute(&mut *conn).await.map(|result| result.rows_affected())
}

pub(super) async fn insert_legacy_allow_block(
    conn: &mut sqlx::SqliteConnection,
    scope_mode: &str,
    tenant_id: &Option<Uuid>,
    object_kind: &Option<String>,
    object_type: &Option<String>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(r#"INSERT INTO permission_blocks
             (scope_mode, tenant_id, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, 'allow', '{}')
           RETURNING id"#).bind(scope_mode).bind(tenant_id).bind(object_kind).bind(object_type).bind(object_id).bind(group_id).fetch_one(&mut *conn).await
}

pub(super) async fn insert_block_action(
    conn: &mut sqlx::SqliteConnection,
    block_id: &Uuid,
    capability_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
           VALUES ($1, $2)"#,
    )
    .bind(block_id)
    .bind(capability_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn insert_role_block(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
    block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
           VALUES ($1, $2)"#,
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_permission_block(
    conn: &mut sqlx::SqliteConnection,
    tenant_id: &Option<Uuid>,
    scope_mode: &str,
    object_kind: &Option<&str>,
    object_type: &Option<&str>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
    effect: &Effect,
    conditions: &Value,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(r#"INSERT INTO permission_blocks
             (tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id"#).bind(tenant_id).bind(scope_mode).bind(object_kind).bind(object_type).bind(object_id).bind(group_id).bind(effect).bind(conditions).fetch_one(&mut *conn).await
}

pub(super) async fn block_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM permission_blocks WHERE id = $1"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn block_is_referenced(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM role_permission_blocks WHERE permission_block_id = $1)
              OR EXISTS (SELECT 1 FROM direct_policies WHERE permission_block_id = $1)"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn remove_block(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM permission_blocks WHERE id = $1"#)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn role_linked_blocks(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT DISTINCT permission_block_id FROM role_permission_blocks WHERE role_id = $1"#,
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn purge_orphaned_blocks(
    conn: &mut sqlx::SqliteConnection,
    candidate_block_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM permission_blocks AS pb WHERE pb.id IN (SELECT unhex(value) FROM json_each($1))
                 AND pb.managed_by IS DISTINCT FROM 'config'
                 AND NOT EXISTS (
                     SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id
                 )"#).bind(crate::db::native::uuid_array_json(candidate_block_ids)).execute(&mut *conn).await.map(|result| result.rows_affected())
}

pub(super) async fn role_blocks_for_action(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
    cap_id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT rpb.permission_block_id
           FROM role_permission_blocks rpb
           JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
           WHERE rpb.role_id = $1 AND pba.action_id = $2"#,
    )
    .bind(role_id)
    .bind(cap_id)
    .fetch_all(&mut *conn)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_legacy_permission_block(
    conn: &mut sqlx::SqliteConnection,
    tenant_id: &Option<Uuid>,
    scope_mode: &str,
    object_kind: &Option<String>,
    object_type: &Option<String>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
    effect: &Effect,
    conditions: &Value,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(r#"INSERT INTO permission_blocks
                     (tenant_id, scope_mode, object_kind, object_type, object_id, group_id, effect, conditions)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   RETURNING id"#).bind(tenant_id).bind(scope_mode).bind(object_kind).bind(object_type).bind(object_id).bind(group_id).bind(effect).bind(conditions).fetch_one(&mut *conn).await
}

pub(super) async fn lock_block_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    permission_block_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM permission_blocks WHERE id = $1"#)
        .bind(permission_block_id)
        .fetch_optional(&mut *conn)
        .await
}
