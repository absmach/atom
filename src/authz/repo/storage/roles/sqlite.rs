use super::*;
use sqlx::Row;

pub(super) async fn read_live_role_tenant_id(
    conn: &mut sqlx::SqliteConnection,
    role_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(role_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::not_found(format!("role {role_id} not found")))
}

pub(super) async fn lock_live_role_row(
    conn: &mut sqlx::SqliteConnection,
    role_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM roles
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL"#,
    )
    .bind(role_id)
    .bind(expected_tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("role {role_id} not found")));
    }
    Ok(())
}

pub(super) async fn get_role(pool: &sqlx::SqlitePool, id: Uuid) -> Result<Role, AppError> {
    sqlx::query_as::<_, Role>(
        r#"SELECT id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at
           FROM roles WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("role {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn list_roles(
    pool: &sqlx::SqlitePool,
    params: ListRoles,
) -> Result<RoleList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let q = params.q;
    let derived_kind = params.derived_kind;
    let deleted = params.deleted.as_str();
    let items = sqlx::query_as::<_, Role>(
        r#"SELECT id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at, managed_by
           FROM roles
           WHERE ($1 IS NULL OR tenant_id = $1)
             AND ($2 IS NULL OR name LIKE $2 OR description LIKE $2)
             AND (
               $3 IS NULL
               OR ($3 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
               OR ($3 = 'composite' AND FALSE)
               OR ($3 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
             )
             AND ($6 = 'all'
                  OR ($6 = 'live' AND deleted_at IS NULL)
                  OR ($6 = 'deleted' AND deleted_at IS NOT NULL))
           ORDER BY name LIMIT $4 OFFSET $5"#,
    )
    .bind(params.tenant_id)
    .bind(q.clone())
    .bind(derived_kind.clone())
    .bind(limit)
    .bind(offset)
    .bind(deleted)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM roles
           WHERE ($1 IS NULL OR tenant_id = $1)
             AND ($2 IS NULL OR name LIKE $2 OR description LIKE $2)
             AND (
               $3 IS NULL
               OR ($3 = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
               OR ($3 = 'composite' AND FALSE)
               OR ($3 = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
             )
             AND ($4 = 'all'
                  OR ($4 = 'live' AND deleted_at IS NULL)
                  OR ($4 = 'deleted' AND deleted_at IS NOT NULL))"#,
    )
    .bind(params.tenant_id)
    .bind(q)
    .bind(derived_kind)
    .bind(deleted)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(RoleList { items, total })
}

pub(super) async fn role_derived_kind(
    pool: &sqlx::SqlitePool,
    role_id: Uuid,
) -> Result<RoleDerivedKind, AppError> {
    let row = sqlx::query(
        r#"SELECT
              EXISTS (SELECT 1 FROM role_permission_blocks WHERE role_id = $1) AS has_permission_blocks,
              FALSE AS has_children"#,
    )
    .bind(role_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let has_permission_blocks: bool = row.try_get("has_permission_blocks").map_err(db_err)?;
    let has_children: bool = row.try_get("has_children").map_err(db_err)?;
    let has_simple_permissions = has_permission_blocks;
    Ok(match (has_simple_permissions, has_children) {
        (true, false) => RoleDerivedKind::Simple,
        (false, true) => RoleDerivedKind::Composite,
        (false, false) => RoleDerivedKind::Empty,
        (true, true) => {
            return Err(AppError::bad_request(
                "role cannot have both permissions and child roles",
            ))
        }
    })
}

pub(super) async fn insert_role(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
    name: &str,
    tenant_id: &Option<Uuid>,
    description: &Option<String>,
) -> Result<Role, sqlx::Error> {
    sqlx::query_as(r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, tenant_id, description, deleted_at, deleted_by, created_at, updated_at"#).bind(id).bind(name).bind(tenant_id).bind(description).fetch_one(&mut *conn).await
}

pub(super) async fn live_role_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(role_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn remove_role_links(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM role_permission_blocks WHERE role_id = $1"#)
        .bind(role_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn composite_role_candidates(
    pool: &sqlx::SqlitePool,
    unique_child_ids: &[Uuid],
) -> Result<Vec<CompositeRoleCandidate>, sqlx::Error> {
    sqlx::query_as(r#"SELECT r.id, r.tenant_id,
                  EXISTS (SELECT 1 FROM effective_role_actions rc WHERE rc.role_id = r.id) AS has_capabilities,
                  FALSE AS has_children
           FROM roles r
           WHERE r.id IN (SELECT unhex(value) FROM json_each($1)) AND r.deleted_at IS NULL"#).bind(crate::db::native::uuid_array_json(unique_child_ids)).fetch_all(pool).await
}

pub(super) async fn update_role_fields(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
    name: &Option<String>,
    description: &Option<String>,
) -> Result<Role, sqlx::Error> {
    sqlx::query_as(
        r#"UPDATE roles
           SET name        = COALESCE($2, name),
               description = COALESCE($3, description),
               updated_at  = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING id, name, tenant_id, description, deleted_at, deleted_by,
                     created_at, updated_at, managed_by"#,
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn role_is_live(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1 AND deleted_at IS NULL)"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn tombstone_role(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
    deleted_by: &Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE roles SET deleted_at = now(), deleted_by = $2
         WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .bind(deleted_by)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn deleted_role_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM roles WHERE id = $1 AND deleted_at IS NOT NULL"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn lock_deleted_role_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
    expected_tenant_id: &Option<Uuid>,
) -> Result<Option<(Option<Uuid>, bool)>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT r.tenant_id, (t.deleted_at IS NOT NULL)
         FROM roles r
         LEFT JOIN tenants t ON t.id = r.tenant_id
         WHERE r.id = $1
           AND r.tenant_id IS NOT DISTINCT FROM $2
           AND r.deleted_at IS NOT NULL"#,
    )
    .bind(id)
    .bind(expected_tenant_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn restore_role_fields(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE roles SET deleted_at = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn role_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM roles WHERE id = $1"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn purge_deleted_role_optional(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(
        r#"DELETE FROM roles WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn lock_role_row_optional(
    conn: &mut sqlx::SqliteConnection,
    role_id: &Uuid,
    role_tenant_id: &Option<Uuid>,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT id FROM roles
           WHERE id = $1 AND tenant_id IS NOT DISTINCT FROM $2"#,
    )
    .bind(role_id)
    .bind(role_tenant_id)
    .fetch_optional(&mut *conn)
    .await
}
