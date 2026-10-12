use super::*;

pub(super) async fn fetch_resource<'e, E: sqlx::Executor<'e, Database = sqlx::Postgres>>(
    executor: E,
    id: Uuid,
) -> Result<Resource, AppError> {
    sqlx::query_as::<_, Resource>(
        "SELECT id, kind, name, alias, tenant_id, owner_id, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by, revision FROM resources WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(executor)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn get_resource_object_groups(
    pool: &sqlx::PgPool,
    resource_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT grp.group_id
           FROM group_resource_parents grp
           JOIN object_groups g ON g.id = grp.group_id AND g.deleted_at IS NULL
           WHERE grp.resource_id = $1
           ORDER BY grp.created_at, grp.group_id"#,
    )
    .bind(resource_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn list_capabilities(
    pool: &sqlx::PgPool,
    params: ListCapabilities,
) -> Result<crate::models::capability::CapabilityList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let items = sqlx::query_as::<_, Capability>(
        r#"SELECT id, name, description, created_at, updated_at, managed_by FROM actions c
           WHERE (
               $1::text IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM action_applicability ca
                   WHERE ca.action_id = c.id
                     AND ca.object_kind = $1
                     AND ($2::text IS NULL OR ca.object_type IS NULL OR ca.object_type = $2)
               )
           )
           ORDER BY name LIMIT $3 OFFSET $4"#,
    )
    .bind(&params.object_kind)
    .bind(&params.object_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM actions c
           WHERE (
               $1::text IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM action_applicability ca
                   WHERE ca.action_id = c.id
                     AND ca.object_kind = $1
                     AND ($2::text IS NULL OR ca.object_type IS NULL OR ca.object_type = $2)
               )
           )"#,
    )
    .bind(&params.object_kind)
    .bind(&params.object_type)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(crate::models::capability::CapabilityList { items, total })
}

pub(super) async fn lock_group_hierarchy(conn: &mut sqlx::PgConnection) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('atom:group-hierarchy', 0))")
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub(super) async fn alias_object_id(
    pool: &sqlx::PgPool,
    tenant_id: Option<Uuid>,
    class: AliasObjectClass,
    object_alias: &str,
) -> Result<Option<Uuid>, AppError> {
    let sql = match class {
        AliasObjectClass::Entity => {
            "SELECT id FROM entities \
             WHERE tenant_id IS NOT DISTINCT FROM $1::uuid \
               AND lower(alias) = $2 \
               AND deleted_at IS NULL"
        }
        AliasObjectClass::Resource => {
            "SELECT id FROM resources \
             WHERE tenant_id IS NOT DISTINCT FROM $1::uuid \
               AND lower(alias) = $2 \
               AND deleted_at IS NULL"
        }
    };

    sqlx::query_scalar::<_, Uuid>(sql)
        .bind(tenant_id)
        .bind(object_alias)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

pub(super) async fn active_tenant_optional(
    pool: &sqlx::PgPool,
    id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT id FROM tenants
                   WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn tenant_by_alias_optional(
    pool: &sqlx::PgPool,
    alias: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT id FROM tenants
                   WHERE lower(alias) = lower($1)
                     AND status = 'active'
                     AND deleted_at IS NULL"#,
    )
    .bind(alias)
    .fetch_optional(pool)
    .await
}

pub(super) async fn resource_tenant_optional(
    conn: &mut sqlx::PgConnection,
    resource_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(resource_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn resource_group_boundary_optional(
    conn: &mut sqlx::PgConnection,
    resource_id: &Uuid,
    group_id: &Uuid,
    resource_tenant_id: &Option<Uuid>,
) -> Result<Option<ResourceGroupBoundary>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT r.tenant_id AS resource_tenant_id, g.tenant_id AS group_tenant_id
           FROM resources r
           CROSS JOIN object_groups g
           WHERE r.id = $1 AND g.id = $2
             AND r.tenant_id IS NOT DISTINCT FROM $3
             AND r.deleted_at IS NULL
             AND g.deleted_at IS NULL
           FOR UPDATE OF r, g"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .bind(resource_tenant_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn insert_resource_membership(
    conn: &mut sqlx::PgConnection,
    group_id: &Uuid,
    resource_id: &Uuid,
    tenant_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO object_group_resources (group_id, resource_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (group_id, resource_id) DO NOTHING"#,
    )
    .bind(group_id)
    .bind(resource_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn lock_resource_optional(
    conn: &mut sqlx::PgConnection,
    resource_id: &Uuid,
    tenant_id: &Option<Uuid>,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT id FROM resources
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL
           FOR UPDATE"#,
    )
    .bind(resource_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn resource_membership_groups(
    conn: &mut sqlx::PgConnection,
    resource_id: &Uuid,
    group_id: &Option<Uuid>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT group_id FROM object_group_resources
           WHERE resource_id = $1 AND ($2::uuid IS NULL OR group_id = $2)
           ORDER BY group_id"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn remove_resource_memberships(
    conn: &mut sqlx::PgConnection,
    resource_id: &Uuid,
    group_id: &Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"DELETE FROM object_group_resources
           WHERE resource_id = $1 AND ($2::uuid IS NULL OR group_id = $2)"#,
    )
    .bind(resource_id)
    .bind(group_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn activate_human_membership(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Uuid,
    member_id: &Uuid,
) -> Result<u64, sqlx::Error> {
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
    .bind(member_id)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn object_group_tenant_optional(
    conn: &mut sqlx::PgConnection,
    group_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT tenant_id FROM object_groups WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(group_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn count_entities(
    pool: &sqlx::PgPool,
    unique_entity_ids: &[Uuid],
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT COUNT(*) FROM entities WHERE id = ANY($1::uuid[])"#)
        .bind(unique_entity_ids)
        .fetch_one(pool)
        .await
}

pub(super) async fn group_tenant_optional(
    pool: &sqlx::PgPool,
    group_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM groups WHERE id = $1"#)
        .bind(group_id)
        .fetch_optional(pool)
        .await
}

pub(super) async fn group_tenants(
    conn: &mut sqlx::PgConnection,
    group_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM groups WHERE id = ANY($1::uuid[])"#)
        .bind(group_ids)
        .fetch_all(&mut *conn)
        .await
}

pub(super) async fn descendant_groups(
    conn: &mut sqlx::PgConnection,
    root_group_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT id FROM UNNEST($1::uuid[]) AS root(id)
               UNION
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
           )
           SELECT id FROM target_groups"#,
    )
    .bind(root_group_ids)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn lock_object_groups(
    conn: &mut sqlx::PgConnection,
    closure: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT id FROM object_groups WHERE id = ANY($1) ORDER BY id FOR UPDATE"#)
        .bind(closure)
        .fetch_all(&mut *conn)
        .await
}

pub(super) async fn lock_principal_groups(
    conn: &mut sqlx::PgConnection,
    closure: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT id FROM principal_groups WHERE id = ANY($1) ORDER BY id FOR UPDATE"#,
    )
    .bind(closure)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn group_member_ids(
    conn: &mut sqlx::PgConnection,
    closure: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT DISTINCT entity_id FROM group_members WHERE group_id = ANY($1)"#)
        .bind(closure)
        .fetch_all(&mut *conn)
        .await
}

pub(super) async fn lock_tenant_optional(
    conn: &mut sqlx::PgConnection,
    tenant_id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT id FROM tenants WHERE id = $1 FOR UPDATE"#)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
}
