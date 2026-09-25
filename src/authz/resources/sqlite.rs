//! SQLite implementation of the resource repository contract declared in
//! [`super`] (`create_resource_with_audit`, `get_resource`, `list_resources`, …).
//! Owns its native SQL, independent of the PostgreSQL adapter in
//! [`super::postgres`] and of the general-purpose `crate::db::translate`
//! compatibility layer used elsewhere in the codebase.
//!
//! Encodings match the rest of the SQLite backend (see
//! `product-docs/development/database-backends/`): UUIDs are 16-byte BLOBs,
//! JSON columns are `TEXT`, booleans are `INTEGER` 0/1. `atom_json_contains`
//! is the jsonb `@>` equivalent, registered on every connection
//! (`crate::db::sqlite_functions`).

use serde_json::Value;
use sqlx::{SqliteConnection, SqlitePool};
use uuid::Uuid;

use crate::{
    db::native::uuid_array_json,
    error::{db_err, AppError},
    models::{
        enums::{ResourceOrderField, SortDir},
        resource::{ListResources, Resource, ResourceList},
    },
};

pub(super) fn order_by(order: ResourceOrderField, dir: SortDir) -> &'static str {
    // SQLite has supported NULLS FIRST/LAST natively since 3.30 (2019),
    // well below the bundled 3.46/3.47 — identical to the PostgreSQL clause.
    match (order, dir) {
        (ResourceOrderField::CreatedAt, SortDir::Asc) => "r.created_at ASC, r.id ASC",
        (ResourceOrderField::CreatedAt, SortDir::Desc) => "r.created_at DESC, r.id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Asc) => "r.updated_at ASC, r.id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Desc) => "r.updated_at DESC NULLS LAST, r.id ASC",
        (ResourceOrderField::Name, SortDir::Asc) => "lower(r.name) ASC, r.id ASC",
        (ResourceOrderField::Name, SortDir::Desc) => "lower(r.name) DESC NULLS LAST, r.id ASC",
        (ResourceOrderField::Kind, SortDir::Asc) => "r.kind ASC, r.id ASC",
        (ResourceOrderField::Kind, SortDir::Desc) => "r.kind DESC, r.id ASC",
    }
}

pub(super) async fn insert(
    tx: &mut SqliteConnection,
    new: super::NewResource<'_>,
) -> Result<Resource, AppError> {
    sqlx::query_as::<_, Resource>(
        r#"INSERT INTO resources (id, kind, name, alias, tenant_id, owner_id, attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, kind, name, alias, tenant_id, owner_id, attributes,
                     deleted_at, deleted_by, created_at, updated_at"#,
    )
    .bind(new.id)
    .bind(new.kind)
    .bind(new.name)
    .bind(new.alias)
    .bind(new.tenant_id)
    .bind(new.owner_id)
    .bind(new.attributes.to_string())
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn get(pool: &SqlitePool, id: Uuid) -> Result<Resource, AppError> {
    sqlx::query_as::<_, Resource>(
        "SELECT id, kind, name, alias, tenant_id, owner_id, attributes, deleted_at, deleted_by, \
         created_at, updated_at, managed_by \
         FROM resources WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn list_by_ids(
    pool: &SqlitePool,
    ids: &[Uuid],
) -> Result<Vec<Resource>, AppError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids_json = uuid_array_json(ids);
    sqlx::query_as::<_, Resource>(
        r#"SELECT id, kind, name, alias, tenant_id, owner_id, attributes, deleted_at, deleted_by,
                  created_at, updated_at, managed_by
           FROM resources
           WHERE id IN (SELECT unhex(value) FROM json_each($1)) AND deleted_at IS NULL
           ORDER BY NULLIF(instr($1, lower(hex(id))), 0)"#,
    )
    .bind(ids_json)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn list(
    pool: &SqlitePool,
    params: &ListResources,
) -> Result<ResourceList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let q = super::search_pattern(params.q.clone());
    let attributes_contains = params
        .attributes_contains
        .clone()
        .filter(|attrs| !attrs.is_null())
        .map(|v| v.to_string());
    let deleted = params.deleted.as_str();
    let order_by = order_by(params.order, params.dir);

    // `LIKE` is case-insensitive over ASCII by default in SQLite, matching
    // PostgreSQL's ILIKE closely enough for these search filters. jsonb `@>`
    // becomes `atom_json_contains`; casts are unnecessary (every column here
    // is already the right native SQLite type) and simply dropped.
    let items_sql = format!(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $4 WHERE $4 IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $5
           )
           SELECT r.id, r.kind, r.name, r.alias, r.tenant_id, r.owner_id, r.attributes,
                  r.deleted_at, r.deleted_by, r.created_at, r.updated_at, r.managed_by
           FROM resources r
           WHERE ($1 IS NULL OR r.kind = $1)
             AND ($2 IS NULL OR r.tenant_id = $2)
             AND ($3 IS NULL OR r.name LIKE $3 OR r.alias LIKE $3 OR r.attributes LIKE $3)
             AND ($4 IS NULL OR EXISTS (
                     SELECT 1 FROM group_resource_parents grp
                     WHERE grp.resource_id = r.id
                       AND grp.group_id IN (SELECT id FROM target_groups)))
             AND ($9 IS NULL OR atom_json_contains(r.attributes, $9))
             AND ($8 = 'all'
                  OR ($8 = 'live' AND r.deleted_at IS NULL)
                  OR ($8 = 'deleted' AND r.deleted_at IS NOT NULL))
           ORDER BY {order_by}
           LIMIT $6 OFFSET $7"#,
    );
    let items = sqlx::query_as::<_, Resource>(&items_sql)
        .bind(params.kind.clone())
        .bind(params.tenant_id)
        .bind(q.clone())
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(limit)
        .bind(offset)
        .bind(deleted)
        .bind(attributes_contains.clone())
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar::<_, i64>(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $4 WHERE $4 IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $5
           )
           SELECT COUNT(*)
           FROM resources r
           WHERE ($1 IS NULL OR r.kind = $1)
             AND ($2 IS NULL OR r.tenant_id = $2)
             AND ($3 IS NULL OR r.name LIKE $3 OR r.alias LIKE $3 OR r.attributes LIKE $3)
             AND ($4 IS NULL OR EXISTS (
                     SELECT 1 FROM group_resource_parents grp
                     WHERE grp.resource_id = r.id
                       AND grp.group_id IN (SELECT id FROM target_groups)))
             AND ($7 IS NULL OR atom_json_contains(r.attributes, $7))
             AND ($6 = 'all'
                  OR ($6 = 'live' AND r.deleted_at IS NULL)
                  OR ($6 = 'deleted' AND r.deleted_at IS NOT NULL))"#,
    )
    .bind(params.kind.clone())
    .bind(params.tenant_id)
    .bind(q)
    .bind(params.parent_group_id)
    .bind(params.include_descendants)
    .bind(deleted)
    .bind(attributes_contains)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ResourceList { items, total })
}

pub(super) async fn live_tenant_id(
    tx: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_live_row(
    tx: &mut SqliteConnection,
    id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<bool, AppError> {
    // No FOR UPDATE: SQLite has no row locks — the write transaction
    // (BEGIN IMMEDIATE) already serialises every mutation. `IS` is SQLite's
    // NULL-safe equality, i.e. PostgreSQL's IS NOT DISTINCT FROM.
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id FROM resources
           WHERE id = $1
             AND tenant_id IS $2
             AND deleted_at IS NULL"#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(tx)
    .await
    .map(|row| row.is_some())
    .map_err(db_err)
}

pub(super) async fn apply_update(
    tx: &mut SqliteConnection,
    id: Uuid,
    name: Option<String>,
    attributes: Option<Value>,
    alias_is_set: bool,
    alias: Option<String>,
) -> Result<Resource, AppError> {
    sqlx::query_as::<_, Resource>(
        r#"UPDATE resources
           SET name       = COALESCE($2, name),
               attributes = COALESCE($3, attributes),
               alias      = CASE WHEN $4 THEN $5 ELSE alias END,
               updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING id, kind, name, alias, tenant_id, owner_id, attributes,
                     deleted_at, deleted_by, created_at, updated_at"#,
    )
    .bind(id)
    .bind(name)
    .bind(attributes.map(|attrs| attrs.to_string()))
    .bind(alias_is_set)
    .bind(alias)
    .fetch_one(tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("resource {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn is_live(tx: &mut SqliteConnection, id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM resources WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn soft_delete(
    tx: &mut SqliteConnection,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<u64, AppError> {
    sqlx::query(
        "UPDATE resources SET deleted_at = now(), deleted_by = $2
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(deleted_by)
    .execute(tx)
    .await
    .map(|result| result.rows_affected())
    .map_err(db_err)
}

pub(super) async fn deleted_tenant_id(
    tx: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT tenant_id FROM resources WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn deleted_tenant_info(
    tx: &mut SqliteConnection,
    id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, bool)>, AppError> {
    sqlx::query_as::<_, (Option<Uuid>, bool)>(
        "SELECT r.tenant_id, (t.deleted_at IS NOT NULL)
         FROM resources r
         LEFT JOIN tenants t ON t.id = r.tenant_id
         WHERE r.id = $1
           AND r.tenant_id IS $2
           AND r.deleted_at IS NOT NULL",
    )
    .bind(id)
    .bind(expected_tenant_id)
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn restore_row(tx: &mut SqliteConnection, id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE resources SET deleted_at = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .execute(tx)
    .await
    .map_err(crate::error::restore_conflict)?;
    Ok(())
}

pub(super) async fn any_tenant_id(
    tx: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM resources WHERE id = $1")
        .bind(id)
        .fetch_optional(tx)
        .await
        .map_err(db_err)
}

pub(super) async fn purge_row(
    tx: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "DELETE FROM resources WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id",
    )
    .bind(id)
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}
