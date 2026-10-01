//! Native storage contract for authorization objects.
mod postgres;
mod sqlite;
use super::super::*;

pub(in crate::authz::repo) async fn fetch_resource<'e, E: crate::db::IntoTarget<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Resource, AppError> {
    match executor.into_target() {
        crate::db::Target::PoolPostgres(executor) => postgres::fetch_resource(executor, id).await,
        crate::db::Target::ConnectionPostgres(executor) => {
            postgres::fetch_resource(executor, id).await
        }
        crate::db::Target::PoolSqlite(executor) => sqlite::fetch_resource(executor, id).await,
        crate::db::Target::ConnectionSqlite(executor) => sqlite::fetch_resource(executor, id).await,
    }
}

pub(in crate::authz::repo) async fn get_resource_object_groups(
    pool: &Database,
    resource_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_resource_object_groups(pool, resource_id).await,
        Database::Sqlite(db) => sqlite::get_resource_object_groups(&db.pool, resource_id).await,
    }
}

pub(in crate::authz::repo) async fn list_capabilities(
    pool: &Database,
    params: ListCapabilities,
) -> Result<crate::models::capability::CapabilityList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_capabilities(pool, params).await,
        Database::Sqlite(db) => sqlite::list_capabilities(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn lock_group_hierarchy(
    tx: &mut DbTransaction<'_>,
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::lock_group_hierarchy(conn).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::lock_group_hierarchy(conn).await,
    }
}

pub(in crate::authz::repo) async fn alias_object_id(
    pool: &Database,
    tenant_id: Option<Uuid>,
    class: AliasObjectClass,
    object_alias: &str,
) -> Result<Option<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::alias_object_id(pool, tenant_id, class, object_alias).await
        }
        Database::Sqlite(db) => {
            sqlite::alias_object_id(&db.pool, tenant_id, class, object_alias).await
        }
    }
}

pub(in crate::authz::repo) async fn active_tenant_optional(
    pool: &Database,
    id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::active_tenant_optional(pool, id).await,
        Database::Sqlite(db) => sqlite::active_tenant_optional(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn tenant_by_alias_optional(
    pool: &Database,
    alias: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::tenant_by_alias_optional(pool, alias).await,
        Database::Sqlite(db) => sqlite::tenant_by_alias_optional(&db.pool, alias).await,
    }
}

pub(in crate::authz::repo) async fn resource_tenant_optional(
    conn: &mut impl DbExecutor,
    resource_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::resource_tenant_optional(conn, resource_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::resource_tenant_optional(conn, resource_id).await
        }
    }
}

pub(in crate::authz::repo) async fn resource_group_boundary_optional(
    conn: &mut impl DbExecutor,
    resource_id: &Uuid,
    group_id: &Uuid,
    resource_tenant_id: &Option<Uuid>,
) -> Result<Option<ResourceGroupBoundary>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::resource_group_boundary_optional(
                conn,
                resource_id,
                group_id,
                resource_tenant_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::resource_group_boundary_optional(
                conn,
                resource_id,
                group_id,
                resource_tenant_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn insert_resource_membership(
    conn: &mut impl DbExecutor,
    group_id: &Uuid,
    resource_id: &Uuid,
    tenant_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_resource_membership(conn, group_id, resource_id, tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_resource_membership(conn, group_id, resource_id, tenant_id).await
        }
    }
}

pub(in crate::authz::repo) async fn lock_resource_optional(
    conn: &mut impl DbExecutor,
    resource_id: &Uuid,
    tenant_id: &Option<Uuid>,
) -> Result<Option<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_resource_optional(conn, resource_id, tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_resource_optional(conn, resource_id, tenant_id).await
        }
    }
}

pub(in crate::authz::repo) async fn resource_membership_groups(
    conn: &mut impl DbExecutor,
    resource_id: &Uuid,
    group_id: &Option<Uuid>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::resource_membership_groups(conn, resource_id, group_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::resource_membership_groups(conn, resource_id, group_id).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_resource_memberships(
    conn: &mut impl DbExecutor,
    resource_id: &Uuid,
    group_id: &Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::remove_resource_memberships(conn, resource_id, group_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::remove_resource_memberships(conn, resource_id, group_id).await
        }
    }
}

pub(in crate::authz::repo) async fn activate_human_membership(
    conn: &mut impl DbExecutor,
    tenant_id: &Uuid,
    member_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::activate_human_membership(conn, tenant_id, member_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::activate_human_membership(conn, tenant_id, member_id).await
        }
    }
}

pub(in crate::authz::repo) async fn object_group_tenant_optional(
    conn: &mut impl DbExecutor,
    group_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::object_group_tenant_optional(conn, group_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::object_group_tenant_optional(conn, group_id).await
        }
    }
}

pub(in crate::authz::repo) async fn count_entities(
    pool: &Database,
    unique_entity_ids: &[Uuid],
) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::count_entities(pool, unique_entity_ids).await,
        Database::Sqlite(db) => sqlite::count_entities(&db.pool, unique_entity_ids).await,
    }
}

pub(in crate::authz::repo) async fn group_tenant_optional(
    pool: &Database,
    group_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::group_tenant_optional(pool, group_id).await,
        Database::Sqlite(db) => sqlite::group_tenant_optional(&db.pool, group_id).await,
    }
}

pub(in crate::authz::repo) async fn group_tenants(
    conn: &mut impl DbExecutor,
    group_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::group_tenants(conn, group_ids).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::group_tenants(conn, group_ids).await,
    }
}

pub(in crate::authz::repo) async fn descendant_groups(
    conn: &mut impl DbExecutor,
    root_group_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::descendant_groups(conn, root_group_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::descendant_groups(conn, root_group_ids).await
        }
    }
}

pub(in crate::authz::repo) async fn lock_object_groups(
    conn: &mut impl DbExecutor,
    closure: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_object_groups(conn, closure).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::lock_object_groups(conn, closure).await,
    }
}

pub(in crate::authz::repo) async fn lock_principal_groups(
    conn: &mut impl DbExecutor,
    closure: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_principal_groups(conn, closure).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_principal_groups(conn, closure).await
        }
    }
}

pub(in crate::authz::repo) async fn group_member_ids(
    conn: &mut impl DbExecutor,
    closure: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::group_member_ids(conn, closure).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::group_member_ids(conn, closure).await,
    }
}

pub(in crate::authz::repo) async fn lock_tenant_optional(
    conn: &mut impl DbExecutor,
    tenant_id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_tenant_optional(conn, tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_tenant_optional(conn, tenant_id).await
        }
    }
}
