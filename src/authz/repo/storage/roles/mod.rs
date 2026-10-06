//! Native storage contract for authorization roles.
mod postgres;
mod sqlite;
use super::super::*;

pub(in crate::authz::repo) async fn read_live_role_tenant_id(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::read_live_role_tenant_id(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::read_live_role_tenant_id(conn, role_id).await
        }
    }
}

pub(in crate::authz::repo) async fn lock_live_role_row(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_live_role_row(conn, role_id, expected_tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_live_role_row(conn, role_id, expected_tenant_id).await
        }
    }
}

pub(in crate::authz::repo) async fn get_role(pool: &Database, id: Uuid) -> Result<Role, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_role(pool, id).await,
        Database::Sqlite(db) => sqlite::get_role(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn list_roles(
    pool: &Database,
    params: ListRoles,
) -> Result<RoleList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_roles(pool, params).await,
        Database::Sqlite(db) => sqlite::list_roles(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn role_derived_kind(
    pool: &Database,
    role_id: Uuid,
) -> Result<RoleDerivedKind, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::role_derived_kind(pool, role_id).await,
        Database::Sqlite(db) => sqlite::role_derived_kind(&db.pool, role_id).await,
    }
}

pub(in crate::authz::repo) async fn insert_role(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    name: &str,
    tenant_id: &Option<Uuid>,
    description: &Option<String>,
) -> Result<Role, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_role(conn, id, name, tenant_id, description).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_role(conn, id, name, tenant_id, description).await
        }
    }
}

pub(in crate::authz::repo) async fn live_role_tenant_optional(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::live_role_tenant_optional(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::live_role_tenant_optional(conn, role_id).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_role_links(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::remove_role_links(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::remove_role_links(conn, role_id).await,
    }
}

pub(in crate::authz::repo) async fn composite_role_candidates(
    pool: &Database,
    unique_child_ids: &[Uuid],
) -> Result<Vec<CompositeRoleCandidate>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::composite_role_candidates(pool, unique_child_ids).await
        }
        Database::Sqlite(db) => sqlite::composite_role_candidates(&db.pool, unique_child_ids).await,
    }
}

pub(in crate::authz::repo) async fn update_role_fields(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    name: &Option<String>,
    description: &Option<String>,
) -> Result<Role, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::update_role_fields(conn, id, name, description).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::update_role_fields(conn, id, name, description).await
        }
    }
}

pub(in crate::authz::repo) async fn role_is_live(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::role_is_live(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_is_live(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn tombstone_role(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    deleted_by: &Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::tombstone_role(conn, id, deleted_by).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::tombstone_role(conn, id, deleted_by).await
        }
    }
}

pub(in crate::authz::repo) async fn deleted_role_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::deleted_role_tenant_optional(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::deleted_role_tenant_optional(conn, id).await
        }
    }
}

pub(in crate::authz::repo) async fn lock_deleted_role_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    expected_tenant_id: &Option<Uuid>,
) -> Result<Option<(Option<Uuid>, bool)>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_deleted_role_tenant_optional(conn, id, expected_tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_deleted_role_tenant_optional(conn, id, expected_tenant_id).await
        }
    }
}

pub(in crate::authz::repo) async fn restore_role_fields(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::restore_role_fields(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::restore_role_fields(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn role_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::role_tenant_optional(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_tenant_optional(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn purge_deleted_role_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::purge_deleted_role_optional(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::purge_deleted_role_optional(conn, id).await
        }
    }
}

pub(in crate::authz::repo) async fn lock_role_row_optional(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
    role_tenant_id: &Option<Uuid>,
) -> Result<Option<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_role_row_optional(conn, role_id, role_tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_role_row_optional(conn, role_id, role_tenant_id).await
        }
    }
}
