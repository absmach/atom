//! Native storage contract for authorization blocks.
mod postgres;
mod sqlite;
use super::super::*;

pub(in crate::authz::repo) async fn delete_orphaned_blocks(
    tx: &mut DbTransaction<'_>,
    block_ids: &[Uuid],
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::delete_orphaned_blocks(conn, block_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::delete_orphaned_blocks(conn, block_ids).await
        }
    }
}

pub(in crate::authz::repo) async fn role_block_ids(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::role_block_ids(conn, role_id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_block_ids(conn, role_id).await,
    }
}

pub(in crate::authz::repo) async fn list_role_permission_blocks(
    pool: &Database,
    role_id: Uuid,
) -> Result<Vec<RolePermissionBlock>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_role_permission_blocks(pool, role_id).await,
        Database::Sqlite(db) => sqlite::list_role_permission_blocks(&db.pool, role_id).await,
    }
}

pub(in crate::authz::repo) async fn list_permission_blocks_for_role(
    pool: &Database,
    role_id: Uuid,
) -> Result<Vec<PermissionBlock>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_permission_blocks_for_role(pool, role_id).await,
        Database::Sqlite(db) => sqlite::list_permission_blocks_for_role(&db.pool, role_id).await,
    }
}

pub(in crate::authz::repo) async fn role_permission_block_capabilities(
    pool: &Database,
    block_id: Uuid,
) -> Result<Vec<Capability>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::role_permission_block_capabilities(pool, block_id).await
        }
        Database::Sqlite(db) => {
            sqlite::role_permission_block_capabilities(&db.pool, block_id).await
        }
    }
}

pub(in crate::authz::repo) async fn fetch_permission_block<'e, E: crate::db::IntoTarget<'e>>(
    executor: E,
    id: Uuid,
) -> Result<PermissionBlock, AppError> {
    match executor.into_target() {
        crate::db::Target::PoolPostgres(executor) => {
            postgres::fetch_permission_block(executor, id).await
        }
        crate::db::Target::ConnectionPostgres(executor) => {
            postgres::fetch_permission_block(executor, id).await
        }
        crate::db::Target::PoolSqlite(executor) => {
            sqlite::fetch_permission_block(executor, id).await
        }
        crate::db::Target::ConnectionSqlite(executor) => {
            sqlite::fetch_permission_block(executor, id).await
        }
    }
}

pub(in crate::authz::repo) async fn list_permission_blocks(
    pool: &Database,
    params: ListPermissionBlocks,
) -> Result<PermissionBlockList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_permission_blocks(pool, params).await,
        Database::Sqlite(db) => sqlite::list_permission_blocks(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn copy_role_permission_blocks(
    tx: &mut DbTransaction<'_>,
    target_role_id: Uuid,
    source_role_id: Uuid,
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::copy_role_permission_blocks(conn, target_role_id, source_role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::copy_role_permission_blocks(conn, target_role_id, source_role_id).await
        }
    }
}

pub(in crate::authz::repo) async fn purge_authz_references_for_ids(
    tx: &mut DbTransaction<'_>,
    ids: &[Uuid],
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::purge_authz_references_for_ids(conn, ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::purge_authz_references_for_ids(conn, ids).await
        }
    }
}

pub(in crate::authz::repo) async fn count_tenant_blocks(
    conn: &mut impl DbExecutor,
    unique_block_ids: &[Uuid],
    role_tenant_id: &Option<Uuid>,
) -> Result<i64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::count_tenant_blocks(conn, unique_block_ids, role_tenant_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::count_tenant_blocks(conn, unique_block_ids, role_tenant_id).await
        }
    }
}

pub(in crate::authz::repo) async fn link_role_block(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
    permission_block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::link_role_block(conn, role_id, permission_block_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::link_role_block(conn, role_id, permission_block_id).await
        }
    }
}

pub(in crate::authz::repo) async fn insert_allow_block(
    conn: &mut impl DbExecutor,
    scope_mode: &str,
    tenant_id: &Option<Uuid>,
    object_kind: &Option<&str>,
    object_type: &Option<&str>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_allow_block(
                conn,
                scope_mode,
                tenant_id,
                object_kind,
                object_type,
                object_id,
                group_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_allow_block(
                conn,
                scope_mode,
                tenant_id,
                object_kind,
                object_type,
                object_id,
                group_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn link_block_action(
    conn: &mut impl DbExecutor,
    block_id: &Uuid,
    capability_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::link_block_action(conn, block_id, capability_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::link_block_action(conn, block_id, capability_id).await
        }
    }
}

pub(in crate::authz::repo) async fn unlink_role_blocks(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
    block_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::unlink_role_blocks(conn, role_id, block_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::unlink_role_blocks(conn, role_id, block_ids).await
        }
    }
}

pub(in crate::authz::repo) async fn insert_legacy_allow_block(
    conn: &mut impl DbExecutor,
    scope_mode: &str,
    tenant_id: &Option<Uuid>,
    object_kind: &Option<String>,
    object_type: &Option<String>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_legacy_allow_block(
                conn,
                scope_mode,
                tenant_id,
                object_kind,
                object_type,
                object_id,
                group_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_legacy_allow_block(
                conn,
                scope_mode,
                tenant_id,
                object_kind,
                object_type,
                object_id,
                group_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn insert_block_action(
    conn: &mut impl DbExecutor,
    block_id: &Uuid,
    capability_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_block_action(conn, block_id, capability_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_block_action(conn, block_id, capability_id).await
        }
    }
}

pub(in crate::authz::repo) async fn insert_role_block(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
    block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_role_block(conn, role_id, block_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_role_block(conn, role_id, block_id).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::authz::repo) async fn insert_permission_block(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    scope_mode: &str,
    object_kind: &Option<&str>,
    object_type: &Option<&str>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
    effect: &Effect,
    conditions: &Value,
) -> Result<Uuid, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_permission_block(
                conn,
                tenant_id,
                scope_mode,
                object_kind,
                object_type,
                object_id,
                group_id,
                effect,
                conditions,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_permission_block(
                conn,
                tenant_id,
                scope_mode,
                object_kind,
                object_type,
                object_id,
                group_id,
                effect,
                conditions,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn block_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::block_tenant_optional(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::block_tenant_optional(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn block_is_referenced(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::block_is_referenced(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::block_is_referenced(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn remove_block(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::remove_block(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::remove_block(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn role_linked_blocks(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::role_linked_blocks(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_linked_blocks(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn purge_orphaned_blocks(
    conn: &mut impl DbExecutor,
    candidate_block_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::purge_orphaned_blocks(conn, candidate_block_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::purge_orphaned_blocks(conn, candidate_block_ids).await
        }
    }
}

pub(in crate::authz::repo) async fn role_blocks_for_action(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
    cap_id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::role_blocks_for_action(conn, role_id, cap_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::role_blocks_for_action(conn, role_id, cap_id).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::authz::repo) async fn insert_legacy_permission_block(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    scope_mode: &str,
    object_kind: &Option<String>,
    object_type: &Option<String>,
    object_id: &Option<Uuid>,
    group_id: &Option<Uuid>,
    effect: &Effect,
    conditions: &Value,
) -> Result<Uuid, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_legacy_permission_block(
                conn,
                tenant_id,
                scope_mode,
                object_kind,
                object_type,
                object_id,
                group_id,
                effect,
                conditions,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_legacy_permission_block(
                conn,
                tenant_id,
                scope_mode,
                object_kind,
                object_type,
                object_id,
                group_id,
                effect,
                conditions,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn lock_block_tenant_optional(
    conn: &mut impl DbExecutor,
    permission_block_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_block_tenant_optional(conn, permission_block_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_block_tenant_optional(conn, permission_block_id).await
        }
    }
}
