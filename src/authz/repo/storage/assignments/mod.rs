//! Native storage contract for authorization assignments.
mod postgres;
mod sqlite;
use super::super::*;

pub(in crate::authz::repo) async fn read_live_subject_tenant_id(
    tx: &mut DbTransaction<'_>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::read_live_subject_tenant_id(conn, subject_kind, subject_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::read_live_subject_tenant_id(conn, subject_kind, subject_id).await
        }
    }
}

pub(in crate::authz::repo) async fn lock_live_subject_row(
    tx: &mut DbTransaction<'_>,
    subject_kind: &SubjectKind,
    subject_id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_live_subject_row(conn, subject_kind, subject_id, expected_tenant_id)
                .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_live_subject_row(conn, subject_kind, subject_id, expected_tenant_id).await
        }
    }
}

pub(in crate::authz::repo) async fn sync_tenant_membership_for_policy(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    match tx.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::sync_tenant_membership_for_policy(conn, tenant_id, entity_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::sync_tenant_membership_for_policy(conn, tenant_id, entity_id).await
        }
    }
}

pub(in crate::authz::repo) async fn get_policy(
    pool: &Database,
    id: Uuid,
) -> Result<PolicyBinding, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_policy(pool, id).await,
        Database::Sqlite(db) => sqlite::get_policy(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn list_role_assignments(
    pool: &Database,
    params: ListRoleAssignments,
) -> Result<RoleAssignmentList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_role_assignments(pool, params).await,
        Database::Sqlite(db) => sqlite::list_role_assignments(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn get_role_assignment(
    pool: &Database,
    id: Uuid,
) -> Result<RoleAssignment, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_role_assignment(pool, id).await,
        Database::Sqlite(db) => sqlite::get_role_assignment(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn get_direct_policy(
    pool: &Database,
    id: Uuid,
) -> Result<DirectPolicy, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_direct_policy(pool, id).await,
        Database::Sqlite(db) => sqlite::get_direct_policy(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn subject_role_assignments(
    pool: &Database,
    params: SubjectRoleAssignmentsQuery,
) -> Result<SubjectRoleAssignmentList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::subject_role_assignments(pool, params).await,
        Database::Sqlite(db) => sqlite::subject_role_assignments(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn list_direct_policies(
    pool: &Database,
    params: ListDirectPolicies,
) -> Result<DirectPolicyList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_direct_policies(pool, params).await,
        Database::Sqlite(db) => sqlite::list_direct_policies(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn insert_entity_role_assignment(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    member_id: &Uuid,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_entity_role_assignment(conn, tenant_id, member_id, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_entity_role_assignment(conn, tenant_id, member_id, id).await
        }
    }
}

pub(in crate::authz::repo) async fn insert_policy_role_assignment(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    grant_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_policy_role_assignment(
                conn,
                id,
                tenant_id,
                subject_kind,
                subject_id,
                grant_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_policy_role_assignment(
                conn,
                id,
                tenant_id,
                subject_kind,
                subject_id,
                grant_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn insert_policy_direct_assignment(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    permission_block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_policy_direct_assignment(
                conn,
                id,
                tenant_id,
                subject_kind,
                subject_id,
                permission_block_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_policy_direct_assignment(
                conn,
                id,
                tenant_id,
                subject_kind,
                subject_id,
                permission_block_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn insert_role_assignment(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    role_id: &Uuid,
) -> Result<RoleAssignment, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_role_assignment(conn, tenant_id, subject_kind, subject_id, role_id)
                .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_role_assignment(conn, tenant_id, subject_kind, subject_id, role_id).await
        }
    }
}

pub(in crate::authz::repo) async fn insert_missing_role_assignment(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    role_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_missing_role_assignment(
                conn,
                tenant_id,
                subject_kind,
                subject_id,
                role_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_missing_role_assignment(
                conn,
                tenant_id,
                subject_kind,
                subject_id,
                role_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn role_assignment_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::role_assignment_tenant_optional(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::role_assignment_tenant_optional(conn, id).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_role_assignment(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::remove_role_assignment(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::remove_role_assignment(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn insert_direct_policy(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    subject_kind: &SubjectKind,
    subject_id: &Uuid,
    permission_block_id: &Uuid,
) -> Result<DirectPolicy, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_direct_policy(
                conn,
                tenant_id,
                subject_kind,
                subject_id,
                permission_block_id,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_direct_policy(
                conn,
                tenant_id,
                subject_kind,
                subject_id,
                permission_block_id,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn direct_policy_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::direct_policy_tenant_optional(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::direct_policy_tenant_optional(conn, id).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_direct_policy_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::remove_direct_policy_optional(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::remove_direct_policy_optional(conn, id).await
        }
    }
}

pub(in crate::authz::repo) async fn live_entity_tenant_optional(
    conn: &mut impl DbExecutor,
    subject_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::live_entity_tenant_optional(conn, subject_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::live_entity_tenant_optional(conn, subject_id).await
        }
    }
}

pub(in crate::authz::repo) async fn active_membership(
    conn: &mut impl DbExecutor,
    tenant_id: &Uuid,
    subject_id: &Uuid,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::active_membership(conn, tenant_id, subject_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::active_membership(conn, tenant_id, subject_id).await
        }
    }
}

pub(in crate::authz::repo) async fn live_principal_group_tenant_optional(
    conn: &mut impl DbExecutor,
    subject_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::live_principal_group_tenant_optional(conn, subject_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::live_principal_group_tenant_optional(conn, subject_id).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_direct_policy(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Uuid, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::remove_direct_policy(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::remove_direct_policy(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn role_entity_subjects(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::role_entity_subjects(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_entity_subjects(conn, role_id).await,
    }
}

pub(in crate::authz::repo) async fn role_group_subjects(
    conn: &mut impl DbExecutor,
    role_id: &Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::role_group_subjects(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_group_subjects(conn, role_id).await,
    }
}
