mod postgres;
mod sqlite;
use super::*;
pub(super) async fn load_rules(conn: &mut impl DbExecutor) -> Result<Vec<Rule>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::load_rules(conn).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::load_rules(conn).await,
    }
}
pub(super) async fn subject_entity_kinds(
    conn: &mut impl DbExecutor,
    subject_kind: SubjectKind,
    subject_id: Uuid,
) -> Result<Vec<String>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::subject_entity_kinds(conn, subject_kind, subject_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::subject_entity_kinds(conn, subject_kind, subject_id).await
        }
    }
}
pub(super) async fn capability_names(
    conn: &mut impl DbExecutor,
    ids: &[Uuid],
) -> Result<Vec<String>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::capability_names(conn, ids).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::capability_names(conn, ids).await,
    }
}
pub(super) async fn role_capability_names(
    conn: &mut impl DbExecutor,
    role_id: Uuid,
) -> Result<Vec<String>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::role_capability_names(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::role_capability_names(conn, role_id).await
        }
    }
}
pub(super) async fn role_permission_assignments(
    conn: &mut impl DbExecutor,
    role_ids: &[Uuid],
) -> Result<Vec<RoleCapabilityAssignment>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::role_permission_assignments(conn, role_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::role_permission_assignments(conn, role_ids).await
        }
    }
}
pub(super) async fn permission_block_assignments(
    conn: &mut impl DbExecutor,
    permission_block_ids: &[Uuid],
) -> Result<Vec<RoleCapabilityAssignment>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::permission_block_assignments(conn, permission_block_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::permission_block_assignments(conn, permission_block_ids).await
        }
    }
}
pub(super) async fn role_recipients(
    conn: &mut impl DbExecutor,
    role_id: Uuid,
) -> Result<Vec<RoleRecipients>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::role_recipients(conn, role_id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::role_recipients(conn, role_id).await,
    }
}
pub(super) async fn inherited_group_grants(
    conn: &mut impl DbExecutor,
    group_id: Uuid,
) -> Result<Vec<InheritedGroupGrants>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::inherited_group_grants(conn, group_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::inherited_group_grants(conn, group_id).await
        }
    }
}
pub(super) async fn assignment_recipients(
    conn: &mut impl DbExecutor,
    role_id: Uuid,
) -> Result<Vec<AssignmentRecipients>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::assignment_recipients(conn, role_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::assignment_recipients(conn, role_id).await
        }
    }
}
pub(super) async fn entity_kinds(
    conn: &mut impl DbExecutor,
    ids: &[Uuid],
) -> Result<Vec<String>, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::entity_kinds(conn, ids).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::entity_kinds(conn, ids).await,
    }
}
pub(super) async fn entity_kind(conn: &mut impl DbExecutor, id: Uuid) -> Result<String, AppError> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::entity_kind(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::entity_kind(conn, id).await,
    }
}
