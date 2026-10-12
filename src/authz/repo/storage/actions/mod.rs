//! Native storage contract for authorization actions.
mod postgres;
mod sqlite;
use super::super::*;

pub(in crate::authz::repo) async fn get_capability(
    pool: &Database,
    id: Uuid,
) -> Result<Capability, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_capability(pool, id).await,
        Database::Sqlite(db) => sqlite::get_capability(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn capability_applicability(
    pool: &Database,
    capability_id: Uuid,
) -> Result<Vec<CapabilityApplicability>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::capability_applicability(pool, capability_id).await,
        Database::Sqlite(db) => sqlite::capability_applicability(&db.pool, capability_id).await,
    }
}

pub(in crate::authz::repo) async fn list_capability_applicability(
    pool: &Database,
    action_name: Option<String>,
    object_kind: Option<String>,
    object_type: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<CapabilityApplicabilityList, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::list_capability_applicability(
                pool,
                action_name,
                object_kind,
                object_type,
                limit,
                offset,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::list_capability_applicability(
                &db.pool,
                action_name,
                object_kind,
                object_type,
                limit,
                offset,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn get_action_assignment_rule(
    pool: &Database,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_action_assignment_rule(pool, id).await,
        Database::Sqlite(db) => sqlite::get_action_assignment_rule(&db.pool, id).await,
    }
}

pub(in crate::authz::repo) async fn list_action_assignment_rules(
    pool: &Database,
    params: ListActionAssignmentRules,
) -> Result<ActionAssignmentRuleList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_action_assignment_rules(pool, params).await,
        Database::Sqlite(db) => sqlite::list_action_assignment_rules(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn find_capability_ids_by_name(
    pool: &Database,
    name: &str,
    object_kind: &str,
    object_type: &str,
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::find_capability_ids_by_name(pool, name, object_kind, object_type).await
        }
        Database::Sqlite(db) => {
            sqlite::find_capability_ids_by_name(&db.pool, name, object_kind, object_type).await
        }
    }
}

pub(in crate::authz::repo) async fn action_identities(
    conn: &mut impl DbExecutor,
    unique_capability_ids: &[Uuid],
) -> Result<Vec<ActionIdentity>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::action_identities(conn, unique_capability_ids).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::action_identities(conn, unique_capability_ids).await
        }
    }
}

pub(in crate::authz::repo) async fn inapplicable_actions(
    conn: &mut impl DbExecutor,
    unique_capability_ids: &[Uuid],
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<Vec<String>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::inapplicable_actions(conn, unique_capability_ids, object_kind, object_type)
                .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::inapplicable_actions(conn, unique_capability_ids, object_kind, object_type)
                .await
        }
    }
}

pub(in crate::authz::repo) async fn insert_action(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    name: &str,
    description: &Option<String>,
) -> Result<Capability, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_action(conn, id, name, description).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_action(conn, id, name, description).await
        }
    }
}

pub(in crate::authz::repo) async fn assignment_rule_exists(
    pool: &Database,
    tenant_id: &Option<Uuid>,
    entity_kind: &EntityKind,
    action_name: &str,
    object_kind: &ObjectKind,
    object_type: &Option<String>,
) -> Result<bool, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::assignment_rule_exists(
                pool,
                tenant_id,
                entity_kind,
                action_name,
                object_kind,
                object_type,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::assignment_rule_exists(
                &db.pool,
                tenant_id,
                entity_kind,
                action_name,
                object_kind,
                object_type,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::authz::repo) async fn insert_assignment_rule(
    conn: &mut impl DbExecutor,
    tenant_id: &Option<Uuid>,
    entity_kind: &EntityKind,
    action_name: &str,
    object_kind: &ObjectKind,
    object_type: &Option<String>,
    decision: &ActionAssignmentDecision,
    is_absolute: &bool,
) -> Result<ActionAssignmentRule, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_assignment_rule(
                conn,
                tenant_id,
                entity_kind,
                action_name,
                object_kind,
                object_type,
                decision,
                is_absolute,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_assignment_rule(
                conn,
                tenant_id,
                entity_kind,
                action_name,
                object_kind,
                object_type,
                decision,
                is_absolute,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn action_exists_by_name(
    conn: &mut impl DbExecutor,
    action_name: &str,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::action_exists_by_name(conn, action_name).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::action_exists_by_name(conn, action_name).await
        }
    }
}

pub(in crate::authz::repo) async fn assignment_rule_tenant_optional(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::assignment_rule_tenant_optional(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::assignment_rule_tenant_optional(conn, id).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_assignment_rule(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<ActionAssignmentRule, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::remove_assignment_rule(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::remove_assignment_rule(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn lock_action_optional(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::lock_action_optional(conn, capability_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::lock_action_optional(conn, capability_id).await
        }
    }
}

pub(in crate::authz::repo) async fn applicability_ownership_optional(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<&str>,
) -> Result<Option<Option<String>>, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::applicability_ownership_optional(
                conn,
                capability_id,
                object_kind,
                object_type,
            )
            .await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::applicability_ownership_optional(conn, capability_id, object_kind, object_type)
                .await
        }
    }
}

pub(in crate::authz::repo) async fn action_exists(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::action_exists(conn, capability_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::action_exists(conn, capability_id).await,
    }
}

pub(in crate::authz::repo) async fn insert_applicability(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::insert_applicability(conn, capability_id, object_kind, object_type).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::insert_applicability(conn, capability_id, object_kind, object_type).await
        }
    }
}

pub(in crate::authz::repo) async fn applicability_entry(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<CapabilityApplicabilityEntry, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::applicability_entry(conn, capability_id, object_kind, object_type).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::applicability_entry(conn, capability_id, object_kind, object_type).await
        }
    }
}

pub(in crate::authz::repo) async fn remove_applicability(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::remove_applicability(conn, capability_id, object_kind, object_type).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::remove_applicability(conn, capability_id, object_kind, object_type).await
        }
    }
}

pub(in crate::authz::repo) async fn update_action_fields(
    conn: &mut impl DbExecutor,
    id: &Uuid,
    name: &Option<String>,
    description: &Option<String>,
) -> Result<Capability, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::update_action_fields(conn, id, name, description).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::update_action_fields(conn, id, name, description).await
        }
    }
}

pub(in crate::authz::repo) async fn action_has_config_applicability(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::action_has_config_applicability(conn, capability_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::action_has_config_applicability(conn, capability_id).await
        }
    }
}

pub(in crate::authz::repo) async fn clear_applicability(
    conn: &mut impl DbExecutor,
    capability_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::clear_applicability(conn, capability_id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => {
            sqlite::clear_applicability(conn, capability_id).await
        }
    }
}

pub(in crate::authz::repo) async fn action_has_config_links(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<bool, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => {
            postgres::action_has_config_links(conn, id).await
        }
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::action_has_config_links(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn remove_action(
    conn: &mut impl DbExecutor,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match conn.connection() {
        crate::db::ConnectionRef::Postgres(conn) => postgres::remove_action(conn, id).await,
        crate::db::ConnectionRef::Sqlite(conn) => sqlite::remove_action(conn, id).await,
    }
}

pub(in crate::authz::repo) async fn action_by_name_optional(
    pool: &Database,
    action_name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::action_by_name_optional(pool, action_name).await,
        Database::Sqlite(db) => sqlite::action_by_name_optional(&db.pool, action_name).await,
    }
}
