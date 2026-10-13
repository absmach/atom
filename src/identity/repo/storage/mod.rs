//! Domain storage operations borrowing the caller transaction.
mod postgres;
mod sqlite;
use super::*;

pub(super) async fn fetch_entity<'e, E: crate::db::IntoTarget<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Entity, AppError> {
    match executor.into_target() {
        crate::db::Target::PoolPostgres(executor) => postgres::fetch_entity(executor, id).await,
        crate::db::Target::ConnectionPostgres(executor) => {
            postgres::fetch_entity(executor, id).await
        }
        crate::db::Target::PoolSqlite(executor) => sqlite::fetch_entity(executor, id).await,
        crate::db::Target::ConnectionSqlite(executor) => sqlite::fetch_entity(executor, id).await,
    }
}

pub(super) async fn list_entities_by_ids(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<Entity>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_entities_by_ids(pool, ids).await,
        Database::Sqlite(db) => sqlite::list_entities_by_ids(&db.pool, ids).await,
    }
}

pub(super) async fn entity_active_session_ids(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::entity_active_session_ids(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::entity_active_session_ids(&db.pool, entity_id).await,
    }
}

pub(super) async fn entity_active_access_token_ids(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::entity_active_access_token_ids(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::entity_active_access_token_ids(&db.pool, entity_id).await,
    }
}

pub(super) async fn get_session(pool: &Database, id: Uuid) -> Result<Session, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_session(pool, id).await,
        Database::Sqlite(db) => sqlite::get_session(&db.pool, id).await,
    }
}

pub(super) async fn revoke_session_in_tx(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::revoke_session_in_tx(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::revoke_session_in_tx(conn, id).await,
    }
}

pub(super) async fn add_authenticated_user_membership_in_tx(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::add_authenticated_user_membership_in_tx(conn, entity_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::add_authenticated_user_membership_in_tx(conn, entity_id).await
        }
    }
}

pub(super) async fn insert_session(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    entity_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<Session, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::insert_session(conn, id, entity_id, expires_at).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_session(conn, id, entity_id, expires_at).await
        }
    }
}

pub(super) async fn extend_session(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    entity_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<Session, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::extend_session(conn, id, entity_id, expires_at).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::extend_session(conn, id, entity_id, expires_at).await
        }
    }
}

pub(super) async fn active_entity_tenant(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::active_entity_tenant(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::active_entity_tenant(conn, id).await,
    }
}

pub(super) async fn lock_active_entity(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Option<(EntityKind, Option<Uuid>)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::lock_active_entity(conn, id, tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_active_entity(conn, id, tenant_id).await,
    }
}

pub(super) struct NewEntity {
    pub id: Uuid,
    pub kind: EntityKind,
    pub name: String,
    pub alias: Option<String>,
    pub external_id: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub attributes: Value,
}

pub(super) async fn insert_entity(
    conn: &mut DbTransaction<'_>,
    entity: NewEntity,
) -> Result<Entity, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::insert_entity(conn, entity).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_entity(conn, entity).await,
    }
}

pub(super) async fn list_entities(
    pool: &Database,
    params: ListEntities,
) -> Result<EntityList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_entities(pool, params).await,
        Database::Sqlite(db) => sqlite::list_entities(&db.pool, params).await,
    }
}

pub(super) async fn entity_tenant(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::entity_tenant(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::entity_tenant(conn, id).await,
    }
}

pub(super) async fn lock_entity_update(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    current_tenant_id: Option<Uuid>,
) -> Result<Option<LockedEntityUpdate>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_entity_update(conn, id, current_tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_entity_update(conn, id, current_tenant_id).await
        }
    }
}

pub(super) async fn name_is_in_use(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    name: &str,
) -> Result<bool, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::name_is_in_use(conn, id, name).await,
        DbTransaction::Sqlite(conn) => sqlite::name_is_in_use(conn, id, name).await,
    }
}

pub(super) struct EntityChanges {
    pub id: Uuid,
    pub request: UpdateEntity,
    pub attributes: Option<Value>,
    pub alias_is_set: bool,
    pub alias: Option<String>,
    pub external_id_is_set: bool,
    pub external_id: Option<String>,
}

pub(super) async fn update_entity(
    conn: &mut DbTransaction<'_>,
    changes: EntityChanges,
) -> Result<Entity, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::update_entity(conn, changes).await,
        DbTransaction::Sqlite(conn) => sqlite::update_entity(conn, changes).await,
    }
}

pub(super) async fn lock_entity_group(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Uuid,
    entity_tenant_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, Option<Uuid>)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_entity_group(conn, entity_id, group_id, entity_tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_entity_group(conn, entity_id, group_id, entity_tenant_id).await
        }
    }
}

pub(super) async fn insert_entity_group(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
    entity_id: Uuid,
    tenant_id: Uuid,
) -> Result<bool, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::insert_entity_group(conn, group_id, entity_id, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_entity_group(conn, group_id, entity_id, tenant_id).await
        }
    }
}

pub(super) async fn lock_entity(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::lock_entity(conn, entity_id, tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_entity(conn, entity_id, tenant_id).await,
    }
}

pub(super) async fn entity_membership_owners(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::entity_membership_owners(conn, entity_id, group_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::entity_membership_owners(conn, entity_id, group_id).await
        }
    }
}

pub(super) async fn remove_entity_memberships(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<u64, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::remove_entity_memberships(conn, entity_id, group_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::remove_entity_memberships(conn, entity_id, group_id).await
        }
    }
}

pub(super) async fn lock_profile(
    conn: &mut DbTransaction<'_>,
    profile_id: Uuid,
) -> Result<Option<(String, String, String)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::lock_profile(conn, profile_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_profile(conn, profile_id).await,
    }
}

pub(super) async fn lock_latest_profile_version(
    conn: &mut DbTransaction<'_>,
    profile_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_latest_profile_version(conn, profile_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::lock_latest_profile_version(conn, profile_id).await,
    }
}

pub(super) async fn lock_profile_version(
    conn: &mut DbTransaction<'_>,
    profile_version_id: Uuid,
) -> Result<Option<(Uuid, Value)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_profile_version(conn, profile_version_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::lock_profile_version(conn, profile_version_id).await,
    }
}

pub(super) async fn deactivate_entity_email_in_tx(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::deactivate_entity_email_in_tx(conn, entity_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::deactivate_entity_email_in_tx(conn, entity_id).await,
    }
}

pub(super) async fn invalidate_email_tokens_in_tx(
    conn: &mut DbTransaction<'_>,
    email_id: Uuid,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::invalidate_email_tokens_in_tx(conn, email_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::invalidate_email_tokens_in_tx(conn, email_id).await,
    }
}

pub(super) async fn sync_entity_email(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    email: String,
) -> Result<(), AppError> {
    let existing = match conn {
        DbTransaction::Postgres(c) => postgres::email_for_sync(c, entity_id).await?,
        DbTransaction::Sqlite(c) => sqlite::email_for_sync(c, entity_id).await?,
    };
    match existing {
        Some((email_id, current_email)) if current_email != email => {
            invalidate_email_tokens_in_tx(conn, email_id).await?;
            match conn {
                DbTransaction::Postgres(c) => {
                    postgres::replace_email(c, entity_id, email_id, &email).await
                }
                DbTransaction::Sqlite(c) => {
                    sqlite::replace_email(c, entity_id, email_id, &email).await
                }
            }
        }
        Some((email_id, _)) => match conn {
            DbTransaction::Postgres(c) => postgres::reactivate_email(c, email_id).await,
            DbTransaction::Sqlite(c) => sqlite::reactivate_email(c, email_id).await,
        },
        None => match conn {
            DbTransaction::Postgres(c) => postgres::insert_email(c, entity_id, &email).await,
            DbTransaction::Sqlite(c) => sqlite::insert_email(c, entity_id, &email).await,
        },
    }
}

pub(super) async fn get_entity_object_groups(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_entity_object_groups(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::get_entity_object_groups(&db.pool, entity_id).await,
    }
}

pub(super) async fn fetch_group<'e, E: crate::db::IntoTarget<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Group, AppError> {
    match executor.into_target() {
        crate::db::Target::PoolPostgres(executor) => postgres::fetch_group(executor, id).await,
        crate::db::Target::ConnectionPostgres(executor) => {
            postgres::fetch_group(executor, id).await
        }
        crate::db::Target::PoolSqlite(executor) => sqlite::fetch_group(executor, id).await,
        crate::db::Target::ConnectionSqlite(executor) => sqlite::fetch_group(executor, id).await,
    }
}

pub(super) async fn list_groups_by_ids(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<Group>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_groups_by_ids(pool, ids).await,
        Database::Sqlite(db) => sqlite::list_groups_by_ids(&db.pool, ids).await,
    }
}

pub(super) async fn list_groups(
    pool: &Database,
    params: ListGroups,
) -> Result<GroupList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_groups(pool, params).await,
        Database::Sqlite(db) => sqlite::list_groups(&db.pool, params).await,
    }
}

pub(super) async fn list_child_groups(
    pool: &Database,
    parent_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<GroupList, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::list_child_groups(pool, parent_id, limit, offset).await
        }
        Database::Sqlite(db) => sqlite::list_child_groups(&db.pool, parent_id, limit, offset).await,
    }
}

pub(super) async fn list_group_members(
    pool: &Database,
    group_id: Uuid,
) -> Result<Vec<Entity>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_group_members(pool, group_id).await,
        Database::Sqlite(db) => sqlite::list_group_members(&db.pool, group_id).await,
    }
}

pub(super) async fn get_entity_groups(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_entity_groups(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::get_entity_groups(&db.pool, entity_id).await,
    }
}

pub(super) async fn list_owned(pool: &Database, owner_id: Uuid) -> Result<Vec<Entity>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_owned(pool, owner_id).await,
        Database::Sqlite(db) => sqlite::list_owned(&db.pool, owner_id).await,
    }
}

pub(super) async fn delete_ownership(
    pool: &Database,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<(), AppError> {
    match pool {
        Database::Postgres(pool) => postgres::delete_ownership(pool, owner_id, owned_id).await,
        Database::Sqlite(db) => sqlite::delete_ownership(&db.pool, owner_id, owned_id).await,
    }
}

pub(super) async fn entity_tenant_including_deleted(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::entity_tenant_including_deleted(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::entity_tenant_including_deleted(conn, id).await,
    }
}

pub(super) async fn entity_revocation_ids(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<(Vec<Uuid>, Vec<Uuid>), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::entity_revocation_ids(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::entity_revocation_ids(conn, id).await,
    }
}

pub(super) async fn deactivate_entity(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    actor_id: Option<Uuid>,
    deleted_by: Option<Uuid>,
) -> Result<(Option<Uuid>, Vec<(Uuid, String, Option<Uuid>)>), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::deactivate_entity(conn, id, actor_id, deleted_by).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::deactivate_entity(conn, id, actor_id, deleted_by).await
        }
    }
}

pub(super) async fn deleted_entity_tenant(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::deleted_entity_tenant(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::deleted_entity_tenant(conn, id).await,
    }
}

pub(super) async fn entity_restore_snapshot(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, bool, DateTime<Utc>)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::entity_restore_snapshot(conn, id, expected_tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::entity_restore_snapshot(conn, id, expected_tenant_id).await
        }
    }
}

pub(super) async fn restore_entity(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    entity_deleted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::restore_entity(conn, id, entity_deleted_at).await
        }
        DbTransaction::Sqlite(conn) => sqlite::restore_entity(conn, id, entity_deleted_at).await,
    }
}

pub(super) async fn purge_entity(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<(Option<Uuid>, Vec<Uuid>), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::purge_entity(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_entity(conn, id).await,
    }
}

pub(super) async fn group_tenant_ids(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Vec<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::group_tenant_ids(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::group_tenant_ids(conn, id).await,
    }
}

pub(super) async fn physical_group_types(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Vec<String>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::physical_group_types(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::physical_group_types(conn, id).await,
    }
}

pub(super) async fn group_is_live(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<bool, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::group_is_live(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::group_is_live(conn, id).await,
    }
}

pub(super) async fn live_group_tenant(
    conn: &mut DbTransaction<'_>,
    child_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::live_group_tenant(conn, child_id).await,
        DbTransaction::Sqlite(conn) => sqlite::live_group_tenant(conn, child_id).await,
    }
}

pub(super) async fn lock_object_group(
    conn: &mut DbTransaction<'_>,
    child_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::lock_object_group(conn, child_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_object_group(conn, child_id).await,
    }
}

pub(super) async fn lock_principal_group(
    conn: &mut DbTransaction<'_>,
    child_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::lock_principal_group(conn, child_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_principal_group(conn, child_id).await,
    }
}

pub(super) async fn group_restore_snapshot(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<(Option<Uuid>, bool)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::group_restore_snapshot(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::group_restore_snapshot(conn, id).await,
    }
}

pub(super) async fn active_principal_group_tenant(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::active_principal_group_tenant(conn, group_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::active_principal_group_tenant(conn, group_id).await,
    }
}

pub(super) async fn active_member_tenant(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::active_member_tenant(conn, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::active_member_tenant(conn, entity_id).await,
    }
}

pub(super) async fn lock_active_member_group(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
    group_tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_active_member_group(conn, group_id, group_tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_active_member_group(conn, group_id, group_tenant_id).await
        }
    }
}

pub(super) async fn lock_active_member(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    entity_tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_active_member(conn, entity_id, entity_tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_active_member(conn, entity_id, entity_tenant_id).await
        }
    }
}

pub(super) async fn insert_member(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::insert_member(conn, group_id, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_member(conn, group_id, entity_id).await,
    }
}

pub(super) async fn principal_group_tenant(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::principal_group_tenant(conn, group_id).await,
        DbTransaction::Sqlite(conn) => sqlite::principal_group_tenant(conn, group_id).await,
    }
}

pub(super) async fn lock_member_group(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_member_group(conn, group_id, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::lock_member_group(conn, group_id, tenant_id).await,
    }
}

pub(super) async fn remove_member(
    conn: &mut DbTransaction<'_>,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::remove_member(conn, group_id, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::remove_member(conn, group_id, entity_id).await,
    }
}

pub(super) struct NewGroup<'a> {
    pub id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub group_type: &'a str,
    pub description: Option<String>,
    pub attributes: Value,
}

pub(super) async fn insert_group(
    conn: &mut DbTransaction<'_>,
    group: NewGroup<'_>,
) -> Result<Group, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::insert_group(conn, group).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_group(conn, group).await,
    }
}

pub(super) struct GroupChanges {
    pub id: Uuid,
    pub request: UpdateGroup,
    pub attributes: Option<Value>,
}

pub(super) async fn update_group(
    conn: &mut DbTransaction<'_>,
    changes: GroupChanges,
) -> Result<Group, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::update_group(conn, changes).await,
        DbTransaction::Sqlite(conn) => sqlite::update_group(conn, changes).await,
    }
}

pub(super) async fn remove_parent(
    conn: &mut DbTransaction<'_>,
    child_id: Uuid,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::remove_parent(conn, child_id).await,
        DbTransaction::Sqlite(conn) => sqlite::remove_parent(conn, child_id).await,
    }
}

pub(super) async fn delete_group(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::delete_group(conn, id, deleted_by).await,
        DbTransaction::Sqlite(conn) => sqlite::delete_group(conn, id, deleted_by).await,
    }
}

pub(super) async fn restore_group(conn: &mut DbTransaction<'_>, id: Uuid) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::restore_group(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::restore_group(conn, id).await,
    }
}

pub(super) async fn purge_group(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::purge_group(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_group(conn, id).await,
    }
}

pub(super) async fn ownership_entities(
    conn: &mut DbTransaction<'_>,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<Vec<(Uuid, Option<Uuid>)>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::ownership_entities(conn, owner_id, owned_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::ownership_entities(conn, owner_id, owned_id).await,
    }
}

pub(super) async fn lock_ownership_entities(
    conn: &mut DbTransaction<'_>,
    entity_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::lock_ownership_entities(conn, entity_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_ownership_entities(conn, entity_ids).await,
    }
}

pub(super) async fn upsert_ownership(
    conn: &mut DbTransaction<'_>,
    owner_id: Uuid,
    owned_id: Uuid,
    relation: String,
) -> Result<Ownership, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::upsert_ownership(conn, owner_id, owned_id, relation).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::upsert_ownership(conn, owner_id, owned_id, relation).await
        }
    }
}

pub(super) async fn hierarchy_group(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<(Option<Uuid>, String), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => postgres::hierarchy_group(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::hierarchy_group(conn, id).await,
    }
}

pub(super) async fn lock_hierarchy_groups(
    conn: &mut DbTransaction<'_>,
    group_table: &str,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::lock_hierarchy_groups(conn, group_table, child_id, parent_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_hierarchy_groups(conn, group_table, child_id, parent_id).await
        }
    }
}

pub(super) async fn hierarchy_creates_cycle(
    conn: &mut DbTransaction<'_>,
    hierarchy_table: &str,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool, AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::hierarchy_creates_cycle(conn, hierarchy_table, parent_id, child_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::hierarchy_creates_cycle(conn, hierarchy_table, parent_id, child_id).await
        }
    }
}

pub(super) async fn set_hierarchy_parent(
    conn: &mut DbTransaction<'_>,
    hierarchy_table: &str,
    parent_id: Uuid,
    child_id: Uuid,
    child_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    match conn {
        DbTransaction::Postgres(conn) => {
            postgres::set_hierarchy_parent(
                conn,
                hierarchy_table,
                parent_id,
                child_id,
                child_tenant_id,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::set_hierarchy_parent(
                conn,
                hierarchy_table,
                parent_id,
                child_id,
                child_tenant_id,
            )
            .await
        }
    }
}

pub(super) async fn credential_tenant_id(
    pool: &Database,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::credential_tenant_id(pool, entity_id, credential_id).await
        }
        Database::Sqlite(db) => {
            sqlite::credential_tenant_id(&db.pool, entity_id, credential_id).await
        }
    }
}
