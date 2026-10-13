//! Native tenant persistence; callers retain validation, transactions and events.
mod postgres;
mod sqlite;
use super::*;

pub(super) async fn verify_invitation_email(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    email: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::verify_invitation_email(conn, entity_id, email).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::verify_invitation_email(conn, entity_id, email).await
        }
    }
}

pub(super) async fn email_by_entity(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::email_by_entity(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::email_by_entity(&db.pool, entity_id).await,
    }
}

pub(super) async fn entity_by_email(
    pool: &Database,
    email: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::entity_by_email(pool, email).await,
        Database::Sqlite(db) => sqlite::entity_by_email(&db.pool, email).await,
    }
}

pub(super) async fn invitation_by_id(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<Option<InvitationRecord>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::invitation_by_id(conn, tenant_id, invitation_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::invitation_by_id(conn, tenant_id, invitation_id).await
        }
    }
}

pub(super) async fn invitation_for_invitee(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<InvitationRecord>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::invitation_for_invitee(conn, tenant_id, invitee_user_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::invitation_for_invitee(conn, tenant_id, invitee_user_id).await
        }
    }
}

pub(super) async fn revoke_invitation_by_id(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::revoke_invitation_by_id(conn, tenant_id, invitation_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::revoke_invitation_by_id(conn, tenant_id, invitation_id).await
        }
    }
}

pub(super) async fn revoke_invitation(
    tx: &mut DbTransaction<'_>,
    invitation_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::revoke_invitation(conn, invitation_id).await,
        DbTransaction::Sqlite(conn) => sqlite::revoke_invitation(conn, invitation_id).await,
    }
}

pub(super) async fn reject_invitation(
    tx: &mut DbTransaction<'_>,
    invitation_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::reject_invitation(conn, invitation_id).await,
        DbTransaction::Sqlite(conn) => sqlite::reject_invitation(conn, invitation_id).await,
    }
}

pub(super) async fn add_invited_member(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::add_invited_member(conn, tenant_id, invitee_user_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::add_invited_member(conn, tenant_id, invitee_user_id).await
        }
    }
}

pub(super) async fn accept_invitation(
    tx: &mut DbTransaction<'_>,
    invitation_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::accept_invitation(conn, invitation_id, invitee_user_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::accept_invitation(conn, invitation_id, invitee_user_id).await
        }
    }
}

pub(super) async fn accept_token(
    tx: &mut DbTransaction<'_>,
    invitation_id: Uuid,
    actor_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::accept_token(conn, invitation_id, actor_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::accept_token(conn, invitation_id, actor_id).await,
    }
}

pub(super) async fn lock_invitation(
    tx: &mut DbTransaction<'_>,
    token_id: Uuid,
) -> Result<InvitationRecord, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_invitation(conn, token_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_invitation(conn, token_id).await,
    }
}

pub(super) async fn add_member(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::add_member(conn, tenant_id, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::add_member(conn, tenant_id, entity_id).await,
    }
}

pub(super) async fn remove_member(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::remove_member(conn, tenant_id, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::remove_member(conn, tenant_id, entity_id).await,
    }
}

pub(super) async fn remove_member_assignments(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::remove_member_assignments(conn, tenant_id, entity_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::remove_member_assignments(conn, tenant_id, entity_id).await
        }
    }
}

pub(super) async fn remove_member_groups(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::remove_member_groups(conn, tenant_id, entity_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::remove_member_groups(conn, tenant_id, entity_id).await
        }
    }
}

pub(super) async fn member_assignments(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::member_assignments(conn, tenant_id, entity_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::member_assignments(conn, tenant_id, entity_id).await,
    }
}

pub(super) async fn member_groups(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::member_groups(conn, tenant_id, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::member_groups(conn, tenant_id, entity_id).await,
    }
}

pub(super) async fn count_assignable_entities(
    pool: &Database,
    tenant_id: Uuid,
    q: Option<String>,
) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::count_assignable_entities(pool, tenant_id, q).await,
        Database::Sqlite(db) => sqlite::count_assignable_entities(&db.pool, tenant_id, q).await,
    }
}

pub(super) async fn assignable_entities(
    pool: &Database,
    tenant_id: Uuid,
    q: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Entity>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::assignable_entities(pool, tenant_id, q, limit, offset).await
        }
        Database::Sqlite(db) => {
            sqlite::assignable_entities(&db.pool, tenant_id, q, limit, offset).await
        }
    }
}

pub(super) async fn count_members(
    pool: &Database,
    tenant_id: Uuid,
    q: Option<String>,
    id: Option<String>,
    status: Option<EntityStatus>,
) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::count_members(pool, tenant_id, q, id, status).await,
        Database::Sqlite(db) => sqlite::count_members(&db.pool, tenant_id, q, id, status).await,
    }
}

pub(super) async fn members(
    pool: &Database,
    tenant_id: Uuid,
    q: Option<String>,
    limit: i64,
    offset: i64,
    id: Option<String>,
    status: Option<EntityStatus>,
) -> Result<Vec<Entity>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::members(pool, tenant_id, q, limit, offset, id, status).await
        }
        Database::Sqlite(db) => {
            sqlite::members(&db.pool, tenant_id, q, limit, offset, id, status).await
        }
    }
}

pub(super) async fn count_user_invitations(
    pool: &Database,
    invitee_user_id: Uuid,
    state: Option<&str>,
) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::count_user_invitations(pool, invitee_user_id, state).await
        }
        Database::Sqlite(db) => {
            sqlite::count_user_invitations(&db.pool, invitee_user_id, state).await
        }
    }
}

pub(super) async fn user_invitations(
    pool: &Database,
    invitee_user_id: Uuid,
    limit: i64,
    offset: i64,
    state: Option<&str>,
) -> Result<Vec<TenantInvitation>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::user_invitations(pool, invitee_user_id, limit, offset, state).await
        }
        Database::Sqlite(db) => {
            sqlite::user_invitations(&db.pool, invitee_user_id, limit, offset, state).await
        }
    }
}

pub(super) async fn count_tenant_invitations(
    pool: &Database,
    tenant_id: Uuid,
    state: Option<&str>,
) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::count_tenant_invitations(pool, tenant_id, state).await
        }
        Database::Sqlite(db) => sqlite::count_tenant_invitations(&db.pool, tenant_id, state).await,
    }
}

pub(super) async fn tenant_invitations(
    pool: &Database,
    tenant_id: Uuid,
    limit: i64,
    offset: i64,
    state: Option<&str>,
) -> Result<Vec<TenantInvitation>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::tenant_invitations(pool, tenant_id, limit, offset, state).await
        }
        Database::Sqlite(db) => {
            sqlite::tenant_invitations(&db.pool, tenant_id, limit, offset, state).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn upsert_invitation(
    pool: &Database,
    tenant_id: Uuid,
    invitee_user_id: Option<Uuid>,
    email: Option<String>,
    invited_by: Uuid,
    req_role_id: Option<Uuid>,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<TenantInvitation, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => {
            postgres::upsert_invitation(
                pool,
                tenant_id,
                invitee_user_id,
                email,
                invited_by,
                req_role_id,
                token_hash,
                expires_at,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::upsert_invitation(
                &db.pool,
                tenant_id,
                invitee_user_id,
                email,
                invited_by,
                req_role_id,
                token_hash,
                expires_at,
            )
            .await
        }
    }
}

pub(super) async fn deactivate_sessions(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::deactivate_sessions(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::deactivate_sessions(conn, id).await,
    }
}

pub(super) async fn change_status(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    status: &TenantStatus,
    actor_id: Option<Uuid>,
) -> Result<Tenant, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::change_status(conn, id, status, actor_id).await,
        DbTransaction::Sqlite(conn) => sqlite::change_status(conn, id, status, actor_id).await,
    }
}

pub(super) async fn purge_tenant(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_tenant(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_tenant(conn, id).await,
    }
}

pub(super) async fn purge_authorities(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_authorities(conn, tenant_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_authorities(conn, tenant_ids).await,
    }
}

pub(super) async fn purge_pki_profiles(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_pki_profiles(conn, tenant_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_pki_profiles(conn, tenant_ids).await,
    }
}

pub(super) async fn purge_rate_windows(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Uuid],
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_rate_windows(conn, tenant_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_rate_windows(conn, tenant_ids).await,
    }
}

pub(super) async fn purge_object_ids(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_object_ids(conn, tenant_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_object_ids(conn, tenant_ids).await,
    }
}

pub(super) async fn reactivate_credentials(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::reactivate_credentials(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::reactivate_credentials(conn, id).await,
    }
}

pub(super) async fn credential_ids(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::credential_ids(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::credential_ids(conn, id).await,
    }
}

pub(super) async fn restore(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<Tenant, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::restore(conn, id, restored_by).await,
        DbTransaction::Sqlite(conn) => sqlite::restore(conn, id, restored_by).await,
    }
}

pub(super) async fn revoke_sessions(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::revoke_sessions(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::revoke_sessions(conn, id).await,
    }
}

pub(super) async fn revoke_credentials(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    actor_id: Option<Uuid>,
) -> Result<Vec<(Uuid, String, Option<Uuid>)>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::revoke_credentials(conn, id, actor_id).await,
        DbTransaction::Sqlite(conn) => sqlite::revoke_credentials(conn, id, actor_id).await,
    }
}

pub(super) async fn soft_delete(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Tenant, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::soft_delete(conn, id, deleted_by).await,
        DbTransaction::Sqlite(conn) => sqlite::soft_delete(conn, id, deleted_by).await,
    }
}

pub(super) async fn session_ids(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::session_ids(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::session_ids(conn, id).await,
    }
}

pub(super) async fn lock_live(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_live(conn, id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_live(conn, id).await,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn update_tenant(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    req_name: Option<String>,
    alias_is_set: bool,
    alias: Option<String>,
    req_tags: Option<Vec<String>>,
    req_attributes: Option<serde_json::Value>,
    updated_by: Option<Uuid>,
) -> Result<Tenant, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::update_tenant(
                conn,
                id,
                req_name,
                alias_is_set,
                alias,
                req_tags,
                req_attributes,
                updated_by,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::update_tenant(
                conn,
                id,
                req_name,
                alias_is_set,
                alias,
                req_tags,
                req_attributes,
                updated_by,
            )
            .await
        }
    }
}

pub(super) async fn get_tenant(pool: &Database, id: Uuid) -> Result<Tenant, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::get_tenant(pool, id).await,
        Database::Sqlite(db) => sqlite::get_tenant(&db.pool, id).await,
    }
}

pub(super) async fn add_creator_membership(
    tx: &mut DbTransaction<'_>,
    plan_tenant_id: Uuid,
    plan_creator_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::add_creator_membership(conn, plan_tenant_id, plan_creator_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::add_creator_membership(conn, plan_tenant_id, plan_creator_id).await
        }
    }
}

pub(super) async fn creator_kind(
    tx: &mut DbTransaction<'_>,
    plan_creator_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::creator_kind(conn, plan_creator_id).await,
        DbTransaction::Sqlite(conn) => sqlite::creator_kind(conn, plan_creator_id).await,
    }
}

pub(super) async fn assign_admin(
    tx: &mut DbTransaction<'_>,
    plan_tenant_id: Uuid,
    plan_creator_id: Uuid,
    role_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::assign_admin(conn, plan_tenant_id, plan_creator_id, role_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::assign_admin(conn, plan_tenant_id, plan_creator_id, role_id).await
        }
    }
}

pub(super) async fn missing_admin_actions(
    tx: &mut DbTransaction<'_>,
    capabilities: &[String],
    permission_block_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::missing_admin_actions(conn, capabilities, permission_block_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::missing_admin_actions(conn, capabilities, permission_block_id).await
        }
    }
}

pub(super) async fn link_admin_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    permission_block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::link_admin_block(conn, role_id, permission_block_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::link_admin_block(conn, role_id, permission_block_id).await
        }
    }
}

pub(super) async fn link_admin_actions(
    tx: &mut DbTransaction<'_>,
    permission_block_id: Uuid,
    capabilities: &[String],
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::link_admin_actions(conn, permission_block_id, capabilities).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::link_admin_actions(conn, permission_block_id, capabilities).await
        }
    }
}

pub(super) async fn insert_admin_block(
    tx: &mut DbTransaction<'_>,
    plan_tenant_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::insert_admin_block(conn, plan_tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_admin_block(conn, plan_tenant_id).await,
    }
}

pub(super) async fn insert_admin_role(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    plan_role_name: &str,
    plan_tenant_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_admin_role(conn, role_id, plan_role_name, plan_tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_admin_role(conn, role_id, plan_role_name, plan_tenant_id).await
        }
    }
}

pub(super) async fn default_actions(
    tx: &mut DbTransaction<'_>,
) -> Result<Vec<String>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::default_actions(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::default_actions(conn).await,
    }
}

pub(super) async fn insert_tenant(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    req_name: String,
    alias: Option<String>,
    req_tags: &[String],
    attrs: serde_json::Value,
    created_by: Option<Uuid>,
) -> Result<Tenant, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_tenant(conn, id, req_name, alias, req_tags, attrs, created_by).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_tenant(conn, id, req_name, alias, req_tags, attrs, created_by).await
        }
    }
}

pub(super) async fn lock_existing(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_existing(conn, tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_existing(conn, tenant_id).await,
    }
}

pub(super) async fn lock_active(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_active(conn, tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_active(conn, tenant_id).await,
    }
}

pub(super) async fn list_tenants(
    pool: &Database,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_tenants(pool, params).await,
        Database::Sqlite(db) => sqlite::list_tenants(&db.pool, params).await,
    }
}

pub(super) async fn list_tenants_for_entity_with_ceiling(
    pool: &Database,
    entity_id: Uuid,
    ceiling_credential_id: Option<Uuid>,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::list_tenants_for_entity_with_ceiling(
                pool,
                entity_id,
                ceiling_credential_id,
                params,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::list_tenants_for_entity_with_ceiling(
                &db.pool,
                entity_id,
                ceiling_credential_id,
                params,
            )
            .await
        }
    }
}

pub(super) async fn list_tenant_role_assignments(
    pool: &Database,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<TenantRoleAssignmentSummary>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::list_tenant_role_assignments(pool, tenant_id, entity_id).await
        }
        Database::Sqlite(db) => {
            sqlite::list_tenant_role_assignments(&db.pool, tenant_id, entity_id).await
        }
    }
}
