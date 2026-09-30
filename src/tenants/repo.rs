mod storage;
use crate::db::Database;
use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use uuid::Uuid;

use crate::{
    db::DbTransaction,
    error::{db_err, restore_conflict, AppError},
    identity::service::{hash_secret, verify_secret},
    models::{
        entity::{Entity, EntityList},
        enums::{
            EntityStatus, InvitationState, SortDir, SubjectKind, TenantOrderField, TenantStatus,
        },
        policy::CreateRoleAssignment,
        tenant::{
            CreateTenant, CreateTenantInvitation, ListTenantInvitations, ListTenants, Tenant,
            TenantInvitation, TenantInvitationList, TenantList, UpdateTenant,
        },
    },
};

pub struct CreatedInvitation {
    pub invitation: TenantInvitation,
    pub token: Option<String>,
    pub email: Option<String>,
}

fn checked_invitation_expiration(expiry_secs: u64) -> Result<DateTime<Utc>, AppError> {
    let seconds = i64::try_from(expiry_secs).map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "ATOM_INVITATION_EXPIRY_SECS is too large to represent as a duration"
        ))
    })?;
    let duration = Duration::try_seconds(seconds).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "ATOM_INVITATION_EXPIRY_SECS is too large to represent as a duration"
        ))
    })?;
    Utc::now().checked_add_signed(duration).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "ATOM_INVITATION_EXPIRY_SECS is too large to represent an invitation expiration"
        ))
    })
}

#[derive(Debug, Clone)]
pub struct PurgedTenant {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAdminBootstrap {
    pub tenant_id: Uuid,
    pub creator_id: Uuid,
    pub role_name: &'static str,
    pub capabilities: Vec<String>,
    pub scope_ref: String,
}

pub const TENANT_ADMIN_BASE_CAPABILITIES: [&str; 9] = [
    "manage",
    "read",
    "write",
    "delete",
    "publish",
    "subscribe",
    "execute",
    "policy.manage",
    "role.manage",
];

#[derive(Debug, Clone)]
pub struct TenantRoleAssignmentSummary {
    pub role_id: Uuid,
    pub role_name: String,
    /// Actions present in the role definition. This is metadata, not an
    /// authorization decision: block effects, conditions, and object scopes are
    /// intentionally not flattened into an inaccurate effective-access claim.
    pub actions: Vec<String>,
    pub assignment_paths: Vec<String>,
}

pub fn tenant_admin_bootstrap(tenant_id: Uuid, creator_id: Uuid) -> TenantAdminBootstrap {
    TenantAdminBootstrap {
        tenant_id,
        creator_id,
        role_name: "tenant-admin",
        capabilities: TENANT_ADMIN_BASE_CAPABILITIES
            .into_iter()
            .map(str::to_string)
            .collect(),
        scope_ref: tenant_id.to_string(),
    }
}

pub async fn lock_active_tenant(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
) -> Result<(), AppError> {
    let locked: Option<Uuid> = storage::lock_active(tx, tenant_id).await.map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!(
            "active tenant {tenant_id} not found"
        )));
    }
    Ok(())
}

pub async fn lock_optional_active_tenant(
    tx: &mut DbTransaction<'_>,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(tenant_id) = tenant_id {
        lock_active_tenant(tx, tenant_id).await?;
    }
    Ok(())
}

/// Lock existing tenant rows in a deterministic order without imposing a
/// lifecycle predicate.
///
/// This is the ordering primitive for mutations which must establish a tenant
/// barrier before taking a group-hierarchy advisory lock or a group row lock.
/// Some of those mutations deliberately operate on tombstoned objects, so the
/// helper only proves that each referenced tenant row still exists; the caller
/// remains responsible for any `active`/`deleted_at` policy check.
pub(crate) async fn lock_tenant_rows_in_order(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Option<Uuid>],
) -> Result<(), AppError> {
    let mut tenant_ids = tenant_ids.iter().copied().flatten().collect::<Vec<_>>();
    tenant_ids.sort_unstable();
    tenant_ids.dedup();

    for tenant_id in tenant_ids {
        let locked: Option<Uuid> = storage::lock_existing(tx, tenant_id)
            .await
            .map_err(db_err)?;
        if locked.is_none() {
            return Err(AppError::not_found(format!("tenant {tenant_id} not found")));
        }
    }
    Ok(())
}

pub async fn create_tenant_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant = create_tenant_in_tx(&mut tx, req, created_by).await?;
    if let Some(creator_id) = created_by {
        bootstrap_tenant_admin(&mut tx, tenant_admin_bootstrap(tenant.id, creator_id)).await?;
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(tenant.id),
        target_kind: "tenant",
        target_id: Some(tenant.id),
        event: "tenant.create",
    };
    let details = serde_json::json!({
        "name": tenant.name,
        "alias": tenant.alias,
    });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

pub async fn create_tenant(
    pool: &Database,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    create_tenant_with_audit(pool, false, None, req, created_by).await
}

async fn create_tenant_in_tx(
    tx: &mut DbTransaction<'_>,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let alias = crate::models::alias::validate_alias_opt(req.alias)?;
    let attrs = if req.attributes.is_null() {
        serde_json::json!({})
    } else {
        req.attributes
    };
    storage::insert_tenant(tx, id, req.name, alias, &req.tags, attrs, created_by)
        .await
        .map_err(db_err)
}

async fn bootstrap_tenant_admin(
    tx: &mut DbTransaction<'_>,
    plan: TenantAdminBootstrap,
) -> Result<(), AppError> {
    let role_id = Uuid::new_v4();
    let configured_capabilities: Vec<String> =
        storage::default_actions(tx).await.map_err(db_err)?;
    let mut capabilities = plan.capabilities;
    capabilities.extend(configured_capabilities);
    capabilities.sort();
    capabilities.dedup();

    storage::insert_admin_role(tx, role_id, plan.role_name, plan.tenant_id)
        .await
        .map_err(db_err)?;

    let permission_block_id: Uuid = storage::insert_admin_block(tx, plan.tenant_id)
        .await
        .map_err(db_err)?;

    storage::link_admin_actions(tx, permission_block_id, &capabilities)
        .await
        .map_err(db_err)?;

    storage::link_admin_block(tx, role_id, permission_block_id)
        .await
        .map_err(db_err)?;

    crate::guardrails::validate_role_assignment_on_connection(
        tx,
        Some(plan.tenant_id),
        SubjectKind::Entity,
        plan.creator_id,
        role_id,
    )
    .await?;

    let missing_names: Vec<String> =
        storage::missing_admin_actions(tx, &capabilities, permission_block_id)
            .await
            .map_err(db_err)?;
    if !missing_names.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "tenant-admin bootstrap missing seeded capabilities: {}",
            missing_names.join(", ")
        )));
    }

    storage::assign_admin(tx, plan.tenant_id, plan.creator_id, role_id)
        .await
        .map_err(db_err)?;

    let creator = storage::creator_kind(tx, plan.creator_id)
        .await
        .map_err(db_err)?;

    if creator.as_deref() == Some("human") {
        storage::add_creator_membership(tx, plan.tenant_id, plan.creator_id)
            .await
            .map_err(db_err)?;
    }

    Ok(())
}

pub async fn get_tenant(pool: &Database, id: Uuid) -> Result<Tenant, AppError> {
    storage::get_tenant(pool, id).await.map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_tenants(pool: &Database, params: ListTenants) -> Result<TenantList, AppError> {
    storage::list_tenants(pool, params).await
}

/// Ceiling-aware tenant visibility listing for request-path callers. The
/// scoped-token ceiling is derived from the caller's `AuthContext`
/// (`ceiling_credential_for`), never passed by hand — same rule as
/// `engine::evaluate` and `authz::repo::authorized_object_ids`.
pub async fn list_tenants_for_entity(
    pool: &Database,
    auth: &crate::auth::AuthContext,
    entity_id: Uuid,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    let ceiling_credential_id = auth.ceiling_credential_for(entity_id);
    list_tenants_for_entity_with_ceiling(pool, entity_id, ceiling_credential_id, params).await
}

/// Low-level visibility listing taking an explicit ceiling credential. For
/// tests; production code must call [`list_tenants_for_entity`].
pub async fn list_tenants_for_entity_with_ceiling(
    pool: &Database,
    entity_id: Uuid,
    ceiling_credential_id: Option<Uuid>,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    storage::list_tenants_for_entity_with_ceiling(pool, entity_id, ceiling_credential_id, params)
        .await
}

pub async fn update_tenant_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateTenant,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let alias = crate::models::alias::validate_alias_update(req.alias)?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "tenants", id).await?;
    let tenant = storage::update_tenant(
        &mut tx,
        id,
        req.name,
        alias_is_set,
        alias,
        req.tags,
        req.attributes,
        updated_by,
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: "tenant.update",
    };
    let details = serde_json::json!({});
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

pub async fn update_tenant(
    pool: &Database,
    id: Uuid,
    req: UpdateTenant,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    update_tenant_with_audit(pool, false, None, id, req, updated_by).await
}

/// Locks the tenant row and, in the *same* transaction, enumerates the exact
/// active session ids of its member entities that a subsequent delete is
/// about to revoke — *before* the tenant is touched. Callers establish the
/// cache barrier on these ids (plus the tenant's own `tenant_status` key)
/// before calling [`deactivate_and_finish_tenant_soft_delete_in_tx`]: starting
/// the barrier only after the status flip would leave a window where a
/// concurrent request can still take a full cache hit on the pre-delete
/// tenant-status/session entries and keep running past the point the delete
/// commits.
///
/// The `SELECT ... FOR UPDATE` below takes the same exclusive row lock on the
/// tenant that `lock_active_tenant`/`lock_optional_active_tenant` take
/// (transitively, via `lock_active_entity`) before any session or credential
/// can be created for an entity in this tenant. So a session created
/// concurrently for a member entity either committed before this lock was
/// acquired (and is therefore visible to the enumeration below, which runs
/// after it, in the same transaction) or is blocked until this transaction
/// commits (and then fails, since the tenant is no longer active by then).
/// Enumerating via a plain pre-transaction pool query — the previous shape of
/// this code — could miss a session created in that window, leaving its
/// cache entry uninvalidated indefinitely. See `src/cache/mod.rs`'s
/// consistency model.
pub async fn lock_tenant_and_collect_session_ids_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "tenants", id).await?;
    let locked = storage::lock_live(tx, id).await.map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("tenant {id} not found")));
    }

    let session_ids: Vec<Uuid> = storage::session_ids(tx, id).await.map_err(db_err)?;

    Ok(session_ids)
}

/// Finishes the tenant soft-delete started by
/// [`lock_tenant_and_collect_session_ids_in_tx`] in the same transaction:
/// flips the tenant to `deleted`, and revokes every active credential and
/// session belonging to the tenant's entities. Does not commit — the caller
/// commits after this succeeds, once the cache barrier established on the
/// enumerated session ids covers the whole transaction.
pub async fn deactivate_and_finish_tenant_soft_delete_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    deleted_by: Option<Uuid>,
    id: Uuid,
) -> Result<Tenant, AppError> {
    let tenant = storage::soft_delete(tx, id, deleted_by)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
            other => AppError::Database(other),
        })?;

    // Stamp the tenant-delete marker on every revoked credential (not just
    // certificates) so restore_tenant can reverse exactly the revocations this
    // delete caused, without disturbing credentials revoked earlier for other
    // reasons.
    let revoked: Vec<(Uuid, String, Option<Uuid>)> = storage::revoke_credentials(tx, id, actor_id)
        .await
        .map_err(db_err)?;
    let revoked_certificates: Vec<(Uuid, Option<Uuid>)> = revoked
        .into_iter()
        .filter(|(_, kind, _)| kind == "certificate")
        .map(|(id, _, issuer_id)| (id, issuer_id))
        .collect();

    storage::revoke_sessions(tx, id).await.map_err(db_err)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: "tenant.delete",
    };
    let details = serde_json::json!({
        "certificate_revocations": {
            "count": revoked_certificates.len(),
            "credential_ids": revoked_certificates
                .iter()
                .map(|(credential_id, _)| credential_id)
                .collect::<Vec<_>>(),
            "issuer_ids": revoked_certificates
                .iter()
                .filter_map(|(_, issuer_id)| *issuer_id)
                .collect::<Vec<_>>(),
            "reason": "tenant_deleted",
        }
    });
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

/// Soft-delete a tenant: mark `status = deleted`, stamp the tombstone, and
/// immediately revoke every active credential and session of entities in the
/// tenant. Physical removal (and the entity cascade) is deferred to the purge
/// cron.
pub async fn soft_delete_tenant(
    pool: &Database,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    soft_delete_tenant_with_audit(pool, false, None, id, deleted_by).await
}

/// Used directly only when no cache is configured; the cache-aware path
/// (`graphql::tenants::delete_tenant`) calls
/// [`lock_tenant_and_collect_session_ids_in_tx`] and
/// [`deactivate_and_finish_tenant_soft_delete_in_tx`] itself so it can
/// establish the cache barrier between them.
pub async fn soft_delete_tenant_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_tenant_and_collect_session_ids_in_tx(&mut tx, id).await?;
    let tenant = deactivate_and_finish_tenant_soft_delete_in_tx(
        &mut tx,
        events_enabled,
        actor_id,
        deleted_by,
        id,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: Some(id),
            target_kind: "tenant",
            target_id: Some(id),
            event: "tenant.delete",
        },
        &serde_json::json!({}),
    );
    Ok(tenant)
}

/// Reverse a tenant soft delete within the retention window. Reactivates the
/// tenant and clears its tombstone; its children (entities, groups, roles,
/// resources) were never individually tombstoned by `soft_delete_tenant` — they
/// were hidden only via the tenant's `deleted_at` — so they become visible again
/// automatically.
///
/// To make the restored tenant operational, the non-certificate child
/// credentials (passwords, API keys) that *this* delete revoked — identified by
/// the `tenant_deleted` revocation marker — are reactivated, so members can log
/// in with their existing secrets. Certificates stay revoked (their revocation
/// is published via the CRL and cannot be safely undone — re-issue is required),
/// and sessions stay revoked, so a fresh login is required. Credentials revoked
/// earlier for other reasons (e.g. an individually soft-deleted child) are left
/// untouched.
///
/// Fails with a conflict if the tenant name/alias was re-taken by a live tenant
/// during the retention window.
///
/// Flips the tenant back to `active` and, in the *same* transaction,
/// enumerates the exact credential ids [`finish_tenant_restore_in_tx`] is
/// about to reactivate — mirrors that function's `UPDATE credentials` `WHERE`
/// clause precisely, so callers can invalidate `atom:v1:credential:*` cache
/// entries for them (see `src/cache/mod.rs`'s consistency model). A stale
/// cached "revoked" credential is a false-deny (fails closed, not a security
/// hole) but is still worth fixing: unlike a tenant or entity status flip,
/// which a later-checked fresh field can catch regardless of earlier stale
/// fields, `verify_api_key_snapshot` checks the credential's own status first
/// — a stale value there is never overridden by anything checked afterward.
///
/// The status-flip `UPDATE` below takes an exclusive row lock on the tenant,
/// so the enumeration that follows it (in the same transaction) sees a
/// consistent snapshot with respect to any concurrent restore/purge of the
/// same tenant — mirroring the same lock-then-enumerate shape used by
/// [`lock_tenant_and_collect_session_ids_in_tx`], even though (unlike
/// that case) no *new* matching credential can appear here: only
/// `soft_delete_tenant` ever stamps the `tenant_deleted` revocation reason,
/// and it cannot run again against an already-deleted tenant.
pub async fn reactivate_tenant_and_collect_credential_ids_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(Tenant, Vec<Uuid>), AppError> {
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "tenants", id).await?;
    let tenant = storage::restore(tx, id, restored_by)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                AppError::not_found(format!("no soft-deleted tenant {id} to restore"))
            }
            other => restore_conflict(other),
        })?;

    let credential_ids: Vec<Uuid> = storage::credential_ids(tx, id).await.map_err(db_err)?;

    Ok((tenant, credential_ids))
}

/// Finishes the tenant restore started by
/// [`reactivate_tenant_and_collect_credential_ids_in_tx`] in the same
/// transaction: reactivates exactly the credentials it enumerated. Does not
/// commit — the caller commits after this succeeds, once the cache barrier
/// established on those credential ids covers the whole transaction.
pub async fn finish_tenant_restore_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<(), AppError> {
    storage::reactivate_credentials(tx, id)
        .await
        .map_err(db_err)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: "tenant.restore",
    };
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &serde_json::json!({})).await?;
    Ok(())
}

pub async fn restore_tenant(
    pool: &Database,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    restore_tenant_with_audit(pool, false, None, id, restored_by).await
}

/// Used directly only when no cache is configured; the cache-aware path
/// (`graphql::tenants::restore_tenant`) calls
/// [`reactivate_tenant_and_collect_credential_ids_in_tx`] and
/// [`finish_tenant_restore_in_tx`] itself so it can establish the cache
/// barrier between them.
pub async fn restore_tenant_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let (tenant, _credential_ids) =
        reactivate_tenant_and_collect_credential_ids_in_tx(&mut tx, id, restored_by).await?;
    finish_tenant_restore_in_tx(&mut tx, events_enabled, actor_id, id).await?;
    tx.commit().await.map_err(db_err)?;
    // The audit_logs row is deliberately written after commit (fire-and-forget,
    // never blocks an already-valid restore) — see `audit::commit_with_audit`'s
    // doc comment. The outbox row, by contrast, went in atomically with the
    // mutation above via `observe_in_tx`.
    crate::audit::write(
        pool,
        false,
        crate::audit::AuditEvent {
            actor_entity_id: actor_id,
            tenant_id: Some(id),
            target_kind: Some("tenant"),
            target_id: Some(id),
            event: "tenant.restore",
            outcome: crate::models::enums::AuditOutcome::Allow,
            details: serde_json::json!({}),
        },
    )
    .await;
    Ok(tenant)
}

pub(crate) async fn tenant_purge_object_ids(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    if tenant_ids.is_empty() {
        return Ok(Vec::new());
    }
    storage::purge_object_ids(tx, tenant_ids)
        .await
        .map_err(db_err)
}

pub(crate) async fn purge_tenant_pki_in_tx(
    tx: &mut DbTransaction<'_>,
    tenant_ids: &[Uuid],
) -> Result<(), AppError> {
    if tenant_ids.is_empty() {
        return Ok(());
    }

    // Rate-limit rows are deliberately independent of subject FKs. Remove
    // both tenant and child-entity scopes while those entities are still
    // available to identify, before the tenant cascade runs.
    storage::purge_rate_windows(tx, tenant_ids)
        .await
        .map_err(db_err)?;

    // Credentials restrict authority deletion, and authorities belong to the
    // tenant being purged. Remove them in dependency order before the tenant.
    storage::purge_pki_profiles(tx, tenant_ids)
        .await
        .map_err(db_err)?;

    storage::purge_authorities(tx, tenant_ids)
        .await
        .map_err(db_err)?;

    Ok(())
}

pub async fn purge_tenant_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<PurgedTenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "tenants", id).await?;

    let doomed = tenant_purge_object_ids(&mut tx, &[id]).await?;
    purge_tenant_pki_in_tx(&mut tx, &[id]).await?;

    let purged = storage::purge_tenant(&mut tx, id).await.map_err(db_err)?;
    let Some((id, name)) = purged else {
        return Err(AppError::not_found(format!(
            "no soft-deleted tenant {id} to purge"
        )));
    };

    crate::authz::repo::purge_authz_references_for_ids(&mut tx, &doomed).await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: None,
        target_kind: Some("tenant"),
        target_id: Some(id),
        event: "tenant.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({
            "tenant_name": name,
        }),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(PurgedTenant { id, name })
}

pub async fn purge_tenant(pool: &Database, id: Uuid) -> Result<PurgedTenant, AppError> {
    purge_tenant_with_audit(pool, false, None, id).await
}

/// `actor_id` is both the audited actor and the row's `updated_by` — they are
/// the same principal, so this takes it once.
pub async fn change_tenant_status_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    status: TenantStatus,
    event_name: &str,
) -> Result<Tenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant =
        change_tenant_status_in_tx(&mut tx, events_enabled, actor_id, id, status, event_name)
            .await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: Some(id),
            target_kind: "tenant",
            target_id: Some(id),
            event: event_name,
        },
        &serde_json::json!({ "status": tenant.status }),
    );
    Ok(tenant)
}

/// Body of [`change_tenant_status_with_audit`]. When `status != Active`, this
/// also bulk-revokes the tenant's members' sessions — a cache-aware caller
/// must already have enumerated those session ids via
/// [`lock_tenant_and_collect_session_ids_in_tx`] and established the barrier
/// on them (alongside `tenant_status`) before calling this, the same way
/// `deleteTenant` does: a barrier put up only after this commits would leave
/// a window where a concurrent read still takes a full cache hit on a
/// session this call is about to revoke, which then survives (with
/// `revoked_at = None`) until the tenant is re-enabled and its own
/// `tenant_status` cache entry stops masking the stale session.
pub(crate) async fn change_tenant_status_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    status: TenantStatus,
    event_name: &str,
) -> Result<Tenant, AppError> {
    if status == TenantStatus::Deleted {
        return Err(AppError::bad_request(
            "use delete tenant to apply the soft-delete lifecycle",
        ));
    }
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "tenants", id).await?;
    let tenant = storage::change_status(tx, id, &status, actor_id)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
            other => AppError::Database(other),
        })?;

    if status != TenantStatus::Active {
        storage::deactivate_sessions(tx, id).await.map_err(db_err)?;
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: event_name,
    };
    let details = serde_json::json!({ "status": tenant.status });
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

pub async fn change_tenant_status(
    pool: &Database,
    id: Uuid,
    status: TenantStatus,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    change_tenant_status_with_audit(pool, false, updated_by, id, status, "tenant.status.update")
        .await
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

pub async fn create_invitation(
    pool: &Database,
    tenant_id: Uuid,
    invited_by: Uuid,
    req: CreateTenantInvitation,
    expiry_secs: u64,
) -> Result<CreatedInvitation, AppError> {
    let invitee_email = req
        .invitee_email
        .as_deref()
        .map(normalize_email)
        .transpose()?;
    let invitee_user_id = match (req.invitee_user_id, invitee_email.as_deref()) {
        (Some(user_id), _) => Some(user_id),
        (None, Some(email)) => entity_id_by_email(pool, email).await?,
        (None, None) => {
            return Err(AppError::bad_request(
                "invitee_user_id or invitee_email is required",
            ))
        }
    };
    let email = match invitee_email {
        Some(email) => Some(email),
        None => match invitee_user_id {
            Some(user_id) => email_by_entity_id(pool, user_id).await?,
            None => None,
        },
    };

    // The secret can be generated upfront -- it doesn't depend on which row
    // ends up holding it -- but the *id* half of the token must come from
    // whichever row this upsert actually resolves to. Re-inviting someone who
    // already has a tenant_invitations row (a resend, or simply inviting them
    // again) hits the UPDATE branch below and keeps that row's existing id;
    // a token built from a speculatively pre-generated id would then point at
    // a row that was never inserted, and accept_invitation_token's `WHERE id
    // = $1` lookup would find nothing ("invitation not found") for an
    // otherwise legitimate invitee.
    let (_, token_secret, _) = new_secret_token("atomi");
    let token_hash = hash_secret(token_secret.as_bytes())?;
    let expires_at = checked_invitation_expiration(expiry_secs)?;

    let invitation = storage::upsert_invitation(
        pool,
        tenant_id,
        invitee_user_id,
        email.clone(),
        invited_by,
        req.role_id,
        token_hash,
        expires_at,
    )
    .await
    .map_err(db_err)?;

    let token = format!(
        "atomi_{}_{}",
        hex::encode(invitation.id.as_bytes()),
        token_secret
    );

    Ok(CreatedInvitation {
        invitation,
        token: email.as_ref().map(|_| token),
        email,
    })
}

/// Maps a state filter to the value bound into each query's `$N::text`
/// state parameter. `None` means no filtering — matches every state,
/// including the "all" tab, where the argument is omitted entirely.
fn invitation_state_str(state: Option<InvitationState>) -> Option<&'static str> {
    match state? {
        InvitationState::Pending => Some("pending"),
        InvitationState::Accepted => Some("accepted"),
        InvitationState::Rejected => Some("rejected"),
        InvitationState::Revoked => Some("revoked"),
    }
}

pub async fn list_tenant_invitations(
    pool: &Database,
    tenant_id: Uuid,
    params: ListTenantInvitations,
) -> Result<TenantInvitationList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let state = invitation_state_str(params.state);
    let items = storage::tenant_invitations(pool, tenant_id, limit, offset, state)
        .await
        .map_err(db_err)?;
    let total: i64 = storage::count_tenant_invitations(pool, tenant_id, state)
        .await
        .map_err(db_err)?;
    Ok(TenantInvitationList { items, total })
}

pub async fn list_user_invitations(
    pool: &Database,
    invitee_user_id: Uuid,
    params: ListTenantInvitations,
) -> Result<TenantInvitationList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let state = invitation_state_str(params.state);
    let items = storage::user_invitations(pool, invitee_user_id, limit, offset, state)
        .await
        .map_err(db_err)?;
    let total: i64 = storage::count_user_invitations(pool, invitee_user_id, state)
        .await
        .map_err(db_err)?;
    Ok(TenantInvitationList { items, total })
}

pub async fn list_tenant_members(
    pool: &Database,
    tenant_id: Uuid,
    q: Option<String>,
    id: Option<String>,
    status: Option<EntityStatus>,
    limit: i64,
    offset: i64,
) -> Result<EntityList, AppError> {
    let limit = limit.clamp(1, 100);
    let offset = offset.max(0);
    let q = search_pattern(q);
    let id = search_pattern(id);

    let items = storage::members(
        pool,
        tenant_id,
        q.clone(),
        limit,
        offset,
        id.clone(),
        status.clone(),
    )
    .await
    .map_err(db_err)?;

    let total: i64 = storage::count_members(pool, tenant_id, q, id, status)
        .await
        .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub async fn list_tenant_assignable_entities(
    pool: &Database,
    tenant_id: Uuid,
    q: String,
    limit: i64,
    offset: i64,
) -> Result<EntityList, AppError> {
    let limit = limit.clamp(1, 20);
    let offset = offset.max(0);
    let q = search_pattern(Some(q));

    let items = storage::assignable_entities(pool, tenant_id, q.clone(), limit, offset)
        .await
        .map_err(db_err)?;

    let total: i64 = storage::count_assignable_entities(pool, tenant_id, q)
        .await
        .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub async fn remove_tenant_member(
    pool: &Database,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    remove_tenant_member_with_audit(pool, false, None, tenant_id, entity_id).await
}

pub async fn remove_tenant_member_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    // Tenant-member removal is also a bulk clear of this entity's principal
    // group memberships and tenant-scoped role assignments. Serialize it with
    // bootstrap and the individual link mutators before checking every
    // affected owner; otherwise a config stamp could land after a pooled
    // precheck and its link would then be deleted out of band.
    lock_tenant_rows_in_order(&mut tx, &[Some(tenant_id)]).await?;
    let affected_group_ids: Vec<Uuid> = storage::member_groups(&mut tx, tenant_id, entity_id)
        .await
        .map_err(db_err)?;
    for group_id in affected_group_ids {
        crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "principal_groups", group_id)
            .await?;
    }
    let affected_assignment_ids: Vec<Uuid> =
        storage::member_assignments(&mut tx, tenant_id, entity_id)
            .await
            .map_err(db_err)?;
    for assignment_id in affected_assignment_ids {
        crate::managed_by::ensure_not_config_managed_in_tx(
            &mut tx,
            "role_assignments",
            assignment_id,
        )
        .await?;
    }

    storage::remove_member_groups(&mut tx, tenant_id, entity_id)
        .await
        .map_err(db_err)?;

    storage::remove_member_assignments(&mut tx, tenant_id, entity_id)
        .await
        .map_err(db_err)?;

    let result = storage::remove_member(&mut tx, tenant_id, entity_id)
        .await
        .map_err(db_err)?;

    if result == 0 {
        return Err(AppError::not_found("tenant member not found"));
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(tenant_id),
        target_kind: "tenant",
        target_id: Some(tenant_id),
        event: "tenant_member.remove",
    };
    let details = serde_json::json!({ "entity_id": entity_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(())
}

pub async fn add_tenant_member(
    pool: &Database,
    tenant_id: Uuid,
    entity_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    add_tenant_member_with_audit(pool, false, None, tenant_id, entity_id, role_id).await
}

pub async fn add_tenant_member_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Uuid,
    entity_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_active_tenant(&mut tx, tenant_id).await?;
    crate::authz::repo::lock_live_entity_subject_in_tx(&mut tx, Some(tenant_id), entity_id).await?;

    // The `WHERE` on the conflict branch keeps `rows_affected` honest: without
    // it a `DO UPDATE` reports one row even when it rewrote 'active' as
    // 'active', and re-adding an existing member would look like a change.
    let membership_changed = storage::add_member(&mut tx, tenant_id, entity_id)
        .await
        .map_err(db_err)?
        > 0;

    let mut role_assigned = false;
    if let Some(role_id) = role_id {
        role_assigned = crate::authz::repo::create_role_assignment_if_missing_in_tx(
            &mut tx,
            &CreateRoleAssignment {
                tenant_id: Some(tenant_id),
                subject_kind: SubjectKind::Entity,
                subject_id: entity_id,
                role_id,
            },
        )
        .await?;
    }

    // Re-adding an already-active member with no new role assignment changed
    // nothing; publishing `tenant_member.add` for it would be a false positive.
    if !membership_changed && !role_assigned {
        tx.commit().await.map_err(db_err)?;
        return Ok(());
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(tenant_id),
        target_kind: "tenant",
        target_id: Some(tenant_id),
        event: "tenant_member.add",
    };
    let details = serde_json::json!({ "entity_id": entity_id, "role_id": role_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(())
}

pub async fn list_tenant_role_assignments(
    pool: &Database,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<TenantRoleAssignmentSummary>, AppError> {
    storage::list_tenant_role_assignments(pool, tenant_id, entity_id).await
}

pub async fn accept_invitation(
    pool: &Database,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let role_id = accept_invitation_row(&mut tx, tenant_id, invitee_user_id).await?;
    grant_invitation_role(&mut tx, tenant_id, invitee_user_id, role_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn accept_invitation_token(
    pool: &Database,
    token: &str,
    actor_id: Uuid,
) -> Result<Uuid, AppError> {
    let (token_id, token_secret) = parse_secret_token(token, "atomi")
        .ok_or_else(|| AppError::bad_request("invalid invitation token"))?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = storage::lock_invitation(&mut tx, token_id)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found("invitation not found"),
            other => AppError::Database(other),
        })?;

    let secret_hash: Option<String> = row.secret_hash.clone();
    let Some(secret_hash) = secret_hash else {
        return Err(AppError::bad_request("invalid invitation token"));
    };
    if !verify_secret(token_secret.as_bytes(), &secret_hash) {
        return Err(AppError::bad_request("invalid invitation token"));
    }
    ensure_invitation_pending(&row)?;

    let tenant_id: Uuid = row.tenant_id;
    let invitee_user_id: Option<Uuid> = row.invitee_user_id;
    if let Some(invitee_user_id) = invitee_user_id {
        if invitee_user_id != actor_id {
            return Err(invitation_wrong_user());
        }
    } else if let Some(email) = row.invitee_email.clone() {
        // The secret was verified before this point. Because email invitations
        // are delivered to this address and the token is never returned by the
        // public mutation, presenting it is proof of mailbox control. Record
        // that proof atomically with acceptance so local-development accounts
        // with an unverified address can redeem their invitation safely.
        if !verify_entity_email_from_invitation(&mut tx, actor_id, &email).await? {
            return Err(invitation_wrong_user());
        }
    }

    let invitation_id: Uuid = row.id;
    let role_id: Option<Uuid> = storage::accept_token(&mut tx, invitation_id, actor_id)
        .await
        .map_err(db_err)?;

    grant_invitation_role(&mut tx, tenant_id, actor_id, role_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(tenant_id)
}

async fn accept_invitation_row(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let row = invitation_row_for_invitee(tx, tenant_id, invitee_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;
    let invitation_id: Uuid = row.id;

    storage::accept_invitation(tx, invitation_id, invitee_user_id)
        .await
        .map_err(db_err)
}

async fn grant_invitation_role(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    lock_active_tenant(tx, tenant_id).await?;
    crate::authz::repo::lock_live_entity_subject_in_tx(tx, Some(tenant_id), invitee_user_id)
        .await?;
    storage::add_invited_member(tx, tenant_id, invitee_user_id)
        .await
        .map_err(db_err)?;

    let Some(role_id) = role_id else {
        return Ok(());
    };

    crate::authz::repo::create_role_assignment_if_missing_in_tx(
        tx,
        &CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: invitee_user_id,
            role_id,
        },
    )
    .await?;
    Ok(())
}

pub async fn reject_invitation(
    pool: &Database,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = invitation_row_for_invitee(&mut tx, tenant_id, invitee_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;
    let invitation_id: Uuid = row.id;

    storage::reject_invitation(&mut tx, invitation_id)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn revoke_invitation(
    pool: &Database,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = invitation_row_for_invitee(&mut tx, tenant_id, invitee_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;
    let invitation_id: Uuid = row.id;

    storage::revoke_invitation(&mut tx, invitation_id)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn revoke_invitation_by_id(
    pool: &Database,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = invitation_row_by_id(&mut tx, tenant_id, invitation_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;

    storage::revoke_invitation_by_id(&mut tx, tenant_id, invitation_id)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

async fn invitation_row_for_invitee(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<InvitationRecord>, AppError> {
    storage::invitation_for_invitee(tx, tenant_id, invitee_user_id)
        .await
        .map_err(db_err)
}

async fn invitation_row_by_id(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<Option<InvitationRecord>, AppError> {
    storage::invitation_by_id(tx, tenant_id, invitation_id)
        .await
        .map_err(db_err)
}

fn ensure_invitation_pending(row: &InvitationRecord) -> Result<(), AppError> {
    let accepted_at: Option<DateTime<Utc>> = row.accepted_at;
    if accepted_at.is_some() {
        return Err(AppError::bad_request("invitation already accepted"));
    }

    let rejected_at: Option<DateTime<Utc>> = row.rejected_at;
    if rejected_at.is_some() {
        return Err(AppError::bad_request("invitation already rejected"));
    }

    let revoked_at: Option<DateTime<Utc>> = row.revoked_at;
    if revoked_at.is_some() {
        return Err(AppError::bad_request("invitation already revoked"));
    }

    let expires_at: Option<DateTime<Utc>> = row.expires_at;
    if expires_at.is_some_and(|expires_at| expires_at < Utc::now()) {
        return Err(AppError::bad_request("invitation expired"));
    }

    Ok(())
}

fn invitation_wrong_user() -> AppError {
    AppError::bad_request("invitation does not belong to this user")
}

async fn entity_id_by_email(pool: &Database, email: &str) -> Result<Option<Uuid>, AppError> {
    storage::entity_by_email(pool, email).await.map_err(db_err)
}

async fn email_by_entity_id(pool: &Database, entity_id: Uuid) -> Result<Option<String>, AppError> {
    storage::email_by_entity(pool, entity_id)
        .await
        .map_err(db_err)
}

async fn verify_entity_email_from_invitation(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    email: &str,
) -> Result<bool, AppError> {
    Ok(storage::verify_invitation_email(tx, entity_id, email)
        .await
        .map_err(db_err)?
        > 0)
}

fn new_secret_token(prefix: &str) -> (Uuid, String, String) {
    let id = Uuid::new_v4();
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);
    let token = format!("{prefix}_{}_{}", hex::encode(id.as_bytes()), secret);
    (id, secret, token)
}

fn parse_secret_token(token: &str, prefix: &str) -> Option<(Uuid, String)> {
    let rest = token.strip_prefix(&format!("{prefix}_"))?;
    if rest.len() != 32 + 1 + 64 {
        return None;
    }
    let (id_hex, tail) = rest.split_at(32);
    let secret = tail.strip_prefix('_')?;
    let id_bytes = hex::decode(id_hex).ok()?;
    let id: [u8; 16] = id_bytes.try_into().ok()?;
    if hex::decode(secret).ok()?.len() != 32 {
        return None;
    }
    Some((Uuid::from_bytes(id), secret.to_string()))
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    let normalized = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(AppError::bad_request("invalid email"));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(AppError::bad_request("invalid email"));
    }
    Ok(normalized)
}

#[derive(sqlx::FromRow)]
struct InvitationRecord {
    id: Uuid,
    tenant_id: Uuid,
    invitee_user_id: Option<Uuid>,
    invitee_email: Option<String>,
    secret_hash: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    accepted_at: Option<DateTime<Utc>>,
    rejected_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}
#[cfg(test)]
mod tests {
    //! DB-gated tests. Each is `#[ignore]` because it needs a live
    //! Postgres reachable via `DATABASE_URL`. Run with:
    //!
    //!     DATABASE_URL=postgres://... cargo test tenants:: -- --ignored
    use super::*;
    use crate::db::Database;
    use crate::models::tenant::{CreateTenant, ListTenants, UpdateTenant};
    use serde_json::{json, Value};

    async fn pool() -> Database {
        crate::db::testing::database().await
    }

    async fn cleanup(pool: &Database, ids: &[Uuid]) {
        for id in ids {
            let _ = crate::test_db::query(
                "DELETE FROM tenants WHERE id = $1",
                r#"DELETE FROM tenants WHERE id = $1"#,
            )
            .bind(id)
            .execute(pool)
            .await;
        }
    }

    fn unique_name(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4())
    }

    #[test]
    fn tenant_admin_bootstrap_plan_matches_m5_contract() {
        let tenant_id = Uuid::new_v4();
        let creator_id = Uuid::new_v4();
        let plan = tenant_admin_bootstrap(tenant_id, creator_id);

        assert_eq!(plan.tenant_id, tenant_id);
        assert_eq!(plan.creator_id, creator_id);
        assert_eq!(plan.role_name, "tenant-admin");
        assert_eq!(plan.scope_ref, tenant_id.to_string());
        assert_eq!(
            plan.capabilities,
            [
                "manage",
                "read",
                "write",
                "delete",
                "publish",
                "subscribe",
                "execute",
                "policy.manage",
                "role.manage"
            ]
        );
        assert!(!plan
            .capabilities
            .iter()
            .any(|capability| capability == "tenant.manage"));
    }

    #[tokio::test]
    #[ignore]
    async fn create_and_get_roundtrips() {
        let pool = pool().await;
        let req = CreateTenant {
            id: None,
            name: unique_name("acme"),
            alias: Some(unique_name("acme-alias")),
            tags: vec!["pilot".into()],
            attributes: json!({"region": "eu"}),
        };
        let created = create_tenant(&pool, req, None).await.expect("create");
        assert_eq!(created.status, TenantStatus::Active);
        assert_eq!(created.tags, vec!["pilot".to_string()]);
        let fetched = get_tenant(&pool, created.id).await.expect("get");
        assert_eq!(fetched.id, created.id);
        cleanup(&pool, &[created.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn list_filters_by_status() {
        let pool = pool().await;
        let a = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("list-a"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create a");
        let b = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("list-b"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create b");
        change_tenant_status(&pool, b.id, TenantStatus::Inactive, None)
            .await
            .expect("disable b");

        let active = list_tenants(
            &pool,
            ListTenants {
                id: None,
                id_contains: None,
                tags: None,
                q: None,
                name: None,
                alias: None,
                status: Some(TenantStatus::Active),
                deleted: crate::models::enums::DeletedFilter::Live,
                limit: 100,
                offset: 0,
                order: Default::default(),
                dir: Default::default(),
            },
        )
        .await
        .expect("list active");
        assert!(active.items.iter().any(|t| t.id == a.id));
        assert!(!active.items.iter().any(|t| t.id == b.id));
        cleanup(&pool, &[a.id, b.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn list_distinguishes_exact_and_substring_id_filters() {
        let pool = pool().await;
        let exact_target = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("id-exact"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create exact target");
        let substring_target = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("id-contains"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create substring target");

        let exact = list_tenants(
            &pool,
            ListTenants {
                id: Some(exact_target.id),
                id_contains: None,
                tags: None,
                q: None,
                name: None,
                alias: None,
                status: None,
                deleted: crate::models::enums::DeletedFilter::Live,
                limit: 100,
                offset: 0,
                order: Default::default(),
                dir: Default::default(),
            },
        )
        .await
        .expect("list by exact id");
        assert_eq!(
            exact
                .items
                .iter()
                .map(|tenant| tenant.id)
                .collect::<Vec<_>>(),
            vec![exact_target.id]
        );

        let id_fragment = substring_target
            .id
            .to_string()
            .rsplit('-')
            .next()
            .expect("uuid suffix")
            .to_owned();
        let substring = list_tenants(
            &pool,
            ListTenants {
                id: None,
                id_contains: Some(id_fragment),
                tags: None,
                q: None,
                name: None,
                alias: None,
                status: None,
                deleted: crate::models::enums::DeletedFilter::Live,
                limit: 100,
                offset: 0,
                order: Default::default(),
                dir: Default::default(),
            },
        )
        .await
        .expect("list by id substring");
        assert_eq!(
            substring
                .items
                .iter()
                .map(|tenant| tenant.id)
                .collect::<Vec<_>>(),
            vec![substring_target.id]
        );

        cleanup(&pool, &[exact_target.id, substring_target.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn update_replaces_only_provided_fields() {
        let pool = pool().await;
        let t = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("upd"),
                alias: Some("orig-alias".into()),
                tags: vec!["x".into()],
                attributes: json!({"k": "v"}),
            },
            None,
        )
        .await
        .expect("create");
        let upd = update_tenant(
            &pool,
            t.id,
            UpdateTenant {
                name: Some("renamed".into()),
                alias: None,
                tags: None,
                attributes: None,
            },
            None,
        )
        .await
        .expect("update");
        assert_eq!(upd.name, "renamed");
        assert_eq!(upd.alias.as_deref(), Some("orig-alias"));
        assert_eq!(upd.tags, vec!["x".to_string()]);
        cleanup(&pool, &[t.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn status_transitions_cover_non_delete_variants() {
        let pool = pool().await;
        let t = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("status"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create");
        for next in [
            TenantStatus::Inactive,
            TenantStatus::Frozen,
            TenantStatus::Active,
        ] {
            let updated = change_tenant_status(&pool, t.id, next.clone(), None)
                .await
                .expect("change status");
            assert_eq!(updated.status, next);
        }
        assert!(
            change_tenant_status(&pool, t.id, TenantStatus::Deleted, None)
                .await
                .is_err()
        );
        cleanup(&pool, &[t.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn entity_with_unknown_tenant_id_is_rejected_by_fk() {
        let pool = pool().await;
        let bogus = Uuid::new_v4();
        let res = crate::test_db::query(
            "INSERT INTO entities (id, kind, name, tenant_id)
             VALUES (gen_random_uuid(), 'service', 'fk-test', $1)",
            r#"INSERT INTO entities (id, kind, name, tenant_id)
             VALUES (gen_random_uuid(), 'service', 'fk-test', $1)"#,
        )
        .bind(bogus)
        .execute(&pool)
        .await;
        let err = res.expect_err("FK should reject unknown tenant_id");
        assert!(
            crate::error::is_foreign_key_violation(&err),
            "unexpected error: {err}"
        );
    }
}
