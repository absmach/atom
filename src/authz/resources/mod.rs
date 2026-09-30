//! Resource repository contract: the domain operations callers use, taking
//! and returning domain types ([`Resource`], [`CreateResource`], …) — never a
//! driver row, a bind parameter, or a SQL fragment.
//!
//! This is the pilot for the repository-per-domain pattern described in
//! `product-docs/development/database-backends/REPOSITORY-PATTERN.md`: the
//! `postgres` and `sqlite` submodules each own their native SQL for the same
//! set of operations, selected by matching on the already-connected
//! [`Database`]/[`DbTransaction`] (no separate backend-selector type —
//! `Database` already *is* that selector). Writes execute their statements
//! inside the caller's transaction and hand control back to the caller for
//! the atomic commit-with-outbox-event step ([`crate::audit`]), so the
//! mutation and its outbox row commit together exactly as every other
//! domain's writes do.

mod postgres;
mod sqlite;

use serde_json::Value;
use uuid::Uuid;

use crate::{
    audit,
    db::{Database, DbTransaction},
    error::{db_err, AppError},
    models::resource::{CreateResource, ListResources, Resource, ResourceList, UpdateResource},
};

/// Object group membership is a set, and a scalar attribute cannot express one.
/// The attribute write path is gone: membership is mutated only through the
/// explicit `addResourceToObjectGroup` / `removeResourceFromObjectGroup` /
/// `clearResourceObjectGroups` mutations. Rejecting the attribute rather than
/// ignoring it keeps the break loud — a caller that still sends it would
/// otherwise believe it had placed the resource in a group.
fn reject_parent_group_attribute(attrs: &Value) -> Result<(), AppError> {
    if attrs.get("parent_group_id").is_some() {
        return Err(AppError::bad_request(
            "the parent_group_id attribute is no longer supported; \
             use addResourceToObjectGroup / removeResourceFromObjectGroup",
        ));
    }
    Ok(())
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

/// The validated fields of a new resource row, bundled so each backend's
/// `insert` takes one argument instead of seven.
pub(super) struct NewResource<'a> {
    pub id: Uuid,
    pub kind: &'a str,
    pub name: Option<&'a str>,
    pub alias: Option<&'a str>,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub attributes: &'a Value,
}

/// Creates a resource and atomically commits its `resource.create` outbox
/// event in the same transaction (`audit::commit_with_observation` performs
/// the commit; nothing here commits early). Locks the owning tenant first,
/// same ordering the rest of the codebase's mutations use.
pub async fn create_resource_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateResource,
) -> Result<Resource, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = if req.attributes.is_null() {
        serde_json::json!({})
    } else {
        req.attributes
    };
    reject_parent_group_attribute(&attrs)?;
    let alias = crate::models::alias::validate_alias_opt(req.alias)?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;

    let new = NewResource {
        id,
        kind: &req.kind,
        name: req.name.as_deref(),
        alias: alias.as_deref(),
        tenant_id: req.tenant_id,
        owner_id: req.owner_id,
        attributes: &attrs,
    };
    let resource = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::insert(pg_tx, new).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::insert(lite_tx, new).await?,
    };

    let meta = audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: "resource",
        target_id: Some(resource.id),
        event: "resource.create",
    };
    let details = serde_json::json!({
        "kind": resource.kind,
        "name": resource.name,
        "alias": resource.alias,
        "attributes": resource.attributes,
    });
    audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(resource)
}

pub async fn create_resource(pool: &Database, req: CreateResource) -> Result<Resource, AppError> {
    create_resource_with_audit(pool, false, None, req).await
}

pub async fn get_resource(pool: &Database, id: Uuid) -> Result<Resource, AppError> {
    match pool {
        Database::Postgres(pg_pool) => postgres::get(pg_pool, id).await,
        Database::Sqlite(db) => sqlite::get(&db.pool, id).await,
    }
}

pub async fn list_resources_by_ids(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<Resource>, AppError> {
    match pool {
        Database::Postgres(pg_pool) => postgres::list_by_ids(pg_pool, ids).await,
        Database::Sqlite(db) => sqlite::list_by_ids(&db.pool, ids).await,
    }
}

pub async fn list_resources(
    pool: &Database,
    params: ListResources,
) -> Result<ResourceList, AppError> {
    match pool {
        Database::Postgres(pg_pool) => postgres::list(pg_pool, &params).await,
        Database::Sqlite(db) => sqlite::list(&db.pool, &params).await,
    }
}

/// Updates a resource's mutable fields and commits its `resource.update`
/// outbox event atomically. Locking order matches every other mutation:
/// read the owning tenant, lock the tenant row, lock the resource row, run
/// the config-managed guard, then write.
pub async fn update_resource_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateResource,
    updated_fields: Vec<&'static str>,
) -> Result<Resource, AppError> {
    if let Some(attrs) = req.attributes.as_ref() {
        reject_parent_group_attribute(attrs)?;
    }
    let alias = crate::models::alias::validate_alias_update(req.alias)?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();

    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::live_tenant_id(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::live_tenant_id(lite_tx, id).await?,
    };
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("resource {id} not found")));
    };
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, tenant_id).await?;
    let locked = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::lock_live_row(pg_tx, id, tenant_id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::lock_live_row(lite_tx, id, tenant_id).await?,
    };
    if !locked {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;
    let resource = match &mut tx {
        DbTransaction::Postgres(pg_tx) => {
            postgres::apply_update(pg_tx, id, req.name, req.attributes, alias_is_set, alias).await?
        }
        DbTransaction::Sqlite(lite_tx) => {
            sqlite::apply_update(lite_tx, id, req.name, req.attributes, alias_is_set, alias).await?
        }
    };

    let event = audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: resource.tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.update",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({ "updated_fields": updated_fields }),
    };
    audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(resource)
}

pub async fn update_resource(
    pool: &Database,
    id: Uuid,
    req: UpdateResource,
) -> Result<Resource, AppError> {
    update_resource_with_audit(pool, false, None, id, req, Vec::new()).await
}

/// Soft-deletes a resource and commits its `resource.delete` outbox event
/// atomically.
pub async fn delete_resource_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::live_tenant_id(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::live_tenant_id(lite_tx, id).await?,
    };
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("resource {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;
    let live = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::is_live(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::is_live(lite_tx, id).await?,
    };
    if !live {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }
    let rows_affected = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::soft_delete(pg_tx, id, deleted_by).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::soft_delete(lite_tx, id, deleted_by).await?,
    };
    if rows_affected == 0 {
        return Err(AppError::not_found(format!("resource {id} not found")));
    }

    let event = audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.delete",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(())
}

pub async fn delete_resource(
    pool: &Database,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_resource_with_audit(pool, false, None, id, deleted_by).await
}

/// Restores a soft-deleted resource and commits its `resource.restore`
/// outbox event atomically. Refuses when the owning tenant is itself
/// soft-deleted (restore the tenant first).
pub async fn restore_resource_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let _ = restored_by;
    let mut tx = pool.begin().await.map_err(db_err)?;

    let expected_tenant_id = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::deleted_tenant_id(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::deleted_tenant_id(lite_tx, id).await?,
    };
    let Some(expected_tenant_id) = expected_tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted resource {id} to restore"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;

    let tenant_info = match &mut tx {
        DbTransaction::Postgres(pg_tx) => {
            postgres::deleted_tenant_info(pg_tx, id, expected_tenant_id).await?
        }
        DbTransaction::Sqlite(lite_tx) => {
            sqlite::deleted_tenant_info(lite_tx, id, expected_tenant_id).await?
        }
    };
    let (tenant_id, _is_tenant_deleted) = match tenant_info {
        None => {
            return Err(AppError::not_found(format!(
                "no soft-deleted resource {id} to restore"
            )))
        }
        Some((_, true)) => {
            return Err(AppError::conflict(
                "the resource's tenant is soft-deleted; restore the tenant first",
            ))
        }
        Some((t_id, false)) => (t_id, false),
    };

    match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::restore_row(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::restore_row(lite_tx, id).await?,
    }

    let event = audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.restore",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(())
}

pub async fn restore_resource(
    pool: &Database,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    restore_resource_with_audit(pool, false, None, id, restored_by).await
}

/// Physically removes an already-soft-deleted resource, bypassing the purge
/// retention window. Irreversible: FK cascades drop its group links, and
/// object-scoped permission blocks referencing it by bare `object_id` (no
/// foreign key) are swept by the shared
/// [`crate::authz::repo::purge_authz_references_for_ids`] cleanup. A soft
/// delete is required first. Returns the purged row's tenant.
pub async fn purge_resource_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let expected_tenant_id = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::any_tenant_id(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::any_tenant_id(lite_tx, id).await?,
    };
    let Some(expected_tenant_id) = expected_tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted resource {id} to purge"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "resources", id).await?;

    let purged_tenant_id = match &mut tx {
        DbTransaction::Postgres(pg_tx) => postgres::purge_row(pg_tx, id).await?,
        DbTransaction::Sqlite(lite_tx) => sqlite::purge_row(lite_tx, id).await?,
    };
    let tenant_id = purged_tenant_id
        .ok_or_else(|| AppError::not_found(format!("no soft-deleted resource {id} to purge")))?;

    crate::authz::repo::purge_authz_references_for_ids(&mut tx, &[id]).await?;

    let event = audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(tenant_id)
}

pub async fn purge_resource(pool: &Database, id: Uuid) -> Result<Option<Uuid>, AppError> {
    purge_resource_with_audit(pool, false, None, id).await
}
