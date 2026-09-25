//! Resource repository contract: the domain operations callers use, taking
//! and returning domain types ([`Resource`], [`CreateResource`], …) — never a
//! driver row, a bind parameter, or a SQL fragment.
//!
//! This is the pilot for the repository-per-domain pattern described in
//! `product-docs/development/database-backends/REPOSITORY-PATTERN.md`: the
//! `postgres` and `sqlite` submodules each own their native SQL for the same
//! set of operations, selected by matching on the already-connected
//! [`Database`]/[`DbTransaction`] (no separate backend-selector type —
//! `Database` already *is* that selector). Both write their INSERT inside the
//! caller's transaction and return control to
//! [`crate::audit::commit_with_observation`] for the atomic
//! commit-with-outbox-event step, so the mutation and its outbox row commit
//! together exactly as every other domain's writes do.

mod postgres;
mod sqlite;

use serde_json::Value;
use uuid::Uuid;

use crate::{
    audit,
    db::{Database, DbTransaction},
    error::{db_err, AppError},
    models::resource::{CreateResource, ListResources, Resource, ResourceList},
};

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
