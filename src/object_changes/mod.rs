//! Transactional application metadata/resources and fenced object reservations.
//! Identity kind, credentials, profile bindings and lifecycle stay on identity APIs.
//!
//! Storage follows the repository-per-domain pattern
//! (`product-docs/development/database-backends/REPOSITORY-PATTERN.md`): this
//! module owns validation, authorization, lock ordering and audit; the private
//! `postgres`/`sqlite` adapters own each backend's native SQL for the same
//! operations, selected by matching on the connected [`Database`] /
//! [`DbTransaction`].
mod postgres;
mod sqlite;

use crate::{
    auth::{AuthContext, Scope},
    db::{Database, DbTransaction},
    error::{db_err, AppError},
    state::AppState,
};
use async_graphql::{Enum, InputObject, ID};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum, Serialize, Deserialize)]
#[graphql(rename_items = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Entity,
    Resource,
}
impl ObjectKind {
    fn table(self) -> &'static str {
        match self {
            Self::Entity => "entities",
            Self::Resource => "resources",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Resource => "resource",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum, Serialize, Deserialize)]
#[graphql(rename_items = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ChangeOperation {
    Create,
    Update,
    Delete,
    Check,
}
#[derive(Clone, InputObject, Serialize, Deserialize)]
pub struct ObjectChangeInput {
    pub object_kind: ObjectKind,
    pub operation: ChangeOperation,
    pub id: ID,
    pub tenant_id: Option<ID>,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub attributes: Option<Value>,
    pub expected_revision: Option<i64>,
}
#[derive(Clone, InputObject, Serialize, Deserialize)]
pub struct ObjectLeaseInput {
    pub object_kind: ObjectKind,
    pub object_id: ID,
    pub holder_id: ID,
    pub operation: String,
    pub ttl_seconds: i32,
}
#[derive(Clone, InputObject, Serialize, Deserialize)]
pub struct ObjectLeaseGuardInput {
    pub object_kind: ObjectKind,
    pub object_id: ID,
    pub holder_id: ID,
    pub fence: i64,
}

/// The fields of an entity/resource row this module reads: its revision and
/// the facts the batch rules check. Resources have no profile or external id;
/// both adapters select `NULL` for those.
#[derive(sqlx::FromRow)]
pub(super) struct ObjectRow {
    pub revision: i64,
    pub tenant_id: Option<Uuid>,
    pub kind: String,
    pub managed_by: Option<String>,
    pub profile_id: Option<Uuid>,
    pub external_id: Option<String>,
}

/// A validated batch create, bundled so each backend's insert takes one
/// argument.
pub(super) struct NewObject<'a> {
    pub object_kind: ObjectKind,
    pub id: Uuid,
    pub kind: &'a str,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub attributes: &'a Value,
}

/// A live-lease key: the object, the authenticated actor, and the holder.
#[derive(Clone, Copy)]
pub(super) struct LeaseKey<'a> {
    pub object_kind: ObjectKind,
    pub object_id: Uuid,
    pub actor_id: Uuid,
    pub holder_id: Uuid,
    pub operation: &'a str,
}

pub fn uuid(id: &ID) -> Result<Uuid, AppError> {
    Uuid::parse_str(id.as_str()).map_err(|_| AppError::bad_request("invalid UUID"))
}
fn conflict(code: &str) -> AppError {
    AppError::conflict(code)
}
async fn authorize(
    pool: &Database,
    auth: &AuthContext,
    kind: ObjectKind,
    id: Uuid,
    create: Option<Option<Uuid>>,
    read: bool,
) -> Result<(), AppError> {
    if let Some(tenant) = create {
        let scope = tenant.map(Scope::Tenant).unwrap_or(Scope::Platform);
        crate::auth::require_any_capability(pool, auth, &[("manage", scope), ("write", scope)])
            .await
    } else {
        let allowed = crate::authz::engine::allows_any(
            pool,
            auth,
            auth.entity_id,
            kind.label(),
            id,
            if read {
                &["read", "manage"]
            } else {
                &["manage"]
            },
        )
        .await?;
        if allowed {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}
async fn lock_key(tx: &mut DbTransaction<'_>, key: &str) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(tx) => postgres::lock_key(tx, key).await,
        // SQLite admits one write transaction at a time (BEGIN IMMEDIATE), so
        // every holder of this key is already serialized.
        DbTransaction::Sqlite(_) => Ok(()),
    }
}
fn lease_lock_key(kind: ObjectKind, id: Uuid) -> String {
    format!("lease:{}:{id}", kind.label())
}
async fn find_receipt_in_tx(
    tx: &mut DbTransaction<'_>,
    actor: Uuid,
    request_id: Uuid,
) -> Result<Option<(Value, Value)>, AppError> {
    match tx {
        DbTransaction::Postgres(tx) => postgres::find_receipt(&mut **tx, actor, request_id).await,
        DbTransaction::Sqlite(tx) => sqlite::find_receipt(&mut **tx, actor, request_id).await,
    }
}
async fn object_tenant(
    tx: &mut DbTransaction<'_>,
    kind: ObjectKind,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    match tx {
        DbTransaction::Postgres(tx) => postgres::object_tenant(tx, kind, id).await,
        DbTransaction::Sqlite(tx) => sqlite::object_tenant(tx, kind, id).await,
    }
}
async fn locked_object(
    tx: &mut DbTransaction<'_>,
    kind: ObjectKind,
    id: Uuid,
    tenant: Option<Uuid>,
) -> Result<ObjectRow, AppError> {
    // Recheck the discovered tenant when locking the object; never acquire a
    // newly discovered tenant out of order if an external writer moved it.
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant).await?;
    match tx {
        DbTransaction::Postgres(tx) => postgres::lock_object(tx, kind, id, tenant).await,
        DbTransaction::Sqlite(tx) => sqlite::lock_object(tx, kind, id, tenant).await,
    }
}
async fn lease_guard(
    tx: &mut DbTransaction<'_>,
    actor: Uuid,
    guard: &ObjectLeaseGuardInput,
) -> Result<(), AppError> {
    let object_id = uuid(&guard.object_id)?;
    let holder_id = uuid(&guard.holder_id)?;
    let found = match tx {
        DbTransaction::Postgres(tx) => {
            postgres::lease_is_live(
                &mut **tx,
                guard.object_kind,
                object_id,
                actor,
                holder_id,
                guard.fence,
            )
            .await?
        }
        DbTransaction::Sqlite(tx) => {
            sqlite::lease_is_live(
                &mut **tx,
                guard.object_kind,
                object_id,
                actor,
                holder_id,
                guard.fence,
            )
            .await?
        }
    };
    if found {
        Ok(())
    } else {
        Err(conflict("LEASE_LOST"))
    }
}
/// Keep cached entity status/grants behind the same barrier as ordinary identity writes.
pub async fn commit(
    state: &AppState,
    auth: &AuthContext,
    request_id: Uuid,
    changes: Vec<ObjectChangeInput>,
    guards: Vec<ObjectLeaseGuardInput>,
) -> Result<Value, AppError> {
    if changes.is_empty() || changes.len() > 100 || guards.len() > 100 {
        return Err(AppError::bad_request("between 1 and 100 changes required"));
    }
    // A receipt belongs to the authenticated actor, and contains only object IDs
    // and revisions. Read it before object authorization: a successful deletion
    // must remain replayable even though its target is no longer visible.
    let prior = match state.pool() {
        Database::Postgres(pool) => {
            postgres::find_receipt(pool, auth.entity_id, request_id).await?
        }
        Database::Sqlite(db) => sqlite::find_receipt(&db.pool, auth.entity_id, request_id).await?,
    };
    if let Some((body, response)) = prior {
        if body != json!({"changes":changes,"guards":guards}) {
            return Err(conflict("IDEMPOTENCY_CONFLICT"));
        }
        return Ok(response);
    }
    let mut entity_ids = Vec::new();
    for c in &changes {
        let id = uuid(&c.id)?;
        authorize(
            state.pool(),
            auth,
            c.object_kind,
            id,
            if c.operation == ChangeOperation::Create {
                Some(c.tenant_id.as_ref().map(uuid).transpose()?)
            } else {
                None
            },
            c.operation == ChangeOperation::Check,
        )
        .await?;
        if c.object_kind == ObjectKind::Entity && c.operation != ChangeOperation::Check {
            entity_ids.push(id);
        }
    }
    let Some(cache) = state.cache.as_deref() else {
        return commit_inner(state, auth, request_id, changes, guards).await;
    };
    entity_ids.sort();
    entity_ids.dedup();
    let status_keys: Vec<_> = entity_ids
        .iter()
        .copied()
        .map(crate::cache::keys::entity_status)
        .collect();
    let grant_keys: Vec<_> = entity_ids
        .iter()
        .copied()
        .map(crate::cache::keys::grants)
        .collect();
    let groups = [
        (
            crate::cache::CacheCategory::EntityStatus,
            status_keys.as_slice(),
        ),
        (crate::cache::CacheCategory::Grants, grant_keys.as_slice()),
    ];
    let barriers = crate::cache::invalidate::begin_all(cache, &groups).await?;
    let result = commit_inner(state, auth, request_id, changes, guards).await;
    crate::cache::invalidate::end_all(cache, barriers).await;
    result
}
async fn commit_inner(
    state: &AppState,
    auth: &AuthContext,
    request_id: Uuid,
    changes: Vec<ObjectChangeInput>,
    guards: Vec<ObjectLeaseGuardInput>,
) -> Result<Value, AppError> {
    if changes.is_empty() || changes.len() > 100 || guards.len() > 100 {
        return Err(AppError::bad_request("between 1 and 100 changes required"));
    }
    let request = json!({"changes": changes, "guards":guards});
    let mut seen = std::collections::HashSet::new();
    for change in &changes {
        let id = uuid(&change.id)?;
        if !seen.insert((change.object_kind.label(), id)) {
            return Err(AppError::bad_request("duplicate object in transaction"));
        }
        let tenant = change.tenant_id.as_ref().map(uuid).transpose()?;
        authorize(
            state.pool(),
            auth,
            change.object_kind,
            id,
            if change.operation == ChangeOperation::Create {
                Some(tenant)
            } else {
                None
            },
            change.operation == ChangeOperation::Check,
        )
        .await?;
        if change.operation != ChangeOperation::Create && change.expected_revision.is_none() {
            return Err(AppError::bad_request("expectedRevision required"));
        }
        if change
            .attributes
            .as_ref()
            .is_some_and(|a| !a.is_object() || a.get("parent_group_id").is_some())
        {
            return Err(AppError::bad_request(
                "attributes must be an object; groups use membership APIs",
            ));
        }
        if change.operation != ChangeOperation::Create
            && (change.tenant_id.is_some()
                || change.kind.is_some()
                || change.name.is_some()
                || change.alias.is_some())
        {
            return Err(AppError::bad_request(
                "batch updates change attributes only; use identity APIs for other fields",
            ));
        }
    }
    for guard in &guards {
        authorize(
            state.pool(),
            auth,
            guard.object_kind,
            uuid(&guard.object_id)?,
            None,
            false,
        )
        .await?;
    }
    let mut tx = state.pool().begin().await.map_err(db_err)?;
    lock_key(&mut tx, &format!("request:{}:{request_id}", auth.entity_id)).await?;
    if let Some((body, response)) = find_receipt_in_tx(&mut tx, auth.entity_id, request_id).await? {
        if body != request {
            return Err(conflict("IDEMPOTENCY_CONFLICT"));
        }
        return Ok(response);
    }
    let mut keys: Vec<_> = guards
        .iter()
        .map(|g| Ok(lease_lock_key(g.object_kind, uuid(&g.object_id)?)))
        .collect::<Result<_, AppError>>()?;
    keys.sort();
    keys.dedup();
    for key in keys {
        lock_key(&mut tx, &key).await?;
    }
    for guard in &guards {
        lease_guard(&mut tx, auth.entity_id, guard).await?;
    }
    let mut results = Vec::with_capacity(changes.len());
    let mut audit_events = Vec::new();
    let mut observations = Vec::new();
    // Tenant locks precede object locks, including tenants of create targets.
    // Disjoint object sets can otherwise acquire the same tenants in reverse.
    let mut planned = Vec::with_capacity(changes.len());
    for change in &changes {
        let id = uuid(&change.id)?;
        let tenant = if change.operation == ChangeOperation::Create {
            change.tenant_id.as_ref().map(uuid).transpose()?
        } else {
            object_tenant(&mut tx, change.object_kind, id).await?
        };
        planned.push((id, tenant, change));
    }
    let tenant_ids = planned
        .iter()
        .map(|(_, tenant, _)| *tenant)
        .collect::<Vec<_>>();
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &tenant_ids).await?;
    // Canonical UUID ordering also prevents alternate spellings from inverting
    // the object row locks. Preserve input order for execution and results.
    let mut ordered = planned.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(id, _, c)| (c.object_kind.label(), *id));
    for (id, tenant, change) in ordered {
        if change.operation != ChangeOperation::Create {
            let existing = locked_object(&mut tx, change.object_kind, *id, *tenant).await?;
            if Some(existing.revision) != change.expected_revision {
                return Err(conflict("REVISION_CONFLICT"));
            }
            if existing.managed_by.as_deref() == Some("config")
                && change.operation != ChangeOperation::Check
            {
                return Err(conflict("CONFIG_MANAGED"));
            }
            if change.object_kind == ObjectKind::Entity
                && change.operation != ChangeOperation::Check
            {
                if existing.kind != "application" || existing.profile_id.is_some() {
                    return Err(AppError::bad_request(
                        "batch entity changes support application metadata without profiles only",
                    ));
                }
                if change.operation == ChangeOperation::Delete {
                    let used = match &mut tx {
                        DbTransaction::Postgres(tx) => {
                            postgres::has_credentials_or_sessions(tx, *id).await?
                        }
                        DbTransaction::Sqlite(tx) => {
                            sqlite::has_credentials_or_sessions(tx, *id).await?
                        }
                    };
                    if used {
                        return Err(AppError::bad_request(
                            "use identity API to delete an application with credentials or sessions",
                        ));
                    }
                }
            }
        }
    }
    for (id, tenant, change) in &planned {
        let id = *id;
        let tenant = *tenant;
        let row = match change.operation {
            ChangeOperation::Create => {
                crate::tenants::repo::lock_optional_active_tenant(&mut tx, tenant).await?;
                let alias = crate::models::alias::validate_alias_opt(change.alias.clone())?;
                let attrs = change.attributes.clone().unwrap_or_else(|| json!({}));
                let kind = change
                    .kind
                    .as_deref()
                    .ok_or_else(|| AppError::bad_request("kind required"))?;
                if change.object_kind == ObjectKind::Entity && kind != "application" {
                    return Err(AppError::bad_request(
                        "use identity API for other entity kinds",
                    ));
                }
                if kind.is_empty() || kind.len() > 255 {
                    return Err(AppError::bad_request("invalid kind"));
                }
                let name = if change.object_kind == ObjectKind::Entity {
                    Some(crate::models::entity::validate_entity_name(
                        change.name.as_deref().unwrap_or(""),
                    )?)
                } else {
                    change.name.clone()
                };
                let new = NewObject {
                    object_kind: change.object_kind,
                    id,
                    kind,
                    name,
                    alias,
                    tenant_id: tenant,
                    attributes: &attrs,
                };
                match &mut tx {
                    DbTransaction::Postgres(tx) => postgres::insert_object(tx, new).await?,
                    DbTransaction::Sqlite(tx) => sqlite::insert_object(tx, new).await?,
                }
            }
            ChangeOperation::Update => {
                let attrs = change
                    .attributes
                    .as_ref()
                    .ok_or_else(|| AppError::bad_request("attributes required"))?;
                match &mut tx {
                    DbTransaction::Postgres(tx) => {
                        postgres::update_attributes(tx, change.object_kind, id, attrs).await?
                    }
                    DbTransaction::Sqlite(tx) => {
                        sqlite::update_attributes(tx, change.object_kind, id, attrs).await?
                    }
                }
            }
            ChangeOperation::Delete => match &mut tx {
                DbTransaction::Postgres(tx) => {
                    postgres::soft_delete(tx, change.object_kind, id, auth.entity_id).await?
                }
                DbTransaction::Sqlite(tx) => {
                    sqlite::soft_delete(tx, change.object_kind, id, auth.entity_id).await?
                }
            },
            ChangeOperation::Check => {
                locked_object(&mut tx, change.object_kind, id, tenant).await?
            }
        };
        if change.operation != ChangeOperation::Check {
            let event = match (change.object_kind, change.operation) {
                (ObjectKind::Entity, ChangeOperation::Create) => "entity.create",
                (ObjectKind::Entity, ChangeOperation::Update) => "entity.update",
                (ObjectKind::Entity, ChangeOperation::Delete) => "entity.delete",
                (ObjectKind::Resource, ChangeOperation::Create) => "resource.create",
                (ObjectKind::Resource, ChangeOperation::Update) => "resource.update",
                (ObjectKind::Resource, ChangeOperation::Delete) => "resource.delete",
                (_, ChangeOperation::Check) => unreachable!(),
            };
            let tenant = row.tenant_id;
            let mut details = json!({"transaction": request_id});
            if event == "entity.update" {
                details["external_id"] = json!(row.external_id);
            }
            if change.operation == ChangeOperation::Create {
                observations.push((
                    crate::audit::AuditMeta {
                        actor_entity_id: Some(auth.entity_id),
                        tenant_id: tenant,
                        target_kind: change.object_kind.label(),
                        target_id: Some(id),
                        event,
                    },
                    details.clone(),
                ));
            } else {
                audit_events.push(crate::audit::AuditEvent {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id: tenant,
                    target_kind: Some(change.object_kind.label()),
                    target_id: Some(id),
                    event,
                    outcome: crate::models::enums::AuditOutcome::Allow,
                    details: details.clone(),
                });
            }
            crate::events::enqueue(
                tx.exec(),
                state.config.events.enabled(),
                Some(auth.entity_id),
                tenant,
                Some(change.object_kind.label()),
                Some(id),
                event,
                "allow",
                &details,
            )
            .await?;
        }
        results
            .push(json!({"id": id, "object_kind": change.object_kind, "revision": row.revision}));
    }
    // Recheck at the actual commit boundary, including time spent waiting for locks.
    for guard in &guards {
        lease_guard(&mut tx, auth.entity_id, guard).await?;
    }
    let response = json!({"objects":results});
    match &mut tx {
        DbTransaction::Postgres(tx) => {
            postgres::record_receipt(tx, auth.entity_id, request_id, &request, &response).await?
        }
        DbTransaction::Sqlite(tx) => {
            sqlite::record_receipt(tx, auth.entity_id, request_id, &request, &response).await?
        }
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: Some(auth.entity_id),
        tenant_id: None,
        target_kind: "transaction",
        target_id: Some(request_id),
        event: "object_changes.commit",
    };
    crate::audit::commit_with_observation(
        tx,
        state.config.events.enabled(),
        &meta,
        &json!({"count":changes.len()}),
    )
    .await?;
    for (meta, details) in observations {
        crate::audit::log_observe_allow(&meta, &details);
    }
    for event in audit_events {
        crate::audit::write(state.pool(), false, event).await;
    }
    Ok(response)
}
pub async fn acquire(
    state: &AppState,
    auth: &AuthContext,
    input: ObjectLeaseInput,
) -> Result<Value, AppError> {
    if !(1..=600).contains(&input.ttl_seconds)
        || input.operation.is_empty()
        || input.operation.len() > 80
    {
        return Err(AppError::bad_request("invalid lease duration or operation"));
    }
    let id = uuid(&input.object_id)?;
    let holder = uuid(&input.holder_id)?;
    authorize(state.pool(), auth, input.object_kind, id, None, false).await?;
    let mut tx = state.pool().begin().await.map_err(db_err)?;
    lock_key(&mut tx, &lease_lock_key(input.object_kind, id)).await?;
    let tenant = object_tenant(&mut tx, input.object_kind, id).await?;
    locked_object(&mut tx, input.object_kind, id, tenant).await?;
    let key = LeaseKey {
        object_kind: input.object_kind,
        object_id: id,
        actor_id: auth.entity_id,
        holder_id: holder,
        operation: &input.operation,
    };
    // A takeover only succeeds over an expired lease; otherwise repeating a
    // live acquisition by the same actor/holder/operation returns that lease.
    let row = match &mut tx {
        DbTransaction::Postgres(tx) => {
            match postgres::take_lease(tx, key, input.ttl_seconds).await? {
                Some(row) => Some(row),
                None => postgres::current_lease(tx, key).await?,
            }
        }
        DbTransaction::Sqlite(tx) => match sqlite::take_lease(tx, key, input.ttl_seconds).await? {
            Some(row) => Some(row),
            None => sqlite::current_lease(tx, key).await?,
        },
    }
    .ok_or_else(|| conflict("LEASE_HELD"))?;
    let meta = crate::audit::AuditMeta {
        actor_entity_id: Some(auth.entity_id),
        tenant_id: None,
        target_kind: input.object_kind.label(),
        target_id: Some(id),
        event: "object_lease.acquire",
    };
    crate::audit::commit_with_observation(tx, state.config.events.enabled(), &meta, &json!({}))
        .await?;
    Ok(row)
}
pub async fn finish_lease(
    state: &AppState,
    auth: &AuthContext,
    guard: ObjectLeaseGuardInput,
    ttl: Option<i32>,
) -> Result<Value, AppError> {
    if ttl.is_some_and(|n| !(1..=600).contains(&n)) {
        return Err(AppError::bad_request("invalid lease duration"));
    }
    let id = uuid(&guard.object_id)?;
    let holder = uuid(&guard.holder_id)?;
    authorize(state.pool(), auth, guard.object_kind, id, None, false).await?;
    let mut tx = state.pool().begin().await.map_err(db_err)?;
    lock_key(&mut tx, &lease_lock_key(guard.object_kind, id)).await?;
    lease_guard(&mut tx, auth.entity_id, &guard).await?;
    // Release is a renewal to zero seconds: the lease stops being live now.
    let ttl_seconds = ttl.unwrap_or(0);
    let row = match &mut tx {
        DbTransaction::Postgres(tx) => {
            postgres::set_lease_expiry(
                tx,
                guard.object_kind,
                id,
                auth.entity_id,
                holder,
                guard.fence,
                ttl_seconds,
            )
            .await?
        }
        DbTransaction::Sqlite(tx) => {
            sqlite::set_lease_expiry(
                tx,
                guard.object_kind,
                id,
                auth.entity_id,
                holder,
                guard.fence,
                ttl_seconds,
            )
            .await?
        }
    };
    let meta = crate::audit::AuditMeta {
        actor_entity_id: Some(auth.entity_id),
        tenant_id: None,
        target_kind: guard.object_kind.label(),
        target_id: Some(id),
        event: if ttl.is_some() {
            "object_lease.renew"
        } else {
            "object_lease.release"
        },
    };
    crate::audit::commit_with_observation(tx, state.config.events.enabled(), &meta, &json!({}))
        .await?;
    Ok(row)
}

pub async fn validate_lease(
    state: &AppState,
    auth: &AuthContext,
    guard: ObjectLeaseGuardInput,
) -> Result<bool, AppError> {
    let id = uuid(&guard.object_id)?;
    let holder = uuid(&guard.holder_id)?;
    authorize(state.pool(), auth, guard.object_kind, id, None, false).await?;
    match state.pool() {
        Database::Postgres(pool) => {
            postgres::lease_is_live(
                pool,
                guard.object_kind,
                id,
                auth.entity_id,
                holder,
                guard.fence,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::lease_is_live(
                &db.pool,
                guard.object_kind,
                id,
                auth.entity_id,
                holder,
                guard.fence,
            )
            .await
        }
    }
}
