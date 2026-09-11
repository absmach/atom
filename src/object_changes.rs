//! Transactional application metadata/resources and fenced object reservations.
//! Identity kind, credentials, profile bindings and lifecycle stay on identity APIs.
use crate::{
    auth::{AuthContext, Scope},
    error::{db_err, AppError},
    state::AppState,
};
use async_graphql::{Enum, InputObject, ID};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
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
pub fn uuid(id: &ID) -> Result<Uuid, AppError> {
    Uuid::parse_str(id.as_str()).map_err(|_| AppError::bad_request("invalid UUID"))
}
fn conflict(code: &str) -> AppError {
    AppError::conflict(code)
}
async fn authorize(
    pool: &PgPool,
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
async fn lock_key(tx: &mut Transaction<'_, Postgres>, key: &str) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 17))")
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}
async fn locked_object(
    tx: &mut Transaction<'_, Postgres>,
    kind: ObjectKind,
    id: Uuid,
) -> Result<Value, AppError> {
    let table = kind.table();
    let tenant: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT tenant_id FROM {table} WHERE id=$1 AND deleted_at IS NULL"
    ))
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant).await?;
    sqlx::query_scalar(&format!("SELECT to_jsonb(o) FROM {table} o WHERE id=$1 AND deleted_at IS NULL AND tenant_id IS NOT DISTINCT FROM $2 FOR UPDATE"))
        .bind(id).bind(tenant).fetch_one(&mut **tx).await.map_err(db_err)
}
async fn lease_guard(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    guard: &ObjectLeaseGuardInput,
) -> Result<(), AppError> {
    let found: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM object_leases WHERE object_kind=$1 AND object_id=$2 AND actor_id=$3 AND holder_id=$4 AND fence=$5 AND expires_at>clock_timestamp())")
        .bind(guard.object_kind.label()).bind(uuid(&guard.object_id)?).bind(actor).bind(uuid(&guard.holder_id)?).bind(guard.fence)
        .fetch_one(&mut **tx).await.map_err(db_err)?;
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
    let prior: Option<(Value, Value)> = sqlx::query_as(
        "SELECT request,response FROM object_change_requests WHERE actor_id=$1 AND request_id=$2",
    )
    .bind(auth.entity_id)
    .bind(request_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(db_err)?;
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
            &state.pool,
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
            &state.pool,
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
            &state.pool,
            auth,
            guard.object_kind,
            uuid(&guard.object_id)?,
            None,
            false,
        )
        .await?;
    }
    let mut tx = state.pool.begin().await.map_err(db_err)?;
    lock_key(&mut tx, &format!("request:{}:{request_id}", auth.entity_id)).await?;
    let prior: Option<(Value, Value)> = sqlx::query_as(
        "SELECT request,response FROM object_change_requests WHERE actor_id=$1 AND request_id=$2",
    )
    .bind(auth.entity_id)
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    if let Some((body, response)) = prior {
        if body != request {
            return Err(conflict("IDEMPOTENCY_CONFLICT"));
        }
        return Ok(response);
    }
    let mut keys: Vec<_> = guards
        .iter()
        .map(|g| format!("lease:{}:{}", g.object_kind.label(), g.object_id.as_str()))
        .collect();
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
    // Deterministic ordering prevents cross-batch object lock inversion.
    let mut ordered = changes.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|c| (c.object_kind.label(), c.id.as_str()));
    for change in &ordered {
        if change.operation != ChangeOperation::Create {
            let existing = locked_object(&mut tx, change.object_kind, uuid(&change.id)?).await?;
            if existing["revision"].as_i64() != change.expected_revision {
                return Err(conflict("REVISION_CONFLICT"));
            }
            if existing["managed_by"] == "config" && change.operation != ChangeOperation::Check {
                return Err(conflict("CONFIG_MANAGED"));
            }
            if change.object_kind == ObjectKind::Entity
                && change.operation != ChangeOperation::Check
            {
                if existing["kind"] != "application" || !existing["profile_id"].is_null() {
                    return Err(AppError::bad_request(
                        "batch entity changes support application metadata without profiles only",
                    ));
                }
                if change.operation == ChangeOperation::Delete {
                    let used: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credentials WHERE entity_id=$1) OR EXISTS(SELECT 1 FROM sessions WHERE entity_id=$1)")
                        .bind(uuid(&change.id)?).fetch_one(&mut *tx).await.map_err(db_err)?;
                    if used {
                        return Err(AppError::bad_request("use identity API to delete an application with credentials or sessions"));
                    }
                }
            }
        }
    }
    for change in &changes {
        let id = uuid(&change.id)?;
        let table = change.object_kind.table();
        let row: Value=match change.operation {
            ChangeOperation::Create=> {
                let tenant=change.tenant_id.as_ref().map(uuid).transpose()?;
                crate::tenants::repo::lock_optional_active_tenant(&mut tx,tenant).await?;
                let alias=crate::models::alias::validate_alias_opt(change.alias.clone())?;
                let attrs=change.attributes.clone().unwrap_or_else(||json!({}));
                let kind=change.kind.as_deref().ok_or_else(||AppError::bad_request("kind required"))?;
                if change.object_kind==ObjectKind::Entity && kind!="application" {return Err(AppError::bad_request("use identity API for other entity kinds"));}
                if kind.is_empty() || kind.len()>255 {return Err(AppError::bad_request("invalid kind"));}
                let name=if change.object_kind==ObjectKind::Entity {Some(crate::models::entity::validate_entity_name(change.name.as_deref().unwrap_or(""))?)} else {change.name.clone()};
                sqlx::query_scalar(&format!("INSERT INTO {table} AS o(id,kind,name,alias,tenant_id,attributes) VALUES($1,$2,$3,$4,$5,$6) RETURNING to_jsonb(o)"))
                    .bind(id).bind(kind).bind(name).bind(alias).bind(tenant).bind(attrs).fetch_one(&mut *tx).await.map_err(db_err)?
            },
            ChangeOperation::Update=>sqlx::query_scalar(&format!("UPDATE {table} AS o SET attributes=$2,updated_at=clock_timestamp() WHERE id=$1 RETURNING to_jsonb(o)"))
                .bind(id).bind(change.attributes.clone().ok_or_else(||AppError::bad_request("attributes required"))?).fetch_one(&mut *tx).await.map_err(db_err)?,
            ChangeOperation::Delete=> {
                let status=if change.object_kind==ObjectKind::Entity {", status='inactive'"}else{""};
                sqlx::query_scalar(&format!("UPDATE {table} AS o SET deleted_at=clock_timestamp(),deleted_by=$2,updated_at=clock_timestamp(){status} WHERE id=$1 RETURNING to_jsonb(o)"))
                    .bind(id).bind(auth.entity_id).fetch_one(&mut *tx).await.map_err(db_err)?
            },
            ChangeOperation::Check=>locked_object(&mut tx,change.object_kind,id).await?,
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
            let tenant = row["tenant_id"]
                .as_str()
                .and_then(|v| Uuid::parse_str(v).ok());
            let mut details = json!({"transaction": request_id});
            if event == "entity.update" {
                details["external_id"] = row["external_id"].clone();
            }
            audit_events.push(crate::audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: tenant,
                target_kind: Some(change.object_kind.label()),
                target_id: Some(id),
                event,
                outcome: crate::models::enums::AuditOutcome::Allow,
                details: details.clone(),
            });
            crate::events::enqueue(
                &mut *tx,
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
        results.push(
            json!({"id": id, "object_kind": change.object_kind, "revision": row["revision"]}),
        );
    }
    // Recheck at the actual commit boundary, including time spent waiting for locks.
    for guard in &guards {
        lease_guard(&mut tx, auth.entity_id, guard).await?;
    }
    let response = json!({"objects":results});
    sqlx::query("DELETE FROM object_change_requests WHERE actor_id=$1 AND created_at < now()-interval '7 days'").bind(auth.entity_id).execute(&mut *tx).await.map_err(db_err)?;
    sqlx::query("INSERT INTO object_change_requests(actor_id,request_id,request,response) VALUES($1,$2,$3,$4)")
        .bind(auth.entity_id).bind(request_id).bind(request).bind(&response).execute(&mut *tx).await.map_err(db_err)?;
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
    for event in audit_events {
        crate::audit::write(&state.pool, false, event).await;
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
    authorize(&state.pool, auth, input.object_kind, id, None, false).await?;
    let mut tx = state.pool.begin().await.map_err(db_err)?;
    lock_key(
        &mut tx,
        &format!("lease:{}:{id}", input.object_kind.label()),
    )
    .await?;
    locked_object(&mut tx, input.object_kind, id).await?;
    let row:Option<Value>=sqlx::query_scalar("INSERT INTO object_leases AS l(object_kind,object_id,actor_id,holder_id,operation,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+make_interval(secs=>$6)) ON CONFLICT(object_kind,object_id) DO UPDATE SET actor_id=EXCLUDED.actor_id,holder_id=EXCLUDED.holder_id,operation=EXCLUDED.operation,fence=l.fence+1,expires_at=EXCLUDED.expires_at WHERE l.expires_at<=clock_timestamp() RETURNING to_jsonb(l)")
        .bind(input.object_kind.label()).bind(id).bind(auth.entity_id).bind(holder).bind(&input.operation).bind(f64::from(input.ttl_seconds)).fetch_optional(&mut *tx).await.map_err(db_err)?;
    let row=match row {Some(row)=>row,None=>sqlx::query_scalar("SELECT to_jsonb(l) FROM object_leases l WHERE object_kind=$1 AND object_id=$2 AND actor_id=$3 AND holder_id=$4 AND operation=$5 AND expires_at>clock_timestamp()")
        .bind(input.object_kind.label()).bind(id).bind(auth.entity_id).bind(holder).bind(&input.operation).fetch_optional(&mut *tx).await.map_err(db_err)?.ok_or_else(||conflict("LEASE_HELD"))?};
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
    authorize(&state.pool, auth, guard.object_kind, id, None, false).await?;
    let mut tx = state.pool.begin().await.map_err(db_err)?;
    lock_key(
        &mut tx,
        &format!("lease:{}:{id}", guard.object_kind.label()),
    )
    .await?;
    lease_guard(&mut tx, auth.entity_id, &guard).await?;
    let row:Value=sqlx::query_scalar("UPDATE object_leases AS l SET expires_at=clock_timestamp()+make_interval(secs=>$6) WHERE object_kind=$1 AND object_id=$2 AND actor_id=$3 AND holder_id=$4 AND fence=$5 RETURNING to_jsonb(l)")
        .bind(guard.object_kind.label()).bind(id).bind(auth.entity_id).bind(uuid(&guard.holder_id)?).bind(guard.fence).bind(f64::from(ttl.unwrap_or(0))).fetch_one(&mut *tx).await.map_err(db_err)?;
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
    authorize(&state.pool, auth, guard.object_kind, id, None, false).await?;
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM object_leases WHERE object_kind=$1 AND object_id=$2 AND actor_id=$3 AND holder_id=$4 AND fence=$5 AND expires_at>clock_timestamp())")
        .bind(guard.object_kind.label()).bind(id).bind(auth.entity_id).bind(uuid(&guard.holder_id)?).bind(guard.fence)
        .fetch_one(&state.pool).await.map_err(db_err)
}
