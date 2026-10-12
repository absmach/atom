//! SQLite implementation of the object-coordination storage operations
//! declared in [`super`], independent of the PostgreSQL adapter.
//!
//! Differences from PostgreSQL, all deliberate:
//! - No advisory or row locks: SQLite admits one write transaction at a time
//!   (`BEGIN IMMEDIATE`), which already serializes every writer.
//! - Timestamps are fixed-width UTC text (`now()`, `atom_ts_add`, registered
//!   per connection by `crate::db::sqlite_functions`), so expiry comparisons
//!   are plain text comparisons.
//! - The revision trigger runs AFTER an update and is invisible to
//!   `RETURNING`, so every update that returns a revision bumps it explicitly
//!   (the trigger's `WHEN NEW.revision = OLD.revision` guard then skips).
//! - There is no `to_jsonb`; lease rows are read as typed columns and turned
//!   into the same JSON shape PostgreSQL returns.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sqlx::{Sqlite, SqliteConnection};
use uuid::Uuid;

use super::{LeaseKey, NewObject, ObjectKind, ObjectRow};
use crate::error::{db_err, AppError};

const RECEIPT_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

const LEASE_COLUMNS: &str =
    "object_kind, object_id, actor_id, holder_id, operation, fence, expires_at";

fn object_columns(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Entity => "revision, tenant_id, kind, managed_by, profile_id, external_id",
        ObjectKind::Resource => {
            "revision, tenant_id, kind, managed_by, NULL AS profile_id, NULL AS external_id"
        }
    }
}

#[derive(sqlx::FromRow)]
struct LeaseRow {
    object_kind: String,
    object_id: Uuid,
    actor_id: Uuid,
    holder_id: Uuid,
    operation: String,
    fence: i64,
    expires_at: DateTime<Utc>,
}

/// The same keys PostgreSQL's `to_jsonb(object_leases)` produces.
fn lease_json(row: LeaseRow) -> Value {
    json!({
        "object_kind": row.object_kind,
        "object_id": row.object_id,
        "actor_id": row.actor_id,
        "holder_id": row.holder_id,
        "operation": row.operation,
        "fence": row.fence,
        "expires_at": row.expires_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
    })
}

fn parse_json(text: &str) -> Result<Value, AppError> {
    serde_json::from_str(text)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("stored receipt is not JSON: {e}")))
}

pub(super) async fn find_receipt<'e, E>(
    executor: E,
    actor: Uuid,
    request_id: Uuid,
) -> Result<Option<(Value, Value)>, AppError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT request, response FROM object_change_requests WHERE actor_id = $1 AND request_id = $2",
    )
    .bind(actor)
    .bind(request_id)
    .fetch_optional(executor)
    .await
    .map_err(db_err)?;
    row.map(|(request, response)| Ok((parse_json(&request)?, parse_json(&response)?)))
        .transpose()
}

pub(super) async fn object_tenant(
    tx: &mut SqliteConnection,
    kind: ObjectKind,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT tenant_id FROM {} WHERE id = $1 AND deleted_at IS NULL",
        kind.table()
    ))
    .bind(id)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_object(
    tx: &mut SqliteConnection,
    kind: ObjectKind,
    id: Uuid,
    tenant: Option<Uuid>,
) -> Result<ObjectRow, AppError> {
    // `IS` is SQLite's NULL-safe equality (PostgreSQL's IS NOT DISTINCT FROM).
    sqlx::query_as::<_, ObjectRow>(&format!(
        "SELECT {} FROM {} WHERE id = $1 AND deleted_at IS NULL AND tenant_id IS $2",
        object_columns(kind),
        kind.table()
    ))
    .bind(id)
    .bind(tenant)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn lease_is_live<'e, E>(
    executor: E,
    kind: ObjectKind,
    object_id: Uuid,
    actor: Uuid,
    holder: Uuid,
    fence: i64,
) -> Result<bool, AppError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM object_leases WHERE object_kind = $1 AND object_id = $2 \
         AND actor_id = $3 AND holder_id = $4 AND fence = $5 AND expires_at > now())",
    )
    .bind(kind.label())
    .bind(object_id)
    .bind(actor)
    .bind(holder)
    .bind(fence)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn has_credentials_or_sessions(
    tx: &mut SqliteConnection,
    entity_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE entity_id = $1) \
         OR EXISTS(SELECT 1 FROM sessions WHERE entity_id = $1)",
    )
    .bind(entity_id)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn insert_object(
    tx: &mut SqliteConnection,
    new: NewObject<'_>,
) -> Result<ObjectRow, AppError> {
    sqlx::query_as::<_, ObjectRow>(&format!(
        "INSERT INTO {} (id, kind, name, alias, tenant_id, attributes) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {}",
        new.object_kind.table(),
        object_columns(new.object_kind)
    ))
    .bind(new.id)
    .bind(new.kind)
    .bind(new.name)
    .bind(new.alias)
    .bind(new.tenant_id)
    .bind(new.attributes.to_string())
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn update_attributes(
    tx: &mut SqliteConnection,
    kind: ObjectKind,
    id: Uuid,
    attributes: &Value,
) -> Result<ObjectRow, AppError> {
    sqlx::query_as::<_, ObjectRow>(&format!(
        "UPDATE {} SET attributes = $2, updated_at = now(), revision = revision + 1 \
         WHERE id = $1 RETURNING {}",
        kind.table(),
        object_columns(kind)
    ))
    .bind(id)
    .bind(attributes.to_string())
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn soft_delete(
    tx: &mut SqliteConnection,
    kind: ObjectKind,
    id: Uuid,
    actor: Uuid,
) -> Result<ObjectRow, AppError> {
    let status = match kind {
        ObjectKind::Entity => ", status = 'inactive'",
        ObjectKind::Resource => "",
    };
    sqlx::query_as::<_, ObjectRow>(&format!(
        "UPDATE {} SET deleted_at = now(), deleted_by = $2, updated_at = now(), \
         revision = revision + 1{status} WHERE id = $1 RETURNING {}",
        kind.table(),
        object_columns(kind)
    ))
    .bind(id)
    .bind(actor)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn record_receipt(
    tx: &mut SqliteConnection,
    actor: Uuid,
    request_id: Uuid,
    request: &Value,
    response: &Value,
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM object_change_requests WHERE actor_id = $1 \
         AND created_at < atom_ts_add(now(), $2)",
    )
    .bind(actor)
    .bind(-RECEIPT_RETENTION_SECS)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO object_change_requests (actor_id, request_id, request, response) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(actor)
    .bind(request_id)
    .bind(request.to_string())
    .bind(response.to_string())
    .execute(tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn take_lease(
    tx: &mut SqliteConnection,
    key: LeaseKey<'_>,
    ttl_seconds: i32,
) -> Result<Option<Value>, AppError> {
    // A conflicting live lease fails the DO UPDATE's WHERE, which returns no
    // row — the caller's cue to look for the caller's own live lease.
    let row = sqlx::query_as::<_, LeaseRow>(&format!(
        "INSERT INTO object_leases AS l \
           (object_kind, object_id, actor_id, holder_id, operation, expires_at) \
         VALUES ($1, $2, $3, $4, $5, atom_ts_add(now(), $6)) \
         ON CONFLICT (object_kind, object_id) DO UPDATE SET actor_id = excluded.actor_id, \
           holder_id = excluded.holder_id, operation = excluded.operation, \
           fence = l.fence + 1, expires_at = excluded.expires_at \
         WHERE l.expires_at <= now() \
         RETURNING {LEASE_COLUMNS}"
    ))
    .bind(key.object_kind.label())
    .bind(key.object_id)
    .bind(key.actor_id)
    .bind(key.holder_id)
    .bind(key.operation)
    .bind(i64::from(ttl_seconds))
    .fetch_optional(tx)
    .await
    .map_err(db_err)?;
    Ok(row.map(lease_json))
}

pub(super) async fn current_lease(
    tx: &mut SqliteConnection,
    key: LeaseKey<'_>,
) -> Result<Option<Value>, AppError> {
    let row = sqlx::query_as::<_, LeaseRow>(&format!(
        "SELECT {LEASE_COLUMNS} FROM object_leases WHERE object_kind = $1 AND object_id = $2 \
         AND actor_id = $3 AND holder_id = $4 AND operation = $5 AND expires_at > now()"
    ))
    .bind(key.object_kind.label())
    .bind(key.object_id)
    .bind(key.actor_id)
    .bind(key.holder_id)
    .bind(key.operation)
    .fetch_optional(tx)
    .await
    .map_err(db_err)?;
    Ok(row.map(lease_json))
}

pub(super) async fn set_lease_expiry(
    tx: &mut SqliteConnection,
    kind: ObjectKind,
    object_id: Uuid,
    actor: Uuid,
    holder: Uuid,
    fence: i64,
    ttl_seconds: i32,
) -> Result<Value, AppError> {
    let row = sqlx::query_as::<_, LeaseRow>(&format!(
        "UPDATE object_leases SET expires_at = atom_ts_add(now(), $6) \
         WHERE object_kind = $1 AND object_id = $2 AND actor_id = $3 AND holder_id = $4 \
         AND fence = $5 RETURNING {LEASE_COLUMNS}"
    ))
    .bind(kind.label())
    .bind(object_id)
    .bind(actor)
    .bind(holder)
    .bind(fence)
    .bind(i64::from(ttl_seconds))
    .fetch_one(tx)
    .await
    .map_err(db_err)?;
    Ok(lease_json(row))
}
