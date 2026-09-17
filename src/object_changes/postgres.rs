//! PostgreSQL implementation of the object-coordination storage operations
//! declared in [`super`]. Owns its native SQL: advisory locks, `FOR UPDATE`,
//! `clock_timestamp()`, and `to_jsonb` for the lease rows returned to clients
//! verbatim.

use serde_json::Value;
use sqlx::{PgConnection, Postgres};
use uuid::Uuid;

use super::{LeaseKey, NewObject, ObjectKind, ObjectRow};
use crate::error::{db_err, AppError};

fn object_columns(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Entity => "revision, tenant_id, kind, managed_by, profile_id, external_id",
        ObjectKind::Resource => {
            "revision, tenant_id, kind, managed_by, NULL::uuid AS profile_id, \
             NULL::text AS external_id"
        }
    }
}

pub(super) async fn lock_key(tx: &mut PgConnection, key: &str) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 17))")
        .bind(key)
        .execute(tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub(super) async fn find_receipt<'e, E>(
    executor: E,
    actor: Uuid,
    request_id: Uuid,
) -> Result<Option<(Value, Value)>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, (Value, Value)>(
        "SELECT request,response FROM object_change_requests WHERE actor_id=$1 AND request_id=$2",
    )
    .bind(actor)
    .bind(request_id)
    .fetch_optional(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn object_tenant(
    tx: &mut PgConnection,
    kind: ObjectKind,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT tenant_id FROM {} WHERE id=$1 AND deleted_at IS NULL",
        kind.table()
    ))
    .bind(id)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_object(
    tx: &mut PgConnection,
    kind: ObjectKind,
    id: Uuid,
    tenant: Option<Uuid>,
) -> Result<ObjectRow, AppError> {
    sqlx::query_as::<_, ObjectRow>(&format!(
        "SELECT {} FROM {} WHERE id=$1 AND deleted_at IS NULL \
         AND tenant_id IS NOT DISTINCT FROM $2 FOR UPDATE",
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
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM object_leases WHERE object_kind=$1 AND object_id=$2 \
         AND actor_id=$3 AND holder_id=$4 AND fence=$5 AND expires_at>clock_timestamp())",
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
    tx: &mut PgConnection,
    entity_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE entity_id=$1) \
         OR EXISTS(SELECT 1 FROM sessions WHERE entity_id=$1)",
    )
    .bind(entity_id)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn insert_object(
    tx: &mut PgConnection,
    new: NewObject<'_>,
) -> Result<ObjectRow, AppError> {
    sqlx::query_as::<_, ObjectRow>(&format!(
        "INSERT INTO {}(id,kind,name,alias,tenant_id,attributes) VALUES($1,$2,$3,$4,$5,$6) \
         RETURNING {}",
        new.object_kind.table(),
        object_columns(new.object_kind)
    ))
    .bind(new.id)
    .bind(new.kind)
    .bind(new.name)
    .bind(new.alias)
    .bind(new.tenant_id)
    .bind(new.attributes)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn update_attributes(
    tx: &mut PgConnection,
    kind: ObjectKind,
    id: Uuid,
    attributes: &Value,
) -> Result<ObjectRow, AppError> {
    sqlx::query_as::<_, ObjectRow>(&format!(
        "UPDATE {} SET attributes=$2,updated_at=clock_timestamp() WHERE id=$1 RETURNING {}",
        kind.table(),
        object_columns(kind)
    ))
    .bind(id)
    .bind(attributes)
    .fetch_one(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn soft_delete(
    tx: &mut PgConnection,
    kind: ObjectKind,
    id: Uuid,
    actor: Uuid,
) -> Result<ObjectRow, AppError> {
    let status = match kind {
        ObjectKind::Entity => ", status='inactive'",
        ObjectKind::Resource => "",
    };
    sqlx::query_as::<_, ObjectRow>(&format!(
        "UPDATE {} SET deleted_at=clock_timestamp(),deleted_by=$2,updated_at=clock_timestamp()\
         {status} WHERE id=$1 RETURNING {}",
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
    tx: &mut PgConnection,
    actor: Uuid,
    request_id: Uuid,
    request: &Value,
    response: &Value,
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM object_change_requests WHERE actor_id=$1 \
         AND created_at < now()-interval '7 days'",
    )
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO object_change_requests(actor_id,request_id,request,response) \
         VALUES($1,$2,$3,$4)",
    )
    .bind(actor)
    .bind(request_id)
    .bind(request)
    .bind(response)
    .execute(tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn take_lease(
    tx: &mut PgConnection,
    key: LeaseKey<'_>,
    ttl_seconds: i32,
) -> Result<Option<Value>, AppError> {
    sqlx::query_scalar(
        "INSERT INTO object_leases AS l(object_kind,object_id,actor_id,holder_id,operation,expires_at) \
         VALUES($1,$2,$3,$4,$5,clock_timestamp()+make_interval(secs=>$6)) \
         ON CONFLICT(object_kind,object_id) DO UPDATE SET actor_id=EXCLUDED.actor_id,\
         holder_id=EXCLUDED.holder_id,operation=EXCLUDED.operation,fence=l.fence+1,\
         expires_at=EXCLUDED.expires_at WHERE l.expires_at<=clock_timestamp() \
         RETURNING to_jsonb(l)",
    )
    .bind(key.object_kind.label())
    .bind(key.object_id)
    .bind(key.actor_id)
    .bind(key.holder_id)
    .bind(key.operation)
    .bind(f64::from(ttl_seconds))
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn current_lease(
    tx: &mut PgConnection,
    key: LeaseKey<'_>,
) -> Result<Option<Value>, AppError> {
    sqlx::query_scalar(
        "SELECT to_jsonb(l) FROM object_leases l WHERE object_kind=$1 AND object_id=$2 \
         AND actor_id=$3 AND holder_id=$4 AND operation=$5 AND expires_at>clock_timestamp()",
    )
    .bind(key.object_kind.label())
    .bind(key.object_id)
    .bind(key.actor_id)
    .bind(key.holder_id)
    .bind(key.operation)
    .fetch_optional(tx)
    .await
    .map_err(db_err)
}

pub(super) async fn set_lease_expiry(
    tx: &mut PgConnection,
    kind: ObjectKind,
    object_id: Uuid,
    actor: Uuid,
    holder: Uuid,
    fence: i64,
    ttl_seconds: i32,
) -> Result<Value, AppError> {
    sqlx::query_scalar(
        "UPDATE object_leases AS l SET expires_at=clock_timestamp()+make_interval(secs=>$6) \
         WHERE object_kind=$1 AND object_id=$2 AND actor_id=$3 AND holder_id=$4 AND fence=$5 \
         RETURNING to_jsonb(l)",
    )
    .bind(kind.label())
    .bind(object_id)
    .bind(actor)
    .bind(holder)
    .bind(fence)
    .bind(f64::from(ttl_seconds))
    .fetch_one(tx)
    .await
    .map_err(db_err)
}
