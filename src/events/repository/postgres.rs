//! Native postgres outbox storage.
use super::{DomainEventPayload, OutboxRow};
use crate::error::{db_err, AppError};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection as Connection, PgPool as Database, Postgres as Driver};
use uuid::Uuid;
pub(super) async fn append<'e, E>(executor: E, payload: &DomainEventPayload) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    let value = serde_json::to_value(payload).map_err(|e| AppError::Internal(e.into()))?;
    sqlx::query("INSERT INTO event_outbox (id, event, actor_entity_id, tenant_id, payload) VALUES ($1, $2, $3, $4, $5)")
        .bind(payload.event_id).bind(&payload.event).bind(payload.actor_entity_id)
        .bind(payload.tenant_id).bind(value).execute(executor).await.map_err(db_err)?;
    Ok(())
}

/// Distinct from the purge cleanup lock — guards the
/// event-outbox delivery batch specifically, so a multi-instance deployment
/// never has two instances publishing (and marking delivered) the same rows
/// concurrently. Transaction-scoped (`pg_try_advisory_xact_lock`), so it
/// releases automatically on commit or rollback — no explicit unlock needed.
pub(super) async fn claim_delivery(
    conn: &mut Connection,
    batch_size: i64,
    max_attempts: i32,
) -> Result<Vec<OutboxRow>, AppError> {
    const EVENT_OUTBOX_ADVISORY_LOCK_ID: i64 = 0x4154_4f4d_4556_4e54;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(EVENT_OUTBOX_ADVISORY_LOCK_ID)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?;
    if !acquired {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT id, payload FROM event_outbox
        WHERE delivered_at IS NULL AND (NOT unparseable OR attempts < $2)
        ORDER BY created_at ASC LIMIT $1",
    )
    .bind(batch_size)
    .bind(max_attempts)
    .fetch_all(conn)
    .await
    .map_err(db_err)
}

pub(super) async fn record_delivery_failure(
    conn: &mut Connection,
    ids: &[Uuid],
    error: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE event_outbox SET attempts = attempts + 1, last_error = $2 WHERE id = ANY($1)",
    )
    .bind(ids)
    .bind(error)
    .execute(conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn mark_delivered(conn: &mut Connection, ids: &[Uuid]) -> Result<(), AppError> {
    sqlx::query("UPDATE event_outbox SET delivered_at = now() WHERE id = ANY($1)")
        .bind(ids)
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub(super) async fn quarantine(
    conn: &mut Connection,
    ids: &[Uuid],
    error: &str,
) -> Result<Vec<(Uuid, i32)>, AppError> {
    sqlx::query_as("UPDATE event_outbox SET attempts = attempts + 1, last_error = $2, unparseable = true WHERE id = ANY($1) RETURNING id, attempts")
        .bind(ids).bind(error).fetch_all(conn).await.map_err(db_err)
}

pub(super) async fn purge_batch(
    pool: &Database,
    cutoff: DateTime<Utc>,
    max_attempts: i32,
    batch_size: i64,
) -> Result<u64, AppError> {
    sqlx::query(
        "WITH doomed AS (
        SELECT id FROM event_outbox
        WHERE (delivered_at IS NOT NULL OR (unparseable = true AND attempts >= $2))
          AND created_at < $1
        ORDER BY created_at ASC LIMIT $3)
        DELETE FROM event_outbox WHERE id IN (SELECT id FROM doomed)",
    )
    .bind(cutoff)
    .bind(max_attempts)
    .bind(batch_size)
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
    .map_err(db_err)
}
