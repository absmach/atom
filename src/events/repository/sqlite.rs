//! Native sqlite outbox storage.
use super::{DomainEventPayload, OutboxRow};
use crate::error::{db_err, AppError};
use chrono::{DateTime, Utc};
use sqlx::{Sqlite as Driver, SqliteConnection as Connection, SqlitePool as Database};
use uuid::Uuid;
pub(super) async fn append<'e, E>(executor: E, payload: &DomainEventPayload) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    let value = serde_json::to_value(payload).map_err(|e| AppError::Internal(e.into()))?;
    sqlx::query("INSERT INTO event_outbox (id, event, actor_entity_id, tenant_id, payload) VALUES ($1, $2, $3, $4, $5)")
        .bind(payload.event_id).bind(&payload.event).bind(payload.actor_entity_id)
        .bind(payload.tenant_id).bind(value.to_string()).execute(executor).await.map_err(db_err)?;
    Ok(())
}

pub(super) async fn claim_delivery(
    conn: &mut Connection,
    batch_size: i64,
    max_attempts: i32,
) -> Result<Vec<OutboxRow>, AppError> {
    // The caller holds BEGIN IMMEDIATE, serializing SQLite delivery.
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
    sqlx::query("UPDATE event_outbox SET attempts = attempts + 1, last_error = $2 WHERE id IN (SELECT unhex(value) FROM json_each($1))")
        .bind(crate::db::native::uuid_array_json(ids)).bind(error).execute(conn).await.map_err(db_err)?;
    Ok(())
}

pub(super) async fn mark_delivered(conn: &mut Connection, ids: &[Uuid]) -> Result<(), AppError> {
    sqlx::query("UPDATE event_outbox SET delivered_at = now() WHERE id IN (SELECT unhex(value) FROM json_each($1))")
        .bind(crate::db::native::uuid_array_json(ids)).execute(conn).await.map_err(db_err)?;
    Ok(())
}

pub(super) async fn quarantine(
    conn: &mut Connection,
    ids: &[Uuid],
    error: &str,
) -> Result<Vec<(Uuid, i32)>, AppError> {
    sqlx::query_as("UPDATE event_outbox SET attempts = attempts + 1, last_error = $2, unparseable = true WHERE id IN (SELECT unhex(value) FROM json_each($1)) RETURNING id, attempts")
        .bind(crate::db::native::uuid_array_json(ids)).bind(error).fetch_all(conn).await.map_err(db_err)
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
    .bind(cutoff.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    .bind(max_attempts)
    .bind(batch_size)
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
    .map_err(db_err)
}
