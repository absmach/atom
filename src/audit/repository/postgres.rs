//! Native postgres audit-log storage.
use crate::{
    audit::AuditEvent,
    error::{db_err, AppError},
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool as Database, Postgres as Driver};
use uuid::Uuid;

pub(super) async fn append<'e, E>(executor: E, event: &AuditEvent<'_>) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query("INSERT INTO audit_logs (id, actor_entity_id, tenant_id, target_kind, target_id, event, outcome, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(Uuid::new_v4()).bind(event.actor_entity_id).bind(event.tenant_id)
        .bind(event.target_kind).bind(event.target_id).bind(event.event)
        .bind(event.outcome.clone()).bind(&event.details)
        .execute(executor).await.map_err(db_err)?;
    Ok(())
}

pub(super) async fn purge_batch(
    pool: &Database,
    cutoff: DateTime<Utc>,
    batch_size: i64,
) -> Result<u64, AppError> {
    sqlx::query(
        "WITH doomed AS (
        SELECT id FROM audit_logs WHERE created_at < $1 ORDER BY created_at ASC LIMIT $2)
        DELETE FROM audit_logs WHERE id IN (SELECT id FROM doomed)",
    )
    .bind(cutoff)
    .bind(batch_size)
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
    .map_err(db_err)
}
