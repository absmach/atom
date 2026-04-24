use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::enums::AuditOutcome;

pub async fn write(pool: &PgPool, entity_id: Option<Uuid>, event: &str, outcome: AuditOutcome, details: Value) {
    let result = sqlx::query(
        "INSERT INTO audit_logs (id, entity_id, event, outcome, details) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(event)
    .bind(outcome)
    .bind(details)
    .execute(pool)
    .await;

    if let Err(e) = result {
        tracing::error!("audit write failed event={event}: {e}");
    }
}
