use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{config::AuditRetentionConfig, models::enums::AuditOutcome, state::AppState};

#[derive(Debug, Clone)]
pub struct AuditCleanupSummary {
    pub deleted_rows: i64,
    pub cutoff: chrono::DateTime<Utc>,
}

pub async fn write(
    pool: &PgPool,
    entity_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    event: &str,
    outcome: AuditOutcome,
    details: Value,
) {
    let result = sqlx::query(
        "INSERT INTO audit_logs (id, entity_id, tenant_id, event, outcome, details) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(tenant_id)
    .bind(event)
    .bind(outcome)
    .bind(details)
    .execute(pool)
    .await;

    if let Err(e) = result {
        crate::metrics::record_audit_failure();
        tracing::error!("audit write failed event={event}: {e}");
    }
}

pub fn spawn_retention_cleanup(state: AppState) {
    let cfg = state.config.audit_retention;
    if !cfg.enabled {
        tracing::info!("audit retention cleanup disabled");
        return;
    }

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(cfg.cleanup_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            match cleanup_expired(&state.pool, cfg).await {
                Ok(summary) if summary.deleted_rows > 0 => {
                    write(
                        &state.pool,
                        None,
                        None,
                        "audit.retention_cleanup",
                        AuditOutcome::Allow,
                        serde_json::json!({
                            "deleted_rows": summary.deleted_rows,
                            "cutoff": summary.cutoff,
                            "retention_days": cfg.days,
                            "batch_size": cfg.cleanup_batch_size,
                        }),
                    )
                    .await;
                }
                Ok(_) => {}
                Err(err) => tracing::warn!("audit retention cleanup failed: {err}"),
            }
        }
    });
}

pub async fn cleanup_expired(
    pool: &PgPool,
    cfg: AuditRetentionConfig,
) -> Result<AuditCleanupSummary, sqlx::Error> {
    let cutoff = Utc::now() - Duration::days(cfg.days);
    let mut deleted_rows = 0_i64;

    loop {
        let result = sqlx::query(
            r#"WITH doomed AS (
                   SELECT id
                   FROM audit_logs
                   WHERE created_at < $1
                   ORDER BY created_at ASC
                   LIMIT $2
               )
               DELETE FROM audit_logs
               WHERE id IN (SELECT id FROM doomed)"#,
        )
        .bind(cutoff)
        .bind(cfg.cleanup_batch_size)
        .execute(pool)
        .await?;

        let batch = i64::try_from(result.rows_affected()).unwrap_or(i64::MAX);
        deleted_rows += batch;
        if batch < cfg.cleanup_batch_size {
            break;
        }
    }

    Ok(AuditCleanupSummary {
        deleted_rows,
        cutoff,
    })
}
