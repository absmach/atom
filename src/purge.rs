//! Physical purge of soft-deleted rows.
//!
//! Soft delete sets a `deleted_at` tombstone and hides the row everywhere
//! (authz, listing, login). This background job permanently removes rows whose
//! tombstone is older than the configured retention, reusing the existing
//! foreign-key cascades (the same removal a hard delete used to perform). It is
//! disabled by default — see [`crate::config::PurgeConfig`].

use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::{audit, config::PurgeConfig, models::enums::AuditOutcome, state::AppState};

/// Tables carrying a `deleted_at` tombstone, purged oldest-first. Tenants come
/// last so their cascade doesn't pre-empt the per-table accounting for rows that
/// would otherwise be counted under their own table.
const PURGE_TABLES: &[&str] = &[
    "entities",
    "object_groups",
    "principal_groups",
    "roles",
    "resources",
    "tenants",
];

#[derive(Debug, Clone)]
pub struct PurgeSummary {
    pub deleted_rows: i64,
    pub cutoff: chrono::DateTime<Utc>,
}

pub fn spawn_purge_cleanup(state: AppState) {
    let cfg = state.config.purge;
    if !cfg.enabled {
        tracing::info!("soft-delete purge disabled");
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cfg.interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            match purge_expired(&state.pool, cfg).await {
                Ok(summary) if summary.deleted_rows > 0 => {
                    audit::write(
                        &state.pool,
                        None,
                        None,
                        "purge.cleanup",
                        AuditOutcome::Allow,
                        serde_json::json!({
                            "deleted_rows": summary.deleted_rows,
                            "cutoff": summary.cutoff,
                            "retention_days": cfg.retention_days,
                            "batch_size": cfg.batch_size,
                        }),
                    )
                    .await;
                }
                Ok(_) => {}
                Err(err) => tracing::warn!("soft-delete purge failed: {err}"),
            }
        }
    });
}

/// Physically delete every tombstoned row older than the retention cutoff, in
/// batches per table, then garbage-collect permission blocks orphaned by purged
/// roles.
pub async fn purge_expired(pool: &PgPool, cfg: PurgeConfig) -> Result<PurgeSummary, sqlx::Error> {
    let cutoff = Utc::now() - Duration::days(cfg.retention_days);
    let mut deleted_rows = 0_i64;

    for table in PURGE_TABLES {
        deleted_rows += purge_table(pool, table, cutoff, cfg.batch_size).await?;
    }

    // Roles cascade their `role_permission_blocks` links but not the blocks; GC
    // any block now referenced by no role and no direct policy (the cleanup the
    // old hard `delete_role` did inline, deferred to purge time).
    sqlx::query(
        r#"DELETE FROM permission_blocks pb
           WHERE NOT EXISTS (SELECT 1 FROM role_permission_blocks WHERE permission_block_id = pb.id)
             AND NOT EXISTS (SELECT 1 FROM direct_policies WHERE permission_block_id = pb.id)"#,
    )
    .execute(pool)
    .await?;

    Ok(PurgeSummary {
        deleted_rows,
        cutoff,
    })
}

async fn purge_table(
    pool: &PgPool,
    table: &str,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<i64, sqlx::Error> {
    // `table` is from the fixed PURGE_TABLES allowlist, never user input.
    let sql = format!(
        r#"WITH doomed AS (
               SELECT id FROM {table}
               WHERE deleted_at IS NOT NULL AND deleted_at < $1
               ORDER BY deleted_at ASC
               LIMIT $2
           )
           DELETE FROM {table} WHERE id IN (SELECT id FROM doomed)"#
    );

    let mut deleted = 0_i64;
    loop {
        let result = sqlx::query(&sql)
            .bind(cutoff)
            .bind(batch_size)
            .execute(pool)
            .await?;
        let batch = i64::try_from(result.rows_affected()).unwrap_or(i64::MAX);
        deleted += batch;
        if batch < batch_size {
            break;
        }
    }
    Ok(deleted)
}
