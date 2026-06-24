//! Physical purge of soft-deleted rows.
//!
//! Soft delete sets a `deleted_at` tombstone and hides the row everywhere
//! (authz, listing, login). This background job permanently removes rows whose
//! tombstone is older than the configured retention, reusing the existing
//! foreign-key cascades (the same removal a hard delete used to perform). It is
//! disabled by default — see [`crate::config::PurgeConfig`].

use chrono::{Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{audit, config::PurgeConfig, models::enums::AuditOutcome, state::AppState};

/// Independently purged tables carrying a `deleted_at` tombstone. Roles need
/// scoped permission-block GC and tenants come last because their cascades can
/// remove rows from every other table.
const PURGE_TABLES: &[&str] = &["entities", "object_groups", "principal_groups", "resources"];

const PURGE_ADVISORY_LOCK_ID: i64 = 0x4154_4f4d_5055_5247;

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

/// Physically delete one bounded batch of tombstoned rows per table.
///
/// A transaction-scoped advisory lock ensures only one application replica
/// performs cleanup at a time. Permission-block GC is limited to blocks linked
/// to roles physically removed by this transaction; standalone blocks are
/// first-class objects and must not be treated as garbage.
pub async fn purge_expired(pool: &PgPool, cfg: PurgeConfig) -> Result<PurgeSummary, sqlx::Error> {
    let cutoff = Utc::now() - Duration::days(cfg.retention_days);
    let mut tx = pool.begin().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(PURGE_ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await?;

    if !acquired {
        return Ok(PurgeSummary {
            deleted_rows: 0,
            cutoff,
        });
    }

    let mut deleted_rows = 0_i64;

    for table in PURGE_TABLES {
        deleted_rows += purge_table(&mut tx, table, cutoff, cfg.batch_size).await?;
    }
    deleted_rows += purge_roles(&mut tx, cutoff, cfg.batch_size).await?;
    deleted_rows += purge_table(&mut tx, "tenants", cutoff, cfg.batch_size).await?;

    tx.commit().await?;

    Ok(PurgeSummary {
        deleted_rows,
        cutoff,
    })
}

async fn purge_table(
    tx: &mut Transaction<'_, Postgres>,
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
               FOR UPDATE SKIP LOCKED
           )
           DELETE FROM {table} WHERE id IN (SELECT id FROM doomed)"#
    );

    let result = sqlx::query(&sql)
        .bind(cutoff)
        .bind(batch_size)
        .execute(&mut **tx)
        .await?;
    Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
}

async fn purge_roles(
    tx: &mut Transaction<'_, Postgres>,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<i64, sqlx::Error> {
    let role_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT id
           FROM roles
           WHERE deleted_at IS NOT NULL AND deleted_at < $1
           ORDER BY deleted_at ASC
           LIMIT $2
           FOR UPDATE SKIP LOCKED"#,
    )
    .bind(cutoff)
    .bind(batch_size)
    .fetch_all(&mut **tx)
    .await?;

    if role_ids.is_empty() {
        return Ok(0);
    }

    let candidate_block_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT DISTINCT permission_block_id
           FROM role_permission_blocks
           WHERE role_id = ANY($1)"#,
    )
    .bind(&role_ids)
    .fetch_all(&mut **tx)
    .await?;

    let result = sqlx::query("DELETE FROM roles WHERE id = ANY($1)")
        .bind(&role_ids)
        .execute(&mut **tx)
        .await?;

    if !candidate_block_ids.is_empty() {
        sqlx::query(
            r#"DELETE FROM permission_blocks pb
               WHERE pb.id = ANY($1)
                 AND NOT EXISTS (
                     SELECT 1 FROM role_permission_blocks
                     WHERE permission_block_id = pb.id
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM direct_policies
                     WHERE permission_block_id = pb.id
                 )"#,
        )
        .bind(&candidate_block_ids)
        .execute(&mut **tx)
        .await?;
    }

    Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
}
