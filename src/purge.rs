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

use crate::{
    audit, config::PurgeConfig, error::AppError, models::enums::AuditOutcome, state::AppState,
};

/// Simple object tables purged generically (one batch each). Entities (their
/// credentials must be captured first), roles (scoped block GC), and tenants
/// (cascade across every table) are handled specially in [`purge_expired`].
const PURGE_TABLES: &[&str] = &["object_groups", "principal_groups", "resources"];

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
/// first-class objects and must not be treated as garbage. Every object UUID
/// removed by the run (including cascaded entity credentials and tenant
/// children) is fed through the canonical
/// [`crate::authz::repo::purge_authz_references_for_ids`] so no bare-UUID authz
/// reference (`permission_blocks.object_id`, `*_id` subject grants) is left
/// dangling — the same cleanup the explicit purge mutations use.
pub async fn purge_expired(pool: &PgPool, cfg: PurgeConfig) -> Result<PurgeSummary, AppError> {
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
    // Every object UUID physically removed by this run, so a single canonical
    // pass can drop the bare-UUID authz references (permission_blocks.object_id,
    // direct_policies/role_assignments.subject_id) that no foreign key cleans up.
    let mut doomed_ids: Vec<Uuid> = Vec::new();

    for table in PURGE_TABLES {
        let ids = select_doomed(&mut tx, table, cutoff, cfg.batch_size).await?;
        deleted_rows += delete_by_ids(&mut tx, table, &ids).await?;
        doomed_ids.extend(ids);
    }

    // Entities: capture cascaded credential ids before the delete removes them.
    let entity_ids = select_doomed(&mut tx, "entities", cutoff, cfg.batch_size).await?;
    if !entity_ids.is_empty() {
        let credential_ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM credentials WHERE entity_id = ANY($1)")
                .bind(&entity_ids)
                .fetch_all(&mut *tx)
                .await?;
        deleted_rows += delete_by_ids(&mut tx, "entities", &entity_ids).await?;
        doomed_ids.extend(entity_ids);
        doomed_ids.extend(credential_ids);
    }

    let role_ids = purge_roles(&mut tx, cutoff, cfg.batch_size).await?;
    deleted_rows += i64::try_from(role_ids.len()).unwrap_or(i64::MAX);
    doomed_ids.extend(role_ids);

    // Tenants: gather the tenant + all cascaded children before the cascade.
    let tenant_ids = select_doomed(&mut tx, "tenants", cutoff, cfg.batch_size).await?;
    if !tenant_ids.is_empty() {
        let child_ids = crate::tenants::repo::tenant_purge_object_ids(&mut tx, &tenant_ids).await?;
        deleted_rows += delete_by_ids(&mut tx, "tenants", &tenant_ids).await?;
        doomed_ids.extend(child_ids); // already includes the tenant ids themselves
    }

    crate::authz::repo::purge_authz_references_for_ids(&mut tx, &doomed_ids).await?;

    tx.commit().await?;

    Ok(PurgeSummary {
        deleted_rows,
        cutoff,
    })
}

/// Locks and returns one bounded batch of tombstoned ids past the cutoff.
async fn select_doomed(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    // `table` is from the fixed PURGE_TABLES allowlist / literals, never input.
    let sql = format!(
        r#"SELECT id FROM {table}
           WHERE deleted_at IS NOT NULL AND deleted_at < $1
           ORDER BY deleted_at ASC
           LIMIT $2
           FOR UPDATE SKIP LOCKED"#
    );
    Ok(sqlx::query_scalar(&sql)
        .bind(cutoff)
        .bind(batch_size)
        .fetch_all(&mut **tx)
        .await?)
}

async fn delete_by_ids(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    ids: &[Uuid],
) -> Result<i64, AppError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let sql = format!("DELETE FROM {table} WHERE id = ANY($1)");
    let result = sqlx::query(&sql).bind(ids).execute(&mut **tx).await?;
    Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
}

/// Purges one batch of tombstoned roles and GCs the permission blocks orphaned
/// by their removal, returning the physically removed role ids so the caller can
/// fold them into the canonical authz-reference cleanup.
async fn purge_roles(
    tx: &mut Transaction<'_, Postgres>,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    let role_ids = select_doomed(tx, "roles", cutoff, batch_size).await?;
    if role_ids.is_empty() {
        return Ok(role_ids);
    }

    let candidate_block_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT DISTINCT permission_block_id
           FROM role_permission_blocks
           WHERE role_id = ANY($1)"#,
    )
    .bind(&role_ids)
    .fetch_all(&mut **tx)
    .await?;

    sqlx::query("DELETE FROM roles WHERE id = ANY($1)")
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

    Ok(role_ids)
}
