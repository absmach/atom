use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::{AuditPolicyConfig, AuditRetentionConfig},
    models::enums::AuditOutcome,
    state::AppState,
};

#[derive(Debug, Clone)]
pub struct AuditCleanupSummary {
    pub deleted_rows: i64,
    pub cutoff: chrono::DateTime<Utc>,
}

pub struct AuditEvent<'a> {
    pub actor_entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub target_kind: Option<&'a str>,
    pub target_id: Option<Uuid>,
    pub event: &'a str,
    pub outcome: AuditOutcome,
    pub details: Value,
}

/// Lightweight descriptor for an operation that is not part of the DB audit
/// trail. The success path is emitted by [`commit_with_observation`] (inside the
/// mutation's own transaction); the failure path by [`observe_error`].
///
/// Forward-compat (request-id correlation, option D): add `request_id:
/// Option<String>` here and populate it from the request span — this is the only
/// struct that needs to change at that point.
pub struct AuditMeta<'a> {
    pub actor_entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub target_kind: &'a str,
    pub target_id: Option<Uuid>,
    pub event: &'a str,
}

/// Emit a structured tracing line for an operation (level keyed to outcome), so
/// both DB-audited events and observability-only operations are tailable in
/// stdout logs. Called from [`write`] (alongside the DB insert) and from the
/// observe path (log only).
fn log_audit_event(event: &AuditEvent<'_>) {
    // Fields use lazy Debug sigils (`?`) so the tracing macro skips evaluation —
    // and the Uuid formatting — entirely when the level is filtered out.
    match event.outcome {
        AuditOutcome::Allow => tracing::info!(
            audit.event = event.event,
            audit.outcome = "allow",
            audit.actor = ?event.actor_entity_id,
            audit.tenant = ?event.tenant_id,
            audit.target_kind = event.target_kind,
            audit.target = ?event.target_id,
            audit.details = %event.details,
            "audit"
        ),
        AuditOutcome::Deny => tracing::warn!(
            audit.event = event.event,
            audit.outcome = "deny",
            audit.actor = ?event.actor_entity_id,
            audit.tenant = ?event.tenant_id,
            audit.target_kind = event.target_kind,
            audit.target = ?event.target_id,
            audit.details = %event.details,
            "audit"
        ),
        AuditOutcome::Error => tracing::error!(
            audit.event = event.event,
            audit.outcome = "error",
            audit.actor = ?event.actor_entity_id,
            audit.tenant = ?event.tenant_id,
            audit.target_kind = event.target_kind,
            audit.target = ?event.target_id,
            audit.details = %event.details,
            "audit"
        ),
    }
}

fn outcome_str(outcome: &AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Allow => "allow",
        AuditOutcome::Deny => "deny",
        AuditOutcome::Error => "error",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotPathAuditKind {
    AuthzCheck,
    AuthLogin,
    AuthCredentialAuthenticate,
}

impl HotPathAuditKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::AuthzCheck => "authz_check",
            Self::AuthLogin => "auth_login",
            Self::AuthCredentialAuthenticate => "auth_credential_authenticate",
        }
    }
}

fn should_write_hot_path_allow(policy: AuditPolicyConfig) -> bool {
    policy.hot_path_allow_db_enabled
}

/// Suppressed hot-path `Allow` outcomes (the default for `AuthzCheck`,
/// `AuthLogin`, `AuthCredentialAuthenticate` — see `AuditPolicyConfig`) never
/// reach [`write`], so they're also never published as domain events. This
/// is deliberate: it's what naturally excludes high-volume AuthN/AuthZ noise
/// from the event stream without needing a separate filter.
pub async fn write_hot_path(
    pool: &PgPool,
    policy: AuditPolicyConfig,
    events_enabled: bool,
    kind: HotPathAuditKind,
    event: AuditEvent<'_>,
) {
    if matches!(event.outcome, AuditOutcome::Allow) && !should_write_hot_path_allow(policy) {
        crate::metrics::record_audit_db_suppressed(kind.as_str());
        tracing::trace!(
            audit_event = event.event,
            audit_category = kind.as_str(),
            "audit DB write suppressed by policy"
        );
        return;
    }

    write(pool, events_enabled, event).await;
}

/// Persists the event to `audit_logs` and, when `events_enabled` is true,
/// enqueues the same event into `event_outbox` — both in the same
/// transaction, so the two are atomic with each other (though, matching this
/// codebase's existing precedent, not atomic with whatever mutation the
/// caller performed beforehand: audit writes have never been strictly
/// transactional with their triggering mutation, and this does not change
/// that).
pub async fn write(pool: &PgPool, events_enabled: bool, event: AuditEvent<'_>) {
    log_audit_event(&event);

    if let Err(e) = write_and_enqueue(pool, events_enabled, &event).await {
        crate::metrics::record_audit_failure();
        tracing::error!("audit write failed event={}: {e}", event.event);
    }
}

/// Atomically commits a mutation and its outbox event, then writes the
/// compliance audit row.
///
/// The two storage channels have deliberately different failure semantics:
/// `event_outbox` is enqueued **inside** the caller's transaction, so a broker
/// event can never describe a mutation that rolled back; `audit_logs` is
/// written **after** the commit through [`write`], so audit storage stays
/// fire-and-forget and can never fail an already-valid domain operation. The
/// cost of that choice is that a crash between the commit and the audit insert
/// loses the audit row — accepted, and unchanged from this codebase's original
/// contract that audit writes never propagate failures to the caller.
pub async fn commit_with_audit(
    pool: &PgPool,
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    events_enabled: bool,
    event: &AuditEvent<'_>,
) -> Result<(), crate::error::AppError> {
    if events_enabled {
        crate::events::enqueue(
            &mut *tx,
            events_enabled,
            event.actor_entity_id,
            event.tenant_id,
            event.target_kind,
            event.target_id,
            event.event,
            outcome_str(&event.outcome),
            &event.details,
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(crate::error::AppError::Database)?;
    write(
        pool,
        false,
        AuditEvent {
            actor_entity_id: event.actor_entity_id,
            tenant_id: event.tenant_id,
            target_kind: event.target_kind,
            target_id: event.target_id,
            event: event.event,
            outcome: event.outcome.clone(),
            details: event.details.clone(),
        },
    )
    .await;
    Ok(())
}

/// Enqueues a domain event outbox row inside an existing DB transaction for
/// non-audited operations (e.g. create mutations), keeping the mutation and outbox
/// event strictly atomic.
async fn observe_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    events_enabled: bool,
    meta: &AuditMeta<'_>,
    details: &Value,
) -> Result<(), crate::error::AppError> {
    let event = AuditEvent {
        actor_entity_id: meta.actor_entity_id,
        tenant_id: meta.tenant_id,
        target_kind: Some(meta.target_kind),
        target_id: meta.target_id,
        event: meta.event,
        outcome: AuditOutcome::Allow,
        details: details.clone(),
    };

    if events_enabled {
        crate::events::enqueue(
            &mut **tx,
            events_enabled,
            event.actor_entity_id,
            event.tenant_id,
            event.target_kind,
            event.target_id,
            event.event,
            outcome_str(&event.outcome),
            &event.details,
        )
        .await?;
    }
    Ok(())
}

/// Atomically commits a non-DB-audited mutation and its outbox event, then
/// emits the structured success log after commit.
pub async fn commit_with_observation(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    events_enabled: bool,
    meta: &AuditMeta<'_>,
    details: &Value,
) -> Result<(), crate::error::AppError> {
    observe_in_tx(&mut tx, events_enabled, meta, details).await?;
    tx.commit()
        .await
        .map_err(crate::error::AppError::Database)?;
    log_observe_allow(meta, details);
    Ok(())
}

/// Emits an audit log tracing line for a successful non-audited operation (observe path)
/// after its database transaction has successfully committed.
fn log_observe_allow(meta: &AuditMeta<'_>, details: &Value) {
    let event = AuditEvent {
        actor_entity_id: meta.actor_entity_id,
        tenant_id: meta.tenant_id,
        target_kind: Some(meta.target_kind),
        target_id: meta.target_id,
        event: meta.event,
        outcome: AuditOutcome::Allow,
        details: details.clone(),
    };
    log_audit_event(&event);
}

/// Emits an audit log tracing line and enqueues a domain event outbox row for a failed or denied operation (observe path).
pub async fn observe_error(
    pool: &PgPool,
    events_enabled: bool,
    meta: &AuditMeta<'_>,
    details: &Value,
    err: &crate::error::AppError,
) {
    let outcome = err.audit_outcome();
    let mut merged = details.clone();
    if let Value::Object(ref mut map) = merged {
        map.insert("error".to_string(), Value::String(err.to_string()));
    }
    let event = AuditEvent {
        actor_entity_id: meta.actor_entity_id,
        tenant_id: meta.tenant_id,
        target_kind: Some(meta.target_kind),
        target_id: meta.target_id,
        event: meta.event,
        outcome,
        details: merged,
    };
    log_audit_event(&event);

    if events_enabled {
        if let Err(e) = crate::events::enqueue(
            pool,
            events_enabled,
            event.actor_entity_id,
            event.tenant_id,
            event.target_kind,
            event.target_id,
            event.event,
            outcome_str(&event.outcome),
            &event.details,
        )
        .await
        {
            tracing::error!("failed to enqueue error domain event {}: {e}", event.event);
        }
    }
}

async fn insert_audit_log<'e, E>(
    executor: E,
    event: &AuditEvent<'_>,
) -> Result<(), crate::error::AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO audit_logs (id, actor_entity_id, tenant_id, target_kind, target_id, event, outcome, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::new_v4())
    .bind(event.actor_entity_id)
    .bind(event.tenant_id)
    .bind(event.target_kind)
    .bind(event.target_id)
    .bind(event.event)
    .bind(event.outcome.clone())
    .bind(&event.details)
    .execute(executor)
    .await
    .map_err(crate::error::AppError::Database)?;
    Ok(())
}

async fn write_and_enqueue(
    pool: &PgPool,
    events_enabled: bool,
    event: &AuditEvent<'_>,
) -> Result<(), crate::error::AppError> {
    if !events_enabled {
        // No transaction needed: there's nothing else here to make atomic
        // with the audit_logs insert once event publishing is off, and
        // wrapping a single INSERT in BEGIN/COMMIT would triple its round
        // trips on every audit write (including hot-path authz checks) for
        // every deployment that hasn't opted into a broker — currently all
        // of them.
        return insert_audit_log(pool, event).await;
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(crate::error::AppError::Database)?;

    insert_audit_log(&mut *tx, event).await?;

    crate::events::enqueue(
        &mut *tx,
        events_enabled,
        event.actor_entity_id,
        event.tenant_id,
        event.target_kind,
        event.target_id,
        event.event,
        outcome_str(&event.outcome),
        &event.details,
    )
    .await?;

    tx.commit().await.map_err(crate::error::AppError::Database)
}

pub fn spawn_retention_cleanup(state: AppState) {
    let cfg = state.config.audit_retention;

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(cfg.cleanup_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            if let Err(err) = crate::events::cleanup_expired_outbox(
                &state.pool,
                cfg.days,
                state.config.events.outbox_max_attempts,
                cfg.cleanup_batch_size,
            )
            .await
            {
                tracing::warn!("event outbox retention cleanup failed: {err}");
            }

            if cfg.enabled {
                match cleanup_expired(&state.pool, cfg).await {
                    Ok(summary) if summary.deleted_rows > 0 => {
                        write(
                            &state.pool,
                            state.config.events.enabled(),
                            AuditEvent {
                                actor_entity_id: None,
                                tenant_id: None,
                                target_kind: None,
                                target_id: None,
                                event: "audit.retention_cleanup",
                                outcome: AuditOutcome::Allow,
                                details: serde_json::json!({
                                    "deleted_rows": summary.deleted_rows,
                                    "cutoff": summary.cutoff,
                                    "retention_days": cfg.days,
                                    "batch_size": cfg.cleanup_batch_size,
                                }),
                            },
                        )
                        .await;
                    }
                    Ok(_) => {}
                    Err(err) => tracing::warn!("audit retention cleanup failed: {err}"),
                }
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

#[cfg(test)]
mod tests {
    use super::should_write_hot_path_allow;
    use crate::config::AuditPolicyConfig;
    use crate::error::AppError;
    use crate::models::enums::AuditOutcome;

    #[test]
    fn hot_path_allow_persistence_defaults_off() {
        assert!(!should_write_hot_path_allow(AuditPolicyConfig::default()));
    }

    #[test]
    fn hot_path_allow_persistence_can_be_enabled() {
        assert!(should_write_hot_path_allow(AuditPolicyConfig {
            hot_path_allow_db_enabled: true,
        }));
    }

    #[test]
    fn audit_outcome_classifies_authz_failures_as_deny() {
        assert_eq!(
            AppError::unauthorized("nope").audit_outcome(),
            AuditOutcome::Deny
        );
        assert_eq!(AppError::Forbidden.audit_outcome(), AuditOutcome::Deny);
    }

    #[test]
    fn audit_outcome_classifies_other_failures_as_error() {
        assert_eq!(
            AppError::bad_request("bad").audit_outcome(),
            AuditOutcome::Error
        );
        assert_eq!(
            AppError::conflict("dup").audit_outcome(),
            AuditOutcome::Error
        );
        assert_eq!(
            AppError::not_found("missing").audit_outcome(),
            AuditOutcome::Error
        );
    }
}
