//! Generic domain-event publishing.
//!
//! Every audit-worthy operation Atom already detects (via `src/audit.rs`) is
//! optionally mirrored to an external broker, so an external system (a
//! billing service, an analytics pipeline, anything) can react without
//! polling Atom. Atom's responsibility ends at a reliable, at-least-once
//! publish — it does not know or care what the consumer does with the event
//! (no quotas, no usage limits, no billing vocabulary anywhere in this
//! module).
//!
//! This module is additive and, when [`crate::config::EventsConfig::enabled`]
//! is `false` (the default — no AMQP URL configured), every entry point here
//! is a no-op: no `event_outbox` rows are written and no delivery task is
//! spawned, so existing deployments see zero behavior change.

pub mod publisher;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    state::AppState,
};
use publisher::EventPublisher;

pub const SCHEMA_VERSION: u32 = 1;
pub const EVENT_SOURCE: &str = "atom";

/// The wire contract delivered to the broker. Mirrors
/// [`crate::audit::AuditEvent`]'s shape almost exactly — this is
/// deliberately a generic domain-event envelope, not a usage/billing-specific
/// payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEventPayload {
    pub schema_version: u32,
    pub event_id: Uuid,
    pub event: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub actor_entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub target_kind: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: String,
    pub details: serde_json::Value,
    pub request_id: Option<String>,
}

/// Enqueues one event into the outbox, if and only if event publishing is
/// configured. A no-op (no query at all) when
/// [`crate::config::EventsConfig::enabled`] is `false`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue<'e, E>(
    executor: E,
    enabled: bool,
    actor_entity_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    target_kind: Option<&str>,
    target_id: Option<Uuid>,
    event: &str,
    outcome: &str,
    details: &serde_json::Value,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if !enabled {
        return Ok(());
    }

    let payload = DomainEventPayload {
        schema_version: SCHEMA_VERSION,
        event_id: Uuid::new_v4(),
        event: event.to_string(),
        occurred_at: chrono::Utc::now(),
        source: EVENT_SOURCE.to_string(),
        actor_entity_id,
        tenant_id,
        target_kind: target_kind.map(str::to_string),
        target_id,
        outcome: outcome.to_string(),
        details: details.clone(),
        request_id: None,
    };

    sqlx::query(
        "INSERT INTO event_outbox (id, event, actor_entity_id, tenant_id, payload)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(payload.event_id)
    .bind(&payload.event)
    .bind(payload.actor_entity_id)
    .bind(payload.tenant_id)
    .bind(serde_json::to_value(&payload).map_err(|e| AppError::Internal(e.into()))?)
    .execute(executor)
    .await
    .map_err(db_err)?;

    Ok(())
}

/// Distinct from [`crate::purge::PURGE_ADVISORY_LOCK_ID`] — guards the
/// event-outbox delivery batch specifically, so a multi-instance deployment
/// never has two instances publishing (and marking delivered) the same rows
/// concurrently. Transaction-scoped (`pg_try_advisory_xact_lock`), so it
/// releases automatically on commit or rollback — no explicit unlock needed.
const EVENT_OUTBOX_ADVISORY_LOCK_ID: i64 = 0x4154_4f4d_4556_4e54;

/// Starts the background outbox-delivery loop, modeled on
/// [`crate::audit::spawn_retention_cleanup`] and
/// [`crate::purge::spawn_purge_cleanup`]. A no-op — no task is spawned at
/// all — when [`crate::config::EventsConfig::enabled`] is `false` (the
/// default, i.e. no broker configured).
pub fn spawn_event_publisher(state: AppState) {
    let cfg = state.config.events.clone();
    if !cfg.enabled() {
        tracing::info!("event publishing disabled (no broker configured)");
        return;
    }
    let Some(publisher) = state.event_publisher.clone() else {
        tracing::warn!("events configured but no publisher installed; not starting poller");
        return;
    };

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            cfg.outbox_poll_interval_secs,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            match deliver_outbox_batch(&state.pool, publisher.as_ref(), &cfg).await {
                Ok(delivered) if delivered > 0 => {
                    tracing::debug!(events.delivered = delivered, "event outbox batch delivered");
                }
                Ok(_) => {}
                Err(err) => tracing::warn!("event outbox delivery failed: {err}"),
            }
        }
    });
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
    id: Uuid,
    payload: serde_json::Value,
}

/// Delivers (at most) one batch of undelivered `event_outbox` rows and
/// returns how many were marked delivered. Public so tests can drive
/// delivery deterministically instead of waiting on the poller's interval,
/// and so a future admin "flush now" operation can reuse it directly.
pub async fn deliver_outbox_batch(
    pool: &PgPool,
    publisher: &dyn EventPublisher,
    cfg: &crate::config::EventsConfig,
) -> Result<usize, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(EVENT_OUTBOX_ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    if !acquired {
        // Another instance's poller is already delivering this tick.
        return Ok(0);
    }

    // `outbox_max_attempts` only ever excludes an `unparseable` row: whether
    // a row's payload deserializes into the current `DomainEventPayload` is
    // a fixed, structural fact about that row (the `payload` column is never
    // updated after insert), so if it fails once it will fail identically
    // forever — safe to stop retrying once we've logged it enough times.
    // A publish failure is different: it may be a transient broker outage,
    // and `unparseable` is never set for it, so it keeps passing the `NOT
    // unparseable` half of this filter and stays eligible no matter how long
    // the outage lasts or how high its `attempts` climbs — capping those
    // too would silently and permanently drop otherwise-valid events the
    // moment an outage outlasts `outbox_max_attempts` polls.
    let rows: Vec<OutboxRow> = sqlx::query_as(
        "SELECT id, payload FROM event_outbox
         WHERE delivered_at IS NULL AND (NOT unparseable OR attempts < $2)
         ORDER BY created_at ASC
         LIMIT $1",
    )
    .bind(cfg.outbox_batch_size)
    .bind(cfg.outbox_max_attempts)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;

    if rows.is_empty() {
        return Ok(0);
    }

    // Split the batch: a row whose payload fails to deserialize must never be
    // marked delivered (it was never actually published) or handed to
    // `publisher.publish`, but it also must not silently vanish. It's left
    // undelivered with `attempts`/`last_error` recorded, same as a publish
    // failure, so it stays visible for operator follow-up instead of being
    // dropped.
    let mut ids: Vec<Uuid> = Vec::with_capacity(rows.len());
    let mut events: Vec<DomainEventPayload> = Vec::with_capacity(rows.len());
    let mut unparseable_ids: Vec<Uuid> = Vec::new();

    for row in &rows {
        match serde_json::from_value(row.payload.clone()) {
            Ok(event) => {
                ids.push(row.id);
                events.push(event);
            }
            Err(err) => {
                tracing::error!(
                    "event_outbox row {} has an unparseable payload, will not be published: {err}",
                    row.id
                );
                unparseable_ids.push(row.id);
            }
        }
    }

    if !unparseable_ids.is_empty() {
        crate::metrics::record_outbox_publish_failure(unparseable_ids.len() as u64);
        record_unparseable_failure(
            &mut tx,
            &unparseable_ids,
            "payload does not deserialize into the current DomainEventPayload schema",
            cfg.outbox_max_attempts,
        )
        .await?;
    }

    if ids.is_empty() {
        tx.commit().await.map_err(db_err)?;
        return Ok(0);
    }

    // Bounded rather than a bare `.await`: a broker that accepts the TCP
    // connection but then stalls internally (rather than erroring outright —
    // a disconnect or a Nack both return promptly) would otherwise hang
    // `publisher.publish` indefinitely. Since that call runs inside this
    // function's still-open transaction, an indefinite hang would hold the
    // checked-out pool connection and the transaction-scoped advisory lock
    // for as long as the stall lasts, and the poller's single background
    // task would simply stop ticking with nothing logged — a quieter version
    // of the same "queued events stop moving" failure mode fixed above for
    // explicit broker errors. A timeout turns a stall into an ordinary,
    // visible publish failure instead: the affected rows stay undelivered
    // and retryable (never `unparseable`, so `outbox_max_attempts` never
    // excludes them), and the connection/lock are released for the next
    // tick.
    let publish_timeout = std::time::Duration::from_secs(cfg.publish_timeout_secs);
    let publish_result =
        match tokio::time::timeout(publish_timeout, publisher.publish(&events)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(publisher::PublishError(format!(
                "publish timed out after {publish_timeout:?} waiting on the broker"
            ))),
        };

    match publish_result {
        Ok(per_event_results) => {
            let mut delivered_ids = Vec::new();
            let mut failed_count = 0;

            for (id, res) in ids.iter().zip(per_event_results) {
                match res {
                    Ok(()) => {
                        delivered_ids.push(*id);
                    }
                    Err(err) => {
                        failed_count += 1;
                        sqlx::query(
                            "UPDATE event_outbox
                             SET attempts = attempts + 1,
                                 last_error = $2
                             WHERE id = $1",
                        )
                        .bind(id)
                        .bind(&err.0)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    }
                }
            }

            if !delivered_ids.is_empty() {
                sqlx::query("UPDATE event_outbox SET delivered_at = now() WHERE id = ANY($1)")
                    .bind(&delivered_ids)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }

            if failed_count > 0 {
                crate::metrics::record_outbox_publish_failure(failed_count as u64);
            }

            tx.commit().await.map_err(db_err)?;
            Ok(delivered_ids.len())
        }
        Err(err) => {
            crate::metrics::record_outbox_publish_failure(ids.len() as u64);
            sqlx::query(
                "UPDATE event_outbox
                 SET attempts = attempts + 1,
                     last_error = $2
                 WHERE id = ANY($1)",
            )
            .bind(&ids)
            .bind(&err.0)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
            Ok(0)
        }
    }
}

/// Deletes delivered and exhausted/unparseable outbox rows older than the
/// retention window (`retention_days`).
pub async fn cleanup_expired_outbox(
    pool: &PgPool,
    retention_days: i64,
    max_attempts: i32,
    batch_size: i64,
) -> Result<i64, AppError> {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);
    let mut deleted_rows = 0_i64;

    loop {
        let result = sqlx::query(
            r#"WITH doomed AS (
                   SELECT id
                   FROM event_outbox
                   WHERE (delivered_at IS NOT NULL OR (unparseable = true AND attempts >= $2))
                     AND created_at < $1
                   ORDER BY created_at ASC
                   LIMIT $3
               )
               DELETE FROM event_outbox
               WHERE id IN (SELECT id FROM doomed)"#,
        )
        .bind(cutoff)
        .bind(max_attempts)
        .bind(batch_size)
        .execute(pool)
        .await
        .map_err(db_err)?;

        let batch = i64::try_from(result.rows_affected()).unwrap_or(0);
        deleted_rows += batch;
        if batch < batch_size {
            break;
        }
    }

    Ok(deleted_rows)
}

/// Increments `attempts`, records `last_error`, and marks a set of rows
/// `unparseable` — the only rows `outbox_max_attempts` is ever allowed to
/// exclude (see the SELECT comment in [`deliver_outbox_batch`]). A row that
/// reaches the limit here stops being selected by every future poll, so
/// this is the only point where that transition — a row giving up for good
/// — is observable; it's logged and counted here rather than silently
/// happening.
async fn record_unparseable_failure(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ids: &[Uuid],
    error: &str,
    max_attempts: i32,
) -> Result<(), AppError> {
    let updated: Vec<(Uuid, i32)> = sqlx::query_as(
        "UPDATE event_outbox
         SET attempts = attempts + 1, last_error = $2, unparseable = true
         WHERE id = ANY($1)
         RETURNING id, attempts",
    )
    .bind(ids)
    .bind(error)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)?;

    for (id, attempts) in updated {
        if attempts >= max_attempts {
            tracing::error!(
                "event_outbox row {id} has reached the {max_attempts}-attempt limit and will not be retried again: {error}"
            );
            crate::metrics::record_outbox_exhausted();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract test: the wire payload must carry every documented field
    /// under its documented name, so a consumer-facing schema regression is
    /// caught in CI.
    #[test]
    fn domain_event_payload_serializes_documented_fields() {
        let payload = DomainEventPayload {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::new_v4(),
            event: "resource.create".to_string(),
            occurred_at: chrono::Utc::now(),
            source: EVENT_SOURCE.to_string(),
            actor_entity_id: Some(Uuid::new_v4()),
            tenant_id: Some(Uuid::new_v4()),
            target_kind: Some("resource".to_string()),
            target_id: Some(Uuid::new_v4()),
            outcome: "allow".to_string(),
            details: serde_json::json!({"kind": "channel"}),
            request_id: None,
        };
        let value = serde_json::to_value(&payload).expect("serialize");
        for field in [
            "schema_version",
            "event_id",
            "event",
            "occurred_at",
            "source",
            "actor_entity_id",
            "tenant_id",
            "target_kind",
            "target_id",
            "outcome",
            "details",
            "request_id",
        ] {
            assert!(
                value.get(field).is_some(),
                "payload is missing documented field {field}"
            );
        }
        assert_eq!(value["event"], "resource.create");
        assert_eq!(value["schema_version"], 1);
    }
}
