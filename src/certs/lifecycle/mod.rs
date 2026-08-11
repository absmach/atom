//! PR-015 certificate expiry visibility and bounded fleet operations.

pub mod repo;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    audit,
    certs::service::{self as certificates, CertificateRevocationSelector, RevokeCertificateV2},
    config::PkiLifecycleConfig,
    error::AppError,
    models::enums::AuditOutcome,
    state::AppState,
};

const LIFECYCLE_SWEEP_ADVISORY_LOCK_ID: i64 = 0x4154_4f4d_504b_493f;
const MAX_BULK_BATCH_SIZE: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkRevocationSelector {
    Tenant(Uuid),
    Issuer(Uuid),
    PrincipalGroup(Uuid),
}

impl BulkRevocationSelector {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Tenant(_) => "tenant",
            Self::Issuer(_) => "issuer",
            Self::PrincipalGroup(_) => "principal_group",
        }
    }

    pub const fn id(self) -> Uuid {
        match self {
            Self::Tenant(id) | Self::Issuer(id) | Self::PrincipalGroup(id) => id,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkRevocationItem {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub outcome: &'static str,
    pub error_code: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkRevocationBatch {
    pub items: Vec<BulkRevocationItem>,
    /// Freeze point for the operation. Pass it unchanged on every resumed
    /// page so certificates issued while a batch is running are handled by a
    /// later operation instead of being silently skipped by UUID pagination.
    pub snapshot_at: DateTime<Utc>,
    /// Pass this value as `after_credential_id` to resume. On a failure it is
    /// the last contiguous success, so the failed item is selected again.
    pub next_cursor: Option<Uuid>,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepSummary {
    pub lock_acquired: bool,
    pub certificate_events: usize,
    pub authority_events: usize,
}

pub fn spawn(state: AppState) {
    let cfg = state.config.pki_lifecycle;
    if !cfg.enabled {
        tracing::info!("PKI lifecycle automation disabled");
        return;
    }
    if !state.config.events.enabled() {
        tracing::warn!(
            "PKI lifecycle automation enabled without event outbox publishing; fleet metrics remain active but expiry events are deferred"
        );
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cfg.interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match sweep_once(&state.pool, cfg, state.config.events.enabled(), Utc::now()).await {
                Ok(summary) if summary.certificate_events + summary.authority_events > 0 => {
                    tracing::info!(
                        certificate_events = summary.certificate_events,
                        authority_events = summary.authority_events,
                        "PKI lifecycle sweep emitted expiry events"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "PKI lifecycle sweep failed"),
            }
        }
    });
}

/// Run one bounded sweep at a caller-supplied time. Public for deterministic
/// restart/replica tests and future operator-triggered maintenance.
pub async fn sweep_once(
    pool: &PgPool,
    cfg: PkiLifecycleConfig,
    events_enabled: bool,
    now: DateTime<Utc>,
) -> Result<SweepSummary, AppError> {
    if !cfg.enabled {
        return Ok(SweepSummary::default());
    }

    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(LIFECYCLE_SWEEP_ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    if !acquired {
        return Ok(SweepSummary::default());
    }

    // Metrics share this bounded periodic pass but never carry identifiers.
    let expiry_metrics = repo::expiry_metrics(&mut tx, now).await?;
    let authority_metrics = repo::authority_metrics(&mut tx, now).await?;
    let mut summary = SweepSummary {
        lock_acquired: true,
        ..SweepSummary::default()
    };

    if events_enabled {
        // Reserve the bounded run for authorities first. A sustained leaf
        // backlog must not hide an approaching CA expiry and turn one tenant's
        // entire fleet into an outage.
        let authority_windows =
            repo::due_authority_windows(&mut tx, now, cfg.authority_warning_secs, cfg.batch_size)
                .await?;
        for window in authority_windows {
            if !repo::claim_notification(
                &mut tx,
                "authority",
                window.issuer_id,
                "authority_expiry",
                window.window_at,
            )
            .await?
            {
                continue;
            }
            // Keep the identifier keys stable across both event types;
            // authority events have no leaf credential or entity.
            let details = serde_json::json!({
                "issuer_id": window.issuer_id,
                "credential_id": null,
                "entity_id": null,
                "tenant_id": window.tenant_id,
                "authority_kind": window.kind,
                "window": "authority_expiry",
                "window_at": window.window_at,
                "expires_at": window.expires_at,
                "rotation_procedure": "PR-003",
            });
            crate::events::enqueue(
                &mut *tx,
                true,
                None,
                window.tenant_id,
                Some("pki_authority"),
                Some(window.issuer_id),
                "certificate.authority_expiring",
                "allow",
                &details,
            )
            .await?;
            summary.authority_events += 1;
        }

        let remaining = cfg
            .batch_size
            .saturating_sub(i64::try_from(summary.authority_events).unwrap_or(i64::MAX));
        if remaining > 0 {
            let certificate_windows =
                repo::due_certificate_windows(&mut tx, now, cfg.expiry_warning_secs, remaining)
                    .await?;
            for window in certificate_windows {
                if !repo::claim_notification(
                    &mut tx,
                    "credential",
                    window.credential_id,
                    &window.window_kind,
                    window.window_at,
                )
                .await?
                {
                    continue;
                }
                let details = serde_json::json!({
                    "issuer_id": window.issuer_id,
                    "credential_id": window.credential_id,
                    "entity_id": window.entity_id,
                    "tenant_id": window.tenant_id,
                    "window": window.window_kind,
                    "window_at": window.window_at,
                    "expires_at": window.expires_at,
                });
                crate::events::enqueue(
                    &mut *tx,
                    true,
                    None,
                    window.tenant_id,
                    Some("credential"),
                    Some(window.credential_id),
                    "certificate.expiring",
                    "allow",
                    &details,
                )
                .await?;
                summary.certificate_events += 1;
            }
        }
    }

    tx.commit().await.map_err(AppError::Database)?;
    crate::metrics::record_pki_fleet_snapshot(&expiry_metrics, &authority_metrics);
    Ok(summary)
}

pub async fn selector_tenant_id(
    pool: &PgPool,
    selector: BulkRevocationSelector,
) -> Result<Option<Uuid>, AppError> {
    repo::selector_tenant_id(pool, selector).await
}

/// Revoke one stable UUID-ordered batch. Each item owns its transaction, audit,
/// and outbox event. A crash or retry can safely repeat the prior cursor:
/// already-committed rows no longer match the active-candidate query.
pub async fn bulk_revoke(
    state: &AppState,
    selector: BulkRevocationSelector,
    actor_entity_id: Uuid,
    reason: Option<String>,
    after_credential_id: Option<Uuid>,
    snapshot_at: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<BulkRevocationBatch, AppError> {
    if !(1..=MAX_BULK_BATCH_SIZE).contains(&limit) {
        return Err(AppError::bad_request(format!(
            "bulk revocation limit must be between 1 and {MAX_BULK_BATCH_SIZE}"
        )));
    }
    if after_credential_id.is_some() && snapshot_at.is_none() {
        return Err(AppError::bad_request(
            "snapshotAt is required when afterCredentialId is provided",
        ));
    }
    let database_now = repo::bulk_snapshot_at(&state.pool).await?;
    if snapshot_at
        .as_ref()
        .is_some_and(|snapshot| snapshot > &database_now)
    {
        return Err(AppError::bad_request(
            "snapshotAt cannot be later than the database clock",
        ));
    }
    let snapshot_at = snapshot_at.unwrap_or(database_now);

    // One look-ahead row determines whether a successful page has more work.
    // The creation-time cutoff freezes membership across all UUID pages.
    let candidates = repo::bulk_candidates(
        &state.pool,
        selector,
        after_credential_id,
        &snapshot_at,
        limit.saturating_add(1),
    )
    .await?;
    let has_more = candidates.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    let mut items = Vec::with_capacity(candidates.len().min(limit as usize));
    let mut last_success = after_credential_id;

    for candidate in candidates.into_iter().take(limit as usize) {
        match revoke_candidate(state, selector, actor_entity_id, reason.clone(), &candidate).await {
            Ok(item) => {
                last_success = Some(candidate.credential_id);
                items.push(item);
            }
            Err(error) => {
                let error_code = public_error_code(&error);
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &audit::AuditMeta {
                        actor_entity_id: Some(actor_entity_id),
                        tenant_id: candidate.tenant_id,
                        target_kind: "credential",
                        target_id: Some(candidate.credential_id),
                        event: "certificate.bulk_revoke",
                    },
                    &serde_json::json!({
                        "selector_kind": selector.kind(),
                        "selector_id": selector.id(),
                        "issuer_id": candidate.issuer_id,
                        "credential_id": candidate.credential_id,
                        "entity_id": candidate.entity_id,
                        "tenant_id": candidate.tenant_id,
                        "error_code": error_code,
                    }),
                    &error,
                )
                .await;
                items.push(BulkRevocationItem {
                    credential_id: candidate.credential_id,
                    issuer_id: candidate.issuer_id,
                    entity_id: candidate.entity_id,
                    tenant_id: candidate.tenant_id,
                    outcome: "failed",
                    error_code: Some(error_code),
                });
                return Ok(BulkRevocationBatch {
                    items,
                    snapshot_at,
                    next_cursor: last_success,
                    complete: false,
                });
            }
        }
    }

    Ok(BulkRevocationBatch {
        items,
        snapshot_at,
        next_cursor: if has_more { last_success } else { None },
        complete: !has_more,
    })
}

async fn revoke_candidate(
    state: &AppState,
    selector: BulkRevocationSelector,
    actor_entity_id: Uuid,
    reason: Option<String>,
    candidate: &repo::BulkCandidate,
) -> Result<BulkRevocationItem, AppError> {
    // Parse the current record before opening the transaction. This avoids a
    // second pool acquisition while a transaction is held and makes malformed
    // legacy data a reportable per-item failure rather than a batch abort.
    let current = certificates::certificate_by_id(&state.pool, candidate.credential_id).await?;
    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;
    let revoked = certificates::revoke_certificate_v2_in_tx(
        &mut tx,
        RevokeCertificateV2 {
            selector: CertificateRevocationSelector::CredentialId(candidate.credential_id),
            reason,
            actor_entity_id: Some(actor_entity_id),
            expected_entity_id: current.entity_id,
            expected_tenant_id: current.tenant_id,
        },
    )
    .await?;
    let details = serde_json::json!({
        "selector_kind": selector.kind(),
        "selector_id": selector.id(),
        "issuer_id": revoked.certificate.issuer_id,
        "credential_id": revoked.certificate.credential_id,
        "entity_id": revoked.certificate.entity_id,
        "tenant_id": revoked.certificate.tenant_id,
        "reason": revoked.reason,
        "revoked_at": revoked.revoked_at,
        "idempotent_replay": revoked.idempotent_replay,
    });
    if revoked.idempotent_replay {
        let commit = tx.commit().await.map_err(AppError::Database);
        certificates::record_lifecycle_commit("revocation", &commit);
        commit?;
        audit::write(
            &state.pool,
            false,
            audit::AuditEvent {
                actor_entity_id: Some(actor_entity_id),
                tenant_id: revoked.certificate.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(revoked.certificate.credential_id),
                event: "certificate.bulk_revoke_replayed",
                outcome: AuditOutcome::Allow,
                details,
            },
        )
        .await;
    } else {
        let commit = audit::commit_with_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(actor_entity_id),
                tenant_id: revoked.certificate.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(revoked.certificate.credential_id),
                event: "certificate.bulk_revoke",
                outcome: AuditOutcome::Allow,
                details,
            },
        )
        .await;
        certificates::record_lifecycle_commit("revocation", &commit);
        commit?;
    }

    Ok(BulkRevocationItem {
        credential_id: revoked.certificate.credential_id,
        issuer_id: revoked.certificate.issuer_id,
        entity_id: revoked.certificate.entity_id,
        tenant_id: revoked.certificate.tenant_id,
        outcome: if revoked.idempotent_replay {
            "already_revoked"
        } else {
            "revoked"
        },
        error_code: None,
    })
}

fn public_error_code(error: &AppError) -> &'static str {
    match error {
        AppError::NotFound(_) => "not_found",
        AppError::BadRequest(_) | AppError::PayloadTooLarge(_) => "invalid_certificate",
        AppError::Unauthorized(_) | AppError::Forbidden => "forbidden",
        AppError::Conflict(_) => "conflict",
        AppError::RateLimited { .. } => "rate_limited",
        AppError::Database(_) | AppError::Internal(_) => "internal",
    }
}
