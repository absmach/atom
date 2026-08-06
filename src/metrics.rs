//! Metrics façade.
//!
//! The rest of the codebase only ever calls the semantic functions here
//! (`record_decision`, `record_audit_failure`, `record_audit_db_suppressed`,
//! `record_rate_limit_rejection`) and never imports the `metrics` crate
//! directly. The backend (the `metrics` facade + Prometheus exporter) is
//! confined to this file and gated behind the `metrics` cargo feature, so:
//!
//! - `--no-default-features` → every function below compiles to an inlined
//!   no-op and the metrics crates are not linked (true zero cost).
//! - feature on but `ATOM_METRICS_ENABLED=false` → the recorder is never
//!   installed and `/metrics` is not mounted; the facade macros fall through to
//!   the global no-op recorder.
//!
//! Swapping Prometheus pull for OTLP push later is an exporter change in
//! `init`/`render` only — call sites do not move.

use sqlx::PgPool;
use std::time::Duration;

/// Histogram (seconds) of PDP decision latency, labelled by `result`.
pub const DECISION_DURATION: &str = "atom_authz_decision_duration_seconds";
/// Counter of audit-log writes that failed and were dropped.
pub const AUDIT_WRITE_FAILURES: &str = "atom_audit_write_failures_total";
/// Counter of hot-path audit events intentionally kept out of `audit_logs`.
pub const AUDIT_DB_SUPPRESSED: &str = "atom_audit_db_suppressed_total";
/// Counter of rate-limiter rejections, labelled by `category`.
pub const RATE_LIMIT_REJECTIONS: &str = "atom_rate_limit_rejections_total";
/// Counter of event-outbox rows whose delivery attempt failed (incremented
/// once per affected row, not once per batch).
pub const EVENT_OUTBOX_PUBLISH_FAILURES: &str = "atom_event_outbox_publish_failures_total";
/// Counter of event-outbox rows with a structurally-unparseable payload that
/// hit `outbox_max_attempts` and stopped being retried. Never incremented
/// for a publish failure (broker outage, etc.) — those stay retryable
/// forever regardless of `outbox_max_attempts`.
pub const EVENT_OUTBOX_EXHAUSTED: &str = "atom_event_outbox_exhausted_total";
/// Gauge of DB pool connections, labelled by `state` (total|idle).
pub const DB_POOL_CONNECTIONS: &str = "atom_db_pool_connections";
/// Counter of callout attempts, labelled by `operation`, `endpoint`,
/// `transport`, and `result` (allow|deny|transport_error|timeout).
pub const CALLOUT_CALLS: &str = "atom_callout_calls_total";
/// Histogram (seconds) of end-to-end callout latency per endpoint.
pub const CALLOUT_DURATION: &str = "atom_callout_call_duration_seconds";
/// Counter of CA key-provider operations. Labels are bounded to provider,
/// operation, and outcome; authority and tenant identifiers are never labels.
pub const PKI_KEY_PROVIDER_OPERATIONS: &str = "atom_pki_key_provider_operations_total";
/// Counter of subject enrollment operations. Labels are the bounded native
/// modes (`first`/`reenroll`) and outcomes; identities are never labels.
pub const PKI_ENROLLMENT_OPERATIONS: &str = "atom_pki_enrollment_operations_total";

#[cfg(feature = "metrics")]
mod backend {
    use super::*;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use std::sync::OnceLock;

    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

    /// Install the Prometheus recorder when enabled. Idempotent; safe to call
    /// once at startup. A failed install is logged and leaves metrics disabled
    /// rather than aborting boot.
    pub fn init(enabled: bool) {
        if !enabled {
            tracing::info!("metrics disabled (ATOM_METRICS_ENABLED=false)");
            return;
        }
        match PrometheusBuilder::new().install_recorder() {
            Ok(handle) => {
                let _ = HANDLE.set(handle);
                tracing::info!("metrics enabled; Prometheus recorder installed");
            }
            Err(e) => tracing::error!("failed to install metrics recorder: {e}"),
        }
    }

    /// True when the recorder is installed (drives the `/metrics` route mount).
    pub fn enabled() -> bool {
        HANDLE.get().is_some()
    }

    /// Render the Prometheus exposition text. Samples DB-pool gauges first so a
    /// scrape always reflects the current pool, without a background sampler.
    pub fn render(pool: &PgPool) -> String {
        let Some(handle) = HANDLE.get() else {
            return String::new();
        };
        metrics::gauge!(DB_POOL_CONNECTIONS, "state" => "total").set(pool.size() as f64);
        metrics::gauge!(DB_POOL_CONNECTIONS, "state" => "idle").set(pool.num_idle() as f64);
        handle.render()
    }

    pub fn record_decision(elapsed: Duration, allowed: bool) {
        let result = if allowed { "allow" } else { "deny" };
        metrics::histogram!(DECISION_DURATION, "result" => result).record(elapsed.as_secs_f64());
    }

    pub fn record_audit_failure() {
        metrics::counter!(AUDIT_WRITE_FAILURES).increment(1);
    }

    pub fn record_audit_db_suppressed(category: &'static str) {
        metrics::counter!(AUDIT_DB_SUPPRESSED, "category" => category).increment(1);
    }

    pub fn record_rate_limit_rejection(category: &'static str) {
        metrics::counter!(RATE_LIMIT_REJECTIONS, "category" => category).increment(1);
    }

    pub fn record_outbox_publish_failure(rows: u64) {
        metrics::counter!(EVENT_OUTBOX_PUBLISH_FAILURES).increment(rows);
    }

    pub fn record_outbox_exhausted() {
        metrics::counter!(EVENT_OUTBOX_EXHAUSTED).increment(1);
    }

    pub fn record_callout(
        operation: &str,
        endpoint: &str,
        transport: &'static str,
        result: &'static str,
        elapsed: Duration,
    ) {
        // Operation and endpoint labels are bounded by the callout config
        // (finite, operator-controlled) — safe as high-cardinality labels.
        metrics::counter!(
            CALLOUT_CALLS,
            "operation" => operation.to_string(),
            "endpoint" => endpoint.to_string(),
            "transport" => transport,
            "result" => result,
        )
        .increment(1);
        metrics::histogram!(
            CALLOUT_DURATION,
            "operation" => operation.to_string(),
            "endpoint" => endpoint.to_string(),
            "transport" => transport,
        )
        .record(elapsed.as_secs_f64());
    }

    pub fn record_pki_key_provider_operation(
        provider: &'static str,
        operation: &'static str,
        outcome: &'static str,
    ) {
        metrics::counter!(
            PKI_KEY_PROVIDER_OPERATIONS,
            "provider" => provider,
            "operation" => operation,
            "outcome" => outcome
        )
        .increment(1);
    }

    pub fn record_pki_enrollment(mode: &'static str, outcome: &'static str) {
        metrics::counter!(
            PKI_ENROLLMENT_OPERATIONS,
            "mode" => mode,
            "outcome" => outcome
        )
        .increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
mod backend {
    use super::*;

    #[inline]
    pub fn init(_enabled: bool) {}
    #[inline]
    pub fn enabled() -> bool {
        false
    }
    #[inline]
    pub fn render(_pool: &PgPool) -> String {
        String::new()
    }
    #[inline]
    pub fn record_decision(_elapsed: Duration, _allowed: bool) {}
    #[inline]
    pub fn record_audit_failure() {}
    #[inline]
    pub fn record_audit_db_suppressed(_category: &'static str) {}
    #[inline]
    pub fn record_rate_limit_rejection(_category: &'static str) {}
    #[inline]
    pub fn record_outbox_publish_failure(_rows: u64) {}
    #[inline]
    pub fn record_outbox_exhausted() {}
    #[inline]
    pub fn record_callout(
        _operation: &str,
        _endpoint: &str,
        _transport: &'static str,
        _result: &'static str,
        _elapsed: Duration,
    ) {
    }
    #[inline]
    pub fn record_pki_key_provider_operation(
        _provider: &'static str,
        _operation: &'static str,
        _outcome: &'static str,
    ) {
    }
    #[inline]
    pub fn record_pki_enrollment(_mode: &'static str, _outcome: &'static str) {}
}

pub use backend::{
    enabled, init, record_audit_db_suppressed, record_audit_failure, record_callout,
    record_decision, record_outbox_exhausted, record_outbox_publish_failure, record_pki_enrollment,
    record_pki_key_provider_operation, record_rate_limit_rejection, render,
};
