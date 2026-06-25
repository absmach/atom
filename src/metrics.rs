//! Metrics façade.
//!
//! The rest of the codebase only ever calls the semantic functions here
//! (`record_decision`, `record_audit_failure`, `record_rate_limit_rejection`)
//! and never imports the `metrics` crate directly. The backend (the `metrics`
//! facade + Prometheus exporter) is confined to this file and gated behind the
//! `metrics` cargo feature, so:
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
/// Counter of rate-limiter rejections, labelled by `category`.
pub const RATE_LIMIT_REJECTIONS: &str = "atom_rate_limit_rejections_total";
/// Gauge of DB pool connections, labelled by `state` (total|idle).
pub const DB_POOL_CONNECTIONS: &str = "atom_db_pool_connections";

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

    pub fn record_rate_limit_rejection(category: &'static str) {
        metrics::counter!(RATE_LIMIT_REJECTIONS, "category" => category).increment(1);
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
    pub fn record_rate_limit_rejection(_category: &'static str) {}
}

pub use backend::{
    enabled, init, record_audit_failure, record_decision, record_rate_limit_rejection, render,
};
