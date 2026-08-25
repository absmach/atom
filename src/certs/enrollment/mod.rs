//! Subject-driven certificate enrollment (PR-014).
//!
//! [`service`] owns every enrollment decision. [`http`] is the native protocol
//! adapter, [`est`] is the RFC 7030 adapter, and [`tls`] supplies the only
//! trusted peer-certificate assertion.

pub mod est;
pub mod http;
pub mod repo;
pub mod service;
pub mod tls;

fn observe_missing_peer(transport: &'static str, error: &crate::error::AppError) {
    crate::metrics::record_pki_enrollment_peer_rejection(transport);
    tracing::debug!(
        audit.event = "certificate.reenroll",
        audit.outcome = "deny",
        audit.target_kind = "credential",
        enrollment.mode = "reenroll",
        enrollment.transport = transport,
        error = %error,
        "anonymous certificate re-enrollment rejected"
    );
}
