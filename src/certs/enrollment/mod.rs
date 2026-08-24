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
    crate::audit::observe_error_log_only(
        &crate::audit::AuditMeta {
            actor_entity_id: None,
            tenant_id: None,
            target_kind: "credential",
            target_id: None,
            event: "certificate.reenroll",
        },
        &serde_json::json!({"mode": "reenroll", "transport": transport}),
        error,
    );
}
