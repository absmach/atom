//! Thin Atom-native enrollment adapter.

use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, FromRequestParts, State},
    http::request::Parts,
    middleware,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

use crate::{audit, auth::AuthContext, error::AppError, state::AppState};

use super::{
    est,
    service::{self, EnrollmentInput, EnrollmentResponse},
    tls::VerifiedPeerCertificate,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEnrollmentRequest {
    csr_pem: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
    idempotency_key: String,
}

/// A native re-enrollment request must prove possession of an existing
/// certificate before Axum reads or parses its body.
struct ReenrollmentPeer(VerifiedPeerCertificate);

#[axum::async_trait]
impl<S> FromRequestParts<S> for ReenrollmentPeer
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<VerifiedPeerCertificate>()
            .cloned()
            .map(Self)
            .ok_or_else(|| AppError::unauthorized("a verified client certificate is required"))
    }
}

impl From<NativeEnrollmentRequest> for EnrollmentInput {
    fn from(value: NativeEnrollmentRequest) -> Self {
        Self {
            csr_pem: value.csr_pem,
            ttl_secs: value.ttl_secs,
            idempotency_key: value.idempotency_key,
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    // The JSON envelope needs a small fixed allowance around the independently
    // checked CSR. Axum rejects larger bodies before allocating the full input.
    let native_body_limit = state
        .config
        .enrollment
        .max_csr_bytes
        .saturating_add(16 * 1024);
    let est_body_limit = est::maximum_der_csr_bytes(state.config.enrollment.max_csr_bytes)
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4)
        .saturating_add(16 * 1024);
    // This is a total request deadline, not an inactivity timeout. It wraps
    // handler body extraction, so a client cannot retain a connection permit
    // indefinitely by sending a body one byte at a time.
    let request_body_timeout =
        Duration::from_secs(state.config.enrollment.request_body_timeout_secs);
    Router::new()
        .route("/pki/enroll", post(first_enrollment))
        .route("/pki/reenroll", post(re_enrollment))
        .merge(est::routes())
        .layer(DefaultBodyLimit::max(native_body_limit.max(est_body_limit)))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::rate_limit::middleware,
        ))
        // Keep the trace outermost relative to the limiter so 429 responses
        // are recorded with the same request span as successful enrollment.
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(request_body_timeout))
        .with_state(state)
}

async fn first_enrollment(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(request): Json<NativeEnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, AppError> {
    let result = service::enroll(&state, auth.clone(), request.into()).await;
    if let Err(ref error) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: auth.tenant_id,
                target_kind: "credential",
                target_id: None,
                event: "certificate.enroll",
            },
            &serde_json::json!({"mode": "first", "transport": "native"}),
            error,
        )
        .await;
    }
    result.map(Json)
}

async fn re_enrollment(
    State(state): State<AppState>,
    ReenrollmentPeer(peer): ReenrollmentPeer,
    Json(request): Json<NativeEnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, AppError> {
    let result = service::re_enroll(&state, peer, request.into()).await;
    if let Err(ref error) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &audit::AuditMeta {
                actor_entity_id: None,
                tenant_id: None,
                target_kind: "credential",
                target_id: None,
                event: "certificate.reenroll",
            },
            &serde_json::json!({"mode": "reenroll", "transport": "native"}),
            error,
        )
        .await;
    }
    result.map(Json)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use tokio::time::sleep;
    use tower::ServiceExt;

    use super::{create_router, TimeoutLayer};

    #[tokio::test]
    async fn request_timeout_is_a_total_deadline() {
        let app = axum::Router::new()
            .route(
                "/",
                post(|| async {
                    sleep(Duration::from_millis(20)).await;
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(1)));

        let response = app
            .oneshot(Request::post("/").body(Body::empty()).expect("request"))
            .await
            .expect("infallible router");

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn native_reenrollment_rejects_missing_peer_before_json_extraction() {
        let app = create_router(crate::certs::test_state_without_database());
        let response = app
            .oneshot(
                Request::post("/pki/reenroll")
                    .header("content-type", "application/json")
                    .body(Body::from("not json"))
                    .expect("request"),
            )
            .await
            .expect("infallible router");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
