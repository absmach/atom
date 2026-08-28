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
impl FromRequestParts<AppState> for ReenrollmentPeer {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<VerifiedPeerCertificate>()
            .cloned()
            .map(Self);
        let Some(peer) = peer else {
            let error = AppError::unauthorized("a verified client certificate is required");
            super::observe_missing_peer("native", &error);
            return Err(error);
        };
        Ok(peer)
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
    let request_timeout = Duration::from_secs(state.config.enrollment.request_timeout_secs);
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
        .layer(TimeoutLayer::new(request_timeout))
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
    use std::{collections::BTreeSet, time::Duration};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use tokio::time::sleep;
    use tower::ServiceExt;

    use super::{create_router, NativeEnrollmentRequest, TimeoutLayer};

    #[tokio::test]
    async fn contract_request_timeout_is_a_total_deadline() {
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
    async fn contract_native_enrollment_requires_auth_before_json_extraction() {
        let app = create_router(crate::certs::test_state_without_database());
        let response = app
            .oneshot(
                Request::post("/pki/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from("not json"))
                    .expect("request"),
            )
            .await
            .expect("infallible router");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn contract_native_reenrollment_requires_peer_before_json_extraction() {
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

    #[test]
    fn contract_native_enrollment_request_serde_matches_openapi_schema() {
        let document: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../../../apidocs/openapi.yaml"))
                .expect("valid OpenAPI YAML");
        let schema = &document["components"]["schemas"]["NativeEnrollmentRequest"];
        let required = schema["required"]
            .as_sequence()
            .expect("required fields")
            .iter()
            .map(|field| field.as_str().expect("string field"))
            .collect::<BTreeSet<_>>();
        assert_eq!(required, BTreeSet::from(["csr_pem", "idempotency_key"]));
        assert_eq!(schema["additionalProperties"].as_bool(), Some(false));

        let complete = serde_json::json!({
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n",
            "ttl_secs": 3600,
            "idempotency_key": "enrollment-1",
        });
        assert!(serde_json::from_value::<NativeEnrollmentRequest>(complete.clone()).is_ok());

        let mut without_optional = complete.clone();
        without_optional
            .as_object_mut()
            .expect("request object")
            .remove("ttl_secs");
        assert!(serde_json::from_value::<NativeEnrollmentRequest>(without_optional).is_ok());

        for field in required {
            let mut missing = complete.clone();
            missing
                .as_object_mut()
                .expect("request object")
                .remove(field);
            assert!(
                serde_json::from_value::<NativeEnrollmentRequest>(missing).is_err(),
                "serde must reject the OpenAPI-required field {field} when absent"
            );
        }

        let mut unknown = complete;
        unknown.as_object_mut().expect("request object").insert(
            "redirect_url".into(),
            serde_json::json!("https://attacker.test"),
        );
        assert!(
            serde_json::from_value::<NativeEnrollmentRequest>(unknown).is_err(),
            "serde(deny_unknown_fields) must match additionalProperties: false"
        );
    }
}
