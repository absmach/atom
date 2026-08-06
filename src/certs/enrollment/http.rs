//! Thin Atom-native enrollment adapter.

use axum::{
    extract::{DefaultBodyLimit, State},
    routing::post,
    Extension, Json, Router,
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;

use crate::{auth::AuthContext, error::AppError, state::AppState};

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
    let est_body_limit = state
        .config
        .enrollment
        .max_csr_bytes
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(16 * 1024);
    Router::new()
        .route("/pki/enroll", post(first_enrollment))
        .route("/pki/reenroll", post(re_enrollment))
        .merge(est::routes())
        .layer(DefaultBodyLimit::max(native_body_limit.max(est_body_limit)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn first_enrollment(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(request): Json<NativeEnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, AppError> {
    service::enroll(&state, auth, request.into())
        .await
        .map(Json)
}

async fn re_enrollment(
    State(state): State<AppState>,
    peer: Option<Extension<VerifiedPeerCertificate>>,
    Json(request): Json<NativeEnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, AppError> {
    let peer = peer
        .map(|Extension(peer)| peer)
        .ok_or_else(|| AppError::unauthorized("a verified client certificate is required"))?;
    service::re_enroll(&state, peer, request.into())
        .await
        .map(Json)
}
