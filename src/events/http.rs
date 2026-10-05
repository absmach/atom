use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{authenticate_token, require_any_capability, scope_for_tenant},
    error::AppError,
    events,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct SynthUsageEvent {
    pub tenant_id: Uuid,
    pub resource: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_quantity")]
    pub quantity: i64,
}

fn default_action() -> String {
    "create".to_string()
}

fn default_quantity() -> i64 {
    1
}

/// Enqueues a Synth usage event into Atom's existing durable event outbox.
/// This endpoint is internal: it requires a bearer token with tenant manage
/// capability and accepts only the fixed Synth usage event shape.
pub async fn publish_synth_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SynthUsageEvent>,
) -> Result<(), AppError> {
    if req.resource.trim().is_empty() || req.quantity == 0 {
        return Err(AppError::bad_request(
            "resource and non-zero quantity are required",
        ));
    }

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::unauthorized("bearer token required"))?;
    let auth = authenticate_token(&state, token).await?;
    require_any_capability(
        &state.pool(),
        &auth,
        &[("manage", scope_for_tenant(Some(req.tenant_id)))],
    )
    .await?;

    let details: Value = json!({
        "resource": req.resource,
        "action": req.action,
        "quantity": req.quantity,
    });

    events::enqueue(
        &state.pool(),
        state.config.events.amqp_url.is_some(),
        Some(auth.entity_id),
        Some(req.tenant_id),
        Some("synth_usage"),
        None,
        "synth.usage",
        "allow",
        &details,
    )
    .await
}
