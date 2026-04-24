use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthContext, RequireManage},
    error::AppError,
    models::{
        capability::{CreateCapability, ListCapabilities},
        enums::AuditOutcome,
        policy::{AuthzRequest, CreatePolicyBinding, ListPolicies},
        resource::{CreateResource, ListResources, UpdateResource},
        role::{AddRoleCapability, CreateRole, ListRoles},
    },
    state::AppState,
};

use super::{engine, repo};

// ─── Resources ────────────────────────────────────────────────────────────────

pub async fn create_resource(
    State(state): State<AppState>,
    _auth: AuthContext,
    Json(req): Json<CreateResource>,
) -> Result<impl IntoResponse, AppError> {
    let resource = repo::create_resource(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(resource)))
}

pub async fn get_resource(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let resource = repo::get_resource(&state.pool, id).await?;
    Ok(Json(resource))
}

pub async fn list_resources(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<ListResources>,
) -> Result<impl IntoResponse, AppError> {
    let list = repo::list_resources(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn update_resource(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateResource>,
) -> Result<impl IntoResponse, AppError> {
    let resource = repo::update_resource(&state.pool, id, req).await?;
    Ok(Json(resource))
}

pub async fn delete_resource(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::delete_resource(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Roles ────────────────────────────────────────────────────────────────────

pub async fn create_role(
    State(state): State<AppState>,
    _auth: AuthContext,
    Json(req): Json<CreateRole>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::create_role(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(role)))
}

pub async fn get_role(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, id).await?;
    Ok(Json(role))
}

pub async fn list_roles(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<ListRoles>,
) -> Result<impl IntoResponse, AppError> {
    let list = repo::list_roles(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn delete_role(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::delete_role(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_role_capability(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(role_id): Path<Uuid>,
    Json(req): Json<AddRoleCapability>,
) -> Result<impl IntoResponse, AppError> {
    repo::add_role_capability(&state.pool, role_id, req.capability_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_role_capability(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path((role_id, cap_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    repo::remove_role_capability(&state.pool, role_id, cap_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_role_capabilities(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(role_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let caps = repo::get_role_capabilities(&state.pool, role_id).await?;
    Ok(Json(serde_json::json!({"items": caps})))
}

// ─── Capabilities (RequireManage) ─────────────────────────────────────────────

pub async fn create_capability(
    State(state): State<AppState>,
    _auth: RequireManage,
    Json(req): Json<CreateCapability>,
) -> Result<impl IntoResponse, AppError> {
    let cap = repo::create_capability(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(cap)))
}

pub async fn get_capability(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let cap = repo::get_capability(&state.pool, id).await?;
    Ok(Json(cap))
}

pub async fn list_capabilities(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<ListCapabilities>,
) -> Result<impl IntoResponse, AppError> {
    let caps = repo::list_capabilities(&state.pool, params).await?;
    Ok(Json(serde_json::json!({"items": caps})))
}

pub async fn delete_capability(
    State(state): State<AppState>,
    _auth: RequireManage,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::delete_capability(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Policy Bindings (RequireManage) ──────────────────────────────────────────

pub async fn create_policy(
    State(state): State<AppState>,
    _auth: RequireManage,
    Json(req): Json<CreatePolicyBinding>,
) -> Result<impl IntoResponse, AppError> {
    let policy = repo::create_policy(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

pub async fn get_policy(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let policy = repo::get_policy(&state.pool, id).await?;
    Ok(Json(policy))
}

pub async fn list_policies(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<ListPolicies>,
) -> Result<impl IntoResponse, AppError> {
    let list = repo::list_policies(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    _auth: RequireManage,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::delete_policy(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Authorization Check (PDP) ────────────────────────────────────────────────

pub async fn check(
    State(state): State<AppState>,
    _auth: AuthContext,
    Json(req): Json<AuthzRequest>,
) -> Result<impl IntoResponse, AppError> {
    let response = engine::evaluate(&state.pool, &req).await?;

    audit::write(
        &state.pool,
        Some(req.subject_id),
        "authz.check",
        if response.allowed {
            AuditOutcome::Allow
        } else {
            AuditOutcome::Deny
        },
        serde_json::json!({
            "action": req.action,
            "resource_id": req.resource_id,
            "reason": response.reason,
        }),
    )
    .await;

    Ok(Json(response))
}
