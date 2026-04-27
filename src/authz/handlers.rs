use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthContext, RequireManage},
    error::AppError,
    models::{
        access::{
            AccessQuery, AdminPageQuery, AuditQuery, BulkAuthzRequest, BulkAuthzResponse,
            BulkAuthzResult, EffectiveCapabilitiesQuery, ExpiringCredentialsQuery,
            GroupAccessQuery, ResourceAccessQuery, RoleHoldersQuery, UnprotectedResourcesQuery,
        },
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

pub async fn resource_access(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<ResourceAccessQuery>,
) -> Result<impl IntoResponse, AppError> {
    let access = repo::resource_access(&state.pool, id, params).await?;
    Ok(Json(access))
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

pub async fn role_holders(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<RoleHoldersQuery>,
) -> Result<impl IntoResponse, AppError> {
    let holders = repo::role_holders(&state.pool, id, params).await?;
    Ok(Json(holders))
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
            "object_kind": req.object_kind,
            "object_id": req.object_id,
            "reason": response.reason,
        }),
    )
    .await;

    Ok(Json(response))
}

pub async fn explain(
    State(state): State<AppState>,
    _auth: AuthContext,
    Json(req): Json<AuthzRequest>,
) -> Result<impl IntoResponse, AppError> {
    let response = engine::explain(&state.pool, &req).await?;

    audit::write(
        &state.pool,
        Some(req.subject_id),
        "authz.explain",
        if response.allowed {
            AuditOutcome::Allow
        } else {
            AuditOutcome::Deny
        },
        serde_json::json!({
            "action": req.action,
            "resource_id": req.resource_id,
            "object_kind": req.object_kind,
            "object_id": req.object_id,
            "reason": response.reason,
        }),
    )
    .await;

    Ok(Json(response))
}

pub async fn bulk_check(
    State(state): State<AppState>,
    _auth: AuthContext,
    Json(req): Json<BulkAuthzRequest>,
) -> Result<impl IntoResponse, AppError> {
    if req.actions.is_empty() {
        return Err(AppError::bad_request(
            "actions must contain at least one item",
        ));
    }
    if req.actions.len() > 20 {
        return Err(AppError::bad_request(
            "actions must contain at most 20 items",
        ));
    }

    let mut results = BTreeMap::new();
    for action in req.actions {
        if results.contains_key(&action) {
            continue;
        }
        let check_req = AuthzRequest {
            subject_id: req.subject_id,
            action: action.clone(),
            resource_id: Some(req.resource_id),
            object_kind: None,
            object_id: None,
            context: req.context.clone(),
        };
        let response = engine::evaluate(&state.pool, &check_req).await?;
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
                "action": action,
                "resource_id": req.resource_id,
                "reason": response.reason,
            }),
        )
        .await;
        results.insert(
            check_req.action,
            BulkAuthzResult {
                allowed: response.allowed,
                reason: response.reason,
            },
        );
    }

    Ok(Json(BulkAuthzResponse {
        subject_id: req.subject_id,
        resource_id: req.resource_id,
        results,
    }))
}

pub async fn entity_access(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<AccessQuery>,
) -> Result<impl IntoResponse, AppError> {
    let access = repo::entity_access(&state.pool, id, params).await?;
    Ok(Json(access))
}

pub async fn group_access(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<GroupAccessQuery>,
) -> Result<impl IntoResponse, AppError> {
    let access = repo::group_access(&state.pool, id, params).await?;
    Ok(Json(access))
}

pub async fn effective_capabilities(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<EffectiveCapabilitiesQuery>,
) -> Result<impl IntoResponse, AppError> {
    let caps = repo::effective_capabilities(&state.pool, id, params).await?;
    Ok(Json(caps))
}

pub async fn audit_logs(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<AuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    let logs = repo::audit_logs(&state.pool, params).await?;
    Ok(Json(logs))
}

pub async fn entity_audit_logs(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(entity_id): Path<Uuid>,
    Query(mut params): Query<AuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    params.entity_id = Some(entity_id);
    let logs = repo::audit_logs(&state.pool, params).await?;
    Ok(Json(logs))
}

pub async fn orphan_policies(
    State(state): State<AppState>,
    _auth: RequireManage,
    Query(params): Query<AdminPageQuery>,
) -> Result<impl IntoResponse, AppError> {
    let response = repo::orphan_policies(&state.pool, params).await?;
    Ok(Json(response))
}

pub async fn unprotected_resources(
    State(state): State<AppState>,
    _auth: RequireManage,
    Query(params): Query<UnprotectedResourcesQuery>,
) -> Result<impl IntoResponse, AppError> {
    let response = repo::unprotected_resources(&state.pool, params).await?;
    Ok(Json(response))
}

pub async fn expiring_credentials(
    State(state): State<AppState>,
    _auth: RequireManage,
    Query(params): Query<ExpiringCredentialsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let response = repo::expiring_credentials(&state.pool, params).await?;
    Ok(Json(response))
}
