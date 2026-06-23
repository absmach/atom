use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::{
    audit,
    auth::{
        has_capability_in_scope, require_capability, require_explain_access, require_list_access,
        require_policy_read, require_read_access, require_role_read, AuthContext, Scope,
    },
    error::AppError,
    models::{
        access::{
            AccessQuery, AdminPageQuery, AuditQuery, BulkAuthzRequest, BulkAuthzResponse,
            BulkAuthzResult, ExpiringCredentialsQuery, GroupAccessQuery, ResourceAccessQuery,
            RoleHoldersQuery, UnprotectedResourcesQuery,
        },
        capability::{CreateCapability, ListCapabilities},
        enums::{AuditOutcome, ScopeKind},
        policy::{AuthzRequest, CreatePolicyBinding, ListPolicies},
        resource::{CreateResource, ListResources, UpdateResource},
        role::{AddRoleCapability, CreateRole, ListRoles, UpdateRole},
    },
    state::AppState,
};

use super::{engine, repo};

fn scope_for_tenant(tenant_id: Option<Uuid>) -> Scope {
    match tenant_id {
        Some(tenant_id) => Scope::Tenant(tenant_id),
        None => Scope::Platform,
    }
}

async fn require_management(
    pool: &PgPool,
    entity_id: Uuid,
    capability_name: &str,
    scope: Scope,
) -> Result<(), AppError> {
    require_capability(pool, entity_id, capability_name, scope).await
}

async fn validate_tenant_owned_policy(
    pool: &PgPool,
    req: &CreatePolicyBinding,
) -> Result<(), AppError> {
    let Some(policy_tenant_id) = req.tenant_id else {
        return Ok(());
    };

    match req.scope_kind {
        ScopeKind::Platform => Err(AppError::bad_request(
            "tenant-owned policy cannot use platform scope",
        )),
        ScopeKind::Tenant => {
            let Some(scope_ref) = req.scope_ref.as_deref() else {
                return Err(AppError::bad_request(
                    "tenant policy scope_ref must match tenant_id",
                ));
            };
            let scope_tenant_id = scope_ref
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("tenant scope_ref must be a UUID"))?;
            if scope_tenant_id == policy_tenant_id {
                Ok(())
            } else {
                Err(AppError::bad_request(
                    "tenant-owned policy cannot reference another tenant",
                ))
            }
        }
        ScopeKind::ObjectKind
        | ScopeKind::ObjectType
        | ScopeKind::GroupObjectType
        | ScopeKind::GroupTreeObjectType
        | ScopeKind::GroupChildKind
        | ScopeKind::GroupDescendantKind => Ok(()),
        ScopeKind::Object => {
            let scope_ref = req
                .scope_ref
                .as_deref()
                .ok_or_else(|| AppError::bad_request("object scope requires scope_ref"))?;
            let object_id = scope_ref
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("object scope_ref must be a UUID"))?;
            match repo::object_tenant_id_by_id(pool, object_id).await? {
                Some(Some(object_tenant_id)) if object_tenant_id == policy_tenant_id => Ok(()),
                Some(Some(_)) => Err(AppError::bad_request(
                    "tenant-owned policy cannot reference an object in another tenant",
                )),
                Some(None) => Err(AppError::bad_request(
                    "tenant-owned policy cannot reference a platform object",
                )),
                None => Err(AppError::bad_request(
                    "tenant-owned policy cannot reference an unknown object",
                )),
            }
        }
    }
}

async fn audit_tenant_filter(
    pool: &PgPool,
    auth: &AuthContext,
    requested_tenant_id: Option<Uuid>,
) -> Result<Option<Vec<Uuid>>, AppError> {
    if has_capability_in_scope(pool, auth.entity_id, "read", Scope::Platform).await?
        || has_capability_in_scope(pool, auth.entity_id, "manage", Scope::Platform).await?
    {
        return Ok(None);
    }

    let mut tenant_ids =
        repo::tenant_ids_for_action_on_object_kind(pool, auth.entity_id, "read", "audit_log")
            .await?;
    tenant_ids.sort_unstable();
    tenant_ids.dedup();

    if let Some(requested_tenant_id) = requested_tenant_id {
        if tenant_ids.contains(&requested_tenant_id) {
            return Ok(Some(vec![requested_tenant_id]));
        }
        return Err(AppError::Forbidden);
    }

    if tenant_ids.is_empty() {
        Err(AppError::Forbidden)
    } else {
        Ok(Some(tenant_ids))
    }
}

// ─── Resources ────────────────────────────────────────────────────────────────

pub async fn create_resource(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateResource>,
) -> Result<impl IntoResponse, AppError> {
    require_management(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(req.tenant_id),
    )
    .await?;
    let resource = repo::create_resource(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(resource)))
}

pub async fn get_resource(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let resource = repo::get_resource(&state.pool, id).await?;
    require_read_access(&state.pool, auth.entity_id, resource.tenant_id, id).await?;
    Ok(Json(resource))
}

pub async fn resource_access(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<ResourceAccessQuery>,
) -> Result<impl IntoResponse, AppError> {
    let resource = repo::get_resource(&state.pool, id).await?;
    require_read_access(&state.pool, auth.entity_id, resource.tenant_id, id).await?;
    let access = repo::resource_access(&state.pool, id, params).await?;
    Ok(Json(access))
}

pub async fn list_resources(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListResources>,
) -> Result<impl IntoResponse, AppError> {
    require_list_access(&state.pool, auth.entity_id, params.tenant_id).await?;
    let list = repo::list_resources(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn update_resource(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateResource>,
) -> Result<impl IntoResponse, AppError> {
    let existing = repo::get_resource(&state.pool, id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(existing.tenant_id),
    )
    .await?;
    let resource = repo::update_resource(&state.pool, id, req).await?;
    Ok(Json(resource))
}

pub async fn delete_resource(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let existing = repo::get_resource(&state.pool, id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(existing.tenant_id),
    )
    .await?;
    repo::delete_resource(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Roles ────────────────────────────────────────────────────────────────────

pub async fn create_role(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateRole>,
) -> Result<impl IntoResponse, AppError> {
    require_management(
        &state.pool,
        auth.entity_id,
        "role.manage",
        scope_for_tenant(req.tenant_id),
    )
    .await?;
    let role = repo::create_role(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(role)))
}

pub async fn get_role(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, id).await?;
    require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
    Ok(Json(role))
}

pub async fn list_roles(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListRoles>,
) -> Result<impl IntoResponse, AppError> {
    require_role_read(&state.pool, auth.entity_id, params.tenant_id).await?;
    let list = repo::list_roles(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn delete_role(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "role.manage",
        scope_for_tenant(role.tenant_id),
    )
    .await?;
    repo::delete_role(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_role(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRole>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "role.manage",
        scope_for_tenant(role.tenant_id),
    )
    .await?;
    let role = repo::update_role(&state.pool, id, req).await?;
    Ok(Json(role))
}

pub async fn add_role_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(role_id): Path<Uuid>,
    Json(req): Json<AddRoleCapability>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, role_id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "role.manage",
        scope_for_tenant(role.tenant_id),
    )
    .await?;
    repo::add_role_capability(&state.pool, role_id, req.capability_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_role_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((role_id, cap_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, role_id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "role.manage",
        scope_for_tenant(role.tenant_id),
    )
    .await?;
    repo::remove_role_capability(&state.pool, role_id, cap_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_role_capabilities(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(role_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, role_id).await?;
    require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
    let caps = repo::get_role_capabilities(&state.pool, role_id).await?;
    Ok(Json(serde_json::json!({"items": caps})))
}

pub async fn role_holders(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<RoleHoldersQuery>,
) -> Result<impl IntoResponse, AppError> {
    let role = repo::get_role(&state.pool, id).await?;
    require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
    let holders = repo::role_holders(&state.pool, id, params).await?;
    Ok(Json(holders))
}

// ─── Capabilities (RequireManage) ─────────────────────────────────────────────

pub async fn create_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateCapability>,
) -> Result<impl IntoResponse, AppError> {
    require_management(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        Scope::Platform,
    )
    .await?;
    let cap = repo::create_capability(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(cap)))
}

pub async fn get_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_policy_read(&state.pool, auth.entity_id, None).await?;
    let cap = repo::get_capability(&state.pool, id).await?;
    Ok(Json(cap))
}

pub async fn list_capabilities(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListCapabilities>,
) -> Result<impl IntoResponse, AppError> {
    require_policy_read(&state.pool, auth.entity_id, None).await?;
    let caps = repo::list_capabilities(&state.pool, params).await?;
    Ok(Json(serde_json::json!({"items": caps})))
}

pub async fn delete_capability(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_management(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        Scope::Platform,
    )
    .await?;
    repo::delete_capability(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Policy Bindings (RequireManage) ──────────────────────────────────────────

pub async fn create_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreatePolicyBinding>,
) -> Result<impl IntoResponse, AppError> {
    req.validate().map_err(AppError::bad_request)?;
    validate_tenant_owned_policy(&state.pool, &req).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        scope_for_tenant(req.tenant_id),
    )
    .await?;
    let policy = repo::create_policy(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

pub async fn get_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_policy_read(&state.pool, auth.entity_id, None).await?;
    let policy = repo::get_policy(&state.pool, id).await?;
    Ok(Json(policy))
}

pub async fn list_policies(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListPolicies>,
) -> Result<impl IntoResponse, AppError> {
    require_policy_read(&state.pool, auth.entity_id, None).await?;
    let list = repo::list_policies(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let policy = repo::get_policy(&state.pool, id).await?;
    require_management(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        scope_for_tenant(policy.tenant_id),
    )
    .await?;
    repo::delete_policy(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Authorization Check (PDP) ────────────────────────────────────────────────

pub async fn check(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<AuthzRequest>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = super::access::authz_request_tenant_id(&state.pool, &req).await?;
    super::access::require_authz_check_access(&state.pool, &auth, req.subject_id, tenant_id)
        .await?;
    let response = engine::evaluate(&state.pool, &req).await?;

    let mut details = serde_json::json!({
        "subject_id": req.subject_id,
        "action": req.action,
        "resource_id": req.resource_id,
        "object_kind": req.object_kind,
        "object_id": req.object_id,
        "reason": response.reason,
    });
    // M3: merge structured details (e.g., tenant lifecycle state) into audit.
    if let Some(extra) = response.details.as_ref().and_then(|v| v.as_object()) {
        if let Some(map) = details.as_object_mut() {
            for (k, v) in extra {
                map.insert(k.clone(), v.clone());
            }
        }
    }

    audit::write(
        &state.pool,
        Some(auth.entity_id),
        tenant_id,
        "authz.check",
        if response.allowed {
            AuditOutcome::Allow
        } else {
            AuditOutcome::Deny
        },
        details,
    )
    .await;

    Ok(Json(response))
}

pub async fn explain(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<AuthzRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_explain_access(&state.pool, auth.entity_id).await?;
    let tenant_id = super::access::authz_request_tenant_id(&state.pool, &req).await?;
    let response = engine::explain(&state.pool, &req).await?;

    let mut details = serde_json::json!({
        "subject_id": req.subject_id,
        "action": req.action,
        "resource_id": req.resource_id,
        "object_kind": req.object_kind,
        "object_id": req.object_id,
        "reason": response.reason,
    });
    // M3: surface tenant-lifecycle reasons (e.g. "tenant is frozen") through
    // explain audit too. Reason text already encodes state; we promote it to
    // a structured field for filtering.
    if response.reason.starts_with("tenant is ") {
        if let Some(state_word) = response.reason.strip_prefix("tenant is ") {
            if let Some(map) = details.as_object_mut() {
                map.insert("tenant_status".into(), serde_json::json!(state_word));
            }
        }
    }

    audit::write(
        &state.pool,
        Some(auth.entity_id),
        tenant_id,
        "authz.explain",
        if response.allowed {
            AuditOutcome::Allow
        } else {
            AuditOutcome::Deny
        },
        details,
    )
    .await;

    Ok(Json(response))
}

pub async fn bulk_check(
    State(state): State<AppState>,
    auth: AuthContext,
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
        let tenant_id = super::access::authz_request_tenant_id(&state.pool, &check_req).await?;
        super::access::require_authz_check_access(
            &state.pool,
            &auth,
            check_req.subject_id,
            tenant_id,
        )
        .await?;
        let response = engine::evaluate(&state.pool, &check_req).await?;
        audit::write(
            &state.pool,
            Some(auth.entity_id),
            tenant_id,
            "authz.check",
            if response.allowed {
                AuditOutcome::Allow
            } else {
                AuditOutcome::Deny
            },
            serde_json::json!({
                "subject_id": req.subject_id,
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
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<AccessQuery>,
) -> Result<impl IntoResponse, AppError> {
    let entity = crate::identity::repo::get_entity(&state.pool, id).await?;
    if auth.entity_id != id {
        require_read_access(&state.pool, auth.entity_id, entity.tenant_id, id).await?;
    }
    let access = repo::entity_access(&state.pool, id, params).await?;
    Ok(Json(access))
}

pub async fn group_access(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<GroupAccessQuery>,
) -> Result<impl IntoResponse, AppError> {
    let group = crate::identity::repo::get_group(&state.pool, id).await?;
    require_read_access(&state.pool, auth.entity_id, group.tenant_id, id).await?;
    let access = repo::group_access(&state.pool, id, params).await?;
    Ok(Json(access))
}

pub async fn audit_logs(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<AuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    let allowed_tenant_ids = audit_tenant_filter(&state.pool, &auth, params.tenant_id).await?;
    let logs = repo::audit_logs(&state.pool, params, allowed_tenant_ids).await?;
    Ok(Json(logs))
}

pub async fn entity_audit_logs(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(entity_id): Path<Uuid>,
    Query(mut params): Query<AuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    params.entity_id = Some(entity_id);
    let allowed_tenant_ids = audit_tenant_filter(&state.pool, &auth, params.tenant_id).await?;
    let logs = repo::audit_logs(&state.pool, params, allowed_tenant_ids).await?;
    Ok(Json(logs))
}

pub async fn orphan_policies(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<AdminPageQuery>,
) -> Result<impl IntoResponse, AppError> {
    require_management(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    let response = repo::orphan_policies(&state.pool, params).await?;
    Ok(Json(response))
}

pub async fn unprotected_resources(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<UnprotectedResourcesQuery>,
) -> Result<impl IntoResponse, AppError> {
    require_management(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    let response = repo::unprotected_resources(&state.pool, params).await?;
    Ok(Json(response))
}

pub async fn expiring_credentials(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ExpiringCredentialsQuery>,
) -> Result<impl IntoResponse, AppError> {
    require_management(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    let response = repo::expiring_credentials(&state.pool, params).await?;
    Ok(Json(response))
}
