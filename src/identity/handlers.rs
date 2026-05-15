use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use uuid::Uuid;

use crate::{
    audit,
    auth::{
        has_capability_in_scope, require_any_capability, require_capability, require_list_access,
        require_read_access, scope_for_tenant, AuthContext, Scope,
    },
    error::AppError,
    models::{
        entity::{CreateEntity, CreateOwnership, ListEntities, UpdateEntity},
        enums::{AuditOutcome, EntityStatus},
        group::{AddMember, CreateGroup, ListGroups, SetGroupParent, UpdateGroup},
        profile::{CreateProfile, CreateProfileVersion, ListProfiles},
        session::{
            LoginRequest, OAuthCallbackQuery, OAuthExchangeRequest, OAuthStartQuery,
            PasswordResetConfirmRequest, PasswordResetRequest, PublicAuthConfigResponse,
            ResendVerificationRequest, SignupRequest, VerifyEmailQuery,
        },
        token::CreateApiKey,
    },
    state::AppState,
};

use super::{profile_repo, repo, service};

async fn require_credential_management(
    state: &AppState,
    actor_id: Uuid,
    target_entity_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let target = repo::get_entity(&state.pool, target_entity_id).await?;
    if has_capability_in_scope(
        &state.pool,
        actor_id,
        "credential.manage",
        Scope::Object(target_entity_id),
    )
    .await?
    {
        return Ok(target.tenant_id);
    }
    require_capability(
        &state.pool,
        actor_id,
        "credential.manage",
        scope_for_tenant(target.tenant_id),
    )
    .await?;
    Ok(target.tenant_id)
}

async fn require_ownership_management(
    state: &AppState,
    actor_id: Uuid,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<(), AppError> {
    let owner = repo::get_entity(&state.pool, owner_id).await?;
    let owned = repo::get_entity(&state.pool, owned_id).await?;
    require_any_capability(
        &state.pool,
        actor_id,
        &[
            ("manage", Scope::Object(owner_id)),
            ("manage", scope_for_tenant(owner.tenant_id)),
        ],
    )
    .await?;
    require_any_capability(
        &state.pool,
        actor_id,
        &[
            ("manage", Scope::Object(owned_id)),
            ("manage", scope_for_tenant(owned.tenant_id)),
        ],
    )
    .await
}

// ─── Health ───────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

pub async fn public_auth_config(State(state): State<AppState>) -> Json<PublicAuthConfigResponse> {
    let oauth_providers = if state.config.signup_enabled {
        state
            .config
            .oidc_providers
            .iter()
            .map(|provider| provider.name.clone())
            .collect()
    } else {
        Vec::new()
    };

    Json(PublicAuthConfigResponse {
        signup_enabled: state.config.signup_enabled,
        oauth_providers,
        email_verification_required: true,
        dev_allow_unverified_email_login: state.config.dev_allow_unverified_email_login,
    })
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    use crate::models::enums::CredentialKind;
    match req.kind {
        CredentialKind::Password => {
            let keys = state.keys.read().await;
            let resp = service::login_password_with_tenant(
                &state.pool,
                &state.config,
                &keys.primary,
                &req.identifier,
                &req.secret,
                req.tenant_id,
                req.tenant_route.as_deref(),
            )
            .await?;
            Ok((StatusCode::OK, Json(resp)))
        }
        other => Err(AppError::bad_request(format!(
            "unsupported credential kind: {other:?}"
        ))),
    }
}

pub async fn signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !state.config.signup_enabled {
        return Err(AppError::Forbidden);
    }

    let resp = service::signup_human(&state.pool, &state.config, req).await?;
    Ok((StatusCode::ACCEPTED, Json(resp)))
}

pub async fn verify_email(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Result<impl IntoResponse, AppError> {
    service::verify_email(&state.pool, &query.token).await?;
    Ok(Json(serde_json::json!({"verified": true})))
}

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<impl IntoResponse, AppError> {
    service::resend_verification(&state.pool, &state.config, &req.email).await?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<impl IntoResponse, AppError> {
    service::request_password_reset(&state.pool, &state.config, req).await?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(req): Json<PasswordResetConfirmRequest>,
) -> Result<impl IntoResponse, AppError> {
    service::reset_password(&state.pool, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn oauth_start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthStartQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !state.config.signup_enabled {
        return Err(AppError::Forbidden);
    }
    let url = service::oauth_start(&state.pool, &state.config, &provider, query.return_to).await?;
    Ok(Redirect::temporary(&url))
}

pub async fn oauth_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<impl IntoResponse, AppError> {
    let keys = state.keys.read().await;
    let url = service::oauth_callback(
        &state.pool,
        &state.config,
        &keys.primary,
        &provider,
        query.code,
        query.state,
        query.error,
    )
    .await;
    Ok(Redirect::temporary(&url))
}

pub async fn oauth_exchange(
    State(state): State<AppState>,
    Json(req): Json<OAuthExchangeRequest>,
) -> Result<impl IntoResponse, AppError> {
    let keys = state.keys.read().await;
    let resp =
        service::oauth_exchange(&state.pool, &state.config, &keys.primary, &req.code).await?;
    Ok(Json(resp))
}

pub async fn logout(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, AppError> {
    if let Some(session_id) = auth.session_id {
        repo::revoke_session(&state.pool, session_id).await?;
    }
    audit::write(
        &state.pool,
        Some(auth.entity_id),
        auth.tenant_id,
        "auth.logout",
        AuditOutcome::Allow,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn introspect(auth: AuthContext) -> Result<impl IntoResponse, AppError> {
    Ok(Json(serde_json::json!({
        "active": true,
        "entity_id": auth.entity_id,
        "tenant_id": auth.tenant_id,
        "session_id": auth.session_id,
    })))
}

pub async fn get_session(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = repo::get_session(&state.pool, id).await?;
    if session.entity_id != auth.entity_id {
        let entity = repo::get_entity(&state.pool, session.entity_id).await?;
        require_read_access(
            &state.pool,
            auth.entity_id,
            entity.tenant_id,
            session.entity_id,
        )
        .await?;
    }
    Ok(Json(session))
}

// ─── Entities ─────────────────────────────────────────────────────────────────

pub async fn create_entity(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateEntity>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(req.tenant_id),
    )
    .await?;
    let entity = repo::create_entity(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(entity)))
}

pub async fn get_entity(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let entity = repo::get_entity(&state.pool, id).await?;
    if auth.entity_id != id {
        require_read_access(&state.pool, auth.entity_id, entity.tenant_id, id).await?;
    }
    Ok(Json(entity))
}

pub async fn list_entities(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListEntities>,
) -> Result<impl IntoResponse, AppError> {
    require_list_access(&state.pool, auth.entity_id, params.tenant_id).await?;
    let list = repo::list_entities(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn update_entity(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateEntity>,
) -> Result<impl IntoResponse, AppError> {
    let existing = repo::get_entity(&state.pool, id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(existing.tenant_id),
    )
    .await?;
    let entity = repo::update_entity(&state.pool, id, req).await?;
    Ok(Json(entity))
}

pub async fn delete_entity(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if auth.entity_id != id {
        let existing = repo::get_entity(&state.pool, id).await?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "manage",
            scope_for_tenant(existing.tenant_id),
        )
        .await?;
    }
    repo::delete_entity(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Profiles ────────────────────────────────────────────────────────────────

pub async fn create_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateProfile>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(req.tenant_id),
    )
    .await?;
    let profile = profile_repo::create_profile(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(profile)))
}

pub async fn list_profiles(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListProfiles>,
) -> Result<impl IntoResponse, AppError> {
    require_list_access(&state.pool, auth.entity_id, params.tenant_id).await?;
    let list = profile_repo::list_profiles(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn get_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let profile = profile_repo::get_profile(&state.pool, id).await?;
    require_read_access(&state.pool, auth.entity_id, profile.tenant_id, id).await?;
    Ok(Json(profile))
}

pub async fn create_profile_version(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(profile_id): Path<Uuid>,
    Json(req): Json<CreateProfileVersion>,
) -> Result<impl IntoResponse, AppError> {
    let profile = profile_repo::get_profile(&state.pool, profile_id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(profile.tenant_id),
    )
    .await?;
    let version = profile_repo::create_profile_version(&state.pool, profile_id, req).await?;
    Ok((StatusCode::CREATED, Json(version)))
}

pub async fn list_profile_versions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(profile_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let profile = profile_repo::get_profile(&state.pool, profile_id).await?;
    require_read_access(&state.pool, auth.entity_id, profile.tenant_id, profile_id).await?;
    let versions = profile_repo::list_profile_versions(&state.pool, profile_id).await?;
    Ok(Json(serde_json::json!({"items": versions})))
}

// ─── Credentials ──────────────────────────────────────────────────────────────

pub async fn create_password(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = require_credential_management(&state, auth.entity_id, entity_id).await?;
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing 'password' field"))?;
    service::create_password(&state.pool, entity_id, password).await?;
    audit::write(
        &state.pool,
        Some(entity_id),
        tenant_id,
        "credential.create",
        AuditOutcome::Allow,
        serde_json::json!({"kind": "password"}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(entity_id): Path<Uuid>,
    Json(req): Json<CreateApiKey>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = require_credential_management(&state, auth.entity_id, entity_id).await?;
    let resp = service::create_api_key(&state.pool, entity_id, req).await?;
    audit::write(
        &state.pool,
        Some(entity_id),
        tenant_id,
        "credential.create",
        AuditOutcome::Allow,
        serde_json::json!({"kind": "api_key", "credential_id": resp.credential_id}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn list_credentials(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(entity_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_credential_management(&state, auth.entity_id, entity_id).await?;
    let creds = service::list_credentials(&state.pool, entity_id).await?;
    Ok(Json(serde_json::json!({"items": creds})))
}

pub async fn revoke_credential(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((entity_id, cred_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = require_credential_management(&state, auth.entity_id, entity_id).await?;
    service::revoke_credential(&state.pool, entity_id, cred_id).await?;
    audit::write(
        &state.pool,
        Some(auth.entity_id),
        tenant_id,
        "credential.revoke",
        AuditOutcome::Allow,
        serde_json::json!({"entity_id": entity_id, "credential_id": cred_id}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Groups ───────────────────────────────────────────────────────────────────

pub async fn create_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateGroup>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(req.tenant_id),
    )
    .await?;
    let group = repo::create_group(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(group)))
}

pub async fn get_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_read_access(&state.pool, auth.entity_id, group.tenant_id, id).await?;
    Ok(Json(group))
}

pub async fn update_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateGroup>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    let group = repo::update_group(&state.pool, id, req).await?;
    Ok(Json(group))
}

pub async fn enable_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    change_group_status(state, auth, id, EntityStatus::Active).await
}

pub async fn disable_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    change_group_status(state, auth, id, EntityStatus::Inactive).await
}

pub async fn suspend_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    change_group_status(state, auth, id, EntityStatus::Suspended).await
}

async fn change_group_status(
    state: AppState,
    auth: AuthContext,
    id: Uuid,
    status: EntityStatus,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    let group = repo::update_group(
        &state.pool,
        id,
        UpdateGroup {
            name: None,
            description: None,
            status: Some(status),
            attributes: None,
        },
    )
    .await?;
    Ok(Json(group))
}

pub async fn list_groups(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListGroups>,
) -> Result<impl IntoResponse, AppError> {
    require_list_access(&state.pool, auth.entity_id, params.tenant_id).await?;
    let list = repo::list_groups(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn delete_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    repo::delete_group(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn set_group_parent(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<SetGroupParent>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    let group = repo::set_group_parent(&state.pool, id, req.parent_id).await?;
    Ok(Json(group))
}

pub async fn remove_group_parent(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    repo::remove_group_parent(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_child_groups(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(params): Query<ListGroups>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    require_read_access(&state.pool, auth.entity_id, group.tenant_id, id).await?;
    let list = repo::list_child_groups(&state.pool, id, params.limit, params.offset).await?;
    Ok(Json(list))
}

pub async fn add_group_member(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMember>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, group_id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    repo::add_group_member(&state.pool, group_id, req.entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_group_members(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(group_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, group_id).await?;
    require_read_access(&state.pool, auth.entity_id, group.tenant_id, group_id).await?;
    let members = repo::list_group_members(&state.pool, group_id).await?;
    Ok(Json(serde_json::json!({"items": members})))
}

pub async fn remove_group_member(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((group_id, entity_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, group_id).await?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "manage",
        scope_for_tenant(group.tenant_id),
    )
    .await?;
    repo::remove_group_member(&state.pool, group_id, entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_entity_groups(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(entity_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let entity = repo::get_entity(&state.pool, entity_id).await?;
    if auth.entity_id != entity_id {
        require_read_access(&state.pool, auth.entity_id, entity.tenant_id, entity_id).await?;
    }
    let group_ids = repo::get_entity_groups(&state.pool, entity_id).await?;
    Ok(Json(serde_json::json!({"items": group_ids})))
}

// ─── Ownerships ───────────────────────────────────────────────────────────────

pub async fn add_ownership(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(owner_id): Path<Uuid>,
    Json(req): Json<CreateOwnership>,
) -> Result<impl IntoResponse, AppError> {
    require_ownership_management(&state, auth.entity_id, owner_id, req.owned_id).await?;
    let ownership =
        repo::create_ownership(&state.pool, owner_id, req.owned_id, req.relation).await?;
    Ok((StatusCode::CREATED, Json(ownership)))
}

pub async fn list_owned(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(owner_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let owner = repo::get_entity(&state.pool, owner_id).await?;
    if auth.entity_id != owner_id {
        require_read_access(&state.pool, auth.entity_id, owner.tenant_id, owner_id).await?;
    }
    let entities = repo::list_owned(&state.pool, owner_id).await?;
    Ok(Json(serde_json::json!({"items": entities})))
}

pub async fn remove_ownership(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((owner_id, owned_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    require_ownership_management(&state, auth.entity_id, owner_id, owned_id).await?;
    repo::delete_ownership(&state.pool, owner_id, owned_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
