use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_global_manage, AuthContext},
    error::AppError,
    models::{
        entity::{CreateEntity, CreateOwnership, ListEntities, UpdateEntity},
        enums::AuditOutcome,
        group::{AddMember, CreateGroup, ListGroups},
        session::LoginRequest,
        token::CreateApiKey,
    },
    state::AppState,
};

use super::{repo, service};

// ─── Health ───────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    use crate::models::enums::CredentialKind;
    match req.kind {
        CredentialKind::Password => {
            let keys = state.keys.read().await;
            let resp = service::login_password(
                &state.pool,
                &state.config,
                &keys.primary,
                &req.identifier,
                &req.secret,
            )
            .await?;
            Ok((StatusCode::OK, Json(resp)))
        }
        other => Err(AppError::bad_request(format!(
            "unsupported credential kind: {other:?}"
        ))),
    }
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
        "auth.logout",
        AuditOutcome::Allow,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_session(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = repo::get_session(&state.pool, id).await?;
    Ok(Json(session))
}

// ─── Entities ─────────────────────────────────────────────────────────────────

pub async fn create_entity(
    State(state): State<AppState>,
    _auth: AuthContext,
    Json(req): Json<CreateEntity>,
) -> Result<impl IntoResponse, AppError> {
    let entity = repo::create_entity(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(entity)))
}

pub async fn get_entity(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let entity = repo::get_entity(&state.pool, id).await?;
    Ok(Json(entity))
}

pub async fn list_entities(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<ListEntities>,
) -> Result<impl IntoResponse, AppError> {
    let list = repo::list_entities(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn update_entity(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateEntity>,
) -> Result<impl IntoResponse, AppError> {
    let entity =
        repo::update_entity(&state.pool, id, req.name, req.status, req.attributes).await?;
    Ok(Json(entity))
}

pub async fn delete_entity(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if auth.entity_id != id && !has_global_manage(&state.pool, auth.entity_id).await? {
        return Err(AppError::Forbidden);
    }
    repo::delete_entity(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Credentials ──────────────────────────────────────────────────────────────

pub async fn create_password(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing 'password' field"))?;
    service::create_password(&state.pool, entity_id, password).await?;
    audit::write(
        &state.pool,
        Some(entity_id),
        "credential.create",
        AuditOutcome::Allow,
        serde_json::json!({"kind": "password"}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_api_key(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(entity_id): Path<Uuid>,
    Json(req): Json<CreateApiKey>,
) -> Result<impl IntoResponse, AppError> {
    let resp = service::create_api_key(&state.pool, entity_id, req).await?;
    audit::write(
        &state.pool,
        Some(entity_id),
        "credential.create",
        AuditOutcome::Allow,
        serde_json::json!({"kind": "api_key", "credential_id": resp.credential_id}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn list_credentials(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(entity_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let creds = service::list_credentials(&state.pool, entity_id).await?;
    Ok(Json(serde_json::json!({"items": creds})))
}

pub async fn revoke_credential(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((entity_id, cred_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    service::revoke_credential(&state.pool, entity_id, cred_id).await?;
    audit::write(
        &state.pool,
        Some(auth.entity_id),
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
    _auth: AuthContext,
    Json(req): Json<CreateGroup>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::create_group(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(group)))
}

pub async fn get_group(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = repo::get_group(&state.pool, id).await?;
    Ok(Json(group))
}

pub async fn list_groups(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<ListGroups>,
) -> Result<impl IntoResponse, AppError> {
    let list = repo::list_groups(&state.pool, params).await?;
    Ok(Json(list))
}

pub async fn delete_group(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::delete_group(&state.pool, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_group_member(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMember>,
) -> Result<impl IntoResponse, AppError> {
    repo::add_group_member(&state.pool, group_id, req.entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_group_members(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(group_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let members = repo::list_group_members(&state.pool, group_id).await?;
    Ok(Json(serde_json::json!({"items": members})))
}

pub async fn remove_group_member(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path((group_id, entity_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    repo::remove_group_member(&state.pool, group_id, entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_entity_groups(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(entity_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group_ids = repo::get_entity_groups(&state.pool, entity_id).await?;
    Ok(Json(serde_json::json!({"items": group_ids})))
}

// ─── Ownerships ───────────────────────────────────────────────────────────────

pub async fn add_ownership(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(owner_id): Path<Uuid>,
    Json(req): Json<CreateOwnership>,
) -> Result<impl IntoResponse, AppError> {
    let ownership =
        repo::create_ownership(&state.pool, owner_id, req.owned_id, req.relation).await?;
    Ok((StatusCode::CREATED, Json(ownership)))
}

pub async fn list_owned(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(owner_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let entities = repo::list_owned(&state.pool, owner_id).await?;
    Ok(Json(serde_json::json!({"items": entities})))
}

pub async fn remove_ownership(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path((owner_id, owned_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    repo::delete_ownership(&state.pool, owner_id, owned_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
