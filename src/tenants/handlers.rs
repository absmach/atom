use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use uuid::Uuid;

use crate::{
    auth::{
        has_capability_in_scope, require_any_capability, require_capability, require_read_access,
        AuthContext, Scope,
    },
    config::{Config, SmtpTls},
    error::AppError,
    models::{
        enums::TenantStatus,
        tenant::{
            CreateTenant, CreateTenantInvitation, InvitationTokenRequest, ListTenantInvitations,
            ListTenants, UpdateTenant,
        },
    },
    state::AppState,
};

use super::repo;

pub async fn create_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateTenant>,
) -> Result<impl IntoResponse, AppError> {
    require_any_capability(
        &state.pool,
        auth.entity_id,
        &[("manage", Scope::Platform), ("create", Scope::Platform)],
    )
    .await?;
    let tenant = repo::create_tenant(&state.pool, req, Some(auth.entity_id)).await?;
    Ok((StatusCode::CREATED, Json(tenant)))
}

pub async fn list_tenants(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListTenants>,
) -> Result<impl IntoResponse, AppError> {
    let list = if can_list_all_tenants(&state.pool, auth.entity_id).await? {
        repo::list_tenants(&state.pool, params).await?
    } else {
        repo::list_tenants_for_entity(&state.pool, auth.entity_id, params).await?
    };
    Ok(Json(list))
}

pub async fn get_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_read_access(&state.pool, auth.entity_id, Some(id), id).await?;
    let tenant = repo::get_tenant(&state.pool, id).await?;
    Ok(Json(tenant))
}

pub async fn update_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTenant>,
) -> Result<impl IntoResponse, AppError> {
    require_any_capability(
        &state.pool,
        auth.entity_id,
        &[("manage", Scope::Platform), ("manage", Scope::Tenant(id))],
    )
    .await?;
    let tenant = repo::update_tenant(&state.pool, id, req, Some(auth.entity_id)).await?;
    Ok(Json(tenant))
}

pub async fn enable_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    let tenant =
        repo::change_tenant_status(&state.pool, id, TenantStatus::Active, Some(auth.entity_id))
            .await?;
    Ok(Json(tenant))
}

pub async fn disable_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    let tenant = repo::change_tenant_status(
        &state.pool,
        id,
        TenantStatus::Inactive,
        Some(auth.entity_id),
    )
    .await?;
    Ok(Json(tenant))
}

pub async fn freeze_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    let tenant =
        repo::change_tenant_status(&state.pool, id, TenantStatus::Frozen, Some(auth.entity_id))
            .await?;
    Ok(Json(tenant))
}

pub async fn delete_tenant(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform).await?;
    repo::soft_delete_tenant(&state.pool, id, Some(auth.entity_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<CreateTenantInvitation>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        Scope::Tenant(tenant_id),
    )
    .await?;
    let redirect_url = req
        .redirect_url
        .clone()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| state.config.invitation_redirect.clone());
    let created = repo::create_invitation(
        &state.pool,
        tenant_id,
        auth.entity_id,
        req,
        state.config.invitation_expiry_secs,
    )
    .await?;
    if let (Some(email), Some(token)) = (created.email.as_deref(), created.token.as_deref()) {
        send_invitation_email(&state.config, email, &redirect_url, token).await?;
    }
    Ok((StatusCode::CREATED, Json(created.invitation)))
}

pub async fn list_tenant_invitations(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<Uuid>,
    Query(params): Query<ListTenantInvitations>,
) -> Result<impl IntoResponse, AppError> {
    require_read_access(&state.pool, auth.entity_id, Some(tenant_id), tenant_id).await?;
    let list = repo::list_tenant_invitations(&state.pool, tenant_id, params).await?;
    Ok(Json(list))
}

pub async fn list_my_invitations(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<ListTenantInvitations>,
) -> Result<impl IntoResponse, AppError> {
    let list = repo::list_user_invitations(&state.pool, auth.entity_id, params).await?;
    Ok(Json(list))
}

pub async fn accept_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::accept_invitation(&state.pool, tenant_id, auth.entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn accept_invitation_token(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<InvitationTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    repo::accept_invitation_token(&state.pool, &req.token, auth.entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reject_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(tenant_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    repo::reject_invitation(&state.pool, tenant_id, auth.entity_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((tenant_id, invitee_user_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        Scope::Tenant(tenant_id),
    )
    .await?;
    repo::revoke_invitation(&state.pool, tenant_id, invitee_user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_invitation_by_id(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((tenant_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    require_capability(
        &state.pool,
        auth.entity_id,
        "policy.manage",
        Scope::Tenant(tenant_id),
    )
    .await?;
    repo::revoke_invitation_by_id(&state.pool, tenant_id, invitation_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn send_invitation_email(
    cfg: &Config,
    email: &str,
    redirect_url: &str,
    token: &str,
) -> Result<(), AppError> {
    let invitation_url = url_with_params(redirect_url, &[("token", token)]);
    let Some(smtp) = cfg.smtp.as_ref() else {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email,
                invitation_url,
                "SMTP is not configured; skipping invitation email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "SMTP is not configured"
        )));
    };

    let message = Message::builder()
        .from(
            smtp.from
                .parse()
                .map_err(|e| AppError::bad_request(format!("invalid SMTP from address: {e}")))?,
        )
        .to(email
            .parse()
            .map_err(|e| AppError::bad_request(format!("invalid email address: {e}")))?)
        .subject("You have been invited")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Accept your invitation by opening this link:\n\n{invitation_url}\n"
        ))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("build email: {e}")))?;

    let mut builder = match smtp.tls {
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp starttls: {e}")))?,
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp tls: {e}")))?,
    }
    .port(smtp.port);

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    builder
        .build()
        .send(message)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("send invitation email: {e}")))?;
    Ok(())
}

async fn can_list_all_tenants(pool: &sqlx::PgPool, entity_id: Uuid) -> Result<bool, AppError> {
    for capability in ["read", "manage"] {
        if has_capability_in_scope(pool, entity_id, capability, Scope::Platform).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn url_with_params(base: &str, params: &[(&str, &str)]) -> String {
    match url::Url::parse(base) {
        Ok(mut parsed) => {
            {
                let mut pairs = parsed.query_pairs_mut();
                for (key, value) in params {
                    if !value.is_empty() {
                        pairs.append_pair(key, value);
                    }
                }
            }
            parsed.to_string()
        }
        Err(_) => {
            let mut url = base.to_string();
            let mut first = !url.contains('?');
            for (key, value) in params {
                if !value.is_empty() {
                    url.push(if first { '?' } else { '&' });
                    first = false;
                    url.push_str(key);
                    url.push('=');
                    url.push_str(value);
                }
            }
            url
        }
    }
}
