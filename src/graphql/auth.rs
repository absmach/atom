use async_graphql::{Context, Object, Result, ID};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_capability_in_scope, require_capability, AuthContext, Scope},
    error::AppError,
    identity::{repo, service},
    models::enums::AuditOutcome,
    state::AppState,
};

use crate::models::session::SignupRequest;

use super::types::{
    parse_id, parse_optional_id, LoginInput, LoginResponse, Session, SignupInput, SignupResponse,
};

#[derive(Default)]
pub struct AuthQuery;

#[Object]
impl AuthQuery {
    async fn health(&self, ctx: &Context<'_>) -> Result<&'static str> {
        let _state = ctx.data::<AppState>()?;
        Ok("ok")
    }

    async fn session(&self, ctx: &Context<'_>, id: ID) -> Result<Session> {
        require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let session = repo::get_session(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        Ok(session.into())
    }
}

#[derive(Default)]
pub struct AuthMutation;

#[Object]
impl AuthMutation {
    async fn login(&self, ctx: &Context<'_>, input: LoginInput) -> Result<LoginResponse> {
        if input.kind != "password" {
            return Err(async_graphql::Error::new(format!(
                "unsupported credential kind: {}",
                input.kind
            )));
        }

        let state = ctx.data::<AppState>()?;
        let keys = state.keys.read().await;
        let response = service::login_password_with_tenant(
            &state.pool,
            &state.config,
            &keys.primary,
            &input.identifier,
            &input.secret,
            parse_optional_id(input.tenant_id, "tenantId")?,
            input.tenant_alias.as_deref(),
        )
        .await
        .map_err(gql_error)?;

        Ok(response.into())
    }

    async fn signup(&self, ctx: &Context<'_>, input: SignupInput) -> Result<SignupResponse> {
        let state = ctx.data::<AppState>()?;
        if !state.config.self_registration_enabled {
            return Err(async_graphql::Error::new("sign up is not enabled"));
        }
        let response = service::signup_human(
            &state.pool,
            &state.config,
            SignupRequest {
                name: input.name,
                email: input.email,
                password: input.password,
                attributes: input.attributes.0,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(response.into())
    }

    async fn logout(&self, ctx: &Context<'_>) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;

        if let Some(session_id) = auth.session_id {
            repo::revoke_session(&state.pool, session_id)
                .await
                .map_err(gql_error)?;
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

        Ok(true)
    }
}

pub(crate) fn gql_error(err: AppError) -> async_graphql::Error {
    match &err {
        AppError::Database(sqlx::Error::Database(db)) => match db.code().as_deref() {
            Some("23505") => async_graphql::Error::new("already exists"),
            Some("23503") => async_graphql::Error::new("invalid reference"),
            Some("23514") => async_graphql::Error::new("invalid value"),
            Some(_) | None => {
                tracing::error!("db error: {}", db);
                async_graphql::Error::new("database error")
            }
        },
        AppError::Database(e) => {
            tracing::error!("db error: {}", e);
            async_graphql::Error::new("database error")
        }
        AppError::Internal(e) => {
            tracing::error!("internal error: {}", e);
            async_graphql::Error::new("internal error")
        }
        AppError::NotFound(_)
        | AppError::BadRequest(_)
        | AppError::Unauthorized(_)
        | AppError::Forbidden
        | AppError::Conflict(_)
        | AppError::PayloadTooLarge(_)
        | AppError::RateLimited { .. } => async_graphql::Error::new(err.to_string()),
    }
}

pub(crate) fn require_auth(ctx: &Context<'_>) -> Result<AuthContext> {
    ctx.data::<AuthContext>()
        .cloned()
        .map_err(|_| async_graphql::Error::new("missing authentication"))
}

pub(crate) fn scope_for_tenant(tenant_id: Option<Uuid>) -> Scope {
    match tenant_id {
        Some(tenant_id) => Scope::Tenant(tenant_id),
        None => Scope::Platform,
    }
}

pub(crate) async fn require_any_capability(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    checks: &[(&str, Scope)],
) -> Result<()> {
    // Delegate to the single core gate. A previous sequential-OR copy here
    // evaluated each scope independently and returned on the first allow, so an
    // exact-object deny was bypassed by a later tenant-wide allow. The core gate
    // evaluates all scopes of an action together (cross-scope deny-override) and
    // enforces tenant boundaries and fail-closed conditions.
    crate::auth::require_any_capability(pool, entity_id, checks)
        .await
        .map_err(gql_error)
}

// Thin GraphQL adapters over the single core gate (map AppError → GraphQL error).
// Keeping the logic in crate::auth avoids a divergent second copy.

pub(crate) async fn require_list_access(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<()> {
    crate::auth::require_list_access(pool, entity_id, tenant_id)
        .await
        .map_err(gql_error)
}

pub(crate) async fn require_read_access(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
    object_id: Uuid,
) -> Result<()> {
    crate::auth::require_read_access(pool, entity_id, tenant_id, object_id)
        .await
        .map_err(gql_error)
}

pub(crate) async fn require_role_read(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<()> {
    crate::auth::require_role_read(pool, entity_id, tenant_id)
        .await
        .map_err(gql_error)
}

pub(crate) async fn require_policy_read(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<()> {
    crate::auth::require_policy_read(pool, entity_id, tenant_id)
        .await
        .map_err(gql_error)
}

pub(crate) async fn require_explain_access(pool: &sqlx::PgPool, entity_id: Uuid) -> Result<()> {
    crate::auth::require_explain_access(pool, entity_id)
        .await
        .map_err(gql_error)
}

pub(crate) async fn require_credential_management(
    state: &AppState,
    actor_id: Uuid,
    target_entity_id: Uuid,
) -> Result<Option<Uuid>> {
    let target = repo::get_entity(&state.pool, target_entity_id)
        .await
        .map_err(gql_error)?;
    if actor_id == target_entity_id {
        return Ok(target.tenant_id);
    }
    if has_capability_in_scope(
        &state.pool,
        actor_id,
        "manage",
        Scope::Object(target_entity_id),
    )
    .await
    .map_err(gql_error)?
    {
        return Ok(target.tenant_id);
    }
    require_capability(
        &state.pool,
        actor_id,
        "manage",
        scope_for_tenant(target.tenant_id),
    )
    .await
    .map_err(gql_error)?;
    Ok(target.tenant_id)
}
