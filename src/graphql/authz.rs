use async_graphql::{Context, Object, Result};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    audit,
    authz::engine,
    models::{
        access as access_model,
        enums::AuditOutcome,
        policy::{AuthzRequest, AuthzResponse as ModelAuthzResponse},
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_explain_access},
    types::{parse_id, parse_optional_id, AuthzCheckInput, AuthzExplainResponse, AuthzResponse},
};

#[derive(Default)]
pub struct AuthzMutation;

#[Object]
impl AuthzMutation {
    async fn authz_check(
        &self,
        ctx: &Context<'_>,
        input: AuthzCheckInput,
    ) -> Result<AuthzResponse> {
        require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let req = authz_request(input)?;
        let tenant_id = authz_request_tenant_id(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        let response = engine::evaluate(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        audit_authz_check(&state.pool, &req, &response, tenant_id).await;
        Ok(response.into())
    }

    async fn authz_explain(
        &self,
        ctx: &Context<'_>,
        input: AuthzCheckInput,
    ) -> Result<AuthzExplainResponse> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_explain_access(&state.pool, auth.entity_id).await?;
        let req = authz_request(input)?;
        let tenant_id = authz_request_tenant_id(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        let response = engine::explain(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        audit_authz_explain(&state.pool, &req, &response, tenant_id).await;
        Ok(response.into())
    }

    async fn authz_bulk_check(
        &self,
        ctx: &Context<'_>,
        input: Vec<AuthzCheckInput>,
    ) -> Result<Vec<AuthzResponse>> {
        require_auth(ctx)?;
        if input.len() > 20 {
            return Err(gql_error(crate::error::AppError::bad_request(
                "input must contain at most 20 items",
            )));
        }
        let state = ctx.data::<AppState>()?;
        let mut responses = Vec::with_capacity(input.len());
        for item in input {
            let req = authz_request(item)?;
            let tenant_id = authz_request_tenant_id(&state.pool, &req)
                .await
                .map_err(gql_error)?;
            let response = engine::evaluate(&state.pool, &req)
                .await
                .map_err(gql_error)?;
            audit_authz_check(&state.pool, &req, &response, tenant_id).await;
            responses.push(response.into());
        }
        Ok(responses)
    }
}

fn authz_request(input: AuthzCheckInput) -> Result<AuthzRequest> {
    Ok(AuthzRequest {
        subject_id: parse_id(input.subject_id, "subjectId")?,
        action: input.action,
        resource_id: parse_optional_id(input.resource_id, "resourceId")?,
        object_kind: input.object_kind,
        object_id: parse_optional_id(input.object_id, "objectId")?,
        context: input.context.unwrap_or_else(|| serde_json::json!({})),
    })
}

async fn authz_request_tenant_id(
    pool: &PgPool,
    req: &AuthzRequest,
) -> std::result::Result<Option<Uuid>, crate::error::AppError> {
    if req.object_kind.as_deref() == Some("tenant") {
        return Ok(req.object_id);
    }

    if let Some(resource_id) = req.resource_id {
        return sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM resources WHERE id = $1",
        )
        .bind(resource_id)
        .fetch_optional(pool)
        .await
        .map(|value| value.flatten())
        .map_err(crate::error::db_err);
    }

    match (req.object_kind.as_deref(), req.object_id) {
        (Some("resource"), Some(id)) => {
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM resources WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await
                .map(|value| value.flatten())
                .map_err(crate::error::db_err)
        }
        (Some("entity"), Some(id)) => {
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM entities WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await
                .map(|value| value.flatten())
                .map_err(crate::error::db_err)
        }
        _ => Ok(None),
    }
}

async fn audit_authz_check(
    pool: &PgPool,
    req: &AuthzRequest,
    response: &ModelAuthzResponse,
    tenant_id: Option<Uuid>,
) {
    let mut details = serde_json::json!({
        "action": req.action,
        "resource_id": req.resource_id,
        "object_kind": req.object_kind,
        "object_id": req.object_id,
        "reason": response.reason,
    });
    if let Some(extra) = response
        .details
        .as_ref()
        .and_then(|value| value.as_object())
    {
        let map = details.as_object_mut().expect("json object");
        for (key, value) in extra {
            map.insert(key.clone(), value.clone());
        }
    }

    audit::write(
        pool,
        Some(req.subject_id),
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
}

async fn audit_authz_explain(
    pool: &PgPool,
    req: &AuthzRequest,
    response: &access_model::AuthzExplainResponse,
    tenant_id: Option<Uuid>,
) {
    let mut details = serde_json::json!({
        "action": req.action,
        "resource_id": req.resource_id,
        "object_kind": req.object_kind,
        "object_id": req.object_id,
        "reason": response.reason,
    });
    if response.reason.starts_with("tenant is ") {
        if let Some(state_word) = response.reason.strip_prefix("tenant is ") {
            details
                .as_object_mut()
                .expect("json object")
                .insert("tenant_status".into(), serde_json::json!(state_word));
        }
    }

    audit::write(
        pool,
        Some(req.subject_id),
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
}
