use async_graphql::{Context, Object, Result};
use uuid::Uuid;

use crate::{
    audit,
    authz::{access, engine, repo as authz_repo},
    models::{
        access::{self as access_model, AuthorizedObjectIdsQuery},
        enums::AuditOutcome,
        policy::{AuthzRequest, AuthzResponse as ModelAuthzResponse},
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_explain_access},
    types::{
        parse_id, parse_optional_id, AuthorizedObjectIdList, AuthorizedObjectIdsInput,
        AuthzCheckInput, AuthzExplainResponse, AuthzResponse,
    },
};

#[derive(Default)]
pub struct AuthzQuery;

#[Object]
impl AuthzQuery {
    async fn authorized_object_ids(
        &self,
        ctx: &Context<'_>,
        input: AuthorizedObjectIdsInput,
    ) -> Result<AuthorizedObjectIdList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let subject_id = parse_id(input.subject_id, "subjectId")?;
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        access::require_authz_check_access(&state.pool, &auth, subject_id, tenant_id)
            .await
            .map_err(gql_error)?;
        let response = authz_repo::authorized_object_ids(
            &state.pool,
            AuthorizedObjectIdsQuery {
                subject_id,
                action: input.action,
                object_kind: input.object_kind,
                object_type: input.object_type,
                tenant_id,
                q: input.q,
                profile_id: None,
                entity_status: None,
                group_type: None,
                parent_group_id: None,
                include_descendants: false,
                limit: input.limit.map(i64::from).unwrap_or(100),
                offset: input.offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(response.into())
    }
}

#[derive(Default)]
pub struct AuthzMutation;

#[Object]
impl AuthzMutation {
    async fn authz_check(
        &self,
        ctx: &Context<'_>,
        input: AuthzCheckInput,
    ) -> Result<AuthzResponse> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let req = authz_request(input)?;
        let tenant_id = access::authz_request_tenant_id(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        access::require_authz_check_access(&state.pool, &auth, req.subject_id, tenant_id)
            .await
            .map_err(gql_error)?;
        let response = engine::evaluate(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        audit_authz_check(&state.pool, auth.entity_id, &req, &response, tenant_id).await;
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
        let tenant_id = access::authz_request_tenant_id(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        let response = engine::explain(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        audit_authz_explain(&state.pool, auth.entity_id, &req, &response, tenant_id).await;
        Ok(response.into())
    }

    async fn authz_bulk_check(
        &self,
        ctx: &Context<'_>,
        input: Vec<AuthzCheckInput>,
    ) -> Result<Vec<AuthzResponse>> {
        let auth = require_auth(ctx)?;
        if input.len() > 20 {
            return Err(gql_error(crate::error::AppError::bad_request(
                "input must contain at most 20 items",
            )));
        }
        let state = ctx.data::<AppState>()?;
        let mut responses = Vec::with_capacity(input.len());
        for item in input {
            let req = authz_request(item)?;
            let tenant_id = access::authz_request_tenant_id(&state.pool, &req)
                .await
                .map_err(gql_error)?;
            access::require_authz_check_access(&state.pool, &auth, req.subject_id, tenant_id)
                .await
                .map_err(gql_error)?;
            let response = engine::evaluate(&state.pool, &req)
                .await
                .map_err(gql_error)?;
            audit_authz_check(&state.pool, auth.entity_id, &req, &response, tenant_id).await;
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

async fn audit_authz_check(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    req: &AuthzRequest,
    response: &ModelAuthzResponse,
    tenant_id: Option<Uuid>,
) {
    let mut details = serde_json::json!({
        "subject_id": req.subject_id,
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
        if let Some(map) = details.as_object_mut() {
            for (key, value) in extra {
                map.insert(key.clone(), value.clone());
            }
        }
    }

    audit::write(
        pool,
        Some(actor_id),
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
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    req: &AuthzRequest,
    response: &access_model::AuthzExplainResponse,
    tenant_id: Option<Uuid>,
) {
    let mut details = serde_json::json!({
        "subject_id": req.subject_id,
        "action": req.action,
        "resource_id": req.resource_id,
        "object_kind": req.object_kind,
        "object_id": req.object_id,
        "reason": response.reason,
    });
    if response.reason.starts_with("tenant is ") {
        if let Some(state_word) = response.reason.strip_prefix("tenant is ") {
            if let Some(map) = details.as_object_mut() {
                map.insert("tenant_status".into(), serde_json::json!(state_word));
            }
        }
    }

    audit::write(
        pool,
        Some(actor_id),
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
