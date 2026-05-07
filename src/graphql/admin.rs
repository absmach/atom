use async_graphql::{Context, Object, Result, ID};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{has_capability_in_scope, require_capability, AuthContext, Scope},
    authz::repo as authz_repo,
    error::AppError,
    models::access::{
        AdminPageQuery, AuditQuery, ExpiringCredentialsQuery, UnprotectedResourcesQuery,
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth},
    types::{
        parse_id, parse_optional_audit_outcome, parse_optional_credential_kind, parse_optional_id,
        parse_optional_timestamp, AuditLog, AuditLogList, Credential, GqlAuditOutcome,
        GqlCredentialKind, PolicyBinding, Resource,
    },
};

#[derive(Default)]
pub struct AdminQuery;

#[Object]
impl AdminQuery {
    #[allow(clippy::too_many_arguments)]
    async fn audit_logs(
        &self,
        ctx: &Context<'_>,
        entity_id: Option<ID>,
        tenant_id: Option<ID>,
        event: Option<String>,
        outcome: Option<GqlAuditOutcome>,
        from: Option<String>,
        to: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<AuditLogList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        let params = AuditQuery {
            entity_id: parse_optional_id(entity_id, "entityId")?,
            tenant_id,
            event,
            outcome: parse_optional_audit_outcome(outcome),
            from: parse_optional_timestamp(from, "from")?,
            to: parse_optional_timestamp(to, "to")?,
            limit: limit.map(i64::from).unwrap_or(50),
            offset: offset.map(i64::from).unwrap_or(0),
        };
        let allowed_tenant_ids = audit_tenant_filter(&state.pool, &auth, tenant_id)
            .await
            .map_err(gql_error)?;
        let logs = authz_repo::audit_logs(&state.pool, params, allowed_tenant_ids)
            .await
            .map_err(gql_error)?;
        Ok(AuditLogList {
            items: logs.items.into_iter().map(AuditLog::from).collect(),
            total: logs.total,
        })
    }

    async fn entity_audit_logs(&self, ctx: &Context<'_>, entity_id: ID) -> Result<AuditLogList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let params = AuditQuery {
            entity_id: Some(parse_id(entity_id, "entityId")?),
            tenant_id: None,
            event: None,
            outcome: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        };
        let logs = authz_repo::audit_logs(
            &state.pool,
            params,
            audit_tenant_filter(&state.pool, &auth, None)
                .await
                .map_err(gql_error)?,
        )
        .await
        .map_err(gql_error)?;
        Ok(AuditLogList {
            items: logs.items.into_iter().map(AuditLog::from).collect(),
            total: logs.total,
        })
    }

    async fn orphan_policies(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<PolicyBinding>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let policies = authz_repo::orphan_policies(
            &state.pool,
            AdminPageQuery {
                limit: limit.map(i64::from).unwrap_or(50),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(policies
            .items
            .into_iter()
            .map(PolicyBinding::from)
            .collect())
    }

    async fn unprotected_resources(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        kind: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<Resource>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let resources = authz_repo::unprotected_resources(
            &state.pool,
            UnprotectedResourcesQuery {
                tenant_id: parse_optional_id(tenant_id, "tenantId")?,
                kind,
                limit: limit.map(i64::from).unwrap_or(50),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        let mut items = Vec::new();
        for resource in resources.items {
            items.push(
                authz_repo::get_resource(&state.pool, resource.id)
                    .await
                    .map(Resource::from)
                    .map_err(gql_error)?,
            );
        }
        Ok(items)
    }

    async fn expiring_credentials(
        &self,
        ctx: &Context<'_>,
        days: Option<i32>,
        entity_id: Option<ID>,
        kind: Option<GqlCredentialKind>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<Credential>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let credentials = authz_repo::expiring_credentials(
            &state.pool,
            ExpiringCredentialsQuery {
                days: days.map(i64::from).unwrap_or(30),
                entity_id: parse_optional_id(entity_id, "entityId")?,
                kind: parse_optional_credential_kind(kind),
                limit: limit.map(i64::from).unwrap_or(50),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(credentials
            .items
            .into_iter()
            .map(Credential::from)
            .collect())
    }
}

async fn audit_tenant_filter(
    pool: &PgPool,
    auth: &AuthContext,
    requested_tenant_id: Option<Uuid>,
) -> std::result::Result<Option<Vec<Uuid>>, AppError> {
    if has_capability_in_scope(pool, auth.entity_id, "audit.read", Scope::Platform).await?
        || has_capability_in_scope(pool, auth.entity_id, "manage", Scope::Platform).await?
    {
        return Ok(None);
    }

    let mut tenant_ids =
        authz_repo::tenant_ids_for_capability(pool, auth.entity_id, "audit.read").await?;
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
