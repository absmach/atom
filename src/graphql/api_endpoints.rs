use async_graphql::{Context, Object, Result, ID};
use serde_json::json;

use crate::{
    api_endpoints::repo as api_endpoint_repo,
    auth::{has_global_manage, AuthContext},
    error::AppError,
    models::api_endpoint::{
        CreateApiEndpoint, ListApiEndpointExecutions, ListApiEndpoints, UpdateApiEndpoint,
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth},
    types::{
        parse_id, parse_optional_id, ApiEndpoint, ApiEndpointExecutionList, ApiEndpointList,
        CreateApiEndpointInput, UpdateApiEndpointInput,
    },
};

#[derive(Default)]
pub struct ApiEndpointQuery;

#[Object]
impl ApiEndpointQuery {
    async fn api_endpoints(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        status: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<ApiEndpointList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_platform_manage(state, &auth).await?;
        let list = api_endpoint_repo::list_api_endpoints(
            &state.pool,
            ListApiEndpoints {
                tenant_id: parse_optional_id(tenant_id, "tenantId")?,
                status,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(ApiEndpointList {
            items: list.items.into_iter().map(ApiEndpoint::from).collect(),
            total: list.total,
        })
    }

    async fn api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_platform_manage(state, &auth).await?;
        let endpoint = api_endpoint_repo::get_api_endpoint(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        Ok(endpoint.into())
    }

    async fn api_endpoint_executions(
        &self,
        ctx: &Context<'_>,
        endpoint_id: ID,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<ApiEndpointExecutionList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_platform_manage(state, &auth).await?;
        let list = api_endpoint_repo::list_api_endpoint_executions(
            &state.pool,
            ListApiEndpointExecutions {
                endpoint_id: parse_id(endpoint_id, "endpointId")?,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(ApiEndpointExecutionList {
            items: list
                .items
                .into_iter()
                .map(super::types::ApiEndpointExecution::from)
                .collect(),
            total: list.total,
        })
    }
}

#[derive(Default)]
pub struct ApiEndpointMutation;

#[Object]
impl ApiEndpointMutation {
    async fn create_api_endpoint(
        &self,
        ctx: &Context<'_>,
        input: CreateApiEndpointInput,
    ) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        let service_entity_id = parse_optional_id(input.service_entity_id, "serviceEntityId")?;
        let result = async {
            require_platform_manage_app(state, &auth).await?;
            api_endpoint_repo::create_api_endpoint(
                &state.pool,
                CreateApiEndpoint {
                    tenant_id,
                    key: input.key,
                    name: input.name,
                    description: input.description,
                    method: input.method,
                    path: input.path,
                    operation_kind: input.operation_kind,
                    graphql: input.graphql,
                    auth_mode: input.auth_mode,
                    service_entity_id,
                    variables_mapping: input.variables_mapping.unwrap_or_else(|| json!({})),
                    request_schema: input.request_schema.unwrap_or_else(|| json!({})),
                    response_mapping: input.response_mapping.unwrap_or_else(|| json!({})),
                    status: input.status,
                },
                Some(auth.entity_id),
            )
            .await
        }
        .await;

        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: "api_endpoint",
                target_id: result.as_ref().ok().map(|e| e.id),
                event: "api_endpoint.create",
            },
            json!({}),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
    }

    async fn update_api_endpoint(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateApiEndpointInput,
    ) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let endpoint_id = parse_id(id, "id")?;
        let service_entity_id = parse_optional_id(input.service_entity_id, "serviceEntityId")?;
        let result = async {
            require_platform_manage_app(state, &auth).await?;
            api_endpoint_repo::update_api_endpoint(
                &state.pool,
                endpoint_id,
                UpdateApiEndpoint {
                    key: input.key,
                    name: input.name,
                    description: input.description,
                    method: input.method,
                    path: input.path,
                    operation_kind: input.operation_kind,
                    graphql: input.graphql,
                    auth_mode: input.auth_mode,
                    service_entity_id,
                    variables_mapping: input.variables_mapping,
                    request_schema: input.request_schema,
                    response_mapping: input.response_mapping,
                    status: input.status,
                },
                Some(auth.entity_id),
            )
            .await
        }
        .await;

        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|e| e.tenant_id),
                target_kind: "api_endpoint",
                target_id: Some(endpoint_id),
                event: "api_endpoint.update",
            },
            json!({}),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
    }

    async fn enable_api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let endpoint_id = parse_id(id, "id")?;
        let result = async {
            require_platform_manage_app(state, &auth).await?;
            api_endpoint_repo::enable_api_endpoint(&state.pool, endpoint_id, Some(auth.entity_id))
                .await
        }
        .await;
        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|e| e.tenant_id),
                target_kind: "api_endpoint",
                target_id: Some(endpoint_id),
                event: "api_endpoint.enable",
            },
            json!({}),
            &result,
        );
        result.map(Into::into).map_err(gql_error)
    }

    async fn disable_api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let endpoint_id = parse_id(id, "id")?;
        let result = async {
            require_platform_manage_app(state, &auth).await?;
            api_endpoint_repo::disable_api_endpoint(&state.pool, endpoint_id, Some(auth.entity_id))
                .await
        }
        .await;
        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|e| e.tenant_id),
                target_kind: "api_endpoint",
                target_id: Some(endpoint_id),
                event: "api_endpoint.disable",
            },
            json!({}),
            &result,
        );
        result.map(Into::into).map_err(gql_error)
    }
}

async fn require_platform_manage(state: &AppState, auth: &AuthContext) -> Result<()> {
    require_platform_manage_app(state, auth)
        .await
        .map_err(gql_error)
}

async fn require_platform_manage_app(
    state: &AppState,
    auth: &AuthContext,
) -> std::result::Result<(), AppError> {
    if has_global_manage(&state.pool, auth).await? {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}
