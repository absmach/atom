use async_graphql::{Context, Object, Result, ID};
use serde_json::json;

use crate::{
    api_endpoints::repo as api_endpoint_repo,
    auth::has_global_manage,
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
        require_platform_manage(state, auth.entity_id).await?;
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
        require_platform_manage(state, auth.entity_id).await?;
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
        require_platform_manage(state, auth.entity_id).await?;
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
        require_platform_manage(state, auth.entity_id).await?;

        let endpoint = api_endpoint_repo::create_api_endpoint(
            &state.pool,
            CreateApiEndpoint {
                tenant_id: parse_optional_id(input.tenant_id, "tenantId")?,
                key: input.key,
                name: input.name,
                description: input.description,
                method: input.method,
                path: input.path,
                operation_kind: input.operation_kind,
                graphql: input.graphql,
                auth_mode: input.auth_mode,
                service_entity_id: parse_optional_id(input.service_entity_id, "serviceEntityId")?,
                variables_mapping: input.variables_mapping.unwrap_or_else(|| json!({})),
                request_schema: input.request_schema.unwrap_or_else(|| json!({})),
                response_mapping: input.response_mapping.unwrap_or_else(|| json!({})),
                status: input.status,
            },
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;

        Ok(endpoint.into())
    }

    async fn update_api_endpoint(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateApiEndpointInput,
    ) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_platform_manage(state, auth.entity_id).await?;
        let endpoint = api_endpoint_repo::update_api_endpoint(
            &state.pool,
            parse_id(id, "id")?,
            UpdateApiEndpoint {
                key: input.key,
                name: input.name,
                description: input.description,
                method: input.method,
                path: input.path,
                operation_kind: input.operation_kind,
                graphql: input.graphql,
                auth_mode: input.auth_mode,
                service_entity_id: parse_optional_id(input.service_entity_id, "serviceEntityId")?,
                variables_mapping: input.variables_mapping,
                request_schema: input.request_schema,
                response_mapping: input.response_mapping,
                status: input.status,
            },
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;

        Ok(endpoint.into())
    }

    async fn enable_api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_platform_manage(state, auth.entity_id).await?;
        let endpoint = api_endpoint_repo::enable_api_endpoint(
            &state.pool,
            parse_id(id, "id")?,
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;
        Ok(endpoint.into())
    }

    async fn disable_api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_platform_manage(state, auth.entity_id).await?;
        let endpoint = api_endpoint_repo::disable_api_endpoint(
            &state.pool,
            parse_id(id, "id")?,
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;
        Ok(endpoint.into())
    }
}

async fn require_platform_manage(state: &AppState, entity_id: uuid::Uuid) -> Result<()> {
    if has_global_manage(&state.pool, entity_id)
        .await
        .map_err(gql_error)?
    {
        Ok(())
    } else {
        Err(async_graphql::Error::new("forbidden"))
    }
}
