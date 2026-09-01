use async_graphql::{Context, Object, Result, ID};
use serde_json::json;

use crate::{
    api_endpoints::repo as api_endpoint_repo,
    auth::{require_capability, Scope},
    authz::{engine::require_any_on_object_or_platform_if_missing, repo as authz_repo},
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
        let list = authz_repo::list_api_endpoints_authorized(
            &state.pool,
            &auth,
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
        let id = parse_id(id, "id")?;
        require_any_on_object_or_platform_if_missing(
            &state.pool,
            &auth,
            "api_endpoint",
            id,
            &["read", "manage"],
        )
        .await
        .map_err(gql_error)?;
        let endpoint = api_endpoint_repo::get_api_endpoint(&state.pool, id)
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
        let endpoint_id = parse_id(endpoint_id, "endpointId")?;
        require_any_on_object_or_platform_if_missing(
            &state.pool,
            &auth,
            "api_endpoint",
            endpoint_id,
            &["read", "manage"],
        )
        .await
        .map_err(gql_error)?;
        let list = api_endpoint_repo::list_api_endpoint_executions(
            &state.pool,
            ListApiEndpointExecutions {
                endpoint_id,
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
            require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            api_endpoint_repo::create_api_endpoint_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
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
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: "api_endpoint",
                    target_id: None,
                    event: "api_endpoint.create",
                },
                &json!({}),
                err,
            )
            .await;
        }

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
            require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            api_endpoint_repo::update_api_endpoint_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
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
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id: None,
                    target_kind: "api_endpoint",
                    target_id: Some(endpoint_id),
                    event: "api_endpoint.update",
                },
                &json!({}),
                err,
            )
            .await;
        }

        result.map(Into::into).map_err(gql_error)
    }

    async fn enable_api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let endpoint_id = parse_id(id, "id")?;
        let result = async {
            require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            api_endpoint_repo::enable_api_endpoint_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                endpoint_id,
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id: None,
                    target_kind: "api_endpoint",
                    target_id: Some(endpoint_id),
                    event: "api_endpoint.enable",
                },
                &json!({}),
                err,
            )
            .await;
        }
        result.map(Into::into).map_err(gql_error)
    }

    async fn disable_api_endpoint(&self, ctx: &Context<'_>, id: ID) -> Result<ApiEndpoint> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let endpoint_id = parse_id(id, "id")?;
        let result = async {
            require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            api_endpoint_repo::disable_api_endpoint_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                endpoint_id,
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id: None,
                    target_kind: "api_endpoint",
                    target_id: Some(endpoint_id),
                    event: "api_endpoint.disable",
                },
                &json!({}),
                err,
            )
            .await;
        }
        result.map(Into::into).map_err(gql_error)
    }
}
