use async_graphql::{Context, Object, Result, ID};

use crate::{
    authz::repo as authz_repo,
    models::resource::{CreateResource, ListResources, UpdateResource},
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_list_access, require_read_access,
        scope_for_tenant,
    },
    types::{
        parse_id, parse_optional_id, CreateResourceInput, Resource, ResourceList,
        UpdateResourceInput,
    },
};

#[derive(Default)]
pub struct ResourceQuery;

#[Object]
impl ResourceQuery {
    async fn resources(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        kind: Option<String>,
        tenant_id: Option<ID>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<ResourceList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_list_access(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_resources(
            &state.pool,
            ListResources {
                q,
                kind,
                tenant_id,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(ResourceList {
            items: list.items.into_iter().map(Resource::from).collect(),
            total: list.total,
        })
    }

    async fn resource(&self, ctx: &Context<'_>, id: ID) -> Result<Resource> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let resource = authz_repo::get_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, auth.entity_id, resource.tenant_id, id).await?;
        Ok(resource.into())
    }
}

#[derive(Default)]
pub struct ResourceMutation;

#[Object]
impl ResourceMutation {
    async fn create_resource(
        &self,
        ctx: &Context<'_>,
        input: CreateResourceInput,
    ) -> Result<Resource> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", scope_for_tenant(tenant_id)),
                ("write", scope_for_tenant(tenant_id)),
            ],
        )
        .await?;

        let resource = authz_repo::create_resource(
            &state.pool,
            CreateResource {
                id: parse_optional_id(input.id, "id")?,
                kind: input.kind,
                name: input.name,
                tenant_id,
                owner_id: parse_optional_id(input.owner_id, "ownerId")?,
                attributes: input.attributes.unwrap_or(serde_json::Value::Null),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(resource.into())
    }

    async fn update_resource(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateResourceInput,
    ) -> Result<Resource> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let existing = authz_repo::get_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", crate::auth::Scope::Object(id)),
                ("manage", scope_for_tenant(existing.tenant_id)),
            ],
        )
        .await?;

        let resource = authz_repo::update_resource(
            &state.pool,
            id,
            UpdateResource {
                name: input.name,
                attributes: input.attributes,
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(resource.into())
    }

    async fn delete_resource(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let existing = authz_repo::get_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", crate::auth::Scope::Object(id)),
                ("manage", scope_for_tenant(existing.tenant_id)),
            ],
        )
        .await?;

        authz_repo::delete_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;

        Ok(true)
    }
}
