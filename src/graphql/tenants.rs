use async_graphql::{Context, Object, Result, ID};

use crate::{
    auth::{require_capability, Scope},
    models::{enums::TenantStatus, tenant as tenant_model, tenant::ListTenants},
    state::AppState,
    tenants::repo as tenant_repo,
};

use super::{
    auth::{gql_error, require_auth, require_list_access, require_read_access},
    types::{
        parse_id, parse_optional_tenant_status, CreateTenantInput, GqlTenantStatus, Tenant,
        TenantList, UpdateTenantInput,
    },
};

#[derive(Default)]
pub struct TenantQuery;

#[Object]
impl TenantQuery {
    #[allow(clippy::too_many_arguments)]
    async fn tenants(
        &self,
        ctx: &Context<'_>,
        name: Option<String>,
        route: Option<String>,
        status: Option<GqlTenantStatus>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<TenantList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_list_access(&state.pool, auth.entity_id, None).await?;
        let list = tenant_repo::list_tenants(
            &state.pool,
            ListTenants {
                name,
                route,
                status: parse_optional_tenant_status(status),
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(TenantList {
            items: list.items.into_iter().map(Tenant::from).collect(),
            total: list.total,
        })
    }

    async fn tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        require_read_access(&state.pool, auth.entity_id, Some(id), id).await?;
        let tenant = tenant_repo::get_tenant(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(tenant.into())
    }
}

#[derive(Default)]
pub struct TenantMutation;

#[Object]
impl TenantMutation {
    async fn create_tenant(&self, ctx: &Context<'_>, input: CreateTenantInput) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "tenant.manage",
            Scope::Platform,
        )
        .await
        .map_err(gql_error)?;

        let tenant = tenant_repo::create_tenant(
            &state.pool,
            tenant_model::CreateTenant {
                name: input.name,
                route: input.route,
                tags: input.tags.unwrap_or_default(),
                attributes: input.attributes.unwrap_or(serde_json::Value::Null),
            },
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;

        Ok(tenant.into())
    }

    async fn update_tenant(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateTenantInput,
    ) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "tenant.manage",
            Scope::Platform,
        )
        .await
        .map_err(gql_error)?;

        let tenant = tenant_repo::update_tenant(
            &state.pool,
            parse_id(id, "id")?,
            tenant_model::UpdateTenant {
                name: input.name,
                route: input.route,
                tags: input.tags,
                attributes: input.attributes,
            },
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;

        Ok(tenant.into())
    }

    async fn delete_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "tenant.manage",
            Scope::Platform,
        )
        .await
        .map_err(gql_error)?;

        tenant_repo::change_tenant_status(
            &state.pool,
            parse_id(id, "id")?,
            TenantStatus::Deleted,
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;

        Ok(true)
    }

    async fn enable_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        change_tenant_status(ctx, id, TenantStatus::Active).await
    }

    async fn disable_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        change_tenant_status(ctx, id, TenantStatus::Inactive).await
    }

    async fn freeze_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        change_tenant_status(ctx, id, TenantStatus::Frozen).await
    }
}

async fn change_tenant_status(ctx: &Context<'_>, id: ID, status: TenantStatus) -> Result<Tenant> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    require_capability(
        &state.pool,
        auth.entity_id,
        "tenant.manage",
        Scope::Platform,
    )
    .await
    .map_err(gql_error)?;

    let tenant = tenant_repo::change_tenant_status(
        &state.pool,
        parse_id(id, "id")?,
        status,
        Some(auth.entity_id),
    )
    .await
    .map_err(gql_error)?;

    Ok(tenant.into())
}
