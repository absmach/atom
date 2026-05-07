use async_graphql::{Context, Object, Result, ID};

use crate::{
    identity::repo,
    models::group::{CreateGroup, ListGroups},
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_list_access, require_read_access,
        scope_for_tenant,
    },
    types::{parse_id, parse_optional_id, CreateGroupInput, Entity, Group, GroupList},
};

#[derive(Default)]
pub struct GroupQuery;

#[Object]
impl GroupQuery {
    async fn groups(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<GroupList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_list_access(&state.pool, auth.entity_id, tenant_id).await?;
        let list = repo::list_groups(
            &state.pool,
            ListGroups {
                tenant_id,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(GroupList {
            items: list.items.into_iter().map(Group::from).collect(),
            total: list.total,
        })
    }

    async fn group(&self, ctx: &Context<'_>, id: ID) -> Result<Group> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_read_access(&state.pool, auth.entity_id, group.tenant_id, id).await?;
        Ok(group.into())
    }

    async fn group_members(&self, ctx: &Context<'_>, group_id: ID) -> Result<Vec<Entity>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let group_id = parse_id(group_id, "groupId")?;
        let group = repo::get_group(&state.pool, group_id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, auth.entity_id, group.tenant_id, group_id).await?;
        let members = repo::list_group_members(&state.pool, group_id)
            .await
            .map_err(gql_error)?;
        Ok(members.into_iter().map(Entity::from).collect())
    }

    async fn entity_groups(&self, ctx: &Context<'_>, entity_id: ID) -> Result<Vec<ID>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let entity = repo::get_entity(&state.pool, entity_id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, auth.entity_id, entity.tenant_id, entity_id).await?;
        let group_ids = repo::get_entity_groups(&state.pool, entity_id)
            .await
            .map_err(gql_error)?;
        Ok(group_ids
            .into_iter()
            .map(|group_id| ID(group_id.to_string()))
            .collect())
    }
}

#[derive(Default)]
pub struct GroupMutation;

#[Object]
impl GroupMutation {
    async fn create_group(&self, ctx: &Context<'_>, input: CreateGroupInput) -> Result<Group> {
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

        let group = repo::create_group(
            &state.pool,
            CreateGroup {
                name: input.name,
                tenant_id,
                description: input.description,
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(group.into())
    }

    async fn delete_group(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", crate::auth::Scope::Object(id)),
                ("manage", scope_for_tenant(group.tenant_id)),
            ],
        )
        .await?;
        repo::delete_group(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn add_group_member(
        &self,
        ctx: &Context<'_>,
        group_id: ID,
        entity_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let group_id = parse_id(group_id, "groupId")?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let group = repo::get_group(&state.pool, group_id)
            .await
            .map_err(gql_error)?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", crate::auth::Scope::Object(group_id)),
                ("manage", scope_for_tenant(group.tenant_id)),
            ],
        )
        .await?;
        repo::add_group_member(&state.pool, group_id, entity_id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn remove_group_member(
        &self,
        ctx: &Context<'_>,
        group_id: ID,
        entity_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let group_id = parse_id(group_id, "groupId")?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let group = repo::get_group(&state.pool, group_id)
            .await
            .map_err(gql_error)?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", crate::auth::Scope::Object(group_id)),
                ("manage", scope_for_tenant(group.tenant_id)),
            ],
        )
        .await?;
        repo::remove_group_member(&state.pool, group_id, entity_id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }
}
