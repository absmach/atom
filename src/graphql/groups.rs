use async_graphql::{Context, Object, Result, ID};

use crate::{
    auth::Scope,
    identity::repo,
    models::{
        enums::EntityStatus,
        group::{CreateGroup, ListGroups, UpdateGroup},
    },
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_list_access, require_read_access,
        scope_for_tenant,
    },
    types::{
        parse_id, parse_optional_entity_status, parse_optional_id, CreateGroupInput, Entity,
        GqlEntityStatus, Group, GroupList, UpdateGroupInput,
    },
};

#[derive(Default)]
pub struct GroupQuery;

#[Object]
impl GroupQuery {
    #[allow(clippy::too_many_arguments)]
    async fn groups(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        tenant_id: Option<ID>,
        parent_id: Option<ID>,
        status: Option<GqlEntityStatus>,
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
                q,
                tenant_id,
                parent_id: parse_optional_id(parent_id, "parentId")?,
                status: parse_optional_entity_status(status),
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

    async fn child_groups(
        &self,
        ctx: &Context<'_>,
        parent_id: ID,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<GroupList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let parent_id = parse_id(parent_id, "parentId")?;
        let group = repo::get_group(&state.pool, parent_id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, auth.entity_id, group.tenant_id, parent_id).await?;
        let list = repo::list_child_groups(
            &state.pool,
            parent_id,
            limit.map(i64::from).unwrap_or(20),
            offset.map(i64::from).unwrap_or(0),
        )
        .await
        .map_err(gql_error)?;
        Ok(GroupList {
            items: list.items.into_iter().map(Group::from).collect(),
            total: list.total,
        })
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
                id: parse_optional_id(input.id, "id")?,
                name: input.name,
                tenant_id,
                description: input.description,
                attributes: input.attributes.unwrap_or(serde_json::Value::Null),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(group.into())
    }

    async fn update_group(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateGroupInput,
    ) -> Result<Group> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_group_manage(&state.pool, auth.entity_id, id, group.tenant_id).await?;
        let group = repo::update_group(
            &state.pool,
            id,
            UpdateGroup {
                name: input.name,
                description: input.description,
                status: input.status.map(Into::into),
                attributes: input.attributes,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(group.into())
    }

    async fn enable_group(&self, ctx: &Context<'_>, id: ID) -> Result<Group> {
        self.change_group_status(ctx, id, EntityStatus::Active)
            .await
    }

    async fn disable_group(&self, ctx: &Context<'_>, id: ID) -> Result<Group> {
        self.change_group_status(ctx, id, EntityStatus::Inactive)
            .await
    }

    async fn suspend_group(&self, ctx: &Context<'_>, id: ID) -> Result<Group> {
        self.change_group_status(ctx, id, EntityStatus::Suspended)
            .await
    }

    async fn set_group_parent(&self, ctx: &Context<'_>, id: ID, parent_id: ID) -> Result<Group> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let parent_id = parse_id(parent_id, "parentId")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_group_manage(&state.pool, auth.entity_id, id, group.tenant_id).await?;
        let group = repo::set_group_parent(&state.pool, id, parent_id)
            .await
            .map_err(gql_error)?;
        Ok(group.into())
    }

    async fn remove_group_parent(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_group_manage(&state.pool, auth.entity_id, id, group.tenant_id).await?;
        repo::remove_group_parent(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn delete_group(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_group_manage(&state.pool, auth.entity_id, id, group.tenant_id).await?;
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

impl GroupMutation {
    async fn change_group_status(
        &self,
        ctx: &Context<'_>,
        id: ID,
        status: EntityStatus,
    ) -> Result<Group> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        require_group_manage(&state.pool, auth.entity_id, id, group.tenant_id).await?;
        let group = repo::update_group(
            &state.pool,
            id,
            UpdateGroup {
                name: None,
                description: None,
                status: Some(status),
                attributes: None,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(group.into())
    }
}

async fn require_group_manage(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    group_id: uuid::Uuid,
    tenant_id: Option<uuid::Uuid>,
) -> Result<()> {
    require_any_capability(
        pool,
        actor_id,
        &[
            ("manage", Scope::Object(group_id)),
            ("manage", scope_for_tenant(tenant_id)),
        ],
    )
    .await
}
