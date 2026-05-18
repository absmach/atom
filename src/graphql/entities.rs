use async_graphql::{Context, Object, Result, ID};

use crate::{
    auth::Scope,
    identity::repo,
    models::{entity as entity_model, entity::ListEntities},
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_list_access, require_read_access,
        scope_for_tenant,
    },
    types::{
        parse_id, parse_optional_entity_kind, parse_optional_entity_status, parse_optional_id,
        CreateEntityInput, Entity, EntityList, GqlEntityKind, GqlEntityStatus, Ownership,
        UpdateEntityInput,
    },
};

#[derive(Default)]
pub struct EntityQuery;

#[Object]
impl EntityQuery {
    async fn owned_entities(&self, ctx: &Context<'_>, owner_id: ID) -> Result<Vec<Entity>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let owner_id = parse_id(owner_id, "ownerId")?;
        let owner = repo::get_entity(&state.pool, owner_id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, auth.entity_id, owner.tenant_id, owner_id).await?;
        let entities = repo::list_owned(&state.pool, owner_id)
            .await
            .map_err(gql_error)?;
        Ok(entities.into_iter().map(Entity::from).collect())
    }

    async fn entity(&self, ctx: &Context<'_>, id: ID) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let entity = repo::get_entity(&state.pool, id).await.map_err(gql_error)?;
        if auth.entity_id != id {
            require_read_access(&state.pool, auth.entity_id, entity.tenant_id, id).await?;
        }
        Ok(entity.into())
    }

    #[allow(clippy::too_many_arguments)]
    async fn entities(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        kind: Option<GqlEntityKind>,
        profile_id: Option<ID>,
        tenant_id: Option<ID>,
        status: Option<GqlEntityStatus>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<EntityList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_list_access(&state.pool, auth.entity_id, tenant_id).await?;
        let list = repo::list_entities(
            &state.pool,
            ListEntities {
                q,
                kind: parse_optional_entity_kind(kind),
                profile_id: parse_optional_id(profile_id, "profileId")?,
                tenant_id,
                status: parse_optional_entity_status(status),
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(EntityList {
            items: list.items.into_iter().map(Entity::from).collect(),
            total: list.total,
        })
    }
}

#[derive(Default)]
pub struct EntityMutation;

#[Object]
impl EntityMutation {
    async fn create_entity(&self, ctx: &Context<'_>, input: CreateEntityInput) -> Result<Entity> {
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

        let entity = repo::create_entity(
            &state.pool,
            entity_model::CreateEntity {
                id: parse_optional_id(input.id, "id")?,
                kind: parse_optional_entity_kind(input.kind),
                profile_id: parse_optional_id(input.profile_id, "profileId")?,
                profile_version_id: parse_optional_id(
                    input.profile_version_id,
                    "profileVersionId",
                )?,
                name: input.name,
                tenant_id,
                attributes: input.attributes,
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(entity.into())
    }

    async fn update_entity(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateEntityInput,
    ) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let existing = repo::get_entity(&state.pool, id).await.map_err(gql_error)?;
        if auth.entity_id != id {
            require_any_capability(
                &state.pool,
                auth.entity_id,
                &[
                    ("manage", Scope::Object(id)),
                    ("manage", scope_for_tenant(existing.tenant_id)),
                    ("write", scope_for_tenant(existing.tenant_id)),
                ],
            )
            .await?;
        }

        let entity = repo::update_entity(
            &state.pool,
            id,
            entity_model::UpdateEntity {
                name: input.name,
                kind: parse_optional_entity_kind(input.kind),
                tenant_id: parse_optional_id(input.tenant_id, "tenantId")?,
                profile_id: parse_optional_id(input.profile_id, "profileId")?,
                profile_version_id: parse_optional_id(
                    input.profile_version_id,
                    "profileVersionId",
                )?,
                status: input.status.map(Into::into),
                attributes: input.attributes,
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(entity.into())
    }

    async fn delete_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        if auth.entity_id != id {
            let existing = repo::get_entity(&state.pool, id).await.map_err(gql_error)?;
            require_any_capability(
                &state.pool,
                auth.entity_id,
                &[
                    ("manage", Scope::Object(id)),
                    ("manage", scope_for_tenant(existing.tenant_id)),
                ],
            )
            .await?;
        }
        repo::delete_entity(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn enable_entity(&self, ctx: &Context<'_>, id: ID) -> Result<Entity> {
        change_entity_status(ctx, id, crate::models::enums::EntityStatus::Active).await
    }

    async fn disable_entity(&self, ctx: &Context<'_>, id: ID) -> Result<Entity> {
        change_entity_status(ctx, id, crate::models::enums::EntityStatus::Inactive).await
    }

    async fn add_ownership(
        &self,
        ctx: &Context<'_>,
        owner_id: ID,
        owned_id: ID,
        relation: Option<String>,
    ) -> Result<Ownership> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let owner_id = parse_id(owner_id, "ownerId")?;
        let owned_id = parse_id(owned_id, "ownedId")?;
        require_ownership_manage(state, auth.entity_id, owner_id, owned_id).await?;
        let ownership = repo::create_ownership(
            &state.pool,
            owner_id,
            owned_id,
            relation.unwrap_or_else(|| "owner".to_string()),
        )
        .await
        .map_err(gql_error)?;
        Ok(ownership.into())
    }

    async fn remove_ownership(
        &self,
        ctx: &Context<'_>,
        owner_id: ID,
        owned_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let owner_id = parse_id(owner_id, "ownerId")?;
        let owned_id = parse_id(owned_id, "ownedId")?;
        require_ownership_manage(state, auth.entity_id, owner_id, owned_id).await?;
        repo::delete_ownership(&state.pool, owner_id, owned_id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }
}

async fn change_entity_status(
    ctx: &Context<'_>,
    id: ID,
    status: crate::models::enums::EntityStatus,
) -> Result<Entity> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    let entity_id = parse_id(id, "id")?;
    let existing = repo::get_entity(&state.pool, entity_id)
        .await
        .map_err(gql_error)?;
    require_any_capability(
        &state.pool,
        auth.entity_id,
        &[
            ("manage", scope_for_tenant(existing.tenant_id)),
            ("write", scope_for_tenant(existing.tenant_id)),
        ],
    )
    .await?;
    let entity = repo::update_entity(
        &state.pool,
        entity_id,
        entity_model::UpdateEntity {
            name: None,
            kind: None,
            tenant_id: None,
            profile_id: None,
            profile_version_id: None,
            status: Some(status),
            attributes: None,
        },
    )
    .await
    .map_err(gql_error)?;
    Ok(entity.into())
}

async fn require_ownership_manage(
    state: &AppState,
    actor_id: uuid::Uuid,
    owner_id: uuid::Uuid,
    owned_id: uuid::Uuid,
) -> Result<()> {
    let owner = repo::get_entity(&state.pool, owner_id)
        .await
        .map_err(gql_error)?;
    let owned = repo::get_entity(&state.pool, owned_id)
        .await
        .map_err(gql_error)?;
    require_any_capability(
        &state.pool,
        actor_id,
        &[
            ("manage", Scope::Object(owner_id)),
            ("manage", scope_for_tenant(owner.tenant_id)),
        ],
    )
    .await?;
    require_any_capability(
        &state.pool,
        actor_id,
        &[
            ("manage", Scope::Object(owned_id)),
            ("manage", scope_for_tenant(owned.tenant_id)),
        ],
    )
    .await
}
