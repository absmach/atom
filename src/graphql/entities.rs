use async_graphql::{Context, Object, Result, ID};

use crate::{
    audit,
    auth::{AuthContext, Scope},
    authz::{engine, repo as authz_repo},
    error::AppError,
    identity::repo,
    models::{
        access::AuthorizedObjectIdsQuery,
        entity as entity_model,
        enums::{AuditOutcome, DeletedFilter, EntityStatus},
    },
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_read_access, scope_for_tenant,
    },
    types::{
        parse_deleted_filter, parse_id, parse_optional_entity_kind, parse_optional_entity_status,
        parse_optional_id, CreateEntityInput, Entity, EntityList, GqlDeletedFilter, GqlEntityKind,
        GqlEntityStatus, Ownership, UpdateEntityInput,
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
        require_read_access(&state.pool, &auth, owner.tenant_id, owner_id).await?;
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
        // Object read decision via the PDP. `manage` implies `read`, so the caller
        // may read the entity if they can read or manage it.
        let allowed = auth.entity_id == id
            || engine::allows_any(
                &state.pool,
                auth.entity_id,
                "entity",
                id,
                &["read", "manage"],
                auth.ceiling_for(auth.entity_id),
            )
            .await
            .map_err(gql_error)?;
        if !allowed {
            return Err(gql_error(AppError::Forbidden));
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
        parent_group_id: Option<ID>,
        include_descendants: Option<bool>,
        status: Option<GqlEntityStatus>,
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<EntityList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        let profile_id = parse_optional_id(profile_id, "profileId")?;
        let parent_group_id = parse_optional_id(parent_group_id, "parentGroupId")?;
        let parsed_kind = parse_optional_entity_kind(kind);
        let parsed_status = parse_optional_entity_status(status);
        let deleted = parse_deleted_filter(deleted);
        let limit = limit.map(i64::from).unwrap_or(20);
        let offset = offset.map(i64::from).unwrap_or(0);

        if deleted != DeletedFilter::Live {
            require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
            let list = repo::list_entities(
                &state.pool,
                entity_model::ListEntities {
                    q,
                    kind: parsed_kind,
                    profile_id,
                    tenant_id,
                    status: parsed_status,
                    deleted,
                    parent_group_id,
                    include_descendants: include_descendants.unwrap_or(false),
                    limit,
                    offset,
                },
            )
            .await
            .map_err(gql_error)?;
            return Ok(EntityList {
                items: list.items.into_iter().map(Entity::from).collect(),
                total: list.total,
            });
        }

        let authorized = authz_repo::authorized_object_ids(
            &state.pool,
            AuthorizedObjectIdsQuery {
                subject_id: auth.entity_id,
                action: "read".to_string(),
                object_kind: "entity".to_string(),
                object_type: parsed_kind.as_ref().map(entity_object_type),
                tenant_id,
                q,
                attributes_contains: None,
                profile_id,
                entity_status: parsed_status,
                group_type: None,
                parent_group_id,
                include_descendants: include_descendants.unwrap_or(false),
                limit,
                offset,
            },
        )
        .await
        .map_err(gql_error)?;
        let items = repo::list_entities_by_ids(&state.pool, &authorized.ids)
            .await
            .map_err(gql_error)?;

        Ok(EntityList {
            items: items.into_iter().map(Entity::from).collect(),
            total: authorized.total,
        })
    }
}

fn entity_object_type(kind: &crate::models::enums::EntityKind) -> String {
    match kind {
        crate::models::enums::EntityKind::Human => "entity:human",
        crate::models::enums::EntityKind::Device => "entity:device",
        crate::models::enums::EntityKind::Service => "entity:service",
        crate::models::enums::EntityKind::Workload => "entity:workload",
        crate::models::enums::EntityKind::Application => "entity:application",
    }
    .to_string()
}

fn entity_update_fields(input: &UpdateEntityInput) -> Vec<&'static str> {
    [
        input.name.is_some().then_some("name"),
        input.kind.is_some().then_some("kind"),
        (!matches!(input.alias, async_graphql::MaybeUndefined::Undefined)).then_some("alias"),
        input.tenant_id.is_some().then_some("tenant_id"),
        input.profile_id.is_some().then_some("profile_id"),
        input
            .profile_version_id
            .is_some()
            .then_some("profile_version_id"),
        input.status.is_some().then_some("status"),
        input.attributes.is_some().then_some("attributes"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn entity_status_event(status: &EntityStatus) -> &'static str {
    match status {
        EntityStatus::Active => "entity.enable",
        EntityStatus::Inactive => "entity.disable",
        EntityStatus::Suspended => "entity.suspend",
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
        let id = parse_optional_id(input.id, "id")?;
        let profile_id = parse_optional_id(input.profile_id, "profileId")?;
        let profile_version_id = parse_optional_id(input.profile_version_id, "profileVersionId")?;
        let kind = parse_optional_entity_kind(input.kind);
        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", scope_for_tenant(tenant_id)),
                    ("write", scope_for_tenant(tenant_id)),
                ],
            )
            .await?;
            repo::create_entity(
                &state.pool,
                entity_model::CreateEntity {
                    id,
                    kind,
                    profile_id,
                    profile_version_id,
                    name: input.name,
                    alias: input.alias,
                    tenant_id,
                    attributes: input.attributes.unwrap_or_default(),
                },
            )
            .await
        }
        .await;

        match &result {
            Ok(entity) => {
                audit::write(
                    &state.pool,
                    audit::AuditEvent {
                        actor_entity_id: Some(auth.entity_id),
                        tenant_id: entity.tenant_id,
                        target_kind: Some("entity"),
                        target_id: Some(entity.id),
                        event: "entity.create",
                        outcome: AuditOutcome::Allow,
                        details: serde_json::json!({}),
                    },
                )
                .await;
            }
            Err(_) => audit::observe_result(
                audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: "entity",
                    target_id: None,
                    event: "entity.create",
                },
                serde_json::json!({}),
                &result,
            ),
        }

        result.map(Into::into).map_err(gql_error)
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
        let updated_fields = entity_update_fields(&input);
        if auth.entity_id != id {
            require_any_capability(
                &state.pool,
                &auth,
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
                alias: input.alias.into(),
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

        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: entity.tenant_id,
                target_kind: Some("entity"),
                target_id: Some(id),
                event: "entity.update",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({ "updated_fields": updated_fields }),
            },
        )
        .await;

        Ok(entity.into())
    }

    async fn delete_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let existing = repo::get_entity(&state.pool, id).await.map_err(gql_error)?;
        if auth.entity_id != id {
            require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", Scope::Object(id)),
                    ("manage", scope_for_tenant(existing.tenant_id)),
                ],
            )
            .await?;
        }
        repo::delete_entity(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: existing.tenant_id,
                target_kind: Some("entity"),
                target_id: Some(id),
                event: "entity.delete",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
        Ok(true)
    }

    /// Restore a soft-deleted entity while it is still within the purge
    /// retention window. Reinstates the identity (and frees the access it
    /// carried), so it is platform-admin-only and audit-logged. Revoked
    /// credentials and sessions are not reinstated — the entity must
    /// re-authenticate.
    async fn restore_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
        let id = parse_id(id, "id")?;
        repo::restore_entity(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        let entity = repo::get_entity(&state.pool, id).await.map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: entity.tenant_id,
                target_kind: Some("entity"),
                target_id: Some(id),
                event: "entity.restore",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
        Ok(true)
    }

    /// Physically purge an already-soft-deleted entity, bypassing the retention
    /// window. Deliberate, irreversible, platform-admin only, and audit-logged.
    async fn purge_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
        let id = parse_id(id, "id")?;
        let tenant_id = repo::purge_entity(&state.pool, id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(id),
                event: "entity.purge",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
        Ok(true)
    }

    async fn set_entity_parent_group(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        group_id: ID,
    ) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let group_id = parse_id(group_id, "groupId")?;
        let result = async {
            let entity = repo::get_entity(&state.pool, entity_id).await?;
            let group = repo::get_group(&state.pool, group_id).await?;
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", Scope::Object(entity_id)),
                    ("write", Scope::Object(entity_id)),
                    ("write", Scope::Object(group_id)),
                    ("manage", scope_for_tenant(entity.tenant_id)),
                    ("write", scope_for_tenant(entity.tenant_id)),
                    ("manage", scope_for_tenant(group.tenant_id)),
                    ("write", scope_for_tenant(group.tenant_id)),
                ],
            )
            .await?;
            repo::set_entity_parent_group(&state.pool, entity_id, group_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|e| e.tenant_id),
                target_kind: "entity",
                target_id: Some(entity_id),
                event: "entity.parent_group.set",
            },
            serde_json::json!({ "group_id": group_id }),
            &result,
        );
        result.map(Entity::from).map_err(gql_error)
    }

    async fn add_entity_to_object_group(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        object_group_id: ID,
    ) -> Result<Entity> {
        self.set_entity_parent_group(ctx, entity_id, object_group_id)
            .await
    }

    async fn clear_entity_parent_group(&self, ctx: &Context<'_>, entity_id: ID) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let result = async {
            let entity = repo::get_entity(&state.pool, entity_id).await?;
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", Scope::Object(entity_id)),
                    ("write", Scope::Object(entity_id)),
                    ("manage", scope_for_tenant(entity.tenant_id)),
                    ("write", scope_for_tenant(entity.tenant_id)),
                ],
            )
            .await?;
            repo::clear_entity_parent_group(&state.pool, entity_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|e| e.tenant_id),
                target_kind: "entity",
                target_id: Some(entity_id),
                event: "entity.parent_group.clear",
            },
            serde_json::json!({}),
            &result,
        );
        result.map(Entity::from).map_err(gql_error)
    }

    async fn remove_entity_from_object_group(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
    ) -> Result<Entity> {
        self.clear_entity_parent_group(ctx, entity_id).await
    }

    async fn enable_entity(&self, ctx: &Context<'_>, id: ID) -> Result<Entity> {
        change_entity_status(ctx, id, EntityStatus::Active).await
    }

    async fn disable_entity(&self, ctx: &Context<'_>, id: ID) -> Result<Entity> {
        change_entity_status(ctx, id, EntityStatus::Inactive).await
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
        require_ownership_manage(state, &auth, owner_id, owned_id).await?;
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
        require_ownership_manage(state, &auth, owner_id, owned_id).await?;
        repo::delete_ownership(&state.pool, owner_id, owned_id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }
}

async fn change_entity_status(ctx: &Context<'_>, id: ID, status: EntityStatus) -> Result<Entity> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    let entity_id = parse_id(id, "id")?;
    let event = entity_status_event(&status);
    let existing = repo::get_entity(&state.pool, entity_id)
        .await
        .map_err(gql_error)?;
    require_any_capability(
        &state.pool,
        &auth,
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
            alias: None,
            tenant_id: None,
            profile_id: None,
            profile_version_id: None,
            status: Some(status),
            attributes: None,
        },
    )
    .await
    .map_err(gql_error)?;
    audit::write(
        &state.pool,
        audit::AuditEvent {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: entity.tenant_id,
            target_kind: Some("entity"),
            target_id: Some(entity_id),
            event,
            outcome: AuditOutcome::Allow,
            details: serde_json::json!({}),
        },
    )
    .await;
    Ok(entity.into())
}

async fn require_ownership_manage(
    state: &AppState,
    auth: &AuthContext,
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
        auth,
        &[
            ("manage", Scope::Object(owner_id)),
            ("manage", scope_for_tenant(owner.tenant_id)),
        ],
    )
    .await?;
    require_any_capability(
        &state.pool,
        auth,
        &[
            ("manage", Scope::Object(owned_id)),
            ("manage", scope_for_tenant(owned.tenant_id)),
        ],
    )
    .await
}
