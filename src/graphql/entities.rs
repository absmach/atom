use async_graphql::{Context, Object, Result, ID};
use serde_json::Value;

use crate::{
    audit,
    auth::{AuthContext, Scope},
    authz::{engine, repo as authz_repo},
    error::AppError,
    identity::repo,
    models::{
        access::AuthorizedObjectIdsQuery,
        entity as entity_model,
        enums::{DeletedFilter, EntityStatus},
    },
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_read_access, scope_for_tenant,
    },
    types::{
        parse_deleted_filter, parse_entity_order, parse_id, parse_optional_entity_kind,
        parse_optional_entity_status, parse_optional_id, parse_sort_dir, CreateEntityInput, Entity,
        EntityList, GqlDeletedFilter, GqlEntityKind, GqlEntityOrderField, GqlEntityStatus,
        GqlSortDir, Ownership, UpdateEntityInput,
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
        // may read the entity if they can read or manage it. The self-read
        // convenience is owner authority, so a scoped token still routes through
        // the ceiling-aware PDP rather than reading its own identity unconditionally.
        let allowed = (auth.entity_id == id && !auth.scoped)
            || engine::allows_any(
                &state.pool,
                &auth,
                auth.entity_id,
                "entity",
                id,
                &["read", "manage"],
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
        id: Option<String>,
        q: Option<String>,
        kind: Option<GqlEntityKind>,
        external_id: Option<String>,
        profile_id: Option<ID>,
        tenant_id: Option<ID>,
        attributes_contains: Option<Value>,
        parent_group_id: Option<ID>,
        include_descendants: Option<bool>,
        status: Option<GqlEntityStatus>,
        deleted: Option<GqlDeletedFilter>,
        order: Option<GqlEntityOrderField>,
        dir: Option<GqlSortDir>,
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
        let order = parse_entity_order(order);
        let dir = parse_sort_dir(dir);
        let limit = limit.map(i64::from).unwrap_or(20);
        let offset = offset.map(i64::from).unwrap_or(0);

        if deleted != DeletedFilter::Live {
            require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
            let list = repo::list_entities(
                &state.pool,
                entity_model::ListEntities {
                    id,
                    q,
                    kind: parsed_kind,
                    external_id,
                    profile_id,
                    tenant_id,
                    attributes_contains,
                    status: parsed_status,
                    deleted,
                    parent_group_id,
                    include_descendants: include_descendants.unwrap_or(false),
                    limit,
                    offset,
                    order,
                    dir,
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
            &auth,
            AuthorizedObjectIdsQuery {
                subject_id: auth.entity_id,
                action: "read".to_string(),
                object_kind: "entity".to_string(),
                object_type: parsed_kind.as_ref().map(entity_object_type),
                tenant_id,
                id,
                q,
                attributes_contains,
                external_id,
                profile_id,
                entity_status: parsed_status,
                group_type: None,
                parent_group_id,
                include_descendants: include_descendants.unwrap_or(false),
                limit,
                offset,
                entity_order: order,
                resource_order: Default::default(),
                group_order: Default::default(),
                dir,
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
        (!matches!(input.external_id, async_graphql::MaybeUndefined::Undefined))
            .then_some("external_id"),
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
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id,
            target_kind: "entity",
            target_id: id,
            event: "entity.create",
        };
        let details = serde_json::json!({
            "kind": kind,
            "name": input.name,
            "alias": input.alias,
            "external_id": input.external_id,
        });

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
            repo::create_entity_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                entity_model::CreateEntity {
                    id,
                    kind,
                    profile_id,
                    profile_version_id,
                    name: input.name,
                    alias: input.alias,
                    external_id: input.external_id,
                    tenant_id,
                    attributes: input.attributes.unwrap_or_default(),
                },
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
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
        let updated_fields = entity_update_fields(&input);
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        let profile_id = parse_optional_id(input.profile_id, "profileId")?;
        let profile_version_id = parse_optional_id(input.profile_version_id, "profileVersionId")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: None,
            target_kind: "entity",
            target_id: Some(id),
            event: "entity.update",
        };
        let details = serde_json::json!({ "updated_fields": updated_fields });

        let result = async {
            let existing = repo::get_entity(&state.pool, id).await?;
            if auth.entity_id != id {
                crate::auth::require_any_capability(
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

            let update = || {
                repo::update_entity_with_audit(
                    &state.pool,
                    state.config.events.enabled(),
                    Some(auth.entity_id),
                    id,
                    entity_model::UpdateEntity {
                        name: input.name,
                        kind: parse_optional_entity_kind(input.kind),
                        alias: input.alias.into(),
                        external_id: input.external_id.into(),
                        tenant_id,
                        profile_id,
                        profile_version_id,
                        status: input.status.map(Into::into),
                        attributes: input.attributes,
                    },
                    "entity.update",
                    details.clone(),
                )
            };
            let Some(cache) = state.cache.as_deref() else {
                return update().await;
            };
            // Entity kind, tenant, and active status all affect the canonical
            // grant expansion, so keep both cache categories behind one
            // barrier for the complete mutation.
            let entity_status_keys = [crate::cache::keys::entity_status(id)];
            let grants_keys = [crate::cache::keys::grants(id)];
            let groups = [
                (
                    crate::cache::CacheCategory::EntityStatus,
                    entity_status_keys.as_slice(),
                ),
                (crate::cache::CacheCategory::Grants, grants_keys.as_slice()),
            ];
            crate::cache::invalidate::begin_all(cache, &groups).await?;
            let result = update().await;
            crate::cache::invalidate::end_all(cache, &groups).await;
            result
        }
        .await;

        if let Err(ref err) = result {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }

        result.map(Entity::from).map_err(gql_error)
    }

    async fn delete_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: None,
            target_kind: "entity",
            target_id: Some(id),
            event: "entity.delete",
        };
        let details = serde_json::json!({});

        let result = async {
            let existing = repo::get_entity(&state.pool, id).await?;
            if auth.entity_id != id {
                crate::auth::require_any_capability(
                    &state.pool,
                    &auth,
                    &[
                        ("manage", Scope::Object(id)),
                        ("manage", scope_for_tenant(existing.tenant_id)),
                    ],
                )
                .await?;
            }
            crate::identity::service::delete_entity(
                &state.pool,
                state.cache.as_deref(),
                state.config.events.enabled(),
                id,
                Some(auth.entity_id),
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }

        result.map(|_| true).map_err(gql_error)
    }

    /// Restore a soft-deleted entity while it is still within the purge
    /// retention window. Reinstates the identity (and frees the access it
    /// carried), so it is platform-admin-only and audit-logged. Revoked
    /// credentials and sessions are not reinstated — the entity must
    /// re-authenticate.
    async fn restore_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: None,
            target_kind: "entity",
            target_id: Some(id),
            event: "entity.restore",
        };
        let details = serde_json::json!({});

        let result = async {
            crate::auth::require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)])
                .await?;
            // Separate function from `update_entity`/`change_entity_status`,
            // so it needs its own `entity_status` invalidation too.
            crate::cache::invalidate::guarded_mutation(
                state.cache.as_deref(),
                crate::cache::CacheCategory::EntityStatus,
                std::slice::from_ref(&crate::cache::keys::entity_status(id)),
                || {
                    repo::restore_entity_with_audit(
                        &state.pool,
                        state.config.events.enabled(),
                        Some(auth.entity_id),
                        id,
                        Some(auth.entity_id),
                    )
                },
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }

        result.map(|_| true).map_err(gql_error)
    }

    /// Physically purge an already-soft-deleted entity, bypassing the retention
    /// window. Deliberate, irreversible, platform-admin only, and audit-logged.
    async fn purge_entity(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: None,
            target_kind: "entity",
            target_id: Some(id),
            event: "entity.purge",
        };
        let details = serde_json::json!({});

        let result = async {
            crate::auth::require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)])
                .await?;
            repo::purge_entity_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                id,
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }

        result.map(|_| true).map_err(gql_error)
    }

    /// Add the entity to an object group. Membership is many-to-many, so this
    /// adds to the set rather than replacing it, and re-adding an existing
    /// membership is an idempotent no-op.
    async fn add_entity_to_object_group(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        object_group_id: ID,
    ) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let group_id = parse_id(object_group_id, "objectGroupId")?;
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
            repo::add_entity_to_object_group_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                entity_id,
                group_id,
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            let meta = audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: None,
                target_kind: "entity",
                target_id: Some(entity_id),
                event: "entity.object_group.add",
            };
            let details = serde_json::json!({ "group_id": group_id });
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }
        result.map(Entity::from).map_err(gql_error)
    }

    /// Remove the entity from **one** object group; its other memberships, and
    /// the grants that flow through them, are untouched.
    async fn remove_entity_from_object_group(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        object_group_id: ID,
    ) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let group_id = parse_id(object_group_id, "objectGroupId")?;
        let result = async {
            require_entity_group_manage(state, &auth, entity_id).await?;
            repo::remove_entity_from_object_group_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                entity_id,
                group_id,
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            let meta = audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: None,
                target_kind: "entity",
                target_id: Some(entity_id),
                event: "entity.object_group.remove",
            };
            let details = serde_json::json!({ "group_id": group_id });
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }
        result.map(Entity::from).map_err(gql_error)
    }

    /// Remove the entity from **every** object group it belongs to. Kept
    /// distinct from `removeEntityFromObjectGroup` so "clear the group" can
    /// never be read as either one by accident.
    async fn clear_entity_object_groups(&self, ctx: &Context<'_>, entity_id: ID) -> Result<Entity> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let result = async {
            require_entity_group_manage(state, &auth, entity_id).await?;
            repo::clear_entity_object_groups_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                entity_id,
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            let meta = audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: None,
                target_kind: "entity",
                target_id: Some(entity_id),
                event: "entity.object_groups.clear",
            };
            let details = serde_json::json!({});
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &meta,
                &details,
                err,
            )
            .await;
        }
        result.map(Entity::from).map_err(gql_error)
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
    let details = serde_json::json!({});
    let meta = audit::AuditMeta {
        actor_entity_id: Some(auth.entity_id),
        tenant_id: None,
        target_kind: "entity",
        target_id: Some(entity_id),
        event,
    };
    let result = async {
        let existing = repo::get_entity(&state.pool, entity_id).await?;
        crate::auth::require_any_capability(
            &state.pool,
            &auth,
            &[
                ("manage", scope_for_tenant(existing.tenant_id)),
                ("write", scope_for_tenant(existing.tenant_id)),
            ],
        )
        .await?;
        crate::cache::invalidate::guarded_mutation(
            state.cache.as_deref(),
            crate::cache::CacheCategory::EntityStatus,
            std::slice::from_ref(&crate::cache::keys::entity_status(entity_id)),
            || {
                repo::update_entity_with_audit(
                    &state.pool,
                    state.config.events.enabled(),
                    Some(auth.entity_id),
                    entity_id,
                    entity_model::UpdateEntity {
                        name: None,
                        kind: None,
                        alias: None,
                        external_id: None,
                        tenant_id: None,
                        profile_id: None,
                        profile_version_id: None,
                        status: Some(status),
                        attributes: None,
                    },
                    event,
                    details.clone(),
                )
            },
        )
        .await
    }
    .await;
    if let Err(ref err) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &meta,
            &details,
            err,
        )
        .await;
    }
    result.map(Into::into).map_err(gql_error)
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

/// Group-membership mutations on an entity need write/manage over the entity
/// itself (or its tenant). Shared by remove-from-one and remove-from-all so the
/// two removal semantics cannot drift apart on authorization.
async fn require_entity_group_manage(
    state: &AppState,
    auth: &AuthContext,
    entity_id: uuid::Uuid,
) -> std::result::Result<(), AppError> {
    let entity = repo::get_entity(&state.pool, entity_id).await?;
    crate::auth::require_any_capability(
        &state.pool,
        auth,
        &[
            ("manage", Scope::Object(entity_id)),
            ("write", Scope::Object(entity_id)),
            ("manage", scope_for_tenant(entity.tenant_id)),
            ("write", scope_for_tenant(entity.tenant_id)),
        ],
    )
    .await
}
