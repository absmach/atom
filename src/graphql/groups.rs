use async_graphql::{Context, Object, Result, ID};

use crate::{
    audit,
    auth::{AuthContext, Scope},
    authz::{engine, repo as authz_repo},
    error::AppError,
    identity::repo,
    models::{
        access::AuthorizedObjectIdsQuery,
        enums::{AuditOutcome, DeletedFilter, EntityStatus},
        group::{CreateGroup, ListGroups, UpdateGroup},
        policy::AuthzRequest,
    },
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_read_access, scope_for_tenant,
    },
    types::{
        parse_deleted_filter, parse_id, parse_optional_entity_status, parse_optional_id,
        CreateGroupInput, Entity, GqlDeletedFilter, GqlEntityStatus, Group, GroupList,
        UpdateGroupInput,
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
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<GroupList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        authorized_group_list(
            state,
            &auth,
            None,
            q,
            tenant_id,
            parse_optional_id(parent_id, "parentId")?,
            parse_optional_entity_status(status),
            parse_deleted_filter(deleted),
            limit,
            offset,
        )
        .await
    }

    async fn group(&self, ctx: &Context<'_>, id: ID) -> Result<Group> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        if !engine::evaluate(
            &state.pool,
            &AuthzRequest {
                subject_id: auth.entity_id,
                action: "read".to_string(),
                resource_id: None,
                object_kind: Some("group".to_string()),
                object_id: Some(id),
                context: serde_json::Value::Null,
            },
            auth.ceiling_for(auth.entity_id),
        )
        .await
        .map_err(gql_error)?
        .allowed
        {
            require_read_access(&state.pool, &auth, group.tenant_id, id).await?;
        }
        Ok(group.into())
    }

    async fn group_members(&self, ctx: &Context<'_>, group_id: ID) -> Result<Vec<Entity>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let group_id = parse_id(group_id, "groupId")?;
        let group = repo::get_group(&state.pool, group_id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, &auth, group.tenant_id, group_id).await?;
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
        require_read_access(&state.pool, &auth, entity.tenant_id, entity_id).await?;
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
        // Reading the parent is a precondition for enumerating its children; the
        // per-child read decision is then made by authorized listing below, so
        // paging and totals reflect the actual authorized set.
        require_read_access(&state.pool, &auth, group.tenant_id, parent_id).await?;
        authorized_group_list(
            state,
            &auth,
            None,
            None,
            None,
            Some(parent_id),
            None,
            DeletedFilter::Live,
            limit,
            offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn object_groups(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        tenant_id: Option<ID>,
        parent_id: Option<ID>,
        status: Option<GqlEntityStatus>,
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<GroupList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        authorized_group_list(
            state,
            &auth,
            Some("object".to_string()),
            q,
            tenant_id,
            parse_optional_id(parent_id, "parentId")?,
            parse_optional_entity_status(status),
            parse_deleted_filter(deleted),
            limit,
            offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn principal_groups(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        tenant_id: Option<ID>,
        status: Option<GqlEntityStatus>,
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<GroupList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        authorized_group_list(
            state,
            &auth,
            Some("principal".to_string()),
            q,
            tenant_id,
            None,
            parse_optional_entity_status(status),
            parse_deleted_filter(deleted),
            limit,
            offset,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn authorized_group_list(
    state: &AppState,
    auth: &AuthContext,
    group_type: Option<String>,
    q: Option<String>,
    tenant_id: Option<uuid::Uuid>,
    parent_group_id: Option<uuid::Uuid>,
    status: Option<EntityStatus>,
    deleted: DeletedFilter,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<GroupList> {
    let limit_value = limit.map(i64::from).unwrap_or(20);
    let offset_value = offset.map(i64::from).unwrap_or(0);
    let subject_id = auth.entity_id;

    if deleted != DeletedFilter::Live {
        require_any_capability(&state.pool, auth, &[("manage", Scope::Platform)]).await?;
        let list = repo::list_groups(
            &state.pool,
            ListGroups {
                q: q.clone(),
                tenant_id,
                group_type: group_type.clone(),
                parent_id: parent_group_id,
                status,
                deleted,
                limit: limit_value,
                offset: offset_value,
            },
        )
        .await
        .map_err(gql_error)?;
        return Ok(GroupList {
            items: list.items.into_iter().map(Group::from).collect(),
            total: list.total,
        });
    }

    let authorized = authz_repo::authorized_object_ids(
        &state.pool,
        AuthorizedObjectIdsQuery {
            subject_id,
            action: "read".to_string(),
            object_kind: "group".to_string(),
            object_type: None,
            tenant_id,
            q,
            attributes_contains: None,
            profile_id: None,
            entity_status: status,
            group_type,
            parent_group_id,
            include_descendants: false,
            limit: limit_value,
            offset: offset_value,
        },
    )
    .await
    .map_err(gql_error)?;
    let items = repo::list_groups_by_ids(&state.pool, &authorized.ids)
        .await
        .map_err(gql_error)?;
    Ok(GroupList {
        items: items.into_iter().map(Group::from).collect(),
        total: authorized.total,
    })
}

#[derive(Default)]
pub struct GroupMutation;

#[Object]
impl GroupMutation {
    async fn create_group(&self, ctx: &Context<'_>, input: CreateGroupInput) -> Result<Group> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        let group_type = input.group_type.clone();
        let id = parse_optional_id(input.id, "id")?;
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
            repo::create_group(
                &state.pool,
                CreateGroup {
                    id,
                    name: input.name,
                    tenant_id,
                    group_type: input.group_type,
                    description: input.description,
                    attributes: input.attributes.unwrap_or(serde_json::Value::Null),
                },
            )
            .await
        }
        .await;

        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: "group",
                target_id: result.as_ref().ok().map(|g| g.id),
                event: "group.create",
            },
            serde_json::json!({ "group_type": group_type }),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
    }

    async fn create_object_group(
        &self,
        ctx: &Context<'_>,
        mut input: CreateGroupInput,
    ) -> Result<Group> {
        input.group_type = Some("object".to_string());
        self.create_group(ctx, input).await
    }

    async fn create_principal_group(
        &self,
        ctx: &Context<'_>,
        mut input: CreateGroupInput,
    ) -> Result<Group> {
        input.group_type = Some("principal".to_string());
        self.create_group(ctx, input).await
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
        let result = async {
            let existing = repo::get_group(&state.pool, id).await?;
            require_group_manage_app(&state.pool, &auth, id, existing.tenant_id).await?;
            repo::update_group(
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
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|g| g.tenant_id),
                target_kind: "group",
                target_id: Some(id),
                event: "group.update",
            },
            serde_json::json!({}),
            &result,
        );
        result.map(Into::into).map_err(gql_error)
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
        let result = async {
            let group = repo::get_group(&state.pool, id).await?;
            require_group_manage_app(&state.pool, &auth, id, group.tenant_id).await?;
            repo::set_group_parent(&state.pool, id, parent_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|g| g.tenant_id),
                target_kind: "group",
                target_id: Some(id),
                event: "group.parent.set",
            },
            serde_json::json!({ "parent_id": parent_id }),
            &result,
        );
        result.map(Into::into).map_err(gql_error)
    }

    async fn set_object_group_parent(
        &self,
        ctx: &Context<'_>,
        object_group_id: ID,
        parent_group_id: ID,
    ) -> Result<Group> {
        self.set_group_parent(ctx, object_group_id, parent_group_id)
            .await
    }

    async fn remove_group_parent(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let result = async {
            let group = repo::get_group(&state.pool, id).await?;
            let tenant_id = group.tenant_id;
            require_group_manage_app(&state.pool, &auth, id, tenant_id).await?;
            repo::remove_group_parent(&state.pool, id).await?;
            Ok(tenant_id)
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().copied().flatten(),
                target_kind: "group",
                target_id: Some(id),
                event: "group.parent.remove",
            },
            serde_json::json!({}),
            &result,
        );
        result.map(|_| true).map_err(gql_error)
    }

    async fn remove_object_group_parent(
        &self,
        ctx: &Context<'_>,
        object_group_id: ID,
    ) -> Result<bool> {
        self.remove_group_parent(ctx, object_group_id).await
    }

    async fn delete_group(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let result = async {
            let existing = repo::get_group(&state.pool, id).await?;
            let tenant_id = existing.tenant_id;
            require_group_manage_app(&state.pool, &auth, id, tenant_id).await?;
            repo::delete_group(&state.pool, id, Some(auth.entity_id)).await?;
            Ok(tenant_id)
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().copied().flatten(),
                target_kind: "group",
                target_id: Some(id),
                event: "group.delete",
            },
            serde_json::json!({}),
            &result,
        );
        result.map(|_| true).map_err(gql_error)
    }

    /// Restore a soft-deleted group within the retention window. Platform-admin
    /// only and audit-logged, since restoring a group reinstates the membership
    /// paths and grants that flowed through it.
    async fn restore_group(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
        let id = parse_id(id, "id")?;
        repo::restore_group(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        let group = repo::get_group(&state.pool, id).await.map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: group.tenant_id,
                target_kind: Some("group"),
                target_id: Some(id),
                event: "group.restore",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
        Ok(true)
    }

    /// Physically purge an already-soft-deleted group, bypassing the retention
    /// window. Deliberate, irreversible, platform-admin only, and audit-logged.
    async fn purge_group(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
        let id = parse_id(id, "id")?;
        let tenant_id = repo::purge_group(&state.pool, id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("group"),
                target_id: Some(id),
                event: "group.purge",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
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
        let result = async {
            let group = repo::get_group(&state.pool, group_id).await?;
            let tenant_id = group.tenant_id;
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", crate::auth::Scope::Object(group_id)),
                    ("manage", scope_for_tenant(tenant_id)),
                ],
            )
            .await?;
            repo::add_group_member(&state.pool, group_id, entity_id).await?;
            Ok(tenant_id)
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().copied().flatten(),
                target_kind: "group",
                target_id: Some(group_id),
                event: "group_member.add",
            },
            serde_json::json!({ "entity_id": entity_id }),
            &result,
        );
        result.map(|_| true).map_err(gql_error)
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
        let result = async {
            let group = repo::get_group(&state.pool, group_id).await?;
            let tenant_id = group.tenant_id;
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", crate::auth::Scope::Object(group_id)),
                    ("manage", scope_for_tenant(tenant_id)),
                ],
            )
            .await?;
            repo::remove_group_member(&state.pool, group_id, entity_id).await?;
            Ok(tenant_id)
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().copied().flatten(),
                target_kind: "group",
                target_id: Some(group_id),
                event: "group_member.remove",
            },
            serde_json::json!({ "entity_id": entity_id }),
            &result,
        );
        result.map(|_| true).map_err(gql_error)
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
        let event = group_status_event(&status);
        let status_detail = status.clone();
        let result = async {
            let group = repo::get_group(&state.pool, id).await?;
            require_group_manage_app(&state.pool, &auth, id, group.tenant_id).await?;
            repo::update_group(
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
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|g| g.tenant_id),
                target_kind: "group",
                target_id: Some(id),
                event,
            },
            serde_json::json!({ "status": status_detail }),
            &result,
        );
        result.map(Into::into).map_err(gql_error)
    }
}

fn group_status_event(status: &EntityStatus) -> &'static str {
    match status {
        EntityStatus::Active => "group.enable",
        EntityStatus::Inactive => "group.disable",
        EntityStatus::Suspended => "group.suspend",
    }
}

async fn require_group_manage_app(
    pool: &sqlx::PgPool,
    auth: &AuthContext,
    group_id: uuid::Uuid,
    tenant_id: Option<uuid::Uuid>,
) -> std::result::Result<(), AppError> {
    crate::auth::require_any_capability(
        pool,
        auth,
        &[
            ("manage", Scope::Object(group_id)),
            ("manage", scope_for_tenant(tenant_id)),
        ],
    )
    .await
}
