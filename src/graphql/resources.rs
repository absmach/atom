use async_graphql::{Context, Object, Result, ID};
use serde_json::Value;

use crate::{
    audit,
    auth::Scope,
    authz::{engine, repo as authz_repo},
    error::AppError,
    models::{
        access::AuthorizedObjectIdsQuery,
        enums::{AuditOutcome, DeletedFilter},
        resource::{CreateResource, ListResources, UpdateResource},
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_any_capability, require_auth, scope_for_tenant},
    types::{
        parse_deleted_filter, parse_id, parse_optional_id, CreateResourceInput, GqlDeletedFilter,
        Resource, ResourceList, UpdateResourceInput,
    },
};

#[derive(Default)]
pub struct ResourceQuery;

#[Object]
impl ResourceQuery {
    async fn resource_kinds(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
    ) -> Result<Vec<String>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;

        authz_repo::authorized_resource_kinds(&state.pool, &auth, auth.entity_id, tenant_id)
            .await
            .map_err(gql_error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn resources(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        kind: Option<String>,
        tenant_id: Option<ID>,
        attributes_contains: Option<Value>,
        parent_group_id: Option<ID>,
        include_descendants: Option<bool>,
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<ResourceList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        let parent_group_id = parse_optional_id(parent_group_id, "parentGroupId")?;
        let deleted = parse_deleted_filter(deleted);
        let limit = limit.map(i64::from).unwrap_or(20);
        let offset = offset.map(i64::from).unwrap_or(0);
        let include_descendants = include_descendants.unwrap_or(false);

        if deleted != DeletedFilter::Live {
            require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
            let list = authz_repo::list_resources(
                &state.pool,
                ListResources {
                    q,
                    kind: kind.clone(),
                    tenant_id,
                    attributes_contains,
                    parent_group_id,
                    include_descendants,
                    deleted,
                    limit,
                    offset,
                },
            )
            .await
            .map_err(gql_error)?;
            return Ok(ResourceList {
                items: list.items.into_iter().map(Resource::from).collect(),
                total: list.total,
            });
        }

        let object_type = kind.as_deref().map(|kind| {
            if kind.contains(':') {
                kind.to_string()
            } else {
                format!("resource:{kind}")
            }
        });
        let authorized = authz_repo::authorized_object_ids(
            &state.pool,
            &auth,
            AuthorizedObjectIdsQuery {
                subject_id: auth.entity_id,
                action: "read".to_string(),
                object_kind: "resource".to_string(),
                object_type,
                tenant_id,
                q,
                attributes_contains,
                profile_id: None,
                entity_status: None,
                group_type: None,
                parent_group_id,
                include_descendants,
                limit,
                offset,
            },
        )
        .await
        .map_err(gql_error)?;
        let items = authz_repo::list_resources_by_ids(&state.pool, &authorized.ids)
            .await
            .map_err(gql_error)?;

        Ok(ResourceList {
            items: items.into_iter().map(Resource::from).collect(),
            total: authorized.total,
        })
    }

    async fn resource(&self, ctx: &Context<'_>, id: ID) -> Result<Resource> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let resource = authz_repo::get_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;
        // Object read decision via the PDP. `manage` implies `read`, so the caller
        // may read the resource if they can read or manage it.
        if !engine::allows_any(
            &state.pool,
            &auth,
            auth.entity_id,
            "resource",
            id,
            &["read", "manage"],
        )
        .await
        .map_err(gql_error)?
        {
            return Err(gql_error(AppError::Forbidden));
        }
        Ok(resource.into())
    }
}

#[derive(Default)]
pub struct ResourceMutation;

fn resource_update_fields(input: &UpdateResourceInput) -> Vec<&'static str> {
    [
        input.name.is_some().then_some("name"),
        (!matches!(input.alias, async_graphql::MaybeUndefined::Undefined)).then_some("alias"),
        input.attributes.is_some().then_some("attributes"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

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
        let kind = input.kind.clone();
        let id = parse_optional_id(input.id, "id")?;
        let owner_id = parse_optional_id(input.owner_id, "ownerId")?;
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
            authz_repo::create_resource(
                &state.pool,
                CreateResource {
                    id,
                    kind: input.kind,
                    name: input.name,
                    alias: input.alias,
                    tenant_id,
                    owner_id,
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
                target_kind: "resource",
                target_id: result.as_ref().ok().map(|r| r.id),
                event: "resource.create",
            },
            serde_json::json!({ "kind": kind }),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
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
        let updated_fields = resource_update_fields(&input);
        require_any_capability(
            &state.pool,
            &auth,
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
                alias: input.alias.into(),
                attributes: input.attributes,
            },
        )
        .await
        .map_err(gql_error)?;

        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: resource.tenant_id,
                target_kind: Some("resource"),
                target_id: Some(id),
                event: "resource.update",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({ "updated_fields": updated_fields }),
            },
        )
        .await;

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
            &auth,
            &[
                ("manage", crate::auth::Scope::Object(id)),
                ("manage", scope_for_tenant(existing.tenant_id)),
            ],
        )
        .await?;

        authz_repo::delete_resource(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;

        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: existing.tenant_id,
                target_kind: Some("resource"),
                target_id: Some(id),
                event: "resource.delete",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;

        Ok(true)
    }

    /// Restore a soft-deleted resource within the retention window. Platform-admin
    /// only and audit-logged.
    async fn restore_resource(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
        let id = parse_id(id, "id")?;
        authz_repo::restore_resource(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        let resource = authz_repo::get_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: resource.tenant_id,
                target_kind: Some("resource"),
                target_id: Some(id),
                event: "resource.restore",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
        Ok(true)
    }

    /// Physically purge an already-soft-deleted resource, bypassing the retention
    /// window. Deliberate, irreversible, platform-admin only, and audit-logged.
    async fn purge_resource(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
        let id = parse_id(id, "id")?;
        let tenant_id = authz_repo::purge_resource(&state.pool, id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("resource"),
                target_id: Some(id),
                event: "resource.purge",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({}),
            },
        )
        .await;
        Ok(true)
    }

    async fn set_resource_parent_group(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
        group_id: ID,
    ) -> Result<Resource> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let resource_id = parse_id(resource_id, "resourceId")?;
        let group_id = parse_id(group_id, "groupId")?;
        let result = async {
            let resource = authz_repo::get_resource(&state.pool, resource_id).await?;
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", crate::auth::Scope::Object(resource_id)),
                    ("write", crate::auth::Scope::Object(resource_id)),
                    ("write", crate::auth::Scope::Object(group_id)),
                    ("manage", scope_for_tenant(resource.tenant_id)),
                    ("write", scope_for_tenant(resource.tenant_id)),
                ],
            )
            .await?;
            authz_repo::set_resource_parent_group(&state.pool, resource_id, group_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|r| r.tenant_id),
                target_kind: "resource",
                target_id: Some(resource_id),
                event: "resource.parent_group.set",
            },
            serde_json::json!({ "group_id": group_id }),
            &result,
        );
        result.map(Resource::from).map_err(gql_error)
    }

    async fn add_resource_to_object_group(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
        object_group_id: ID,
    ) -> Result<Resource> {
        self.set_resource_parent_group(ctx, resource_id, object_group_id)
            .await
    }

    async fn clear_resource_parent_group(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
    ) -> Result<Resource> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let resource_id = parse_id(resource_id, "resourceId")?;
        let result = async {
            let resource = authz_repo::get_resource(&state.pool, resource_id).await?;
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", crate::auth::Scope::Object(resource_id)),
                    ("write", crate::auth::Scope::Object(resource_id)),
                    ("manage", scope_for_tenant(resource.tenant_id)),
                    ("write", scope_for_tenant(resource.tenant_id)),
                ],
            )
            .await?;
            authz_repo::clear_resource_parent_group(&state.pool, resource_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: result.as_ref().ok().and_then(|r| r.tenant_id),
                target_kind: "resource",
                target_id: Some(resource_id),
                event: "resource.parent_group.clear",
            },
            serde_json::json!({}),
            &result,
        );
        result.map(Resource::from).map_err(gql_error)
    }

    async fn remove_resource_from_object_group(
        &self,
        ctx: &Context<'_>,
        resource_id: ID,
    ) -> Result<Resource> {
        self.clear_resource_parent_group(ctx, resource_id).await
    }
}
