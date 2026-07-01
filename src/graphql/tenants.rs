use async_graphql::{Context, Object, Result, SimpleObject, ID};

use crate::{
    audit,
    auth::{has_capability_in_scope, require_capability, AuthContext, Scope},
    authz::engine,
    error::AppError,
    models::{
        enums::{AuditOutcome, DeletedFilter, TenantStatus},
        tenant as tenant_model,
        tenant::ListTenants,
    },
    state::AppState,
    tenants::{email as tenant_email, repo as tenant_repo},
};

use super::{
    auth::{gql_error, require_any_capability, require_auth},
    types::{
        parse_deleted_filter, parse_id, parse_optional_id, parse_optional_tenant_status,
        CreateTenantInput, CreateTenantInvitationInput, EntityList, GqlDeletedFilter,
        GqlTenantStatus, InvitationTokenInput, Tenant, TenantInvitation, TenantInvitationList,
        TenantList, UpdateTenantInput,
    },
};

#[derive(Default)]
pub struct TenantQuery;

#[derive(Clone, SimpleObject)]
pub struct TenantRoleAssignment {
    role_id: ID,
    role_name: String,
    /// Actions defined by the role's permission blocks. This is role metadata,
    /// not a claim that every action is currently authorized.
    actions: Vec<String>,
    assignment_paths: Vec<String>,
}

#[Object]
impl TenantQuery {
    #[allow(clippy::too_many_arguments)]
    async fn tenants(
        &self,
        ctx: &Context<'_>,
        q: Option<String>,
        name: Option<String>,
        alias: Option<String>,
        status: Option<GqlTenantStatus>,
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<TenantList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let deleted = parse_deleted_filter(deleted);
        let params = ListTenants {
            q,
            name,
            alias,
            status: parse_optional_tenant_status(status),
            deleted,
            limit: limit.map(i64::from).unwrap_or(20),
            offset: offset.map(i64::from).unwrap_or(0),
        };
        let list = if deleted != DeletedFilter::Live {
            require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)])
                .await?;
            tenant_repo::list_tenants(&state.pool, params)
                .await
                .map_err(gql_error)?
        } else if can_list_all_tenants(&state.pool, &auth).await? {
            tenant_repo::list_tenants(&state.pool, params)
                .await
                .map_err(gql_error)?
        } else {
            tenant_repo::list_tenants_for_entity(&state.pool, auth.entity_id, params)
                .await
                .map_err(gql_error)?
        };

        Ok(TenantList {
            items: list.items.into_iter().map(Tenant::from).collect(),
            total: list.total,
        })
    }

    async fn tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        require_tenant_read_access(state, auth.entity_id, id, auth.ceiling_for(auth.entity_id))
            .await?;
        let tenant = tenant_repo::get_tenant(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(tenant.into())
    }

    async fn tenant_members(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        q: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<EntityList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_any_capability(
            &state.pool,
            &auth,
            &[
                ("manage", Scope::Tenant(tenant_id)),
                ("role.manage", Scope::Tenant(tenant_id)),
                ("policy.manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        let list = tenant_repo::list_tenant_members(
            &state.pool,
            tenant_id,
            q,
            limit.map(i64::from).unwrap_or(20),
            offset.map(i64::from).unwrap_or(0),
        )
        .await
        .map_err(gql_error)?;

        Ok(EntityList {
            items: list.items.into_iter().map(Into::into).collect(),
            total: list.total,
        })
    }

    async fn tenant_assignable_entities(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        q: String,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<EntityList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        let q = q.trim().to_string();
        if q.len() < 3 {
            return Err(gql_error(crate::error::AppError::bad_request(
                "q must contain at least 3 characters",
            )));
        }
        require_any_capability(
            &state.pool,
            &auth,
            &[
                ("manage", Scope::Tenant(tenant_id)),
                ("role.manage", Scope::Tenant(tenant_id)),
                ("policy.manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        let list = tenant_repo::list_tenant_assignable_entities(
            &state.pool,
            tenant_id,
            q,
            limit.map(i64::from).unwrap_or(20),
            offset.map(i64::from).unwrap_or(0),
        )
        .await
        .map_err(gql_error)?;

        Ok(EntityList {
            items: list.items.into_iter().map(Into::into).collect(),
            total: list.total,
        })
    }

    async fn tenant_invitations(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<TenantInvitationList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_any_capability(
            &state.pool,
            &auth,
            &[
                ("manage", Scope::Tenant(tenant_id)),
                ("policy.manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        let list = tenant_repo::list_tenant_invitations(
            &state.pool,
            tenant_id,
            tenant_model::ListTenantInvitations {
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(TenantInvitationList {
            items: list.items.into_iter().map(TenantInvitation::from).collect(),
            total: list.total,
        })
    }

    async fn my_tenant_roles(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
    ) -> Result<Vec<TenantRoleAssignment>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_tenant_read_access(state, auth.entity_id, tenant_id, auth.ceiling_for(auth.entity_id))
            .await?;
        let roles =
            tenant_repo::list_tenant_role_assignments(&state.pool, tenant_id, auth.entity_id)
                .await
                .map_err(gql_error)?;
        Ok(roles
            .into_iter()
            .map(|role| TenantRoleAssignment {
                role_id: ID::from(role.role_id.to_string()),
                role_name: role.role_name,
                actions: role.actions,
                assignment_paths: role.assignment_paths,
            })
            .collect())
    }

    async fn my_tenant_invitations(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<TenantInvitationList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let list = tenant_repo::list_user_invitations(
            &state.pool,
            auth.entity_id,
            tenant_model::ListTenantInvitations {
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(TenantInvitationList {
            items: list.items.into_iter().map(TenantInvitation::from).collect(),
            total: list.total,
        })
    }
}

#[derive(Default)]
pub struct TenantMutation;

#[Object]
impl TenantMutation {
    async fn create_tenant(&self, ctx: &Context<'_>, input: CreateTenantInput) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_optional_id(input.id, "id")?;
        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[("manage", Scope::Platform), ("create", Scope::Platform)],
            )
            .await?;
            tenant_repo::create_tenant(
                &state.pool,
                tenant_model::CreateTenant {
                    id,
                    name: input.name,
                    alias: input.alias,
                    tags: input.tags.unwrap_or_default(),
                    attributes: input.attributes.unwrap_or(serde_json::Value::Null),
                },
                Some(auth.entity_id),
            )
            .await
        }
        .await;

        let tenant_id = result.as_ref().ok().map(|t| t.id);
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: "tenant",
                target_id: tenant_id,
                event: "tenant.create",
            },
            serde_json::json!({}),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
    }

    async fn update_tenant(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateTenantInput,
    ) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(id, "id")?;
        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", Scope::Platform),
                    ("manage", Scope::Tenant(tenant_id)),
                ],
            )
            .await?;
            tenant_repo::update_tenant(
                &state.pool,
                tenant_id,
                tenant_model::UpdateTenant {
                    name: input.name,
                    alias: input.alias.into(),
                    tags: input.tags,
                    attributes: input.attributes,
                },
                Some(auth.entity_id),
            )
            .await
        }
        .await;

        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant_id),
                target_kind: "tenant",
                target_id: Some(tenant_id),
                event: "tenant.update",
            },
            serde_json::json!({}),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
    }

    async fn delete_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(id, "id")?;
        let result = async {
            crate::auth::require_capability(&state.pool, &auth, "manage", Scope::Platform)
                .await?;
            tenant_repo::soft_delete_tenant(&state.pool, tenant_id, Some(auth.entity_id)).await
        }
        .await;

        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant_id),
                target_kind: "tenant",
                target_id: Some(tenant_id),
                event: "tenant.delete",
            },
            serde_json::json!({}),
            &result,
        );

        result.map(|_| true).map_err(gql_error)
    }

    /// Restore a soft-deleted tenant within the retention window. Reactivates the
    /// tenant and un-hides its children automatically; revoked sessions and
    /// certificates are not reinstated, so members must re-authenticate.
    /// Admin-only and audit-logged.
    async fn restore_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, &auth, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;

        let tenant_id = parse_id(id, "id")?;
        let tenant = tenant_repo::restore_tenant(&state.pool, tenant_id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant.id),
                target_kind: Some("tenant"),
                target_id: Some(tenant.id),
                event: "tenant.restore",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "tenant_name": tenant.name,
                }),
            },
        )
        .await;

        Ok(tenant.into())
    }

    /// Physically purge an already-soft-deleted tenant and all its data,
    /// bypassing the purge retention window. Deliberate, irreversible, admin-only.
    async fn purge_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, &auth, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;

        let tenant_id = parse_id(id, "id")?;
        let purged = tenant_repo::purge_tenant(&state.pool, tenant_id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: None,
                target_kind: Some("tenant"),
                target_id: Some(purged.id),
                event: "tenant.purge",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "tenant_name": purged.name,
                }),
            },
        )
        .await;

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

    async fn create_tenant_invitation(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        input: CreateTenantInvitationInput,
    ) -> Result<TenantInvitation> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_any_capability(
            &state.pool,
            &auth,
            &[
                ("manage", Scope::Tenant(tenant_id)),
                ("policy.manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;

        let redirect_url = input
            .redirect_url
            .clone()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| state.config.invitation_redirect.clone());
        let created = tenant_repo::create_invitation(
            &state.pool,
            tenant_id,
            auth.entity_id,
            tenant_model::CreateTenantInvitation {
                invitee_user_id: parse_optional_id(input.invitee_user_id, "inviteeUserId")?,
                invitee_email: input.invitee_email,
                role_id: parse_optional_id(input.role_id, "roleId")?,
                resend: input.resend.unwrap_or(false),
                redirect_url: input.redirect_url,
            },
            state.config.invitation_expiry_secs,
        )
        .await
        .map_err(gql_error)?;

        if let (Some(email), Some(token)) = (created.email.as_deref(), created.token.as_deref()) {
            tenant_email::send_invitation_email(&state.config, email, &redirect_url, token)
                .await
                .map_err(gql_error)?;
        }

        Ok(created.invitation.into())
    }

    async fn accept_tenant_invitation(&self, ctx: &Context<'_>, tenant_id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        tenant_repo::accept_invitation(
            &state.pool,
            parse_id(tenant_id, "tenantId")?,
            auth.entity_id,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn accept_tenant_invitation_token(
        &self,
        ctx: &Context<'_>,
        input: InvitationTokenInput,
    ) -> Result<ID> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id =
            tenant_repo::accept_invitation_token(&state.pool, &input.token, auth.entity_id)
                .await
                .map_err(gql_error)?;
        Ok(ID::from(tenant_id.to_string()))
    }

    async fn reject_tenant_invitation(&self, ctx: &Context<'_>, tenant_id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        tenant_repo::reject_invitation(
            &state.pool,
            parse_id(tenant_id, "tenantId")?,
            auth.entity_id,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn revoke_tenant_invitation(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        invitation_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_capability(
            &state.pool,
            &auth,
            "policy.manage",
            Scope::Tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        tenant_repo::revoke_invitation_by_id(
            &state.pool,
            tenant_id,
            parse_id(invitation_id, "invitationId")?,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn remove_tenant_member(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        entity_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let result = async {
            crate::auth::require_capability(
                &state.pool,
                &auth,
                "policy.manage",
                Scope::Tenant(tenant_id),
            )
            .await?;
            tenant_repo::remove_tenant_member(&state.pool, tenant_id, entity_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant_id),
                target_kind: "tenant",
                target_id: Some(tenant_id),
                event: "tenant_member.remove",
            },
            serde_json::json!({ "entity_id": entity_id }),
            &result,
        );
        result.map(|_| true).map_err(gql_error)
    }

    async fn add_tenant_member(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        entity_id: ID,
        role_id: Option<ID>,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let role_id = role_id.map(|id| parse_id(id, "roleId")).transpose()?;
        let result = async {
            crate::auth::require_capability(
                &state.pool,
                &auth,
                "policy.manage",
                Scope::Tenant(tenant_id),
            )
            .await?;
            tenant_repo::add_tenant_member(&state.pool, tenant_id, entity_id, role_id).await
        }
        .await;
        audit::observe_result(
            audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant_id),
                target_kind: "tenant",
                target_id: Some(tenant_id),
                event: "tenant_member.add",
            },
            serde_json::json!({ "entity_id": entity_id, "role_id": role_id }),
            &result,
        );
        result.map(|_| true).map_err(gql_error)
    }
}

async fn change_tenant_status(ctx: &Context<'_>, id: ID, status: TenantStatus) -> Result<Tenant> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    let tenant_id = parse_id(id, "id")?;
    let event = tenant_status_event(&status);
    let status_detail = status.clone();
    let result = async {
        crate::auth::require_capability(&state.pool, &auth, "manage", Scope::Platform)
            .await?;
        tenant_repo::change_tenant_status(&state.pool, tenant_id, status, Some(auth.entity_id))
            .await
    }
    .await;
    audit::observe_result(
        audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: Some(tenant_id),
            target_kind: "tenant",
            target_id: Some(tenant_id),
            event,
        },
        serde_json::json!({ "status": status_detail }),
        &result,
    );
    result.map(Into::into).map_err(gql_error)
}

fn tenant_status_event(status: &TenantStatus) -> &'static str {
    match status {
        TenantStatus::Active => "tenant.enable",
        TenantStatus::Inactive => "tenant.disable",
        TenantStatus::Frozen => "tenant.freeze",
        TenantStatus::Deleted => "tenant.delete",
    }
}

async fn require_tenant_read_access(
    state: &AppState,
    entity_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    ceiling: Option<&crate::authz::repo::CredentialCeiling>,
) -> Result<()> {
    if engine::allows_any(
        &state.pool,
        entity_id,
        "tenant",
        tenant_id,
        &["read", "manage"],
        ceiling,
    )
    .await
    .map_err(gql_error)?
    {
        Ok(())
    } else {
        Err(gql_error(AppError::Forbidden))
    }
}

async fn can_list_all_tenants(pool: &sqlx::PgPool, auth: &AuthContext) -> Result<bool> {
    for capability in ["read", "manage"] {
        if has_capability_in_scope(pool, auth, capability, Scope::Platform)
            .await
            .map_err(gql_error)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
