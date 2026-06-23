use async_graphql::{Context, Object, Result, SimpleObject, ID};

use crate::{
    auth::{has_capability_in_scope, require_capability, Scope},
    authz::engine,
    error::AppError,
    models::{enums::TenantStatus, tenant as tenant_model, tenant::ListTenants},
    state::AppState,
    tenants::{handlers as tenant_handlers, repo as tenant_repo},
};

use super::{
    auth::{gql_error, require_any_capability, require_auth},
    types::{
        parse_id, parse_optional_id, parse_optional_tenant_status, CreateTenantInput,
        CreateTenantInvitationInput, EntityList, GqlTenantStatus, InvitationTokenInput, Tenant,
        TenantInvitation, TenantInvitationList, TenantList, UpdateTenantInput,
    },
};

#[derive(Default)]
pub struct TenantQuery;

#[derive(Clone, SimpleObject)]
pub struct TenantRoleAction {
    role_id: ID,
    role_name: String,
    actions: Vec<String>,
    access_type: String,
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
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<TenantList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let params = ListTenants {
            q,
            name,
            alias,
            status: parse_optional_tenant_status(status),
            limit: limit.map(i64::from).unwrap_or(20),
            offset: offset.map(i64::from).unwrap_or(0),
        };
        let list = if can_list_all_tenants(&state.pool, auth.entity_id).await? {
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
        require_tenant_read_access(state, auth.entity_id, id).await?;
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
        require_tenant_read_access(state, auth.entity_id, tenant_id).await?;
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
            auth.entity_id,
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
        require_tenant_read_access(state, auth.entity_id, tenant_id).await?;
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
    ) -> Result<Vec<TenantRoleAction>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_tenant_read_access(state, auth.entity_id, tenant_id).await?;
        let roles = tenant_repo::list_tenant_role_actions(&state.pool, tenant_id, auth.entity_id)
            .await
            .map_err(gql_error)?;
        Ok(roles
            .into_iter()
            .map(|role| TenantRoleAction {
                role_id: ID::from(role.role_id.to_string()),
                role_name: role.role_name,
                actions: role.actions,
                access_type: role.access_type,
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
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[("manage", Scope::Platform), ("create", Scope::Platform)],
        )
        .await?;

        let tenant = tenant_repo::create_tenant(
            &state.pool,
            tenant_model::CreateTenant {
                id: parse_optional_id(input.id, "id")?,
                name: input.name,
                alias: input.alias,
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
        let tenant_id = parse_id(id, "id")?;
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", Scope::Platform),
                ("manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;

        let tenant = tenant_repo::update_tenant(
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
        .map_err(gql_error)?;

        Ok(tenant.into())
    }

    async fn delete_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
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

    async fn create_tenant_invitation(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        input: CreateTenantInvitationInput,
    ) -> Result<TenantInvitation> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            Scope::Tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;

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
            tenant_handlers::send_invitation_email(&state.config, email, &redirect_url, token)
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
            auth.entity_id,
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
        require_any_capability(
            &state.pool,
            auth.entity_id,
            &[
                ("manage", Scope::Tenant(tenant_id)),
                ("policy.manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        tenant_repo::remove_tenant_member(&state.pool, tenant_id, parse_id(entity_id, "entityId")?)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }
}

async fn change_tenant_status(ctx: &Context<'_>, id: ID, status: TenantStatus) -> Result<Tenant> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
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

async fn require_tenant_read_access(
    state: &AppState,
    entity_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
) -> Result<()> {
    if engine::allows_any(
        &state.pool,
        entity_id,
        "tenant",
        tenant_id,
        &["read", "manage"],
    )
    .await
    .map_err(gql_error)?
    {
        Ok(())
    } else {
        Err(gql_error(AppError::Forbidden))
    }
}

async fn can_list_all_tenants(pool: &sqlx::PgPool, entity_id: uuid::Uuid) -> Result<bool> {
    for capability in ["read", "manage"] {
        if has_capability_in_scope(pool, entity_id, capability, Scope::Platform)
            .await
            .map_err(gql_error)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
