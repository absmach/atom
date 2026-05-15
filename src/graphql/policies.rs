use async_graphql::{Context, Object, Result, ID};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    auth::{require_capability, Scope},
    authz::repo as authz_repo,
    error::AppError,
    identity::repo as identity_repo,
    models::{
        access::RoleHoldersQuery,
        capability::{CreateCapability, ListCapabilities, UpdateCapability},
        enums::ScopeKind,
        policy::{CreatePolicyBinding, ListPolicies},
        role::{CreateRole, ListRoles, UpdateRole},
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_policy_read, require_role_read, scope_for_tenant},
    types::{
        parse_effect_or_default, parse_grant_kind, parse_id, parse_optional_id,
        parse_optional_subject_kind, parse_scope_kind, parse_subject_kind, Capability,
        CapabilityList, CreateCapabilityInput, CreatePolicyInput, CreateRoleInput, Entity,
        GqlSubjectKind, PolicyBinding, PolicyBindingList, Role, RoleList, UpdateCapabilityInput,
        UpdateRoleInput,
    },
};

#[derive(Default)]
pub struct PolicyQuery;

#[Object]
impl PolicyQuery {
    #[allow(clippy::too_many_arguments)]
    async fn roles(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        scope_kind: Option<String>,
        scope_ref: Option<String>,
        q: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<RoleList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_role_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_roles(
            &state.pool,
            ListRoles {
                tenant_id,
                scope_kind,
                scope_ref,
                q,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(RoleList {
            items: list.items.into_iter().map(Role::from).collect(),
            total: list.total,
        })
    }

    async fn role(&self, ctx: &Context<'_>, id: ID) -> Result<Role> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let role = authz_repo::get_role(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
        Ok(role.into())
    }

    async fn role_capabilities(&self, ctx: &Context<'_>, role_id: ID) -> Result<Vec<Capability>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let role_id = parse_id(role_id, "roleId")?;
        let role = authz_repo::get_role(&state.pool, role_id)
            .await
            .map_err(gql_error)?;
        require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
        let capabilities = authz_repo::get_role_capabilities(&state.pool, role_id)
            .await
            .map_err(gql_error)?;
        Ok(capabilities.into_iter().map(Capability::from).collect())
    }

    async fn role_holders(&self, ctx: &Context<'_>, role_id: ID) -> Result<Vec<Entity>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let role_id = parse_id(role_id, "roleId")?;
        let role = authz_repo::get_role(&state.pool, role_id)
            .await
            .map_err(gql_error)?;
        require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
        let holders = authz_repo::role_holders(
            &state.pool,
            role_id,
            RoleHoldersQuery {
                tenant_id: None,
                subject_kind: None,
                limit: 200,
                offset: 0,
            },
        )
        .await
        .map_err(gql_error)?;

        let mut seen = HashSet::new();
        let mut entities = Vec::new();
        for holder in holders.items {
            if let Some(entity) = holder.entity {
                if seen.insert(entity.id) {
                    let full = identity_repo::get_entity(&state.pool, entity.id)
                        .await
                        .map_err(gql_error)?;
                    entities.push(Entity::from(full));
                }
            }
            if let Some(group) = holder.group {
                let members = identity_repo::list_group_members(&state.pool, group.id)
                    .await
                    .map_err(gql_error)?;
                for member in members {
                    if seen.insert(member.id) {
                        entities.push(Entity::from(member));
                    }
                }
            }
        }

        Ok(entities)
    }

    async fn role_policies(
        &self,
        ctx: &Context<'_>,
        role_id: ID,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<PolicyBindingList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let role_id = parse_id(role_id, "roleId")?;
        let role = authz_repo::get_role(&state.pool, role_id)
            .await
            .map_err(gql_error)?;
        require_role_read(&state.pool, auth.entity_id, role.tenant_id).await?;
        let list = authz_repo::role_policies(
            &state.pool,
            role_id,
            limit.map(i64::from).unwrap_or(20),
            offset.map(i64::from).unwrap_or(0),
        )
        .await
        .map_err(gql_error)?;

        Ok(PolicyBindingList {
            items: list.items.into_iter().map(PolicyBinding::from).collect(),
            total: list.total,
        })
    }

    async fn capabilities(
        &self,
        ctx: &Context<'_>,
        resource_kind: Option<String>,
        tenant_id: Option<ID>,
        #[graphql(default = 50)] limit: i64,
        #[graphql(default = 0)] offset: i64,
    ) -> Result<CapabilityList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_capabilities(
            &state.pool,
            ListCapabilities {
                resource_kind,
                limit,
                offset,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(CapabilityList {
            items: list.items.into_iter().map(Capability::from).collect(),
            total: list.total,
        })
    }

    async fn capability(&self, ctx: &Context<'_>, id: ID) -> Result<Capability> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_policy_read(&state.pool, auth.entity_id, None).await?;
        let capability = authz_repo::get_capability(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        Ok(capability.into())
    }

    async fn policies(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        subject_id: Option<ID>,
        subject_kind: Option<GqlSubjectKind>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<PolicyBindingList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_policies(
            &state.pool,
            ListPolicies {
                tenant_id,
                subject_id: parse_optional_id(subject_id, "subjectId")?,
                subject_kind: parse_optional_subject_kind(subject_kind),
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(PolicyBindingList {
            items: list.items.into_iter().map(PolicyBinding::from).collect(),
            total: list.total,
        })
    }

    async fn policy(&self, ctx: &Context<'_>, id: ID) -> Result<PolicyBinding> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let policy = authz_repo::get_policy(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        require_policy_read(&state.pool, auth.entity_id, policy.tenant_id).await?;
        Ok(policy.into())
    }
}

#[derive(Default)]
pub struct PolicyMutation;

#[Object]
impl PolicyMutation {
    async fn create_role(&self, ctx: &Context<'_>, input: CreateRoleInput) -> Result<Role> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "role.manage",
            scope_for_tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let role = authz_repo::create_role(
            &state.pool,
            CreateRole {
                name: input.name,
                tenant_id,
                description: input.description,
                scope_kind: input.scope_kind,
                scope_ref: input.scope_ref,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(role.into())
    }

    async fn update_role(&self, ctx: &Context<'_>, id: ID, input: UpdateRoleInput) -> Result<Role> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let role = authz_repo::get_role(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "role.manage",
            scope_for_tenant(role.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let updated = authz_repo::update_role(
            &state.pool,
            id,
            UpdateRole {
                name: input.name,
                description: input.description,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(updated.into())
    }

    async fn delete_role(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let role = authz_repo::get_role(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "role.manage",
            scope_for_tenant(role.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        authz_repo::delete_role(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn add_role_capability(
        &self,
        ctx: &Context<'_>,
        role_id: ID,
        capability_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let role_id = parse_id(role_id, "roleId")?;
        let role = authz_repo::get_role(&state.pool, role_id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "role.manage",
            scope_for_tenant(role.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        authz_repo::add_role_capability(
            &state.pool,
            role_id,
            parse_id(capability_id, "capabilityId")?,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn remove_role_capability(
        &self,
        ctx: &Context<'_>,
        role_id: ID,
        capability_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let role_id = parse_id(role_id, "roleId")?;
        let role = authz_repo::get_role(&state.pool, role_id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "role.manage",
            scope_for_tenant(role.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        authz_repo::remove_role_capability(
            &state.pool,
            role_id,
            parse_id(capability_id, "capabilityId")?,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_capability(
        &self,
        ctx: &Context<'_>,
        input: CreateCapabilityInput,
    ) -> Result<Capability> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            Scope::Platform,
        )
        .await
        .map_err(gql_error)?;
        let capability = authz_repo::create_capability(
            &state.pool,
            CreateCapability {
                name: input.name,
                resource_kind: input.resource_kind,
                description: input.description,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(capability.into())
    }

    async fn update_capability(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateCapabilityInput,
    ) -> Result<Capability> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            Scope::Platform,
        )
        .await
        .map_err(gql_error)?;
        let updated = authz_repo::update_capability(
            &state.pool,
            parse_id(id, "id")?,
            UpdateCapability {
                name: input.name,
                resource_kind: input.resource_kind,
                description: input.description,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(updated.into())
    }

    async fn delete_capability(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            Scope::Platform,
        )
        .await
        .map_err(gql_error)?;
        authz_repo::delete_capability(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_policy(
        &self,
        ctx: &Context<'_>,
        input: CreatePolicyInput,
    ) -> Result<PolicyBinding> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let req = create_policy_binding(input)?;
        req.validate()
            .map_err(|err| gql_error(AppError::bad_request(err)))?;
        validate_tenant_owned_policy(&state.pool, &req)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(req.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let policy = authz_repo::create_policy(&state.pool, req)
            .await
            .map_err(gql_error)?;
        Ok(policy.into())
    }

    async fn delete_policy(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let policy = authz_repo::get_policy(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(policy.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        authz_repo::delete_policy(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }
}

fn create_policy_binding(input: CreatePolicyInput) -> Result<CreatePolicyBinding> {
    Ok(CreatePolicyBinding {
        tenant_id: parse_optional_id(input.tenant_id, "tenantId")?,
        subject_kind: parse_subject_kind(input.subject_kind),
        subject_id: parse_id(input.subject_id, "subjectId")?,
        grant_kind: parse_grant_kind(input.grant_kind),
        grant_id: parse_id(input.grant_id, "grantId")?,
        scope_kind: parse_scope_kind(input.scope_kind),
        scope_ref: input.scope_ref,
        effect: parse_effect_or_default(input.effect),
        conditions: input.conditions.unwrap_or_else(|| serde_json::json!({})),
    })
}

async fn validate_tenant_owned_policy(
    pool: &PgPool,
    req: &CreatePolicyBinding,
) -> std::result::Result<(), AppError> {
    let Some(policy_tenant_id) = req.tenant_id else {
        return Ok(());
    };

    match req.scope_kind {
        ScopeKind::Platform => Err(AppError::bad_request(
            "tenant-owned policy cannot use platform scope",
        )),
        ScopeKind::Tenant => {
            let Some(scope_ref) = req.scope_ref.as_deref() else {
                return Err(AppError::bad_request(
                    "tenant policy scope_ref must match tenant_id",
                ));
            };
            let scope_tenant_id = scope_ref
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("tenant scope_ref must be a UUID"))?;
            if scope_tenant_id == policy_tenant_id {
                Ok(())
            } else {
                Err(AppError::bad_request(
                    "tenant-owned policy cannot reference another tenant",
                ))
            }
        }
        ScopeKind::ObjectKind | ScopeKind::ObjectType => Ok(()),
        ScopeKind::Object => {
            let scope_ref = req
                .scope_ref
                .as_deref()
                .ok_or_else(|| AppError::bad_request("object scope requires scope_ref"))?;
            let object_id = scope_ref
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("object scope_ref must be a UUID"))?;
            match authz_repo::object_tenant_id_by_id(pool, object_id).await? {
                Some(Some(object_tenant_id)) if object_tenant_id == policy_tenant_id => Ok(()),
                Some(Some(_)) => Err(AppError::bad_request(
                    "tenant-owned policy cannot reference an object in another tenant",
                )),
                Some(None) => Err(AppError::bad_request(
                    "tenant-owned policy cannot reference a platform object",
                )),
                None => Err(AppError::bad_request(
                    "tenant-owned policy cannot reference an unknown object",
                )),
            }
        }
    }
}
