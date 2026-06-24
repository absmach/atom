use async_graphql::{Context, Object, Result, ID};

use crate::{
    audit,
    auth::{require_capability, Scope},
    authz::repo as authz_repo,
    models::{
        action_assignment_rule::{CreateActionAssignmentRule, ListActionAssignmentRules},
        capability::{CreateCapability, ListCapabilities, UpdateCapability},
        enums::{AuditOutcome, DeletedFilter},
        policy::{
            CreateDirectPolicy, CreatePermissionBlock, CreateRoleAssignment, ListDirectPolicies,
            ListPermissionBlocks, ListRoleAssignments,
        },
        role::{CreateRole, ListRoles, UpdateRole},
    },
    state::AppState,
};

use super::{
    auth::{
        gql_error, require_any_capability, require_auth, require_policy_read, require_role_read,
        scope_for_tenant,
    },
    types::{
        parse_deleted_filter, parse_effect_or_default, parse_id, parse_object_kind,
        parse_optional_action_assignment_decision, parse_optional_entity_kind, parse_optional_id,
        parse_optional_subject_kind, parse_subject_kind, Action, ActionApplicabilityEntry,
        ActionApplicabilityList, ActionAssignmentRule, ActionAssignmentRuleList, ActionList,
        AddActionApplicabilityInput, CreateActionAssignmentRuleInput, CreateActionInput,
        CreateDirectPolicyInput, CreatePermissionBlockInput, CreateRoleAssignmentInput,
        CreateRoleInput, DirectPolicy, DirectPolicyList, GqlActionAssignmentRuleDecision,
        GqlDeletedFilter, GqlEntityKind, GqlSubjectKind, PermissionBlock, PermissionBlockList,
        RemoveActionApplicabilityInput, Role, RoleAssignment, RoleAssignmentList, RoleList,
        UpdateActionInput, UpdateRoleInput,
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
        derived_kind: Option<String>,
        q: Option<String>,
        deleted: Option<GqlDeletedFilter>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<RoleList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        let deleted = parse_deleted_filter(deleted);
        if deleted != DeletedFilter::Live {
            require_any_capability(&state.pool, auth.entity_id, &[("manage", Scope::Platform)])
                .await?;
        } else {
            require_role_read(&state.pool, auth.entity_id, tenant_id).await?;
        }
        let list = authz_repo::list_roles(
            &state.pool,
            ListRoles {
                tenant_id,
                derived_kind,
                q,
                deleted,
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

    async fn actions(
        &self,
        ctx: &Context<'_>,
        object_kind: Option<String>,
        object_type: Option<String>,
        tenant_id: Option<ID>,
        #[graphql(default = 50)] limit: i64,
        #[graphql(default = 0)] offset: i64,
    ) -> Result<ActionList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_capabilities(
            &state.pool,
            ListCapabilities {
                object_kind,
                object_type,
                limit,
                offset,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(ActionList {
            items: list.items.into_iter().map(Action::from).collect(),
            total: list.total,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn action_applicability(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        action_name: Option<String>,
        object_kind: Option<String>,
        object_type: Option<String>,
        #[graphql(default = 50)] limit: i64,
        #[graphql(default = 0)] offset: i64,
    ) -> Result<ActionApplicabilityList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_capability_applicability(
            &state.pool,
            action_name,
            object_kind,
            object_type,
            limit,
            offset,
        )
        .await
        .map_err(gql_error)?;
        Ok(ActionApplicabilityList {
            items: list
                .items
                .into_iter()
                .map(ActionApplicabilityEntry)
                .collect(),
            total: list.total,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn action_assignment_rules(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        entity_kind: Option<GqlEntityKind>,
        action_name: Option<String>,
        object_kind: Option<String>,
        object_type: Option<String>,
        decision: Option<GqlActionAssignmentRuleDecision>,
        #[graphql(default = 50)] limit: i64,
        #[graphql(default = 0)] offset: i64,
    ) -> Result<ActionAssignmentRuleList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let object_kind = object_kind
            .map(|value| parse_object_kind(value, "objectKind"))
            .transpose()?;
        let list = authz_repo::list_action_assignment_rules(
            &state.pool,
            ListActionAssignmentRules {
                tenant_id,
                entity_kind: parse_optional_entity_kind(entity_kind),
                action_name,
                object_kind,
                object_type,
                decision: parse_optional_action_assignment_decision(decision),
                limit,
                offset,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(ActionAssignmentRuleList {
            items: list.items.into_iter().map(ActionAssignmentRule).collect(),
            total: list.total,
        })
    }

    async fn action(&self, ctx: &Context<'_>, id: ID) -> Result<Action> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_policy_read(&state.pool, auth.entity_id, None).await?;
        let action = authz_repo::get_capability(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        Ok(action.into())
    }

    async fn permission_blocks(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        scope_mode: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<PermissionBlockList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_permission_blocks(
            &state.pool,
            ListPermissionBlocks {
                tenant_id,
                scope_mode,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(PermissionBlockList {
            items: list.items.into_iter().map(Into::into).collect(),
            total: list.total,
        })
    }

    async fn permission_block(&self, ctx: &Context<'_>, id: ID) -> Result<PermissionBlock> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let block = authz_repo::get_permission_block(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        require_policy_read(&state.pool, auth.entity_id, block.tenant_id).await?;
        Ok(block.into())
    }

    #[allow(clippy::too_many_arguments)]
    async fn role_assignments(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        subject_kind: Option<GqlSubjectKind>,
        subject_id: Option<ID>,
        role_id: Option<ID>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<RoleAssignmentList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_role_assignments(
            &state.pool,
            ListRoleAssignments {
                tenant_id,
                subject_kind: parse_optional_subject_kind(subject_kind),
                subject_id: parse_optional_id(subject_id, "subjectId")?,
                role_id: parse_optional_id(role_id, "roleId")?,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(RoleAssignmentList {
            items: list.items.into_iter().map(Into::into).collect(),
            total: list.total,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn direct_policies(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
        subject_kind: Option<GqlSubjectKind>,
        subject_id: Option<ID>,
        permission_block_id: Option<ID>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<DirectPolicyList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_policy_read(&state.pool, auth.entity_id, tenant_id).await?;
        let list = authz_repo::list_direct_policies(
            &state.pool,
            ListDirectPolicies {
                tenant_id,
                subject_kind: parse_optional_subject_kind(subject_kind),
                subject_id: parse_optional_id(subject_id, "subjectId")?,
                permission_block_id: parse_optional_id(permission_block_id, "permissionBlockId")?,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(DirectPolicyList {
            items: list.items.into_iter().map(Into::into).collect(),
            total: list.total,
        })
    }
}

#[derive(Default)]
pub struct PolicyMutation;

#[Object]
impl PolicyMutation {
    async fn create_role(&self, ctx: &Context<'_>, input: CreateRoleInput) -> Result<Role> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id.clone(), "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "role.manage",
            scope_for_tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let create_req = CreateRole {
            name: input.name,
            tenant_id,
            description: input.description,
        };
        let role = authz_repo::create_role(&state.pool, create_req)
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

    async fn replace_role_permission_blocks(
        &self,
        ctx: &Context<'_>,
        role_id: ID,
        permission_block_ids: Vec<ID>,
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
        let permission_block_ids = permission_block_ids
            .into_iter()
            .map(|id| parse_id(id, "permissionBlockId"))
            .collect::<Result<Vec<_>>>()?;
        authz_repo::replace_role_permission_block_links(
            &state.pool,
            role_id,
            &permission_block_ids,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
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
        authz_repo::delete_role(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    /// Restore a soft-deleted role within the retention window. The role's
    /// permission blocks survived the soft delete, so its grants resume flowing
    /// through the PDP the moment it is restored — hence platform-admin only and
    /// audit-logged.
    async fn restore_role(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let id = parse_id(id, "id")?;
        authz_repo::restore_role(&state.pool, id, Some(auth.entity_id))
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            Some(auth.entity_id),
            None,
            "role.restore",
            AuditOutcome::Allow,
            serde_json::json!({ "role_id": id }),
        )
        .await;
        Ok(true)
    }

    /// Physically purge an already-soft-deleted role, bypassing the retention
    /// window. GCs permission blocks left orphaned by the removal. Deliberate,
    /// irreversible, platform-admin only, and audit-logged.
    async fn purge_role(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let id = parse_id(id, "id")?;
        authz_repo::purge_role(&state.pool, id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            Some(auth.entity_id),
            None,
            "role.purge",
            AuditOutcome::Allow,
            serde_json::json!({ "role_id": id }),
        )
        .await;
        Ok(true)
    }

    async fn create_action(&self, ctx: &Context<'_>, input: CreateActionInput) -> Result<Action> {
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
        let action = authz_repo::create_capability(
            &state.pool,
            CreateCapability {
                name: input.name,
                description: input.description,
                applicability: input.applicability.map(|items| {
                    items
                        .into_iter()
                        .map(
                            |item| crate::models::capability::CapabilityApplicabilityInput {
                                object_kind: item.object_kind,
                                object_type: item.object_type,
                            },
                        )
                        .collect()
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(action.into())
    }

    async fn add_action_applicability(
        &self,
        ctx: &Context<'_>,
        input: AddActionApplicabilityInput,
    ) -> Result<ActionApplicabilityEntry> {
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
        let entry = authz_repo::add_capability_applicability(
            &state.pool,
            parse_id(input.action_id, "actionId")?,
            input.object_kind,
            input.object_type,
        )
        .await
        .map_err(gql_error)?;
        Ok(ActionApplicabilityEntry(entry))
    }

    async fn remove_action_applicability(
        &self,
        ctx: &Context<'_>,
        input: RemoveActionApplicabilityInput,
    ) -> Result<bool> {
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
        authz_repo::remove_capability_applicability(
            &state.pool,
            parse_id(input.action_id, "actionId")?,
            input.object_kind,
            input.object_type,
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_action_assignment_rule(
        &self,
        ctx: &Context<'_>,
        input: CreateActionAssignmentRuleInput,
    ) -> Result<ActionAssignmentRule> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id.clone(), "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let rule = authz_repo::create_action_assignment_rule(
            &state.pool,
            CreateActionAssignmentRule {
                tenant_id,
                entity_kind: input.entity_kind.into(),
                action_name: input.action_name,
                object_kind: parse_object_kind(input.object_kind, "objectKind")?,
                object_type: input.object_type,
                decision: input.decision.into(),
                is_absolute: input.is_absolute.unwrap_or(false),
            },
        )
        .await
        .map_err(gql_error)?;
        audit_action_assignment_rule(&state.pool, auth.entity_id, &rule, "create").await;
        Ok(ActionAssignmentRule(rule))
    }

    async fn delete_action_assignment_rule(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let existing = authz_repo::get_action_assignment_rule(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(existing.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let rule = authz_repo::delete_action_assignment_rule(&state.pool, id)
            .await
            .map_err(gql_error)?;
        audit_action_assignment_rule(&state.pool, auth.entity_id, &rule, "delete").await;
        Ok(true)
    }

    async fn update_action(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateActionInput,
    ) -> Result<Action> {
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
                description: input.description,
                applicability: input.applicability.map(|items| {
                    items
                        .into_iter()
                        .map(
                            |item| crate::models::capability::CapabilityApplicabilityInput {
                                object_kind: item.object_kind,
                                object_type: item.object_type,
                            },
                        )
                        .collect()
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(updated.into())
    }

    async fn delete_action(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
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

    async fn create_permission_block(
        &self,
        ctx: &Context<'_>,
        input: CreatePermissionBlockInput,
    ) -> Result<PermissionBlock> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id.clone(), "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let block = authz_repo::create_permission_block(
            &state.pool,
            CreatePermissionBlock {
                tenant_id,
                scope_mode: input.scope_mode,
                object_kind: input.object_kind,
                object_type: input.object_type,
                object_id: parse_optional_id(input.object_id, "objectId")?,
                group_id: parse_optional_id(input.group_id, "groupId")?,
                effect: parse_effect_or_default(input.effect),
                conditions: input.conditions.unwrap_or_else(|| serde_json::json!({})),
                action_ids: input
                    .action_ids
                    .into_iter()
                    .map(|id| parse_id(id, "actionId"))
                    .collect::<Result<Vec<_>>>()?,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(block.into())
    }

    async fn delete_permission_block(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let block = authz_repo::get_permission_block(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(block.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        authz_repo::delete_permission_block(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_role_assignment(
        &self,
        ctx: &Context<'_>,
        input: CreateRoleAssignmentInput,
    ) -> Result<RoleAssignment> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id.clone(), "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let assignment = authz_repo::create_role_assignment(
            &state.pool,
            CreateRoleAssignment {
                tenant_id,
                subject_kind: parse_subject_kind(input.subject_kind),
                subject_id: parse_id(input.subject_id, "subjectId")?,
                role_id: parse_id(input.role_id, "roleId")?,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(assignment.into())
    }

    async fn delete_role_assignment(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let assignment = authz_repo::get_role_assignment(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(assignment.tenant_id),
        )
        .await
        .map_err(gql_error)?;
        authz_repo::delete_role_assignment(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_direct_policy(
        &self,
        ctx: &Context<'_>,
        input: CreateDirectPolicyInput,
    ) -> Result<DirectPolicy> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id.clone(), "tenantId")?;
        require_capability(
            &state.pool,
            auth.entity_id,
            "policy.manage",
            scope_for_tenant(tenant_id),
        )
        .await
        .map_err(gql_error)?;
        let policy = authz_repo::create_direct_policy(
            &state.pool,
            CreateDirectPolicy {
                tenant_id,
                subject_kind: parse_subject_kind(input.subject_kind),
                subject_id: parse_id(input.subject_id, "subjectId")?,
                permission_block_id: parse_id(input.permission_block_id, "permissionBlockId")?,
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(policy.into())
    }

    async fn delete_direct_policy(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let policy = authz_repo::get_direct_policy(&state.pool, id)
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
        authz_repo::delete_direct_policy(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(true)
    }
}

async fn audit_action_assignment_rule(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    rule: &crate::models::action_assignment_rule::ActionAssignmentRule,
    action: &str,
) {
    audit::write(
        pool,
        Some(actor_id),
        rule.tenant_id,
        &format!("action_assignment_rule.{action}"),
        AuditOutcome::Allow,
        serde_json::json!({
            "rule_id": rule.id,
            "entity_kind": &rule.entity_kind,
            "action_name": rule.action_name,
            "object_kind": rule.object_kind.as_str(),
            "object_type": &rule.object_type,
            "decision": &rule.decision,
            "is_absolute": rule.is_absolute,
            "transport": "graphql",
        }),
    )
    .await;
}
