use async_graphql::{Context, Object, Result, SimpleObject, ID};

use crate::{
    audit,
    auth::{has_capability_in_scope, require_capability, AuthContext, Scope},
    authz::engine,
    error::AppError,
    models::{
        enums::{DeletedFilter, TenantStatus},
        tenant as tenant_model,
        tenant::ListTenants,
    },
    state::AppState,
    tenants::{email as tenant_email, repo as tenant_repo},
};

use super::{
    auth::{gql_error, require_any_capability, require_auth},
    types::{
        parse_deleted_filter, parse_id, parse_invitation_state, parse_optional_entity_status,
        parse_optional_id, parse_optional_tenant_status, parse_sort_dir, parse_tenant_order,
        CreateTenantInput, CreateTenantInvitationInput, EntityList, GqlDeletedFilter,
        GqlEntityStatus, GqlInvitationState, GqlSortDir, GqlTenantOrderField, GqlTenantStatus,
        InvitationTokenInput, Tenant, TenantInvitation, TenantInvitationList, TenantList,
        UpdateTenantInput,
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
        id: Option<ID>,
        id_contains: Option<String>,
        q: Option<String>,
        name: Option<String>,
        alias: Option<String>,
        tags: Option<String>,
        status: Option<GqlTenantStatus>,
        deleted: Option<GqlDeletedFilter>,
        order: Option<GqlTenantOrderField>,
        dir: Option<GqlSortDir>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<TenantList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let deleted = parse_deleted_filter(deleted);
        let params = ListTenants {
            id: parse_optional_id(id, "id")?,
            id_contains,
            q,
            name,
            alias,
            tags,
            status: parse_optional_tenant_status(status),
            deleted,
            limit: limit.map(i64::from).unwrap_or(20),
            offset: offset.map(i64::from).unwrap_or(0),
            order: parse_tenant_order(order),
            dir: parse_sort_dir(dir),
        };
        let list = if deleted != DeletedFilter::Live {
            require_any_capability(&state.pool, &auth, &[("manage", Scope::Platform)]).await?;
            tenant_repo::list_tenants(&state.pool, params)
                .await
                .map_err(gql_error)?
        } else if can_list_all_tenants(&state.pool, &auth).await? {
            tenant_repo::list_tenants(&state.pool, params)
                .await
                .map_err(gql_error)?
        } else {
            tenant_repo::list_tenants_for_entity(&state.pool, &auth, auth.entity_id, params)
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
        require_tenant_read_access(state, &auth, id).await?;
        let tenant = tenant_repo::get_tenant(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(tenant.into())
    }

    #[allow(clippy::too_many_arguments)]
    async fn tenant_members(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        q: Option<String>,
        id: Option<String>,
        status: Option<GqlEntityStatus>,
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
            id,
            parse_optional_entity_status(status),
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
        state: Option<GqlInvitationState>,
    ) -> Result<TenantInvitationList> {
        let auth = require_auth(ctx)?;
        let app_state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        require_any_capability(
            &app_state.pool,
            &auth,
            &[
                ("manage", Scope::Tenant(tenant_id)),
                ("policy.manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        let list = tenant_repo::list_tenant_invitations(
            &app_state.pool,
            tenant_id,
            tenant_model::ListTenantInvitations {
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
                state: parse_invitation_state(state),
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
        require_tenant_read_access(state, &auth, tenant_id).await?;
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
        state: Option<GqlInvitationState>,
    ) -> Result<TenantInvitationList> {
        let auth = require_auth(ctx)?;
        let app_state = ctx.data::<AppState>()?;
        let list = tenant_repo::list_user_invitations(
            &app_state.pool,
            auth.entity_id,
            tenant_model::ListTenantInvitations {
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
                state: parse_invitation_state(state),
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
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: None,
            target_kind: "tenant",
            target_id: id,
            event: "tenant.create",
        };
        let details = serde_json::json!({
            "name": input.name,
            "alias": input.alias,
        });

        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[("manage", Scope::Platform), ("create", Scope::Platform)],
            )
            .await?;
            // `create_tenant` bootstraps a tenant-admin role, role assignment
            // and membership for the creator in the same transaction, so it
            // grows the creator's own grant set. The capability gate directly
            // above has just warmed that exact `grants` entry, so without this
            // barrier a creator who isn't already a platform admin cannot
            // manage the tenant they just created until the grants TTL lapses.
            crate::cache::invalidate::guarded_mutation(
                state.cache.as_deref(),
                crate::cache::CacheCategory::Grants,
                std::slice::from_ref(&crate::cache::keys::grants(auth.entity_id)),
                || {
                    tenant_repo::create_tenant_with_audit(
                        &state.pool,
                        state.config.events.enabled(),
                        Some(auth.entity_id),
                        tenant_model::CreateTenant {
                            id,
                            name: input.name,
                            alias: input.alias,
                            tags: input.tags.unwrap_or_default(),
                            attributes: input.attributes.unwrap_or(serde_json::Value::Null),
                        },
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
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: Some(tenant_id),
            target_kind: "tenant",
            target_id: Some(tenant_id),
            event: "tenant.update",
        };
        let details = serde_json::json!({});

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
            tenant_repo::update_tenant_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
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

    async fn delete_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(id, "id")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: Some(tenant_id),
            target_kind: "tenant",
            target_id: Some(tenant_id),
            event: "tenant.delete",
        };
        let details = serde_json::json!({});

        let result: std::result::Result<(), AppError> = async {
            crate::auth::require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            // `tenant_status` invalidation alone is *not* sufficient: this
            // also bulk-revokes sessions, which would otherwise become a
            // stale cache hit again the moment `restoreTenant` repopulates
            // tenant_status as active. Credentials don't need the same
            // treatment — `restore_tenant`'s own invalidation (see
            // `reactivate_tenant_and_collect_credential_ids_in_tx`) already
            // covers that side by the time a restore could matter. See
            // `lock_tenant_and_collect_session_ids_in_tx` for why session ids
            // are enumerated inside the same locked transaction, and why that
            // lock-and-enumerate step must run before the barrier below is
            // established, not after the tenant is flipped to `deleted`.
            let Some(cache) = state.cache.as_deref() else {
                tenant_repo::soft_delete_tenant_with_audit(
                    &state.pool,
                    state.config.events.enabled(),
                    Some(auth.entity_id),
                    tenant_id,
                    Some(auth.entity_id),
                )
                .await?;
                return Ok(());
            };
            let mut tx = state.pool.begin().await.map_err(crate::error::db_err)?;
            let session_ids =
                tenant_repo::lock_tenant_and_collect_session_ids_in_tx(&mut tx, tenant_id).await?;
            let session_keys: Vec<String> = session_ids
                .iter()
                .map(|id| crate::cache::keys::session(*id))
                .collect();
            let tenant_status_keys = [crate::cache::keys::tenant_status(tenant_id)];
            let groups: [(crate::cache::CacheCategory, &[String]); 2] = [
                (
                    crate::cache::CacheCategory::TenantStatus,
                    &tenant_status_keys,
                ),
                (crate::cache::CacheCategory::Session, &session_keys),
            ];
            let leases = crate::cache::invalidate::begin_all(cache, &groups).await?;
            let outcome = tenant_repo::deactivate_and_finish_tenant_soft_delete_in_tx(
                &mut tx,
                state.config.events.enabled(),
                Some(auth.entity_id),
                Some(auth.entity_id),
                tenant_id,
            )
            .await;
            match outcome {
                Ok(tenant) => audit::commit_observed_with_cache_groups(
                    tx, cache, leases, tenant, &meta, &details,
                )
                .await
                .map(|_| ()),
                Err(err) => {
                    crate::cache::invalidate::end_all(cache, leases).await;
                    Err(err)
                }
            }
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

    /// Restore a soft-deleted tenant within the retention window. Reactivates the
    /// tenant and un-hides its children automatically; revoked sessions and
    /// certificates are not reinstated, so members must re-authenticate.
    /// Admin-only and audit-logged.
    async fn restore_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<Tenant> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(id, "id")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: Some(tenant_id),
            target_kind: "tenant",
            target_id: Some(tenant_id),
            event: "tenant.restore",
        };
        let details = serde_json::json!({});

        let result = async {
            crate::auth::require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            // Unlike the tenant-status-only case in `delete_tenant`, this
            // also reactivates credentials, which need their own
            // invalidation: `verify_api_key_snapshot` checks a credential's
            // status first and isn't overridden by a fresher tenant_status
            // check afterward, so a just-restored API key would keep
            // getting denied until its own cache entry's TTL expires
            // otherwise. See
            // `reactivate_tenant_and_collect_credential_ids_in_tx` for why
            // credential ids are enumerated inside the same locked
            // transaction.
            let Some(cache) = state.cache.as_deref() else {
                return tenant_repo::restore_tenant_with_audit(
                    &state.pool,
                    state.config.events.enabled(),
                    Some(auth.entity_id),
                    tenant_id,
                    Some(auth.entity_id),
                )
                .await;
            };
            let mut tx = state.pool.begin().await.map_err(crate::error::db_err)?;
            let (tenant, credential_ids) =
                tenant_repo::reactivate_tenant_and_collect_credential_ids_in_tx(
                    &mut tx,
                    tenant_id,
                    Some(auth.entity_id),
                )
                .await?;
            let credential_keys: Vec<String> = credential_ids
                .iter()
                .map(|id| crate::cache::keys::credential(*id))
                .collect();
            let tenant_status_keys = [crate::cache::keys::tenant_status(tenant_id)];
            let groups: [(crate::cache::CacheCategory, &[String]); 2] = [
                (
                    crate::cache::CacheCategory::TenantStatus,
                    &tenant_status_keys,
                ),
                (crate::cache::CacheCategory::Credential, &credential_keys),
            ];
            let leases = crate::cache::invalidate::begin_all(cache, &groups).await?;
            let outcome = tenant_repo::finish_tenant_restore_in_tx(
                &mut tx,
                state.config.events.enabled(),
                Some(auth.entity_id),
                tenant_id,
            )
            .await;
            match outcome {
                Ok(()) => {
                    audit::commit_observed_with_cache_and_audit(
                        &state.pool,
                        tx,
                        cache,
                        leases,
                        (),
                        audit::AuditEvent {
                            actor_entity_id: Some(auth.entity_id),
                            tenant_id: Some(tenant.id),
                            target_kind: Some("tenant"),
                            target_id: Some(tenant.id),
                            event: "tenant.restore",
                            outcome: crate::models::enums::AuditOutcome::Allow,
                            details: details.clone(),
                        },
                    )
                    .await?
                }
                Err(err) => {
                    crate::cache::invalidate::end_all(cache, leases).await;
                    return Err(err);
                }
            }
            Ok(tenant)
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

    /// Physically purge an already-soft-deleted tenant and all its data,
    /// bypassing the purge retention window. Deliberate, irreversible, admin-only.
    async fn purge_tenant(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(id, "id")?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: Some(tenant_id),
            target_kind: "tenant",
            target_id: Some(tenant_id),
            event: "tenant.purge",
        };
        let details = serde_json::json!({});

        let result = async {
            crate::auth::require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
            tenant_repo::purge_tenant_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                tenant_id,
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
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        // Invitation acceptance grants tenant membership (and possibly a
        // role) to `auth.entity_id` — easy to miss since it doesn't go
        // through the "obvious" policy/role-assignment mutation entry
        // points.
        crate::cache::invalidate::guarded_mutation(
            state.cache.as_deref(),
            crate::cache::CacheCategory::Grants,
            std::slice::from_ref(&crate::cache::keys::grants(auth.entity_id)),
            || tenant_repo::accept_invitation(&state.pool, tenant_id, auth.entity_id),
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
        let tenant_id = crate::cache::invalidate::guarded_mutation(
            state.cache.as_deref(),
            crate::cache::CacheCategory::Grants,
            std::slice::from_ref(&crate::cache::keys::grants(auth.entity_id)),
            || tenant_repo::accept_invitation_token(&state.pool, &input.token, auth.entity_id),
        )
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
            crate::cache::invalidate::guarded_mutation(
                state.cache.as_deref(),
                crate::cache::CacheCategory::Grants,
                std::slice::from_ref(&crate::cache::keys::grants(entity_id)),
                || {
                    tenant_repo::remove_tenant_member_with_audit(
                        &state.pool,
                        state.config.events.enabled(),
                        Some(auth.entity_id),
                        tenant_id,
                        entity_id,
                    )
                },
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            let meta = audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant_id),
                target_kind: "tenant",
                target_id: Some(tenant_id),
                event: "tenant_member.remove",
            };
            let details = serde_json::json!({ "entity_id": entity_id });
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
            crate::cache::invalidate::guarded_mutation(
                state.cache.as_deref(),
                crate::cache::CacheCategory::Grants,
                std::slice::from_ref(&crate::cache::keys::grants(entity_id)),
                || {
                    tenant_repo::add_tenant_member_with_audit(
                        &state.pool,
                        state.config.events.enabled(),
                        Some(auth.entity_id),
                        tenant_id,
                        entity_id,
                        role_id,
                    )
                },
            )
            .await
        }
        .await;
        if let Err(ref err) = result {
            let meta = audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: Some(tenant_id),
                target_kind: "tenant",
                target_id: Some(tenant_id),
                event: "tenant_member.add",
            };
            let details = serde_json::json!({ "entity_id": entity_id, "role_id": role_id });
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
}

async fn change_tenant_status(ctx: &Context<'_>, id: ID, status: TenantStatus) -> Result<Tenant> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    let tenant_id = parse_id(id, "id")?;
    let event = tenant_status_event(&status);
    let status_detail = status.clone();
    let result = async {
        crate::auth::require_capability(&state.pool, &auth, "manage", Scope::Platform).await?;
        // Only `tenant_status`, not `grants`: the PDP's tenant-lifecycle deny
        // check runs before grant matching (see `authz::engine::
        // load_decision_context`), so a stale tenant-membership-implicit
        // grant inside a cached `grants` entry is harmless as long as this
        // key itself invalidates.
        let Some(cache) = state.cache.as_deref() else {
            return tenant_repo::change_tenant_status_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                tenant_id,
                status,
                event,
            )
            .await;
        };
        if status == TenantStatus::Active {
            // Re-enabling never revokes anything (see
            // `change_tenant_status_in_tx`), so `tenant_status` is the only
            // key that needs a barrier here.
            return crate::cache::invalidate::guarded_mutation(
                Some(cache),
                crate::cache::CacheCategory::TenantStatus,
                std::slice::from_ref(&crate::cache::keys::tenant_status(tenant_id)),
                || {
                    tenant_repo::change_tenant_status_with_audit(
                        &state.pool,
                        state.config.events.enabled(),
                        Some(auth.entity_id),
                        tenant_id,
                        status,
                        event,
                    )
                },
            )
            .await;
        }
        // Disabling/freezing also bulk-revokes the tenant's members'
        // sessions (see `change_tenant_status_in_tx`) — lock the tenant and
        // enumerate those session ids first, establish the barrier on both
        // categories, then mutate. Mirrors `deleteTenant` exactly, and for
        // the same reason: a session cache entry this call is about to
        // revoke must never be left reachable as a stale hit, or it survives
        // (with `revoked_at = None`) until the tenant is re-enabled and its
        // own fresh `tenant_status` hit stops masking the stale session.
        let mut tx = state.pool.begin().await.map_err(crate::error::db_err)?;
        let session_ids =
            tenant_repo::lock_tenant_and_collect_session_ids_in_tx(&mut tx, tenant_id).await?;
        let session_keys: Vec<String> = session_ids
            .iter()
            .map(|id| crate::cache::keys::session(*id))
            .collect();
        let tenant_status_keys = [crate::cache::keys::tenant_status(tenant_id)];
        let groups: [(crate::cache::CacheCategory, &[String]); 2] = [
            (
                crate::cache::CacheCategory::TenantStatus,
                &tenant_status_keys,
            ),
            (crate::cache::CacheCategory::Session, &session_keys),
        ];
        let leases = crate::cache::invalidate::begin_all(cache, &groups).await?;
        let outcome = tenant_repo::change_tenant_status_in_tx(
            &mut tx,
            state.config.events.enabled(),
            Some(auth.entity_id),
            tenant_id,
            status,
            event,
        )
        .await;
        match outcome {
            Ok(tenant) => {
                audit::commit_observed_with_cache_groups(
                    tx,
                    cache,
                    leases,
                    tenant,
                    &audit::AuditMeta {
                        actor_entity_id: Some(auth.entity_id),
                        tenant_id: Some(tenant_id),
                        target_kind: "tenant",
                        target_id: Some(tenant_id),
                        event,
                    },
                    &serde_json::json!({ "status": status_detail.clone() }),
                )
                .await
            }
            Err(err) => {
                crate::cache::invalidate::end_all(cache, leases).await;
                Err(err)
            }
        }
    }
    .await;
    if let Err(ref err) = result {
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: Some(tenant_id),
            target_kind: "tenant",
            target_id: Some(tenant_id),
            event,
        };
        let details = serde_json::json!({ "status": status_detail });
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
    auth: &AuthContext,
    tenant_id: uuid::Uuid,
) -> Result<()> {
    if can_list_all_tenants(&state.pool, auth).await?
        || has_inactive_tenant_read_role(&state.pool, auth.entity_id, tenant_id).await?
    {
        return Ok(());
    }

    if engine::allows_any(
        &state.pool,
        auth,
        auth.entity_id,
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

async fn has_inactive_tenant_read_role(
    pool: &sqlx::PgPool,
    entity_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
) -> Result<bool> {
    let roles = tenant_repo::list_tenant_role_assignments(pool, tenant_id, entity_id)
        .await
        .map_err(gql_error)?;
    Ok(roles.iter().any(|role| {
        role.actions
            .iter()
            .any(|action| action == "read" || action == "manage")
    }))
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

#[cfg(test)]
mod tests {
    #[test]
    fn tenant_id_filters_keep_the_frozen_graphql_signature() {
        let schema = crate::graphql::schema_sdl();
        let tenants_field = schema
            .lines()
            .find(|line| line.trim_start().starts_with("tenants("))
            .expect("tenants query field");

        assert!(
            tenants_field.starts_with("\ttenants(id: ID, idContains: String,"),
            "unexpected tenants query signature: {tenants_field}"
        );
        assert!(!tenants_field.contains("tenants(id: String"));
    }
}
