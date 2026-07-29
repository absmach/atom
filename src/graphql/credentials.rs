use async_graphql::{Context, Object, Result, ID};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_capability_in_scope, Scope},
    error::{db_err, AppError},
    identity::service,
    models::{enums::AuditOutcome, token as token_model},
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_credential_management},
    types::{
        parse_id, parse_optional_timestamp, AccessToken, AccessTokenList,
        AccessTokenPermissionInput, AccessTokenResponse, CreateAccessTokenInput,
        CreateSharedKeyInput, Credential, CredentialList, SharedKeyResponse,
    },
};

#[derive(Default)]
pub struct CredentialQuery;

#[Object]
impl CredentialQuery {
    async fn credentials(&self, ctx: &Context<'_>, entity_id: ID) -> Result<CredentialList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        require_credential_management(state, &auth, entity_id).await?;
        let credentials = service::list_credentials(&state.pool, entity_id)
            .await
            .map_err(gql_error)?;
        let total = credentials.len() as i64;
        Ok(CredentialList {
            items: credentials.into_iter().map(Credential::from).collect(),
            total,
        })
    }

    /// The caller's own tokens by default. `subjectId` names another owner —
    /// a *delegated* listing gated exactly like delegated minting (unscoped
    /// caller with `manage` on the target or its tenant), so the admin who
    /// provisions a service token can inspect its ceiling and usage afterwards.
    async fn access_tokens(
        &self,
        ctx: &Context<'_>,
        subject_id: Option<ID>,
        status: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<AccessTokenList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let owner_id = subject_id
            .map(|id| parse_id(id, "subjectId"))
            .transpose()?
            .unwrap_or(auth.entity_id);
        if owner_id != auth.entity_id {
            require_credential_management(state, &auth, owner_id).await?;
        }
        let status = parse_credential_status(status.as_deref())?;
        let (tokens, total) = service::list_access_tokens(
            &state.pool,
            owner_id,
            service::ListAccessTokens {
                status,
                limit: limit.map(i64::from).unwrap_or(100),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(AccessTokenList {
            items: tokens.into_iter().map(AccessToken::from).collect(),
            total,
        })
    }
}

#[derive(Default)]
pub struct CredentialMutation;

#[Object]
impl CredentialMutation {
    async fn change_own_password(
        &self,
        ctx: &Context<'_>,
        current_password: String,
        new_password: String,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: auth.tenant_id,
            target_kind: "credential",
            target_id: None,
            event: "credential.create",
        };
        let details = serde_json::json!({
            "entity_id": auth.entity_id,
            "kind": "password",
            "self_service": true,
        });

        let result: std::result::Result<bool, AppError> = async {
            auth.reject_scoped_credential_management()?;
            let mut tx = state.pool.begin().await.map_err(db_err)?;
            let credential_id = service::change_own_password_in_tx(
                &mut tx,
                auth.entity_id,
                &current_password,
                &new_password,
            )
            .await?;
            audit::commit_with_audit(
                &state.pool,
                tx,
                state.config.events.enabled(),
                &audit::AuditEvent {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id: auth.tenant_id,
                    target_kind: Some("credential"),
                    target_id: Some(credential_id),
                    event: "credential.create",
                    outcome: AuditOutcome::Allow,
                    details: details.clone(),
                },
            )
            .await?;
            Ok(true)
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

        result.map_err(gql_error)
    }

    async fn create_password(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        password: String,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let credential_id = service::create_password_in_tx(&mut tx, entity_id, &password)
            .await
            .map_err(gql_error)?;
        audit::commit_with_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("credential"),
                target_id: Some(credential_id),
                event: "credential.create",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "entity_id": entity_id,
                    "kind": "password",
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_access_token(
        &self,
        ctx: &Context<'_>,
        input: CreateAccessTokenInput,
    ) -> Result<AccessTokenResponse> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let scoped = input.scoped.unwrap_or(true);
        // Resolve the token owner. Absent or self => self-service. A different
        // subject => delegated mint. Authorization:
        //  - scoped self-mint: a scoped token could build a broader sibling, so
        //    deny_scoped_token blocks it; any unscoped caller may self-mint (the
        //    token can never exceed the caller's own live grants).
        //  - unscoped mint, or any delegated mint: routed through the
        //    credential-management gate (self OK, delegated needs `manage` on the
        //    target, scoped callers always rejected). An unscoped token carries the
        //    owner's full authority, so minting one is a credential-management act.
        let owner_id = input
            .subject_id
            .clone()
            .map(|id| parse_id(id, "subjectId"))
            .transpose()?
            .unwrap_or(auth.entity_id);
        let delegated = owner_id != auth.entity_id;
        // Audit rows are stamped with the token owner's tenant so the event is
        // visible in that tenant's audit trail (a delegated mint may cross
        // tenants); the credential-management gate already resolves it.
        let audit_tenant_id = if delegated || !scoped {
            require_credential_management(state, &auth, owner_id).await?
        } else {
            crate::graphql::auth::deny_scoped_token(&auth)?;
            auth.tenant_id
        };
        let permissions = input
            .permissions
            .into_iter()
            .map(permission_input_into_model)
            .collect::<Result<Vec<_>>>()?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let response = service::create_access_token_in_tx(
            &mut tx,
            &state.config.signing_keys,
            owner_id,
            token_model::CreateAccessToken {
                name: input.name,
                description: input.description,
                expires_at: parse_optional_timestamp(input.expires_at, "expiresAt")?,
                permissions,
            },
            scoped,
        )
        .await
        .map_err(gql_error)?;
        audit::commit_with_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: audit_tenant_id,
                target_kind: Some("credential"),
                target_id: Some(response.credential_id),
                event: "credential.create",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "entity_id": owner_id,
                    "kind": "access_token",
                    "scoped": scoped,
                    "delegated": delegated,
                    "name": &response.name,
                    "credential_id": response.credential_id
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(response.into())
    }

    async fn replace_access_token_permissions(
        &self,
        ctx: &Context<'_>,
        credential_id: ID,
        permissions: Vec<AccessTokenPermissionInput>,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        // A scoped token cannot widen its own (or any) ceiling.
        crate::graphql::auth::deny_scoped_token(&auth)?;
        let state = ctx.data::<AppState>()?;
        let credential_id = parse_id(credential_id, "credentialId")?;
        let (owner_id, delegated, audit_tenant_id) =
            resolve_token_lifecycle_target(state, &auth, credential_id).await?;
        let permissions = permissions
            .into_iter()
            .map(permission_input_into_model)
            .collect::<Result<Vec<_>>>()?;
        crate::cache::invalidate::guarded_mutation(
            state.cache.as_deref(),
            crate::cache::CacheCategory::CredentialCeiling,
            std::slice::from_ref(&crate::cache::keys::cred_ceiling(credential_id)),
            || async {
                let mut tx = state.pool.begin().await.map_err(db_err)?;
                service::replace_access_token_permissions_in_tx(
                    &mut tx,
                    owner_id,
                    credential_id,
                    permissions,
                )
                .await?;
                audit::commit_with_audit(
                    &state.pool,
                    tx,
                    state.config.events.enabled(),
                    &audit::AuditEvent {
                        actor_entity_id: Some(auth.entity_id),
                        tenant_id: audit_tenant_id,
                        target_kind: Some("credential"),
                        target_id: Some(credential_id),
                        event: "credential.update",
                        outcome: AuditOutcome::Allow,
                        details: serde_json::json!({
                            "entity_id": owner_id,
                            "kind": "access_token",
                            "delegated": delegated,
                            "credential_id": credential_id
                        }),
                    },
                )
                .await
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn revoke_access_token(&self, ctx: &Context<'_>, credential_id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        crate::graphql::auth::deny_scoped_token(&auth)?;
        let state = ctx.data::<AppState>()?;
        let credential_id = parse_id(credential_id, "credentialId")?;
        let (owner_id, delegated, audit_tenant_id) =
            resolve_token_lifecycle_target(state, &auth, credential_id).await?;
        crate::cache::invalidate::guarded_mutation(
            state.cache.as_deref(),
            crate::cache::CacheCategory::Credential,
            std::slice::from_ref(&crate::cache::keys::credential(credential_id)),
            || async {
                let mut tx = state.pool.begin().await.map_err(db_err)?;
                service::revoke_access_token_in_tx(&mut tx, owner_id, credential_id).await?;
                audit::commit_with_audit(
                    &state.pool,
                    tx,
                    state.config.events.enabled(),
                    &audit::AuditEvent {
                        actor_entity_id: Some(auth.entity_id),
                        tenant_id: audit_tenant_id,
                        target_kind: Some("credential"),
                        target_id: Some(credential_id),
                        event: "credential.revoke",
                        outcome: AuditOutcome::Allow,
                        details: serde_json::json!({
                            "entity_id": owner_id,
                            "kind": "access_token",
                            "delegated": delegated,
                            "credential_id": credential_id
                        }),
                    },
                )
                .await
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }

    async fn create_shared_key(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        input: CreateSharedKeyInput,
    ) -> Result<SharedKeyResponse> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let response = service::create_shared_key_in_tx(
            &mut tx,
            &state.config.signing_keys,
            entity_id,
            token_model::CreateSharedKey {
                expires_at: parse_optional_timestamp(input.expires_at, "expiresAt")?,
                description: input.description,
                key: input.key,
            },
        )
        .await
        .map_err(gql_error)?;
        audit::commit_with_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(entity_id),
                event: "credential.create",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "kind": "shared_key",
                    "credential_id": response.credential_id
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(response.into())
    }

    async fn reveal_shared_key(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        credential_id: ID,
    ) -> Result<SharedKeyResponse> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let credential_id = parse_id(credential_id, "credentialId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let response = service::reveal_shared_key(
            &state.pool,
            &state.config.signing_keys,
            entity_id,
            credential_id,
        )
        .await
        .map_err(gql_error)?;
        audit::write(
            &state.pool,
            state.config.events.enabled(),
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(entity_id),
                event: "credential.reveal",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "kind": "shared_key",
                    "credential_id": response.credential_id
                }),
            },
        )
        .await;
        Ok(response.into())
    }

    async fn revoke_credential(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        credential_id: ID,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        // Credential lifecycle is unscoped-only: a scoped access token must not
        // revoke credentials even when its ceiling grants `revoke` on the object.
        crate::graphql::auth::deny_scoped_token(&auth)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let credential_id = parse_id(credential_id, "credentialId")?;
        let tenant_id =
            if has_capability_in_scope(&state.pool, &auth, "revoke", Scope::Object(credential_id))
                .await
                .map_err(gql_error)?
            {
                credential_tenant_id(&state.pool, entity_id, credential_id).await?
            } else {
                require_credential_management(state, &auth, entity_id).await?
            };
        crate::cache::invalidate::guarded_mutation(
            state.cache.as_deref(),
            crate::cache::CacheCategory::Credential,
            std::slice::from_ref(&crate::cache::keys::credential(credential_id)),
            || async {
                let mut tx = state.pool.begin().await.map_err(db_err)?;
                service::revoke_credential_in_tx(&mut tx, entity_id, credential_id).await?;
                audit::commit_with_audit(
                    &state.pool,
                    tx,
                    state.config.events.enabled(),
                    &audit::AuditEvent {
                        actor_entity_id: Some(auth.entity_id),
                        tenant_id,
                        target_kind: Some("entity"),
                        target_id: Some(entity_id),
                        event: "credential.revoke",
                        outcome: AuditOutcome::Allow,
                        details: serde_json::json!({"credential_id": credential_id}),
                    },
                )
                .await
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(true)
    }
}

/// Resolve who a token-lifecycle mutation acts on and how it is authorized.
/// Owner acting on its own token passes with just the scoped-caller guard (the
/// resolver applies it before calling this); a different caller is a *delegated*
/// operation and must pass the credential-management gate for the owner — the
/// same gate as delegated minting. Returns (owner, delegated, audit tenant):
/// audit rows are stamped with the owner's tenant so the event lands in that
/// tenant's trail.
async fn resolve_token_lifecycle_target(
    state: &AppState,
    auth: &crate::auth::AuthContext,
    credential_id: Uuid,
) -> Result<(Uuid, bool, Option<Uuid>)> {
    let owner_id = service::access_token_owner(&state.pool, credential_id)
        .await
        .map_err(gql_error)?;
    if owner_id == auth.entity_id {
        return Ok((owner_id, false, auth.tenant_id));
    }
    let tenant_id = require_credential_management(state, auth, owner_id).await?;
    Ok((owner_id, true, tenant_id))
}

fn parse_credential_status(
    status: Option<&str>,
) -> Result<Option<crate::models::enums::CredentialStatus>> {
    match status {
        None => Ok(None),
        Some("active") => Ok(Some(crate::models::enums::CredentialStatus::Active)),
        Some("revocation_pending") => Ok(Some(
            crate::models::enums::CredentialStatus::RevocationPending,
        )),
        Some("revoked") => Ok(Some(crate::models::enums::CredentialStatus::Revoked)),
        Some(other) => Err(gql_error(crate::error::AppError::bad_request(format!(
            "invalid status filter: {other} (expected 'active', 'revocation_pending', or 'revoked')"
        )))),
    }
}

async fn credential_tenant_id(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<Uuid>> {
    let tenant_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT e.tenant_id FROM credentials c JOIN entities e ON e.id = c.entity_id WHERE c.id = $1 AND c.entity_id = $2",
    )
    .bind(credential_id)
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(crate::error::AppError::Database)
    .map_err(gql_error)?
    .ok_or_else(|| async_graphql::Error::new("credential not found"))?;
    Ok(tenant_id)
}

fn permission_input_into_model(
    input: AccessTokenPermissionInput,
) -> Result<token_model::AccessTokenPermission> {
    let tenant_id = input
        .tenant_id
        .map(|id| parse_id(id, "tenantId"))
        .transpose()?;
    let object_id = input
        .object_id
        .map(|id| parse_id(id, "objectId"))
        .transpose()?;
    Ok(token_model::AccessTokenPermission {
        actions: input.actions,
        scope_mode: input.scope_mode,
        tenant_id,
        object_kind: input.object_kind,
        object_type: input.object_type,
        object_id,
        conditions: input.conditions,
    })
}
