use async_graphql::{Context, Object, Result, ID};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_capability_in_scope, Scope},
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

    async fn access_tokens(&self, ctx: &Context<'_>) -> Result<AccessTokenList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tokens = service::list_access_tokens(&state.pool, auth.entity_id)
            .await
            .map_err(gql_error)?;
        let total = tokens.len() as i64;
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
        let credential_id = service::create_password(&state.pool, entity_id, &password)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
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
        .await;
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
        let response = service::create_access_token(
            &state.pool,
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
        audit::write(
            &state.pool,
            audit::AuditEvent {
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
        .await;
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
        let permissions = permissions
            .into_iter()
            .map(permission_input_into_model)
            .collect::<Result<Vec<_>>>()?;
        service::replace_access_token_permissions(
            &state.pool,
            auth.entity_id,
            credential_id,
            permissions,
        )
        .await
        .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: auth.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(credential_id),
                event: "credential.update",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "kind": "access_token",
                    "credential_id": credential_id
                }),
            },
        )
        .await;
        Ok(true)
    }

    async fn revoke_access_token(&self, ctx: &Context<'_>, credential_id: ID) -> Result<bool> {
        let auth = require_auth(ctx)?;
        crate::graphql::auth::deny_scoped_token(&auth)?;
        let state = ctx.data::<AppState>()?;
        let credential_id = parse_id(credential_id, "credentialId")?;
        service::revoke_access_token(&state.pool, auth.entity_id, credential_id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: auth.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(credential_id),
                event: "credential.revoke",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "kind": "access_token",
                    "credential_id": credential_id
                }),
            },
        )
        .await;
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
        let response = service::create_shared_key(
            &state.pool,
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
        audit::write(
            &state.pool,
            audit::AuditEvent {
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
        .await;
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
        service::revoke_credential(&state.pool, entity_id, credential_id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(entity_id),
                event: "credential.revoke",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({"credential_id": credential_id}),
            },
        )
        .await;
        Ok(true)
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
