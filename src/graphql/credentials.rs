use async_graphql::{Context, Object, Result, ID};

use crate::{
    audit,
    identity::service,
    models::{enums::AuditOutcome, token as token_model},
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_credential_management},
    types::{
        parse_id, parse_optional_timestamp, ApiKeyResponse, CreateApiKeyInput, Credential,
        CredentialList,
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
        require_credential_management(state, auth.entity_id, entity_id).await?;
        let credentials = service::list_credentials(&state.pool, entity_id)
            .await
            .map_err(gql_error)?;
        let total = credentials.len() as i64;
        Ok(CredentialList {
            items: credentials.into_iter().map(Credential::from).collect(),
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
        let tenant_id = require_credential_management(state, auth.entity_id, entity_id).await?;
        service::create_password(&state.pool, entity_id, &password)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            Some(entity_id),
            tenant_id,
            "credential.create",
            AuditOutcome::Allow,
            serde_json::json!({"kind": "password"}),
        )
        .await;
        Ok(true)
    }

    async fn create_api_key(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyResponse> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, auth.entity_id, entity_id).await?;
        let response = service::create_api_key(
            &state.pool,
            entity_id,
            token_model::CreateApiKey {
                expires_at: parse_optional_timestamp(input.expires_at, "expiresAt")?,
                description: input.description,
            },
        )
        .await
        .map_err(gql_error)?;
        audit::write(
            &state.pool,
            Some(entity_id),
            tenant_id,
            "credential.create",
            AuditOutcome::Allow,
            serde_json::json!({"kind": "api_key", "credential_id": response.credential_id}),
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
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let credential_id = parse_id(credential_id, "credentialId")?;
        let tenant_id = require_credential_management(state, auth.entity_id, entity_id).await?;
        service::revoke_credential(&state.pool, entity_id, credential_id)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            Some(auth.entity_id),
            tenant_id,
            "credential.revoke",
            AuditOutcome::Allow,
            serde_json::json!({"entity_id": entity_id, "credential_id": credential_id}),
        )
        .await;
        Ok(true)
    }
}
