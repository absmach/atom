use async_graphql::{Context, Object, Result, ID};
use uuid::Uuid;

use crate::{
    audit,
    auth::{require_capability, Scope},
    error::{db_err, AppError},
    graphql::{
        auth::{gql_error, require_auth},
        types::parse_id,
    },
    models::enums::AuditOutcome,
    state::AppState,
};

use super::{provisioning, repo, AuthorityKind, AuthorityRecord};

#[derive(Default)]
pub struct AuthorityQuery;

#[Object]
impl AuthorityQuery {
    async fn pki_authority(&self, ctx: &Context<'_>, id: ID) -> Result<Authority> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let authority = repo::authority_by_id(&state.pool, parse_id(id, "id")?)
            .await
            .map_err(gql_error)?;
        require_authority_access(state, &auth, &authority).await?;
        Ok(authority.into())
    }

    async fn pki_authorities(
        &self,
        ctx: &Context<'_>,
        tenant_id: Option<ID>,
    ) -> Result<Vec<Authority>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = tenant_id.map(|id| parse_id(id, "tenantId")).transpose()?;
        require_pki_capability(state, &auth, scope_for_authority(tenant_id)).await?;
        repo::list_authorities(&state.pool, tenant_id)
            .await
            .map(|items| items.into_iter().map(Authority::from).collect())
            .map_err(gql_error)
    }
}

#[derive(Default)]
pub struct AuthorityMutation;

#[Object]
impl AuthorityMutation {
    async fn begin_tenant_authority_provisioning(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
    ) -> Result<Authority> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        let result = async {
            require_mutation_access(state, &auth, Scope::Tenant(tenant_id)).await?;
            let mut tx = state.pool.begin().await.map_err(db_err)?;
            let mut outcome = provisioning::begin_tenant_authority_mutation_in_tx(
                &mut tx,
                &state.config.pki_ca_keys,
                tenant_id,
            )
            .await?;
            commit_authority_mutation(
                state,
                tx,
                &auth,
                &outcome.value,
                outcome.changed,
                "pki.authority.provisioning_started",
                "pki.authority.provisioning_replayed",
                AuditOutcome::Allow,
                lifecycle_details(&outcome.value),
            )
            .await?;
            outcome.commit_generated_key();
            Ok(outcome.value.into())
        }
        .await;
        observe_authority_result(
            state,
            &auth,
            Some(tenant_id),
            None,
            "pki.authority.provisioning_started",
            serde_json::json!({"transport": "graphql", "kind": "tenant_intermediate"}),
            result,
        )
        .await
    }

    async fn provision_tenant_authority_automatically(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
    ) -> Result<AuthorityImportResult> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_id(tenant_id, "tenantId")?;
        let result = async {
            auth.reject_scoped_credential_management()?;
            require_capability(
                &state.pool,
                &auth,
                "pki.provision",
                Scope::Tenant(tenant_id),
            )
            .await?;
            require_capability(
                &state.pool,
                &auth,
                "pki.provision_automated",
                Scope::Platform,
            )
            .await?;
            let mut tx = state.pool.begin().await.map_err(db_err)?;
            let mut mutation = provisioning::provision_tenant_automatically_mutation_in_tx(
                &mut tx,
                &state.config.pki_ca_keys,
                tenant_id,
            )
            .await?;
            let outcome = &mutation.value;
            commit_authority_mutation(
                state,
                tx,
                &auth,
                &outcome.authority,
                mutation.changed,
                "pki.authority.provisioned_automatically",
                "pki.authority.automated_provisioning_replayed",
                AuditOutcome::Allow,
                serde_json::json!({
                    "kind": authority_kind(&outcome.authority),
                    "version": outcome.authority.version,
                    "replaced_authorities": outcome.replaced_authorities.clone()
                }),
            )
            .await?;
            mutation.commit_generated_key();
            Ok(mutation.value.into())
        }
        .await;
        observe_authority_result(
            state,
            &auth,
            Some(tenant_id),
            None,
            "pki.authority.provisioned_automatically",
            serde_json::json!({"transport": "graphql"}),
            result,
        )
        .await
    }

    async fn begin_authority_retirement(
        &self,
        ctx: &Context<'_>,
        authority_id: ID,
    ) -> Result<Authority> {
        self.transition_retirement(ctx, authority_id, false).await
    }

    async fn complete_authority_retirement(
        &self,
        ctx: &Context<'_>,
        authority_id: ID,
    ) -> Result<Authority> {
        self.transition_retirement(ctx, authority_id, true).await
    }
}

impl AuthorityMutation {
    async fn transition_retirement(
        &self,
        ctx: &Context<'_>,
        authority_id: ID,
        complete: bool,
    ) -> Result<Authority> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let authority_id = parse_id(authority_id, "authorityId")?;
        let event = if complete {
            "pki.authority.retired"
        } else {
            "pki.authority.retiring"
        };
        let replay_event = if complete {
            "pki.authority.retirement_completion_replayed"
        } else {
            "pki.authority.retirement_start_replayed"
        };
        let mut observed_tenant_id = auth.tenant_id;
        let result = async {
            let existing = repo::authority_by_id(&state.pool, authority_id).await?;
            observed_tenant_id = existing.tenant_id;
            require_mutation_access(state, &auth, authority_scope(&existing)).await?;
            let mut tx = state.pool.begin().await.map_err(db_err)?;
            let mut outcome = if complete {
                provisioning::complete_retirement_mutation_in_tx(&mut tx, authority_id).await?
            } else {
                provisioning::begin_retirement_mutation_in_tx(
                    &mut tx,
                    &state.config.pki_ca_keys,
                    authority_id,
                )
                .await?
            };
            commit_authority_mutation(
                state,
                tx,
                &auth,
                &outcome.value,
                outcome.changed,
                event,
                replay_event,
                AuditOutcome::Allow,
                lifecycle_details(&outcome.value),
            )
            .await?;
            outcome.commit_generated_key();
            Ok(outcome.value.into())
        }
        .await;
        observe_authority_result(
            state,
            &auth,
            observed_tenant_id,
            Some(authority_id),
            event,
            serde_json::json!({"transport": "graphql"}),
            result,
        )
        .await
    }
}

pub struct Authority(pub AuthorityRecord);

#[Object]
impl Authority {
    async fn id(&self) -> ID {
        ID(self.0.id.to_string())
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(|id| ID(id.to_string()))
    }

    async fn parent_id(&self) -> Option<ID> {
        self.0.parent_id.map(|id| ID(id.to_string()))
    }

    async fn kind(&self) -> &'static str {
        authority_kind(&self.0)
    }

    async fn version(&self) -> i32 {
        self.0.version
    }

    async fn status(&self) -> &'static str {
        authority_status(&self.0)
    }

    async fn issuance_enabled(&self) -> bool {
        self.0.issuance_enabled
    }

    async fn subject(&self) -> &str {
        &self.0.subject
    }

    async fn serial_number(&self) -> Option<&str> {
        self.0.serial_number.as_deref()
    }

    async fn fingerprint_sha256(&self) -> Option<&str> {
        self.0.fingerprint_sha256.as_deref()
    }

    async fn subject_key_id(&self) -> Option<&str> {
        self.0.subject_key_id.as_deref()
    }

    async fn authority_key_id(&self) -> Option<&str> {
        self.0.authority_key_id.as_deref()
    }

    async fn certificate_pem(&self) -> Option<&str> {
        self.0.certificate_pem.as_deref()
    }

    async fn chain_pem(&self) -> Option<&str> {
        self.0.chain_pem.as_deref()
    }

    async fn csr_pem(&self) -> Option<&str> {
        self.0.csr_pem.as_deref()
    }

    async fn key_backend(&self) -> &'static str {
        key_backend(&self.0)
    }

    async fn provisioning_mode(&self) -> &str {
        &self.0.provisioning_mode
    }

    async fn failure_reason(&self) -> Option<&str> {
        self.0.failure_reason.as_deref()
    }

    async fn not_before(&self) -> Option<String> {
        self.0.not_before.map(|value| value.to_rfc3339())
    }

    async fn not_after(&self) -> Option<String> {
        self.0.not_after.map(|value| value.to_rfc3339())
    }

    async fn created_at(&self) -> String {
        self.0.created_at.to_rfc3339()
    }

    async fn activated_at(&self) -> Option<String> {
        self.0.activated_at.map(|value| value.to_rfc3339())
    }

    async fn retiring_at(&self) -> Option<String> {
        self.0.retiring_at.map(|value| value.to_rfc3339())
    }

    async fn retired_at(&self) -> Option<String> {
        self.0.retired_at.map(|value| value.to_rfc3339())
    }

    async fn updated_at(&self) -> String {
        self.0.updated_at.to_rfc3339()
    }

    async fn ocsp_url(&self) -> Option<&str> {
        self.0.ocsp_url.as_deref()
    }

    async fn ca_issuers_url(&self) -> Option<&str> {
        self.0.ca_issuers_url.as_deref()
    }

    async fn crl_distribution_point_url(&self) -> Option<&str> {
        self.0.crl_distribution_point_url.as_deref()
    }
}

impl From<AuthorityRecord> for Authority {
    fn from(value: AuthorityRecord) -> Self {
        Self(value)
    }
}

pub struct AuthorityImportResult {
    authority: Authority,
    validation_error: Option<String>,
    replaced_authority_ids: Vec<ID>,
}

#[Object]
impl AuthorityImportResult {
    async fn authority(&self) -> &Authority {
        &self.authority
    }

    async fn succeeded(&self) -> bool {
        self.validation_error.is_none()
    }

    async fn validation_error(&self) -> Option<&str> {
        self.validation_error.as_deref()
    }

    async fn replaced_authority_ids(&self) -> &[ID] {
        &self.replaced_authority_ids
    }
}

impl From<provisioning::AuthorityImportOutcome> for AuthorityImportResult {
    fn from(value: provisioning::AuthorityImportOutcome) -> Self {
        Self {
            authority: value.authority.into(),
            validation_error: value.validation_error,
            replaced_authority_ids: value
                .replaced_authorities
                .into_iter()
                .map(|id| ID(id.to_string()))
                .collect(),
        }
    }
}

async fn require_authority_access(
    state: &AppState,
    auth: &crate::auth::AuthContext,
    authority: &AuthorityRecord,
) -> Result<()> {
    require_pki_capability(state, auth, authority_scope(authority)).await
}

async fn require_mutation_access(
    state: &AppState,
    auth: &crate::auth::AuthContext,
    scope: Scope,
) -> std::result::Result<(), AppError> {
    auth.reject_scoped_credential_management()?;
    require_capability(&state.pool, auth, "pki.provision", scope).await
}

async fn require_pki_capability(
    state: &AppState,
    auth: &crate::auth::AuthContext,
    scope: Scope,
) -> Result<()> {
    require_capability(&state.pool, auth, "pki.provision", scope)
        .await
        .map_err(gql_error)
}

fn authority_scope(authority: &AuthorityRecord) -> Scope {
    scope_for_authority(authority.tenant_id)
}

fn scope_for_authority(tenant_id: Option<Uuid>) -> Scope {
    tenant_id.map_or(Scope::Platform, Scope::Tenant)
}

async fn commit_authority_event(
    state: &AppState,
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    auth: &crate::auth::AuthContext,
    authority: &AuthorityRecord,
    event: &'static str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> std::result::Result<(), AppError> {
    audit::commit_with_audit(
        &state.pool,
        tx,
        state.config.events.enabled(),
        &audit::AuditEvent {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: authority.tenant_id,
            target_kind: Some("pki_authority"),
            target_id: Some(authority.id),
            event,
            outcome,
            details,
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn commit_authority_mutation(
    state: &AppState,
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    auth: &crate::auth::AuthContext,
    authority: &AuthorityRecord,
    changed: bool,
    event: &'static str,
    replay_event: &'static str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> std::result::Result<(), AppError> {
    if changed {
        return commit_authority_event(state, tx, auth, authority, event, outcome, details).await;
    }

    tx.commit().await.map_err(db_err)?;
    let mut replay_details = details;
    if let serde_json::Value::Object(ref mut object) = replay_details {
        object.insert("replay".to_string(), serde_json::Value::Bool(true));
    }
    audit::write(
        &state.pool,
        false,
        audit::AuditEvent {
            actor_entity_id: Some(auth.entity_id),
            tenant_id: authority.tenant_id,
            target_kind: Some("pki_authority"),
            target_id: Some(authority.id),
            event: replay_event,
            outcome,
            details: replay_details,
        },
    )
    .await;
    Ok(())
}

async fn observe_authority_result<T>(
    state: &AppState,
    auth: &crate::auth::AuthContext,
    tenant_id: Option<Uuid>,
    target_id: Option<Uuid>,
    event: &'static str,
    details: serde_json::Value,
    result: std::result::Result<T, AppError>,
) -> Result<T> {
    if let Err(ref error) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: "pki_authority",
                target_id,
                event,
            },
            &details,
            error,
        )
        .await;
    }
    result.map_err(gql_error)
}

fn lifecycle_details(authority: &AuthorityRecord) -> serde_json::Value {
    serde_json::json!({
        "kind": authority_kind(authority),
        "version": authority.version,
        "status": authority_status(authority),
        "provisioning_mode": authority.provisioning_mode
    })
}

fn authority_kind(authority: &AuthorityRecord) -> &'static str {
    match authority.kind {
        AuthorityKind::Root => "root",
        AuthorityKind::PlatformIntermediate => "platform_intermediate",
        AuthorityKind::PlatformLeafIssuer => "platform_leaf_issuer",
        AuthorityKind::TenantIntermediate => "tenant_intermediate",
    }
}

fn authority_status(authority: &AuthorityRecord) -> &'static str {
    use super::AuthorityStatus;
    match authority.status {
        AuthorityStatus::Provisioning => "provisioning",
        AuthorityStatus::PendingSignature => "pending_signature",
        AuthorityStatus::Active => "active",
        AuthorityStatus::Retiring => "retiring",
        AuthorityStatus::Retired => "retired",
        AuthorityStatus::Revoked => "revoked",
        AuthorityStatus::Expired => "expired",
        AuthorityStatus::Failed => "failed",
    }
}

fn key_backend(authority: &AuthorityRecord) -> &'static str {
    use super::AuthorityKeyBackend;
    match authority.key_backend {
        AuthorityKeyBackend::PublicOnly => "public_only",
        AuthorityKeyBackend::EncryptedDatabase => "encrypted_database",
        AuthorityKeyBackend::Pkcs11 => "pkcs11",
        AuthorityKeyBackend::Kms => "kms",
    }
}
