use async_graphql::{Context, InputObject, Object, Result, ID};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_capability_in_scope, AuthContext, Scope},
    certs::{lifecycle, service},
    error::{db_err, AppError},
    models::enums::AuditOutcome,
    state::AppState,
};

use crate::graphql::{
    auth::{
        gql_error, require_any_capability, require_auth, require_credential_management,
        scope_for_tenant,
    },
    types::parse_id,
};

#[derive(Default)]
pub struct CertificateQuery;

#[Object]
impl CertificateQuery {
    #[allow(clippy::too_many_arguments)]
    async fn certificates(
        &self,
        ctx: &Context<'_>,
        entity_id: Option<ID>,
        tenant_id: Option<ID>,
        issuer_id: Option<ID>,
        status: Option<String>,
        expires_from: Option<String>,
        expires_before: Option<String>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<CertificateList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = entity_id.map(|id| parse_id(id, "entityId")).transpose()?;
        let tenant_id = tenant_id.map(|id| parse_id(id, "tenantId")).transpose()?;
        let issuer_id = issuer_id.map(|id| parse_id(id, "issuerId")).transpose()?;
        let expires_from = expires_from
            .as_deref()
            .map(|value| parse_timestamp(value, "expiresFrom"))
            .transpose()?;
        let expires_before = expires_before
            .as_deref()
            .map(|value| parse_timestamp(value, "expiresBefore"))
            .transpose()?;
        let tenant_filter = if let Some(entity_id) = entity_id {
            require_entity_credential_read(state, &auth, entity_id).await?;
            tenant_id
        } else {
            resolve_list_tenant_filter(state, &auth, auth.tenant_id, tenant_id).await?
        };
        let certs = service::list_certificates_filtered(
            &state.pool,
            service::CertificateListFilter {
                entity_id,
                tenant_id: tenant_filter,
                issuer_id,
                status,
                expires_from,
                expires_before,
                limit: limit.unwrap_or(20),
                offset: offset.unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(CertificateList {
            items: certs.items.into_iter().map(Certificate::from).collect(),
            total: certs.total,
        })
    }

    async fn certificate(&self, ctx: &Context<'_>, credential_id: ID) -> Result<Certificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let cert =
            service::certificate_by_id(&state.pool, parse_id(credential_id, "credentialId")?)
                .await
                .map_err(gql_error)?;
        require_certificate_read(state, &auth, &cert).await?;
        Ok(cert.into())
    }
}

fn parse_timestamp(value: &str, field: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| async_graphql::Error::new(format!("{field} must be an RFC3339 timestamp")))
}

async fn commit_with_lifecycle_audit(
    pool: &sqlx::PgPool,
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    events_enabled: bool,
    event: &audit::AuditEvent<'_>,
) -> std::result::Result<(), AppError> {
    let result = audit::commit_with_audit(pool, tx, events_enabled, event).await;
    let operation = match event.event {
        "certificate.issue" => Some("issuance"),
        "certificate.renew" => Some("renewal"),
        "certificate.revoke" | "certificate.revoke_entity" => Some("revocation"),
        _ => None,
    };
    if let Some(operation) = operation {
        service::record_lifecycle_commit(operation, &result);
    }
    result
}

async fn commit_lifecycle_replay(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &'static str,
) -> std::result::Result<(), AppError> {
    let result = tx.commit().await.map_err(AppError::Database);
    service::record_lifecycle_commit(operation, &result);
    result
}

#[derive(Default)]
pub struct CertificateMutation;

#[Object]
impl CertificateMutation {
    /// Managed one-time key bootstrap.
    async fn issue_generated_certificate_v2(
        &self,
        ctx: &Context<'_>,
        input: IssueGeneratedCertificateV2Input,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(input.entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let error_meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id,
            target_kind: "entity",
            target_id: Some(entity_id),
            event: "certificate.issue",
        };
        let error_details = serde_json::json!({
            "csr": false,
            "generated_key": true,
            "managed": true,
            "transport": "graphql",
        });
        let mut tx = match state.pool.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                let error = db_err(error);
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &error_meta,
                    &error_details,
                    &error,
                )
                .await;
                return Err(gql_error(error));
            }
        };
        let issued = match service::issue_generated_certificate_v2_in_tx(
            &mut tx,
            &state.config,
            tenant_id,
            service::IssueGeneratedCertificateV2 {
                entity_id,
                ttl_secs: input.ttl_secs,
            },
        )
        .await
        {
            Ok(issued) => issued,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(
                        "failed to roll back generated certificate issuance: {rollback_error}"
                    );
                }
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &error_meta,
                    &error_details,
                    &error,
                )
                .await;
                return Err(gql_error(error));
            }
        };
        if let Err(error) = commit_with_lifecycle_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(entity_id),
                event: "certificate.issue",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "credential_id": issued.certificate.credential_id,
                    "serial_number": issued.certificate.serial_number,
                    "issuer_id": issued.certificate.issuer_id,
                    "profile_id": issued.certificate.profile_id,
                    "csr": false,
                    "generated_key": true,
                    "managed": true,
                }),
            },
        )
        .await
        {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &error_meta,
                &error_details,
                &error,
            )
            .await;
            return Err(gql_error(error));
        }
        Ok(issued.into())
    }

    /// Managed-issuer CSR issuance.
    async fn issue_certificate_from_csr_v2(
        &self,
        ctx: &Context<'_>,
        input: IssueCertificateFromCsrV2Input,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(input.entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let error_meta = audit::AuditMeta {
            actor_entity_id: Some(auth.entity_id),
            tenant_id,
            target_kind: "entity",
            target_id: Some(entity_id),
            event: "certificate.issue",
        };
        let error_details = serde_json::json!({
            "csr": true,
            "managed": true,
            "transport": "graphql",
        });
        let mut tx = match state.pool.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                let error = db_err(error);
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &error_meta,
                    &error_details,
                    &error,
                )
                .await;
                return Err(gql_error(error));
            }
        };
        let issued = match service::issue_certificate_from_csr_v2_in_tx(
            &mut tx,
            &state.config,
            tenant_id,
            service::IssueCertificateFromCsrV2 {
                entity_id,
                ttl_secs: input.ttl_secs,
                csr_pem: input.csr_pem,
                idempotency_key: input.idempotency_key,
            },
        )
        .await
        {
            Ok(issued) => issued,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(
                        "failed to roll back CSR certificate issuance: {rollback_error}"
                    );
                }
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &error_meta,
                    &error_details,
                    &error,
                )
                .await;
                return Err(gql_error(error));
            }
        };
        let details = serde_json::json!({
            "credential_id": issued.certificate.credential_id,
            "serial_number": issued.certificate.serial_number,
            "issuer_id": issued.certificate.issuer_id,
            "profile_id": issued.certificate.profile_id,
            "csr": true,
            "managed": true,
            "replay": issued.idempotent_replay,
        });
        if issued.idempotent_replay {
            if let Err(error) = commit_lifecycle_replay(tx, "issuance").await {
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &error_meta,
                    &error_details,
                    &error,
                )
                .await;
                return Err(gql_error(error));
            }
            audit::write(
                &state.pool,
                false,
                audit::AuditEvent {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: Some("entity"),
                    target_id: Some(entity_id),
                    event: "certificate.issue_replayed",
                    outcome: AuditOutcome::Allow,
                    details,
                },
            )
            .await;
        } else {
            if let Err(error) = commit_with_lifecycle_audit(
                &state.pool,
                tx,
                state.config.events.enabled(),
                &audit::AuditEvent {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: Some("entity"),
                    target_id: Some(entity_id),
                    event: "certificate.issue",
                    outcome: AuditOutcome::Allow,
                    details,
                },
            )
            .await
            {
                audit::observe_error(
                    &state.pool,
                    state.config.events.enabled(),
                    &error_meta,
                    &error_details,
                    &error,
                )
                .await;
                return Err(gql_error(error));
            }
        }
        Ok(issued.into())
    }

    /// Exact-credential managed renewal using a subject-owned CSR.
    async fn renew_certificate_from_csr_v2(
        &self,
        ctx: &Context<'_>,
        input: RenewCertificateFromCsrV2Input,
    ) -> Result<IssuedCertificate> {
        renew_certificate_v2(
            ctx,
            parse_id(input.credential_id, "credentialId")?,
            input.ttl_secs,
            input.revoke_old.unwrap_or(false),
            input.idempotency_key,
            service::RenewalKeySource::Csr(input.csr_pem),
        )
        .await
    }

    /// Exact-credential managed renewal with a new one-time private key.
    async fn renew_generated_certificate_v2(
        &self,
        ctx: &Context<'_>,
        input: RenewGeneratedCertificateV2Input,
    ) -> Result<IssuedCertificate> {
        renew_certificate_v2(
            ctx,
            parse_id(input.credential_id, "credentialId")?,
            input.ttl_secs,
            input.revoke_old.unwrap_or(false),
            input.idempotency_key,
            service::RenewalKeySource::Generated,
        )
        .await
    }

    /// Issuer-aware revocation by exact credential, fingerprint, or issuer and serial.
    async fn revoke_certificate_v2(
        &self,
        ctx: &Context<'_>,
        input: RevokeCertificateV2Input,
    ) -> Result<CertificateRevocation> {
        let selector = match (
            input.credential_id,
            input.fingerprint_sha256,
            input.issuer_id,
            input.serial_number,
        ) {
            (Some(credential_id), None, None, None) => {
                service::CertificateRevocationSelector::CredentialId(parse_id(
                    credential_id,
                    "credentialId",
                )?)
            }
            (None, Some(fingerprint), None, None) => {
                service::CertificateRevocationSelector::FingerprintSha256(fingerprint)
            }
            (None, None, Some(issuer_id), Some(serial_number)) => {
                service::CertificateRevocationSelector::IssuerSerial {
                    issuer_id: parse_id(issuer_id, "issuerId")?,
                    serial_number,
                }
            }
            _ => {
                return Err(async_graphql::Error::new(
                    "provide exactly one selector: credentialId, fingerprintSha256, or issuerId with serialNumber",
                ))
            }
        };
        revoke_certificate_exact(ctx, selector, input.reason).await
    }

    async fn revoke_entity_certificates(
        &self,
        ctx: &Context<'_>,
        entity_id: ID,
        reason: Option<String>,
    ) -> Result<i64> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let revoked = service::revoke_entity_certificates_v2_in_tx(
            &mut tx,
            entity_id,
            reason,
            Some(auth.entity_id),
        )
        .await
        .map_err(gql_error)?;
        commit_with_lifecycle_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(entity_id),
                event: "certificate.revoke_entity",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "count": revoked.count,
                    "credential_ids": revoked.credential_ids,
                    "issuer_ids": revoked.issuer_ids,
                    "reason": revoked.reason,
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(revoked.count as i64)
    }

    /// Bounded, UUID-cursor fleet revocation by exactly one generic selector.
    /// Per-item commits make repeating the previous cursor safe after a crash.
    async fn bulk_revoke_certificates(
        &self,
        ctx: &Context<'_>,
        input: BulkRevokeCertificatesInput,
    ) -> Result<BulkRevokeCertificatesPayload> {
        let auth = require_auth(ctx)?;
        crate::graphql::auth::deny_scoped_token(&auth)?;
        let state = ctx.data::<AppState>()?;
        let selector = match (input.tenant_id, input.issuer_id, input.principal_group_id) {
            (Some(id), None, None) => {
                lifecycle::BulkRevocationSelector::Tenant(parse_id(id, "tenantId")?)
            }
            (None, Some(id), None) => {
                lifecycle::BulkRevocationSelector::Issuer(parse_id(id, "issuerId")?)
            }
            (None, None, Some(id)) => {
                lifecycle::BulkRevocationSelector::PrincipalGroup(parse_id(id, "principalGroupId")?)
            }
            _ => {
                return Err(async_graphql::Error::new(
                    "provide exactly one selector: tenantId, issuerId, or principalGroupId",
                ))
            }
        };
        let selector_tenant = lifecycle::selector_tenant_id(&state.pool, selector)
            .await
            .map_err(gql_error)?;
        let scope = scope_for_tenant(selector_tenant);
        require_any_capability(&state.pool, &auth, &[("revoke", scope), ("manage", scope)]).await?;
        let after = input
            .after_credential_id
            .map(|id| parse_id(id, "afterCredentialId"))
            .transpose()?;
        let snapshot_at = input
            .snapshot_at
            .as_deref()
            .map(|value| parse_timestamp(value, "snapshotAt"))
            .transpose()?;
        lifecycle::bulk_revoke(
            state,
            selector,
            auth.entity_id,
            input.reason,
            after,
            snapshot_at,
            input.limit.unwrap_or(100),
        )
        .await
        .map(BulkRevokeCertificatesPayload::from)
        .map_err(gql_error)
    }
}

async fn revoke_certificate_exact(
    ctx: &Context<'_>,
    selector: service::CertificateRevocationSelector,
    reason: Option<String>,
) -> Result<CertificateRevocation> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    let cert = service::certificate_by_revocation_selector(&state.pool, &selector)
        .await
        .map_err(gql_error)?;
    require_certificate_revoke(state, &auth, &cert).await?;
    let selector_kind = selector.kind();
    let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
    let revoked = service::revoke_certificate_v2_in_tx(
        &mut tx,
        service::RevokeCertificateV2 {
            selector,
            reason,
            actor_entity_id: Some(auth.entity_id),
            expected_entity_id: cert.entity_id,
            expected_tenant_id: cert.tenant_id,
        },
    )
    .await
    .map_err(gql_error)?;
    let details = serde_json::json!({
        "credential_id": revoked.certificate.credential_id,
        "entity_id": revoked.certificate.entity_id,
        "issuer_id": revoked.certificate.issuer_id,
        "issuer_fingerprint_sha256": revoked.issuer_fingerprint_sha256,
        "serial_number": revoked.certificate.serial_number,
        "reason": revoked.reason,
        "revoked_at": revoked.revoked_at,
        "selector": selector_kind,
        "idempotent_replay": revoked.idempotent_replay,
    });
    if revoked.idempotent_replay {
        commit_lifecycle_replay(tx, "revocation")
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            false,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: revoked.certificate.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(revoked.certificate.credential_id),
                event: "certificate.revoke_replayed",
                outcome: AuditOutcome::Allow,
                details,
            },
        )
        .await;
    } else {
        commit_with_lifecycle_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: revoked.certificate.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(revoked.certificate.credential_id),
                event: "certificate.revoke",
                outcome: AuditOutcome::Allow,
                details,
            },
        )
        .await
        .map_err(gql_error)?;
    }
    Ok(revoked.into())
}

async fn renew_certificate_v2(
    ctx: &Context<'_>,
    credential_id: Uuid,
    ttl_secs: Option<u64>,
    revoke_old: bool,
    idempotency_key: String,
    key_source: service::RenewalKeySource,
) -> Result<IssuedCertificate> {
    let auth = require_auth(ctx)?;
    let state = ctx.data::<AppState>()?;
    let old = service::certificate_by_id(&state.pool, credential_id)
        .await
        .map_err(gql_error)?;
    require_certificate_rotate(state, &auth, &old).await?;
    let key_mode = key_source.mode();
    let error_meta = audit::AuditMeta {
        actor_entity_id: Some(auth.entity_id),
        tenant_id: old.tenant_id,
        target_kind: "credential",
        target_id: Some(old.credential_id),
        event: "certificate.renew",
    };
    let error_details = serde_json::json!({
        "key_mode": key_mode,
        "revoke_old": revoke_old,
        "managed": true,
        "transport": "graphql",
    });
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            let error = db_err(error);
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &error_meta,
                &error_details,
                &error,
            )
            .await;
            return Err(gql_error(error));
        }
    };
    let issued = match service::renew_certificate_v2_in_tx(
        &mut tx,
        &state.config,
        service::CertificateRenewalAuthorization::Operator {
            actor_entity_id: Some(auth.entity_id),
            expected_entity_id: old.entity_id,
            expected_tenant_id: old.tenant_id,
        },
        service::RenewCertificateV2 {
            credential_id,
            ttl_secs,
            key_source,
            revoke_old,
            idempotency_key,
        },
    )
    .await
    {
        Ok(issued) => issued,
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!("failed to roll back certificate renewal: {rollback_error}");
            }
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &error_meta,
                &error_details,
                &error,
            )
            .await;
            return Err(gql_error(error));
        }
    };
    let details = serde_json::json!({
        "old_credential_id": old.credential_id,
        "new_credential_id": issued.certificate.credential_id,
        "old_serial_number": old.serial_number,
        "new_serial_number": issued.certificate.serial_number,
        "old_issuer_id": old.issuer_id,
        "new_issuer_id": issued.certificate.issuer_id,
        "profile_id": issued.certificate.profile_id,
        "key_mode": key_mode,
        "revoke_old": revoke_old,
        "replay": issued.idempotent_replay,
        "managed": true,
    });
    if issued.idempotent_replay {
        if let Err(error) = commit_lifecycle_replay(tx, "renewal").await {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &error_meta,
                &error_details,
                &error,
            )
            .await;
            return Err(gql_error(error));
        }
        audit::write(
            &state.pool,
            false,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: old.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(old.credential_id),
                event: "certificate.renew_replayed",
                outcome: AuditOutcome::Allow,
                details,
            },
        )
        .await;
    } else {
        if let Err(error) = commit_with_lifecycle_audit(
            &state.pool,
            tx,
            state.config.events.enabled(),
            &audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: old.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(old.credential_id),
                event: "certificate.renew",
                outcome: AuditOutcome::Allow,
                details,
            },
        )
        .await
        {
            audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &error_meta,
                &error_details,
                &error,
            )
            .await;
            return Err(gql_error(error));
        }
    }
    Ok(issued.into())
}

#[derive(InputObject)]
pub struct IssueCertificateInput {
    pub entity_id: ID,
    pub ttl_secs: Option<u64>,
    pub common_name: Option<String>,
    pub dns_names: Option<Vec<String>>,
    pub ip_addresses: Option<Vec<String>>,
}

#[derive(InputObject)]
pub struct IssueGeneratedCertificateV2Input {
    pub entity_id: ID,
    pub ttl_secs: Option<u64>,
}

#[derive(InputObject)]
pub struct IssueCertificateFromCsrInput {
    pub entity_id: ID,
    pub ttl_secs: Option<u64>,
    pub csr_pem: String,
}

#[derive(InputObject)]
pub struct IssueCertificateFromCsrV2Input {
    pub entity_id: ID,
    pub ttl_secs: Option<u64>,
    pub csr_pem: String,
    pub idempotency_key: String,
}

#[derive(InputObject)]
pub struct RenewCertificateInput {
    pub serial_number: String,
    pub ttl_secs: Option<u64>,
    pub revoke_old: Option<bool>,
}

#[derive(InputObject)]
pub struct RenewCertificateFromCsrV2Input {
    pub credential_id: ID,
    pub ttl_secs: Option<u64>,
    pub csr_pem: String,
    pub revoke_old: Option<bool>,
    pub idempotency_key: String,
}

#[derive(InputObject)]
pub struct RenewGeneratedCertificateV2Input {
    pub credential_id: ID,
    pub ttl_secs: Option<u64>,
    pub revoke_old: Option<bool>,
    pub idempotency_key: String,
}

#[derive(InputObject)]
pub struct RevokeCertificateInput {
    pub serial_number: String,
    pub reason: Option<String>,
}

#[derive(InputObject)]
pub struct RevokeCertificateV2Input {
    pub credential_id: Option<ID>,
    pub fingerprint_sha256: Option<String>,
    pub issuer_id: Option<ID>,
    pub serial_number: Option<String>,
    pub reason: Option<String>,
}

#[derive(InputObject)]
pub struct BulkRevokeCertificatesInput {
    pub tenant_id: Option<ID>,
    pub issuer_id: Option<ID>,
    pub principal_group_id: Option<ID>,
    pub reason: Option<String>,
    pub after_credential_id: Option<ID>,
    pub snapshot_at: Option<String>,
    pub limit: Option<i64>,
}

#[derive(async_graphql::SimpleObject)]
pub struct BulkRevokeCertificateItem {
    pub credential_id: ID,
    pub issuer_id: Option<ID>,
    pub entity_id: ID,
    pub tenant_id: Option<ID>,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(async_graphql::SimpleObject)]
pub struct BulkRevokeCertificatesPayload {
    pub items: Vec<BulkRevokeCertificateItem>,
    pub snapshot_at: String,
    pub next_cursor: Option<ID>,
    pub complete: bool,
}

impl From<lifecycle::BulkRevocationBatch> for BulkRevokeCertificatesPayload {
    fn from(value: lifecycle::BulkRevocationBatch) -> Self {
        Self {
            snapshot_at: value.snapshot_at.to_rfc3339(),
            items: value
                .items
                .into_iter()
                .map(|item| BulkRevokeCertificateItem {
                    credential_id: ID(item.credential_id.to_string()),
                    issuer_id: item.issuer_id.map(|id| ID(id.to_string())),
                    entity_id: ID(item.entity_id.to_string()),
                    tenant_id: item.tenant_id.map(|id| ID(id.to_string())),
                    outcome: item.outcome.to_string(),
                    error_code: item.error_code.map(str::to_string),
                })
                .collect(),
            next_cursor: value.next_cursor.map(|id| ID(id.to_string())),
            complete: value.complete,
        }
    }
}

pub struct CertificateList {
    pub items: Vec<Certificate>,
    pub total: i64,
}

pub struct CertificateRevocation {
    certificate: Certificate,
    reason: String,
    actor_entity_id: Option<Uuid>,
    revoked_at: chrono::DateTime<chrono::Utc>,
    idempotent_replay: bool,
}

impl From<service::CertificateRevocationResult> for CertificateRevocation {
    fn from(value: service::CertificateRevocationResult) -> Self {
        Self {
            certificate: value.certificate.into(),
            reason: value.reason,
            actor_entity_id: value.actor_entity_id,
            revoked_at: value.revoked_at,
            idempotent_replay: value.idempotent_replay,
        }
    }
}

#[Object]
impl CertificateRevocation {
    async fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    async fn reason(&self) -> &str {
        &self.reason
    }

    async fn actor_entity_id(&self) -> Option<ID> {
        self.actor_entity_id.map(|id| ID(id.to_string()))
    }

    async fn revoked_at(&self) -> String {
        self.revoked_at.to_rfc3339()
    }

    async fn idempotent_replay(&self) -> bool {
        self.idempotent_replay
    }
}

#[Object]
impl CertificateList {
    async fn items(&self) -> &[Certificate] {
        &self.items
    }

    async fn total(&self) -> i64 {
        self.total
    }
}

pub struct IssuedCertificate {
    pub certificate: Certificate,
    pub private_key_pem: Option<service::OneTimePrivateKey>,
    pub chain_pem: Option<String>,
    pub idempotent_replay: bool,
}

#[Object]
impl IssuedCertificate {
    async fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    async fn private_key_pem(&self) -> Option<&str> {
        self.private_key_pem
            .as_ref()
            .map(service::OneTimePrivateKey::expose)
    }

    async fn chain_pem(&self) -> Option<&str> {
        self.chain_pem.as_deref()
    }

    async fn idempotent_replay(&self) -> bool {
        self.idempotent_replay
    }
}

pub struct Certificate(pub service::CertificateRecord);

#[Object]
impl Certificate {
    async fn credential_id(&self) -> ID {
        ID(self.0.credential_id.to_string())
    }

    async fn entity_id(&self) -> ID {
        ID(self.0.entity_id.to_string())
    }

    async fn issuer_id(&self) -> Option<ID> {
        self.0.issuer_id.map(|id| ID(id.to_string()))
    }

    async fn tenant_id(&self) -> Option<ID> {
        self.0.tenant_id.map(|id| ID(id.to_string()))
    }

    async fn serial_number(&self) -> &str {
        &self.0.serial_number
    }

    async fn status(&self) -> &str {
        &self.0.status
    }

    async fn certificate_pem(&self) -> &str {
        &self.0.certificate_pem
    }

    async fn subject(&self) -> &serde_json::Value {
        &self.0.subject
    }

    async fn dns_names(&self) -> &[String] {
        &self.0.dns_names
    }

    async fn ip_addresses(&self) -> &[String] {
        &self.0.ip_addresses
    }

    async fn fingerprint_sha256(&self) -> &str {
        &self.0.fingerprint_sha256
    }

    async fn profile_id(&self) -> Option<ID> {
        self.0.profile_id.map(|id| ID(id.to_string()))
    }

    async fn profile_name(&self) -> Option<&str> {
        self.0.profile_name.as_deref()
    }

    async fn identity_uri(&self) -> Option<&str> {
        self.0.identity_uri.as_deref()
    }

    async fn renewed_from_credential_id(&self) -> Option<ID> {
        self.0
            .renewed_from_credential_id
            .map(|id| ID(id.to_string()))
    }

    async fn renewal_due_at(&self, ctx: &Context<'_>) -> Result<String> {
        let due_at = match self.0.renewal_due_at {
            Some(value) => value,
            None => {
                let state = ctx.data::<AppState>()?;
                service::certificate_renewal_due_at(&state.pool, self.0.credential_id)
                    .await
                    .map_err(gql_error)?
            }
        };
        Ok(due_at.to_rfc3339())
    }

    async fn expires_at(&self) -> Option<String> {
        self.0.expires_at.map(|ts| ts.to_rfc3339())
    }

    async fn created_at(&self) -> String {
        self.0.created_at.to_rfc3339()
    }

    async fn revoked_at(&self) -> Option<String> {
        self.0.revoked_at.map(|ts| ts.to_rfc3339())
    }

    async fn revocation_reason(&self) -> Option<&str> {
        self.0.revocation_reason.as_deref()
    }
}

impl From<service::IssuedCertificate> for IssuedCertificate {
    fn from(value: service::IssuedCertificate) -> Self {
        IssuedCertificate {
            certificate: Certificate(value.certificate),
            private_key_pem: value.private_key_pem,
            chain_pem: value.chain_pem,
            idempotent_replay: value.idempotent_replay,
        }
    }
}

impl From<service::CertificateRecord> for Certificate {
    fn from(value: service::CertificateRecord) -> Self {
        Certificate(value)
    }
}

async fn require_entity_credential_read(
    state: &AppState,
    auth: &AuthContext,
    entity_id: Uuid,
) -> Result<()> {
    let tenant_id = crate::certs::repo::entity_tenant_id(&state.pool, entity_id)
        .await
        .map_err(gql_error)?;
    require_any_capability(
        &state.pool,
        auth,
        &[
            ("read", Scope::Object(entity_id)),
            ("manage", Scope::Object(entity_id)),
            ("read", scope_for_tenant(tenant_id)),
            ("manage", scope_for_tenant(tenant_id)),
        ],
    )
    .await
}

async fn resolve_list_tenant_filter(
    state: &AppState,
    auth: &AuthContext,
    actor_tenant_id: Option<Uuid>,
    requested_tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    if let Some(tenant_id) = requested_tenant_id {
        require_any_capability(
            &state.pool,
            auth,
            &[
                ("read", Scope::Tenant(tenant_id)),
                ("manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        return Ok(Some(tenant_id));
    }

    if has_capability_in_scope(&state.pool, auth, "read", Scope::Platform)
        .await
        .map_err(gql_error)?
        || has_capability_in_scope(&state.pool, auth, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?
    {
        return Ok(None);
    }

    if let Some(tenant_id) = actor_tenant_id {
        require_any_capability(
            &state.pool,
            auth,
            &[
                ("read", Scope::Tenant(tenant_id)),
                ("manage", Scope::Tenant(tenant_id)),
            ],
        )
        .await?;
        return Ok(Some(tenant_id));
    }

    Err(gql_error(crate::error::AppError::Forbidden))
}

async fn require_certificate_read(
    state: &AppState,
    auth: &AuthContext,
    cert: &service::CertificateRecord,
) -> Result<()> {
    if has_capability_in_scope(&state.pool, auth, "read", Scope::Object(cert.credential_id))
        .await
        .map_err(gql_error)?
        || has_capability_in_scope(
            &state.pool,
            auth,
            "manage",
            Scope::Object(cert.credential_id),
        )
        .await
        .map_err(gql_error)?
    {
        return Ok(());
    }
    require_entity_credential_read(state, auth, cert.entity_id).await
}

async fn require_certificate_rotate(
    state: &AppState,
    auth: &AuthContext,
    cert: &service::CertificateRecord,
) -> Result<()> {
    if has_capability_in_scope(
        &state.pool,
        auth,
        "rotate",
        Scope::Object(cert.credential_id),
    )
    .await
    .map_err(gql_error)?
        || has_capability_in_scope(
            &state.pool,
            auth,
            "manage",
            Scope::Object(cert.credential_id),
        )
        .await
        .map_err(gql_error)?
    {
        return Ok(());
    }
    require_credential_management(state, auth, cert.entity_id).await?;
    Ok(())
}

async fn require_certificate_revoke(
    state: &AppState,
    auth: &AuthContext,
    cert: &service::CertificateRecord,
) -> Result<()> {
    if has_capability_in_scope(
        &state.pool,
        auth,
        "revoke",
        Scope::Object(cert.credential_id),
    )
    .await
    .map_err(gql_error)?
        || has_capability_in_scope(
            &state.pool,
            auth,
            "manage",
            Scope::Object(cert.credential_id),
        )
        .await
        .map_err(gql_error)?
    {
        return Ok(());
    }
    require_credential_management(state, auth, cert.entity_id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use async_graphql::Request;

    use super::*;

    #[tokio::test]
    async fn bulk_revocation_rejects_scoped_tokens_before_database_access() {
        let schema = crate::graphql::build_schema(test_state());
        let tenant_id = Uuid::new_v4();
        let response = schema
            .execute(
                Request::new(format!(
                    r#"mutation {{ bulkRevokeCertificates(input: {{ tenantId: "{tenant_id}" }}) {{ complete }} }}"#
                ))
                .data(AuthContext {
                    entity_id: Uuid::new_v4(),
                    scoped: true,
                    ..Default::default()
                }),
            )
            .await;

        assert_eq!(response.errors.len(), 1, "{:#?}", response.errors);
        assert_eq!(response.errors[0].message, "forbidden");
    }

    fn test_state() -> AppState {
        crate::certs::test_state_without_database()
    }
}
