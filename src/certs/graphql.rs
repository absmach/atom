use async_graphql::{Context, InputObject, Object, Result, ID};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_capability_in_scope, AuthContext, Scope},
    certs::service,
    error::db_err,
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
    async fn ca_chain(&self, ctx: &Context<'_>) -> Result<String> {
        let state = ctx.data::<AppState>()?;
        service::ca_chain(&state.config, state.certificate_issuer.as_deref()).map_err(gql_error)
    }

    async fn certificates(
        &self,
        ctx: &Context<'_>,
        entity_id: Option<ID>,
        tenant_id: Option<ID>,
        status: Option<String>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<CertificateList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = entity_id.map(|id| parse_id(id, "entityId")).transpose()?;
        let tenant_id = tenant_id.map(|id| parse_id(id, "tenantId")).transpose()?;
        let tenant_filter = if let Some(entity_id) = entity_id {
            require_entity_credential_read(state, &auth, entity_id).await?;
            None
        } else {
            resolve_list_tenant_filter(state, &auth, auth.tenant_id, tenant_id).await?
        };
        let certs = service::list_certificates(
            &state.pool,
            entity_id,
            tenant_filter,
            status,
            limit.unwrap_or(20),
            offset.unwrap_or(0),
        )
        .await
        .map_err(gql_error)?;
        let total = certs.len() as i64;
        Ok(CertificateList {
            items: certs.into_iter().map(Certificate::from).collect(),
            total,
        })
    }

    async fn certificate(
        &self,
        ctx: &Context<'_>,
        credential_id: Option<ID>,
        serial_number: Option<String>,
    ) -> Result<Certificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let cert = match (credential_id, serial_number) {
            (Some(id), None) => {
                service::certificate_by_id(&state.pool, parse_id(id, "credentialId")?)
                    .await
                    .map_err(gql_error)?
            }
            (None, Some(serial)) => service::legacy_certificate_by_serial(&state.pool, &serial)
                .await
                .map_err(gql_error)?,
            _ => {
                return Err(async_graphql::Error::new(
                    "provide credentialId or serialNumber",
                ))
            }
        };
        require_certificate_read(state, &auth, &cert).await?;
        Ok(cert.into())
    }
}

#[derive(Default)]
pub struct CertificateMutation;

#[Object]
impl CertificateMutation {
    async fn issue_certificate(
        &self,
        ctx: &Context<'_>,
        input: IssueCertificateInput,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(input.entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let issued = service::issue_certificate_in_tx(
            &mut tx,
            &state.config,
            state.certificate_issuer.as_deref(),
            service::IssueCertificate {
                entity_id,
                ttl_secs: input.ttl_secs,
                common_name: input.common_name,
                dns_names: input.dns_names.unwrap_or_default(),
                ip_addresses: input.ip_addresses.unwrap_or_default(),
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
                event: "certificate.issue",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "credential_id": issued.certificate.credential_id,
                    "serial_number": issued.certificate.serial_number,
                    "csr": false
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(issued.into())
    }

    /// Managed one-time key bootstrap. The legacy `issueCertificate` mutation
    /// remains the explicit file-issuer compatibility path.
    async fn issue_generated_certificate_v2(
        &self,
        ctx: &Context<'_>,
        input: IssueGeneratedCertificateV2Input,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(input.entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let issued = service::issue_generated_certificate_v2_in_tx(
            &mut tx,
            &state.config,
            tenant_id,
            service::IssueGeneratedCertificateV2 {
                entity_id,
                ttl_secs: input.ttl_secs,
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
        .map_err(gql_error)?;
        Ok(issued.into())
    }

    async fn issue_certificate_from_csr(
        &self,
        ctx: &Context<'_>,
        input: IssueCertificateFromCsrInput,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(input.entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let issued = service::issue_certificate_from_csr_in_tx(
            &mut tx,
            &state.config,
            state.certificate_issuer.as_deref(),
            service::IssueCertificateFromCsr {
                entity_id,
                ttl_secs: input.ttl_secs,
                csr_pem: input.csr_pem,
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
                event: "certificate.issue",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "credential_id": issued.certificate.credential_id,
                    "serial_number": issued.certificate.serial_number,
                    "csr": true
                }),
            },
        )
        .await
        .map_err(gql_error)?;
        Ok(issued.into())
    }

    /// Explicitly versioned managed-issuer path.  The v1 mutation above keeps
    /// its file-issuer behavior for compatibility.
    async fn issue_certificate_from_csr_v2(
        &self,
        ctx: &Context<'_>,
        input: IssueCertificateFromCsrV2Input,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let entity_id = parse_id(input.entity_id, "entityId")?;
        let tenant_id = require_credential_management(state, &auth, entity_id).await?;
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|error| gql_error(db_err(error)))?;
        let issued = service::issue_certificate_from_csr_v2_in_tx(
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
        .map_err(gql_error)?;
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
            tx.commit()
                .await
                .map_err(|error| gql_error(db_err(error)))?;
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
            audit::commit_with_audit(
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
            .map_err(gql_error)?;
        }
        Ok(issued.into())
    }

    async fn renew_certificate(
        &self,
        ctx: &Context<'_>,
        input: RenewCertificateInput,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let old = service::legacy_certificate_by_serial(&state.pool, &input.serial_number)
            .await
            .map_err(gql_error)?;
        require_certificate_rotate(state, &auth, &old).await?;
        let mut tx = state.pool.begin().await.map_err(|e| gql_error(db_err(e)))?;
        let issued = service::renew_certificate_in_tx(
            &mut tx,
            &state.config,
            state.certificate_issuer.as_deref(),
            service::RenewCertificate {
                serial_number: input.serial_number,
                ttl_secs: input.ttl_secs,
                revoke_old: input.revoke_old.unwrap_or(false),
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
                tenant_id: old.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(old.credential_id),
                event: "certificate.renew",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "entity_id": old.entity_id,
                    "old_serial_number": old.serial_number,
                    "new_serial_number": issued.certificate.serial_number,
                    "new_credential_id": issued.certificate.credential_id
                }),
            },
        )
        .await
        .map_err(gql_error)?;
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

    async fn revoke_certificate(
        &self,
        ctx: &Context<'_>,
        input: RevokeCertificateInput,
    ) -> Result<Certificate> {
        let state = ctx.data::<AppState>()?;
        let cert = service::legacy_certificate_by_serial(&state.pool, &input.serial_number)
            .await
            .map_err(gql_error)?;
        if cert.issuer_id.is_some() {
            return Err(async_graphql::Error::new(
                "managed certificate revocation requires revokeCertificateV2",
            ));
        }
        Ok(revoke_certificate_exact(
            ctx,
            service::CertificateRevocationSelector::CredentialId(cert.credential_id),
            input.reason,
        )
        .await?
        .certificate)
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
        audit::commit_with_audit(
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
        tx.commit()
            .await
            .map_err(|error| gql_error(db_err(error)))?;
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
        audit::commit_with_audit(
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
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| gql_error(db_err(error)))?;
    let issued = service::renew_certificate_v2_in_tx(
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
    .map_err(gql_error)?;
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
        tx.commit()
            .await
            .map_err(|error| gql_error(db_err(error)))?;
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
        audit::commit_with_audit(
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
        .map_err(gql_error)?;
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
