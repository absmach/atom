use async_graphql::{Context, InputObject, Object, Result, ID};
use uuid::Uuid;

use crate::{
    audit,
    auth::{has_capability_in_scope, AuthContext, Scope},
    certs::service,
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
            (None, Some(serial)) => service::certificate_by_serial(&state.pool, &serial)
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
        let issued = service::issue_certificate(
            &state.pool,
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
        audit::write(
            &state.pool,
            audit::AuditEvent {
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
        .await;
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
        let issued = service::issue_certificate_from_csr(
            &state.pool,
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
        audit::write(
            &state.pool,
            audit::AuditEvent {
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
        .await;
        Ok(issued.into())
    }

    async fn renew_certificate(
        &self,
        ctx: &Context<'_>,
        input: RenewCertificateInput,
    ) -> Result<IssuedCertificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let old = service::certificate_by_serial(&state.pool, &input.serial_number)
            .await
            .map_err(gql_error)?;
        require_certificate_rotate(state, &auth, &old).await?;
        let issued = service::renew_certificate(
            &state.pool,
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
        audit::write(
            &state.pool,
            audit::AuditEvent {
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
        .await;
        Ok(issued.into())
    }

    async fn revoke_certificate(
        &self,
        ctx: &Context<'_>,
        input: RevokeCertificateInput,
    ) -> Result<Certificate> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let cert = service::certificate_by_serial(&state.pool, &input.serial_number)
            .await
            .map_err(gql_error)?;
        require_certificate_revoke(state, &auth, &cert).await?;
        let revoked = service::revoke_certificate(&state.pool, &input.serial_number, input.reason)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: cert.tenant_id,
                target_kind: Some("credential"),
                target_id: Some(cert.credential_id),
                event: "certificate.revoke",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({
                    "entity_id": cert.entity_id,
                    "serial_number": cert.serial_number
                }),
            },
        )
        .await;
        Ok(revoked.into())
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
        let count = service::revoke_entity_certificates(&state.pool, entity_id, reason)
            .await
            .map_err(gql_error)?;
        audit::write(
            &state.pool,
            audit::AuditEvent {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: Some("entity"),
                target_id: Some(entity_id),
                event: "certificate.revoke_entity",
                outcome: AuditOutcome::Allow,
                details: serde_json::json!({"count": count}),
            },
        )
        .await;
        Ok(count as i64)
    }
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
pub struct IssueCertificateFromCsrInput {
    pub entity_id: ID,
    pub ttl_secs: Option<u64>,
    pub csr_pem: String,
}

#[derive(InputObject)]
pub struct RenewCertificateInput {
    pub serial_number: String,
    pub ttl_secs: Option<u64>,
    pub revoke_old: Option<bool>,
}

#[derive(InputObject)]
pub struct RevokeCertificateInput {
    pub serial_number: String,
    pub reason: Option<String>,
}

pub struct CertificateList {
    pub items: Vec<Certificate>,
    pub total: i64,
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
    pub private_key_pem: Option<String>,
}

#[Object]
impl IssuedCertificate {
    async fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    async fn private_key_pem(&self) -> Option<&str> {
        self.private_key_pem.as_deref()
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
