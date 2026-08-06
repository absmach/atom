use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    audit,
    auth::AuthContext,
    certs::service::{
        self as certificates, CertificateRenewalAuthorization, IssueCertificateFromCsrV2,
        RenewCertificateV2, RenewalKeySource, ResolveCertificateV2,
    },
    error::AppError,
    models::enums::AuditOutcome,
    state::AppState,
};

use super::{
    repo::{self, RateLimitScope},
    tls::VerifiedPeerCertificate,
};

#[derive(Debug, Clone)]
pub struct EnrollmentInput {
    pub csr_pem: String,
    pub ttl_secs: Option<u64>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentResponse {
    pub credential_id: Uuid,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub issuer_id: Uuid,
    pub profile_id: Uuid,
    pub profile_name: String,
    pub identity_uri: String,
    pub serial_number: String,
    pub certificate_pem: String,
    pub chain_pem: String,
    pub not_after: DateTime<Utc>,
    pub renewal_threshold_seconds: u64,
    pub renewal_due_at: DateTime<Utc>,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, Copy)]
struct Subject {
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
}

/// First enrollment using an already-authenticated non-certificate Atom
/// credential. Entity and tenant scope come exclusively from `AuthContext`.
pub async fn enroll(
    state: &AppState,
    auth: AuthContext,
    input: EnrollmentInput,
) -> Result<EnrollmentResponse, AppError> {
    let result = enroll_inner(
        state,
        Subject {
            entity_id: auth.entity_id,
            tenant_id: auth.tenant_id,
        },
        input,
    )
    .await;
    crate::metrics::record_pki_enrollment("first", outcome(&result));
    result
}

async fn enroll_inner(
    state: &AppState,
    subject: Subject,
    input: EnrollmentInput,
) -> Result<EnrollmentResponse, AppError> {
    enforce_input_and_rate_limits(state, subject, &input).await?;

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;
    let issued = certificates::issue_certificate_from_csr_v2_in_tx(
        &mut tx,
        &state.config,
        subject.tenant_id,
        IssueCertificateFromCsrV2 {
            entity_id: subject.entity_id,
            ttl_secs: input.ttl_secs,
            csr_pem: input.csr_pem,
            idempotency_key: input.idempotency_key,
        },
    )
    .await?;
    let response = response_from_issued(&issued)?;
    let details = serde_json::json!({
        "mode": "first",
        "credential_id": response.credential_id,
        "serial_number": response.serial_number,
        "issuer_id": response.issuer_id,
        "profile_id": response.profile_id,
        "renewal_due_at": response.renewal_due_at,
        "replay": response.idempotent_replay,
    });
    commit_with_mode_audit(
        state,
        tx,
        subject,
        response.credential_id,
        response.idempotent_replay,
        "certificate.enroll",
        "certificate.enroll_replayed",
        details,
    )
    .await?;
    Ok(response)
}

/// Re-enrollment using only the certificate verified by the enrollment TLS
/// listener. The authoritative resolver derives the exact credential and
/// rejects every invalid lifecycle state before renewal begins.
pub async fn re_enroll(
    state: &AppState,
    peer: VerifiedPeerCertificate,
    input: EnrollmentInput,
) -> Result<EnrollmentResponse, AppError> {
    let result = re_enroll_inner(state, peer, input).await;
    crate::metrics::record_pki_enrollment("reenroll", outcome(&result));
    result
}

async fn re_enroll_inner(
    state: &AppState,
    peer: VerifiedPeerCertificate,
    input: EnrollmentInput,
) -> Result<EnrollmentResponse, AppError> {
    let identity = certificates::resolve_certificate_identity_v2(
        &state.pool,
        ResolveCertificateV2 {
            certificate_der: Some(peer.as_der().to_vec()),
            fingerprint_sha256: None,
            issuer_fingerprint_sha256: None,
            serial_number: None,
            expected_tenant_id: None,
        },
    )
    .await
    .map_err(hide_peer_resolution_error)?;
    let subject = Subject {
        entity_id: identity.entity_id,
        tenant_id: identity.tenant_id,
    };
    enforce_input_and_rate_limits(state, subject, &input).await?;

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;
    let issued = certificates::renew_certificate_v2_in_tx(
        &mut tx,
        &state.config,
        CertificateRenewalAuthorization::PresentedCertificate {
            credential_id: identity.credential_id,
        },
        RenewCertificateV2 {
            credential_id: identity.credential_id,
            ttl_secs: input.ttl_secs,
            key_source: RenewalKeySource::Csr(input.csr_pem),
            // Preserve the normal renewal overlap window. A caller that loses
            // the response can retry with the still-valid source certificate;
            // lifecycle automation may revoke superseded credentials later.
            revoke_old: false,
            idempotency_key: input.idempotency_key,
        },
    )
    .await?;
    let response = response_from_issued(&issued)?;
    let details = serde_json::json!({
        "mode": "reenroll",
        "old_credential_id": identity.credential_id,
        "new_credential_id": response.credential_id,
        "serial_number": response.serial_number,
        "issuer_id": response.issuer_id,
        "profile_id": response.profile_id,
        "renewal_due_at": response.renewal_due_at,
        "replay": response.idempotent_replay,
    });
    commit_with_mode_audit(
        state,
        tx,
        subject,
        response.credential_id,
        response.idempotent_replay,
        "certificate.reenroll",
        "certificate.reenroll_replayed",
        details,
    )
    .await?;
    Ok(response)
}

async fn enforce_input_and_rate_limits(
    state: &AppState,
    subject: Subject,
    input: &EnrollmentInput,
) -> Result<(), AppError> {
    if input.csr_pem.len() > state.config.enrollment.max_csr_bytes {
        return Err(AppError::payload_too_large(format!(
            "csr_pem exceeds {} bytes",
            state.config.enrollment.max_csr_bytes
        )));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;
    let entity = repo::consume_rate_limit(
        &mut tx,
        RateLimitScope::Entity,
        subject.entity_id,
        state.config.enrollment.entity_rate_limit,
    )
    .await?;
    if !entity.allowed {
        tx.commit().await.map_err(AppError::Database)?;
        crate::metrics::record_rate_limit_rejection("pki_enrollment_entity");
        return Err(AppError::rate_limited(
            "entity enrollment rate limit exceeded",
            entity.retry_after_secs,
        ));
    }

    // Global entities share a platform enrollment bucket represented by the
    // nil UUID; tenant entities use their immutable tenant UUID.
    let tenant_scope = subject.tenant_id.unwrap_or_else(Uuid::nil);
    let tenant = repo::consume_rate_limit(
        &mut tx,
        RateLimitScope::Tenant,
        tenant_scope,
        state.config.enrollment.tenant_rate_limit,
    )
    .await?;
    tx.commit().await.map_err(AppError::Database)?;
    if !tenant.allowed {
        crate::metrics::record_rate_limit_rejection("pki_enrollment_tenant");
        return Err(AppError::rate_limited(
            "tenant enrollment rate limit exceeded",
            tenant.retry_after_secs,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn commit_with_mode_audit(
    state: &AppState,
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    subject: Subject,
    target_id: Uuid,
    replay: bool,
    event: &'static str,
    replay_event: &'static str,
    details: serde_json::Value,
) -> Result<(), AppError> {
    let audit_event = audit::AuditEvent {
        actor_entity_id: Some(subject.entity_id),
        tenant_id: subject.tenant_id,
        target_kind: Some("credential"),
        target_id: Some(target_id),
        event: if replay { replay_event } else { event },
        outcome: AuditOutcome::Allow,
        details,
    };
    if replay {
        tx.commit().await.map_err(AppError::Database)?;
        audit::write(&state.pool, false, audit_event).await;
        Ok(())
    } else {
        audit::commit_with_audit(&state.pool, tx, state.config.events.enabled(), &audit_event).await
    }
}

fn response_from_issued(
    issued: &certificates::IssuedCertificate,
) -> Result<EnrollmentResponse, AppError> {
    let certificate = &issued.certificate;
    let issuer_id = certificate.issuer_id.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "enrollment produced an unmanaged certificate"
        ))
    })?;
    let profile_id = certificate
        .profile_id
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("enrollment profile is missing")))?;
    let profile_name = certificate
        .profile_name
        .clone()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("enrollment profile name is missing")))?;
    let identity_uri = certificate
        .identity_uri
        .clone()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("enrollment identity URI is missing")))?;
    let not_after = certificate
        .expires_at
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("certificate expiry is missing")))?;
    let renewal_due_at = certificate.renewal_due_at.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("certificate renewal threshold is missing"))
    })?;
    let renewal_threshold_seconds = certificate.renewal_threshold_seconds.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "certificate profile renewal threshold is missing"
        ))
    })?;
    if renewal_threshold_seconds == 0 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "certificate renewal threshold is zero"
        )));
    }
    let chain_pem = issued
        .chain_pem
        .clone()
        .or_else(|| certificate.chain_pem.clone())
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("certificate chain is missing")))?;

    Ok(EnrollmentResponse {
        credential_id: certificate.credential_id,
        entity_id: certificate.entity_id,
        tenant_id: certificate.tenant_id,
        issuer_id,
        profile_id,
        profile_name,
        identity_uri,
        serial_number: certificate.serial_number.clone(),
        certificate_pem: certificate.certificate_pem.clone(),
        chain_pem,
        not_after,
        renewal_threshold_seconds,
        renewal_due_at,
        idempotent_replay: issued.idempotent_replay,
    })
}

fn hide_peer_resolution_error(error: AppError) -> AppError {
    match error {
        AppError::Database(_) | AppError::Internal(_) => error,
        _ => AppError::unauthorized("verified peer certificate is not eligible for re-enrollment"),
    }
}

fn outcome(result: &Result<EnrollmentResponse, AppError>) -> &'static str {
    match result {
        Ok(_) => "success",
        Err(AppError::RateLimited { .. }) => "rate_limited",
        Err(AppError::Unauthorized(_) | AppError::Forbidden) => "denied",
        Err(_) => "error",
    }
}
