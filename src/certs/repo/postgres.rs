//! Native postgres certificate storage. Mutations borrow the caller transaction.
use super::{
    CertificateCredential, CertificateIssuanceRequestClaim, CertificateListFilter,
    CertificateRenewalRequestClaim, CertificateRevocationRecord, CrlState, IssuerRevocationEntry,
    RuntimeCertificateCredential,
};
use crate::error::{db_err, AppError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection as Connection, PgPool as Database, Postgres as Driver};
use uuid::Uuid;

pub(super) async fn entity_tenant_id<'e, E>(
    executor: E,
    entity_id: Uuid,
) -> Result<Option<Uuid>, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_scalar(
        r#"
        SELECT e.tenant_id
        FROM entities e
        LEFT JOIN tenants t ON t.id = e.tenant_id
        WHERE e.id = $1
          AND e.status = 'active'
          AND e.deleted_at IS NULL
          AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))
        "#,
    )
    .bind(entity_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::not_found("entity not found"))
}

pub(super) async fn insert_managed_certificate_credential(
    tx: &mut Connection,
    entity_id: Uuid,
    issuer_id: Uuid,
    serial_number: &str,
    metadata: Value,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, AppError> {
    sqlx::query_scalar(
        r#"
        INSERT INTO credentials (
            id, entity_id, kind, identifier, metadata, expires_at, issuer_id
        )
        VALUES ($1, $2, 'certificate', $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(serial_number)
    .bind(metadata)
    .bind(expires_at)
    .bind(issuer_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)
}

pub(super) async fn claim_certificate_issuance_request(
    tx: &mut Connection,
    entity_id: Uuid,
    request_key_hash: &str,
    request_fingerprint_sha256: &str,
) -> Result<CertificateIssuanceRequestClaim, AppError> {
    let request_id = Uuid::new_v4();
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO certificate_issuance_requests (
            id, entity_id, request_key_hash, request_fingerprint_sha256
        )
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (entity_id, request_key_hash) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(request_id)
    .bind(entity_id)
    .bind(request_key_hash)
    .bind(request_fingerprint_sha256)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if inserted.is_some() {
        return Ok(CertificateIssuanceRequestClaim::New { request_id });
    }

    let existing = sqlx::query_as::<_, (String, Option<Uuid>)>(
        r#"
        SELECT request_fingerprint_sha256, credential_id
        FROM certificate_issuance_requests
        WHERE entity_id = $1 AND request_key_hash = $2
        FOR UPDATE
        "#,
    )
    .bind(entity_id)
    .bind(request_key_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    super::existing_issuance_claim(existing, request_fingerprint_sha256)
}

pub(super) async fn complete_certificate_issuance_request(
    tx: &mut Connection,
    request_id: Uuid,
    credential_id: Uuid,
) -> Result<(), AppError> {
    let completed = sqlx::query_scalar::<_, Uuid>(
        r#"
        UPDATE certificate_issuance_requests
        SET credential_id = $2, completed_at = now()
        WHERE id = $1 AND credential_id IS NULL
        RETURNING id
        "#,
    )
    .bind(request_id)
    .bind(credential_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if completed.is_none() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "certificate issuance request could not be completed"
        )));
    }
    Ok(())
}

pub(super) async fn claim_certificate_renewal(
    tx: &mut Connection,
    previous_credential_id: Uuid,
    request_key_hash: &str,
    request_fingerprint_sha256: &str,
    key_mode: &str,
) -> Result<CertificateRenewalRequestClaim, AppError> {
    let renewal_id = Uuid::new_v4();
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO certificate_renewals (
            id, previous_credential_id, request_key_hash,
            request_fingerprint_sha256, key_mode
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (previous_credential_id) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(renewal_id)
    .bind(previous_credential_id)
    .bind(request_key_hash)
    .bind(request_fingerprint_sha256)
    .bind(key_mode)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if inserted.is_some() {
        return Ok(CertificateRenewalRequestClaim::New { renewal_id });
    }

    let existing = sqlx::query_as::<_, (String, String, String, Option<Uuid>)>(
        r#"
        SELECT request_key_hash, request_fingerprint_sha256, key_mode,
               replacement_credential_id
        FROM certificate_renewals
        WHERE previous_credential_id = $1
        FOR UPDATE
        "#,
    )
    .bind(previous_credential_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    super::existing_renewal_claim(
        existing,
        request_key_hash,
        request_fingerprint_sha256,
        key_mode,
    )
}

pub(super) async fn complete_certificate_renewal(
    tx: &mut Connection,
    renewal_id: Uuid,
    replacement_credential_id: Uuid,
) -> Result<(), AppError> {
    let completed = sqlx::query_scalar::<_, Uuid>(
        r#"
        UPDATE certificate_renewals
        SET replacement_credential_id = $2, completed_at = now()
        WHERE id = $1 AND replacement_credential_id IS NULL
        RETURNING id
        "#,
    )
    .bind(renewal_id)
    .bind(replacement_credential_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if completed.is_none() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "certificate renewal request could not be completed"
        )));
    }
    Ok(())
}

pub(super) async fn runtime_certificate_by_fingerprint(
    pool: &Database,
    fingerprint_sha256: &str,
) -> Result<RuntimeCertificateCredential, AppError> {
    sqlx::query_as::<_, RuntimeCertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier,
               c.status AS credential_status, c.metadata, c.expires_at,
               e.status AS entity_status, e.deleted_at AS entity_deleted_at,
               t.status AS tenant_status, t.deleted_at AS tenant_deleted_at,
               a.status AS issuer_status,
               a.issuance_enabled AS issuer_issuance_enabled,
               a.not_before AS issuer_not_before,
               a.not_after AS issuer_not_after
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        LEFT JOIN tenants t ON t.id = e.tenant_id
        LEFT JOIN pki_authorities a ON a.id = c.issuer_id
        WHERE c.kind = 'certificate'
          AND c.issuer_id IS NOT NULL
          AND c.metadata->>'fingerprint_sha256' = $1
        "#,
    )
    .bind(fingerprint_sha256)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn runtime_certificate_by_issuer_fingerprint_serial(
    pool: &Database,
    issuer_fingerprint_sha256: &str,
    serial_number: &str,
) -> Result<RuntimeCertificateCredential, AppError> {
    sqlx::query_as::<_, RuntimeCertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier,
               c.status AS credential_status, c.metadata, c.expires_at,
               e.status AS entity_status, e.deleted_at AS entity_deleted_at,
               t.status AS tenant_status, t.deleted_at AS tenant_deleted_at,
               a.status AS issuer_status,
               a.issuance_enabled AS issuer_issuance_enabled,
               a.not_before AS issuer_not_before,
               a.not_after AS issuer_not_after
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        LEFT JOIN tenants t ON t.id = e.tenant_id
        LEFT JOIN pki_authorities a ON a.id = c.issuer_id
        WHERE c.kind = 'certificate'
          AND c.issuer_id IS NOT NULL
          AND c.identifier = $2
          AND a.fingerprint_sha256 = $1
        "#,
    )
    .bind(issuer_fingerprint_sha256)
    .bind(serial_number)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn fetch_certificate_by_id<'e, E>(
    executor: E,
    credential_id: Uuid,
) -> Result<CertificateCredential, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate' AND c.id = $1
        "#,
    )
    .bind(credential_id)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_certificate_by_id(
    tx: &mut Connection,
    credential_id: Uuid,
) -> Result<CertificateCredential, AppError> {
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate' AND c.id = $1
        FOR UPDATE OF c
        "#,
    )
    .bind(credential_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)
}

pub(super) async fn certificate_by_fingerprint<'e, E>(
    executor: E,
    fingerprint_sha256: &str,
) -> Result<CertificateCredential, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate'
          AND c.metadata->>'fingerprint_sha256' = $1
        "#,
    )
    .bind(fingerprint_sha256)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_certificate_by_fingerprint(
    tx: &mut Connection,
    fingerprint_sha256: &str,
) -> Result<CertificateCredential, AppError> {
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate'
          AND c.metadata->>'fingerprint_sha256' = $1
        FOR UPDATE OF c
        "#,
    )
    .bind(fingerprint_sha256)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)
}

pub(super) async fn certificate_by_issuer_serial<'e, E>(
    executor: E,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<CertificateCredential, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate'
          AND c.issuer_id = $1
          AND c.identifier = $2
        "#,
    )
    .bind(issuer_id)
    .bind(serial_number)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_certificate_by_issuer_serial(
    tx: &mut Connection,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<CertificateCredential, AppError> {
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate'
          AND c.issuer_id = $1
          AND c.identifier = $2
        FOR UPDATE OF c
        "#,
    )
    .bind(issuer_id)
    .bind(serial_number)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)
}

pub(super) async fn list_certificates_filtered(
    pool: &Database,
    filter: &CertificateListFilter,
) -> Result<Vec<CertificateCredential>, AppError> {
    let mut query = sqlx::QueryBuilder::new(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate'
        "#,
    );
    if let Some(entity_id) = filter.entity_id {
        query.push(" AND c.entity_id = ");
        query.push_bind(entity_id);
    }
    if let Some(tenant_id) = filter.tenant_id {
        query.push(" AND e.tenant_id = ");
        query.push_bind(tenant_id);
    }
    if let Some(issuer_id) = filter.issuer_id {
        query.push(" AND c.issuer_id = ");
        query.push_bind(issuer_id);
    }
    if let Some(status) = filter.status.as_deref() {
        query.push(" AND c.status = ");
        query.push_bind(status);
    }
    if let Some(expires_from) = filter.expires_from.as_ref() {
        query.push(" AND c.expires_at >= ");
        query.push_bind(expires_from);
    }
    if let Some(expires_before) = filter.expires_before.as_ref() {
        query.push(" AND c.expires_at < ");
        query.push_bind(expires_before);
    }
    if filter.expires_from.is_some() || filter.expires_before.is_some() {
        query.push(" ORDER BY c.expires_at ASC NULLS LAST, c.id ASC LIMIT ");
    } else {
        query.push(" ORDER BY c.created_at DESC, c.id ASC LIMIT ");
    }
    query.push_bind(filter.limit);
    query.push(" OFFSET ");
    query.push_bind(filter.offset);

    query
        .build_query_as::<CertificateCredential>()
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)
}

pub(super) async fn count_certificates(
    pool: &Database,
    filter: &CertificateListFilter,
) -> Result<i64, AppError> {
    let mut query = sqlx::QueryBuilder::new(
        r#"
        SELECT COUNT(*)::bigint
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate'
        "#,
    );
    if let Some(entity_id) = filter.entity_id {
        query.push(" AND c.entity_id = ");
        query.push_bind(entity_id);
    }
    if let Some(tenant_id) = filter.tenant_id {
        query.push(" AND e.tenant_id = ");
        query.push_bind(tenant_id);
    }
    if let Some(issuer_id) = filter.issuer_id {
        query.push(" AND c.issuer_id = ");
        query.push_bind(issuer_id);
    }
    if let Some(status) = filter.status.as_deref() {
        query.push(" AND c.status = ");
        query.push_bind(status);
    }
    if let Some(expires_from) = filter.expires_from.as_ref() {
        query.push(" AND c.expires_at >= ");
        query.push_bind(expires_from);
    }
    if let Some(expires_before) = filter.expires_before.as_ref() {
        query.push(" AND c.expires_at < ");
        query.push_bind(expires_before);
    }
    query
        .build_query_scalar()
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)
}

pub(super) async fn revoke_certificate<'e, E>(
    executor: E,
    credential_id: Uuid,
    metadata: Value,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query(
        r#"
        UPDATE credentials
        SET status = 'revoked', metadata = $2
        WHERE id = $1 AND kind = 'certificate'
        "#,
    )
    .bind(credential_id)
    .bind(metadata)
    .execute(executor)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

pub(super) async fn revoke_certificate_if_active(
    tx: &mut Connection,
    credential_id: Uuid,
    metadata: Value,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        r#"
        UPDATE credentials
        SET status = 'revoked', metadata = $2
        WHERE id = $1 AND kind = 'certificate' AND status = 'active'
        "#,
    )
    .bind(credential_id)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    Ok(result.rows_affected() == 1)
}

pub(super) async fn certificate_revocation_by_id<'e, E>(
    executor: E,
    credential_id: Uuid,
) -> Result<CertificateRevocationRecord, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, CertificateRevocationRecord>(
        r#"
        SELECT credential_id, issuer_id, issuer_fingerprint_sha256,
               serial_number, reason, actor_entity_id, revoked_at
        FROM certificate_revocations
        WHERE credential_id = $1
        "#,
    )
    .bind(credential_id)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn certificate_revocation_by_issuer_serial<'e, E>(
    executor: E,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<Option<CertificateRevocationRecord>, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, CertificateRevocationRecord>(
        r#"
        SELECT credential_id, issuer_id, issuer_fingerprint_sha256,
               serial_number, reason, actor_entity_id, revoked_at
        FROM certificate_revocations
        WHERE issuer_id = $1 AND serial_number = $2
        "#,
    )
    .bind(issuer_id)
    .bind(serial_number)
    .fetch_optional(executor)
    .await
    .map_err(AppError::Database)
}

pub(super) async fn active_entity_certificates<'e, E>(
    executor: E,
    entity_id: Uuid,
) -> Result<Vec<CertificateCredential>, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, CertificateCredential>(
        r#"
        SELECT c.id, c.issuer_id, c.entity_id, e.tenant_id, c.identifier, c.status, c.metadata,
               c.expires_at, c.created_at
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.kind = 'certificate' AND c.entity_id = $1 AND c.status = 'active'
        FOR UPDATE OF c
        "#,
    )
    .bind(entity_id)
    .fetch_all(executor)
    .await
    .map_err(AppError::Database)
}

pub(super) async fn issuer_crl_state(
    pool: &Database,
    issuer_id: Uuid,
) -> Result<Option<CrlState>, AppError> {
    sqlx::query_as::<_, CrlState>(
        r#"
        SELECT issuer_fingerprint_sha256, crl_number, crl_der, crl_sha256,
               this_update, next_update, dirty
        FROM certificate_crl_state
        WHERE issuer_id = $1
        "#,
    )
    .bind(issuer_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)
}

pub(super) async fn issuer_crl_state_tx(
    tx: &mut Connection,
    issuer_id: Uuid,
    issuer_fingerprint_sha256: &str,
) -> Result<CrlState, AppError> {
    sqlx::query(
        r#"
        INSERT INTO certificate_crl_state
            (issuer_id, issuer_fingerprint_sha256, crl_number, dirty)
        VALUES ($1, $2, 0, TRUE)
        ON CONFLICT (issuer_id) DO NOTHING
        "#,
    )
    .bind(issuer_id)
    .bind(issuer_fingerprint_sha256)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    let state = sqlx::query_as::<_, CrlState>(
        r#"
        SELECT issuer_fingerprint_sha256, crl_number, crl_der, crl_sha256,
               this_update, next_update, dirty
        FROM certificate_crl_state
        WHERE issuer_id = $1
        FOR UPDATE
        "#,
    )
    .bind(issuer_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    Ok(state)
}

pub(super) async fn issuer_revocations_tx(
    tx: &mut Connection,
    issuer_id: Uuid,
) -> Result<Vec<IssuerRevocationEntry>, AppError> {
    sqlx::query_as::<_, IssuerRevocationEntry>(
        r#"
        SELECT credential_id, serial_number, reason, revoked_at
        FROM certificate_revocations
        WHERE issuer_id = $1
          AND expires_at > now()
        ORDER BY revoked_at, credential_id
        "#,
    )
    .bind(issuer_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::Database)
}

pub(super) async fn store_issuer_crl_tx(
    tx: &mut Connection,
    issuer_id: Uuid,
    crl_number: i64,
    crl_der: &[u8],
    crl_sha256: &str,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"
        UPDATE certificate_crl_state
        SET crl_number = $1,
            crl_der = $2,
            crl_sha256 = $3,
            this_update = $4,
            next_update = $5,
            dirty = FALSE,
            updated_at = now()
        WHERE issuer_id = $6
        "#,
    )
    .bind(crl_number)
    .bind(crl_der)
    .bind(crl_sha256)
    .bind(this_update)
    .bind(next_update)
    .bind(issuer_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if result.rows_affected() != 1 {
        return Err(AppError::not_found("issuer CRL state not found"));
    }
    Ok(())
}

const ISSUER_CRL_LOCK_DOMAIN: i64 = 0x504b_4939_4352_4c00;

fn issuer_crl_lock_id(issuer_id: Uuid) -> i64 {
    let bytes = issuer_id.as_bytes();
    let first = i64::from_be_bytes(bytes[..8].try_into().expect("UUID first half"));
    let second = i64::from_be_bytes(bytes[8..].try_into().expect("UUID second half"));
    first ^ second ^ ISSUER_CRL_LOCK_DOMAIN
}
pub(super) async fn lock_crl_publication(
    conn: &mut Connection,
    issuer_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(issuer_crl_lock_id(issuer_id))
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}
