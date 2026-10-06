mod postgres;
mod sqlite;

use crate::db::Database;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{db::DbTransaction, error::AppError};

#[derive(Debug, Clone, FromRow)]
pub struct CertificateCredential {
    pub id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub identifier: String,
    pub status: String,
    pub metadata: Value,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Certificate row plus every lifecycle state needed by the authoritative
/// runtime resolver. Keeping this projection separate prevents management
/// queries from accidentally treating their less restrictive joins as an
/// authentication decision.
#[derive(Debug, Clone, FromRow)]
pub struct RuntimeCertificateCredential {
    pub id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub identifier: String,
    pub credential_status: String,
    pub metadata: Value,
    pub expires_at: Option<DateTime<Utc>>,
    pub entity_status: String,
    pub entity_deleted_at: Option<DateTime<Utc>>,
    pub tenant_status: Option<String>,
    pub tenant_deleted_at: Option<DateTime<Utc>>,
    pub issuer_status: Option<String>,
    pub issuer_issuance_enabled: Option<bool>,
    pub issuer_not_before: Option<DateTime<Utc>>,
    pub issuer_not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateIssuanceRequestClaim {
    New { request_id: Uuid },
    Replay { credential_id: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRenewalRequestClaim {
    New { renewal_id: Uuid },
    Replay { credential_id: Uuid },
}

#[derive(Debug, Clone, FromRow)]
pub struct CrlState {
    pub issuer_fingerprint_sha256: String,
    pub crl_number: i64,
    pub crl_der: Option<Vec<u8>>,
    pub crl_sha256: Option<String>,
    pub this_update: Option<DateTime<Utc>>,
    pub next_update: Option<DateTime<Utc>>,
    pub dirty: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct IssuerRevocationEntry {
    pub credential_id: Uuid,
    pub serial_number: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct CertificateRevocationRecord {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub issuer_fingerprint_sha256: Option<String>,
    pub serial_number: String,
    pub reason: String,
    pub actor_entity_id: Option<Uuid>,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct CertificateListFilter {
    pub entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub issuer_id: Option<Uuid>,
    pub status: Option<String>,
    pub expires_from: Option<DateTime<Utc>>,
    pub expires_before: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn entity_tenant_id<'e, E>(executor: E, entity_id: Uuid) -> Result<Option<Uuid>, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => postgres::entity_tenant_id(conn, entity_id).await,
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::entity_tenant_id(conn, entity_id).await
        }
        crate::db::Target::PoolSqlite(conn) => sqlite::entity_tenant_id(conn, entity_id).await,
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::entity_tenant_id(conn, entity_id).await
        }
    }
}

pub async fn insert_managed_certificate_credential(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    issuer_id: Uuid,
    serial_number: &str,
    metadata: Value,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_managed_certificate_credential(
                conn,
                entity_id,
                issuer_id,
                serial_number,
                metadata,
                expires_at,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_managed_certificate_credential(
                conn,
                entity_id,
                issuer_id,
                serial_number,
                metadata,
                expires_at,
            )
            .await
        }
    }
}

pub async fn claim_certificate_issuance_request(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    request_key_hash: &str,
    request_fingerprint_sha256: &str,
) -> Result<CertificateIssuanceRequestClaim, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::claim_certificate_issuance_request(
                conn,
                entity_id,
                request_key_hash,
                request_fingerprint_sha256,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::claim_certificate_issuance_request(
                conn,
                entity_id,
                request_key_hash,
                request_fingerprint_sha256,
            )
            .await
        }
    }
}

pub async fn complete_certificate_issuance_request(
    tx: &mut DbTransaction<'_>,
    request_id: Uuid,
    credential_id: Uuid,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::complete_certificate_issuance_request(conn, request_id, credential_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::complete_certificate_issuance_request(conn, request_id, credential_id).await
        }
    }
}

pub async fn claim_certificate_renewal(
    tx: &mut DbTransaction<'_>,
    previous_credential_id: Uuid,
    request_key_hash: &str,
    request_fingerprint_sha256: &str,
    key_mode: &str,
) -> Result<CertificateRenewalRequestClaim, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::claim_certificate_renewal(
                conn,
                previous_credential_id,
                request_key_hash,
                request_fingerprint_sha256,
                key_mode,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::claim_certificate_renewal(
                conn,
                previous_credential_id,
                request_key_hash,
                request_fingerprint_sha256,
                key_mode,
            )
            .await
        }
    }
}

pub async fn complete_certificate_renewal(
    tx: &mut DbTransaction<'_>,
    renewal_id: Uuid,
    replacement_credential_id: Uuid,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::complete_certificate_renewal(conn, renewal_id, replacement_credential_id)
                .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::complete_certificate_renewal(conn, renewal_id, replacement_credential_id).await
        }
    }
}

pub async fn runtime_certificate_by_fingerprint(
    pool: &Database,
    fingerprint_sha256: &str,
) -> Result<RuntimeCertificateCredential, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::runtime_certificate_by_fingerprint(pool, fingerprint_sha256).await
        }
        Database::Sqlite(db) => {
            sqlite::runtime_certificate_by_fingerprint(&db.pool, fingerprint_sha256).await
        }
    }
}

pub async fn runtime_certificate_by_issuer_fingerprint_serial(
    pool: &Database,
    issuer_fingerprint_sha256: &str,
    serial_number: &str,
) -> Result<RuntimeCertificateCredential, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::runtime_certificate_by_issuer_fingerprint_serial(
                pool,
                issuer_fingerprint_sha256,
                serial_number,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::runtime_certificate_by_issuer_fingerprint_serial(
                &db.pool,
                issuer_fingerprint_sha256,
                serial_number,
            )
            .await
        }
    }
}

pub async fn certificate_by_id(
    pool: &Database,
    credential_id: Uuid,
) -> Result<CertificateCredential, AppError> {
    fetch_certificate_by_id(pool, credential_id).await
}

/// Executor-generic `certificate_by_id`, so an issuing transaction can read the
/// row it just wrote without committing first.
pub async fn fetch_certificate_by_id<'e, E>(
    executor: E,
    credential_id: Uuid,
) -> Result<CertificateCredential, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::fetch_certificate_by_id(conn, credential_id).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::fetch_certificate_by_id(conn, credential_id).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::fetch_certificate_by_id(conn, credential_id).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::fetch_certificate_by_id(conn, credential_id).await
        }
    }
}

pub async fn lock_certificate_by_id(
    tx: &mut DbTransaction<'_>,
    credential_id: Uuid,
) -> Result<CertificateCredential, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::lock_certificate_by_id(conn, credential_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::lock_certificate_by_id(conn, credential_id).await,
    }
}

pub async fn certificate_by_fingerprint<'e, E>(
    executor: E,
    fingerprint_sha256: &str,
) -> Result<CertificateCredential, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::certificate_by_fingerprint(conn, fingerprint_sha256).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::certificate_by_fingerprint(conn, fingerprint_sha256).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::certificate_by_fingerprint(conn, fingerprint_sha256).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::certificate_by_fingerprint(conn, fingerprint_sha256).await
        }
    }
}

pub async fn lock_certificate_by_fingerprint(
    tx: &mut DbTransaction<'_>,
    fingerprint_sha256: &str,
) -> Result<CertificateCredential, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::lock_certificate_by_fingerprint(conn, fingerprint_sha256).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_certificate_by_fingerprint(conn, fingerprint_sha256).await
        }
    }
}

pub async fn certificate_by_issuer_serial<'e, E>(
    executor: E,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<CertificateCredential, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::certificate_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::certificate_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::certificate_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::certificate_by_issuer_serial(conn, issuer_id, serial_number).await
        }
    }
}

pub async fn lock_certificate_by_issuer_serial(
    tx: &mut DbTransaction<'_>,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<CertificateCredential, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::lock_certificate_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_certificate_by_issuer_serial(conn, issuer_id, serial_number).await
        }
    }
}

pub async fn list_certificates(
    pool: &Database,
    entity_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<CertificateCredential>, AppError> {
    list_certificates_filtered(
        pool,
        &CertificateListFilter {
            entity_id,
            tenant_id,
            status: status.map(str::to_string),
            limit,
            offset,
            ..CertificateListFilter::default()
        },
    )
    .await
}

pub async fn list_certificates_filtered(
    pool: &Database,
    filter: &CertificateListFilter,
) -> Result<Vec<CertificateCredential>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_certificates_filtered(pool, filter).await,
        Database::Sqlite(db) => sqlite::list_certificates_filtered(&db.pool, filter).await,
    }
}

pub async fn count_certificates(
    pool: &Database,
    filter: &CertificateListFilter,
) -> Result<i64, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::count_certificates(pool, filter).await,
        Database::Sqlite(db) => sqlite::count_certificates(&db.pool, filter).await,
    }
}

pub async fn revoke_certificate<'e, E>(
    executor: E,
    credential_id: Uuid,
    metadata: Value,
) -> Result<(), AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::revoke_certificate(conn, credential_id, metadata).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::revoke_certificate(conn, credential_id, metadata).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::revoke_certificate(conn, credential_id, metadata).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::revoke_certificate(conn, credential_id, metadata).await
        }
    }
}

pub async fn revoke_certificate_if_active(
    tx: &mut DbTransaction<'_>,
    credential_id: Uuid,
    metadata: Value,
) -> Result<bool, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::revoke_certificate_if_active(conn, credential_id, metadata).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::revoke_certificate_if_active(conn, credential_id, metadata).await
        }
    }
}

pub async fn certificate_revocation_by_id<'e, E>(
    executor: E,
    credential_id: Uuid,
) -> Result<CertificateRevocationRecord, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::certificate_revocation_by_id(conn, credential_id).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::certificate_revocation_by_id(conn, credential_id).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::certificate_revocation_by_id(conn, credential_id).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::certificate_revocation_by_id(conn, credential_id).await
        }
    }
}

pub async fn certificate_revocation_by_issuer_serial<'e, E>(
    executor: E,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<Option<CertificateRevocationRecord>, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::certificate_revocation_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::certificate_revocation_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::certificate_revocation_by_issuer_serial(conn, issuer_id, serial_number).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::certificate_revocation_by_issuer_serial(conn, issuer_id, serial_number).await
        }
    }
}

pub async fn active_entity_certificates<'e, E>(
    executor: E,
    entity_id: Uuid,
) -> Result<Vec<CertificateCredential>, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::active_entity_certificates(conn, entity_id).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::active_entity_certificates(conn, entity_id).await
        }
        crate::db::Target::PoolSqlite(pool) => {
            let mut tx = pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map_err(crate::error::db_err)?;
            let result = sqlite::active_entity_certificates(&mut *tx, entity_id).await?;
            tx.commit().await.map_err(crate::error::db_err)?;
            Ok(result)
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::active_entity_certificates(conn, entity_id).await
        }
    }
}

pub async fn issuer_crl_state(
    pool: &Database,
    issuer_id: Uuid,
) -> Result<Option<CrlState>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::issuer_crl_state(pool, issuer_id).await,
        Database::Sqlite(db) => sqlite::issuer_crl_state(&db.pool, issuer_id).await,
    }
}

pub async fn issuer_crl_state_tx(
    tx: &mut DbTransaction<'_>,
    issuer_id: Uuid,
    issuer_fingerprint_sha256: &str,
) -> Result<CrlState, AppError> {
    let state = match tx {
        DbTransaction::Postgres(conn) => {
            postgres::issuer_crl_state_tx(conn, issuer_id, issuer_fingerprint_sha256).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::issuer_crl_state_tx(conn, issuer_id, issuer_fingerprint_sha256).await
        }
    }?;
    if state.issuer_fingerprint_sha256 != issuer_fingerprint_sha256 {
        return Err(AppError::conflict(
            "issuer CRL state fingerprint does not match the authority certificate",
        ));
    }

    Ok(state)
}

pub async fn issuer_revocations_tx(
    tx: &mut DbTransaction<'_>,
    issuer_id: Uuid,
) -> Result<Vec<IssuerRevocationEntry>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::issuer_revocations_tx(conn, issuer_id).await,
        DbTransaction::Sqlite(conn) => sqlite::issuer_revocations_tx(conn, issuer_id).await,
    }
}

pub async fn store_issuer_crl_tx(
    tx: &mut DbTransaction<'_>,
    issuer_id: Uuid,
    crl_number: i64,
    crl_der: &[u8],
    crl_sha256: &str,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::store_issuer_crl_tx(
                conn,
                issuer_id,
                crl_number,
                crl_der,
                crl_sha256,
                this_update,
                next_update,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::store_issuer_crl_tx(
                conn,
                issuer_id,
                crl_number,
                crl_der,
                crl_sha256,
                this_update,
                next_update,
            )
            .await
        }
    }
}

fn existing_issuance_claim(
    existing: (String, Option<Uuid>),
    request_fingerprint_sha256: &str,
) -> Result<CertificateIssuanceRequestClaim, AppError> {
    if existing.0 != request_fingerprint_sha256 {
        return Err(AppError::conflict(
            "idempotency key was already used for a different certificate request",
        ));
    }
    existing
        .1
        .map(|credential_id| CertificateIssuanceRequestClaim::Replay { credential_id })
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "stored certificate issuance request is incomplete"
            ))
        })
}

fn existing_renewal_claim(
    existing: (String, String, String, Option<Uuid>),
    request_key_hash: &str,
    request_fingerprint_sha256: &str,
    key_mode: &str,
) -> Result<CertificateRenewalRequestClaim, AppError> {
    if existing.0 != request_key_hash
        || existing.1 != request_fingerprint_sha256
        || existing.2 != key_mode
    {
        return Err(AppError::conflict(
            "certificate was already renewed by a different request",
        ));
    }
    existing
        .3
        .map(|credential_id| CertificateRenewalRequestClaim::Replay { credential_id })
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "stored certificate renewal request is incomplete"
            ))
        })
}

pub(crate) async fn lock_crl_publication(
    tx: &mut DbTransaction<'_>,
    issuer_id: Uuid,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_crl_publication(conn, issuer_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_crl_publication(conn, issuer_id).await,
    }
}
