use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{db_err, AppError};

use super::{key_provider::ManagedAuthorityKey, AuthorityKind, AuthorityRecord, AuthorityStatus};

const PROVISIONING_ADVISORY_LOCK_ID: i64 = 0x4154_4f4d_504b_4933;

/// Per-authority publication routes recorded at activation so
/// `PkiIssuer::from_managed_authority` finds populated values for every
/// active leaf issuer. Provisioning derives these from the deployment's
/// public base URL; `None` fields preserve any existing column value
/// (COALESCE), so an operator's manual SQL update survives a re-activation.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryUrls {
    pub ocsp_url: Option<String>,
    pub ca_issuers_url: Option<String>,
    pub crl_distribution_point_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct EncryptedKeyRequirement {
    pub key_encryption_key_id: String,
    pub encryption_algorithm: String,
}

const AUTHORITY_COLUMNS: &str = r#"
    id,
    tenant_id,
    parent_id,
    kind,
    version,
    status,
    issuance_enabled,
    subject,
    serial_number,
    fingerprint_sha256,
    subject_key_id,
    authority_key_id,
    certificate_pem,
    chain_pem,
    not_before,
    not_after,
    key_backend,
    key_reference,
    encrypted_private_key,
    private_key_nonce,
    wrapped_dek,
    wrapped_dek_nonce,
    key_encryption_key_id,
    encryption_algorithm,
    provisioning_mode,
    csr_pem,
    failure_reason,
    ocsp_url,
    ca_issuers_url,
    crl_distribution_point_url,
    created_at,
    updated_at,
    activated_at,
    retiring_at,
    retired_at
"#;

pub async fn authority_by_id(
    pool: &PgPool,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    fetch_authority_by_id(pool, authority_id).await
}

pub async fn fetch_authority_by_id<'e, E>(
    executor: E,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let query = format!("SELECT {AUTHORITY_COLUMNS} FROM pki_authorities WHERE id = $1");
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(authority_id)
        .fetch_one(executor)
        .await
        .map_err(db_err)
}

/// Return the active leaf issuer for a stored entity scope.
///
/// Tenant entities use their tenant intermediate. Global entities use the one
/// active platform leaf issuer. Callers derive this scope from the stored entity;
/// public requests never choose an issuer.
pub async fn active_leaf_issuer_for_scope(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError> {
    fetch_active_leaf_issuer_for_scope(pool, tenant_id).await
}

pub async fn fetch_active_leaf_issuer_for_scope<'e, E>(
    executor: E,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let query = format!(
        r#"
        SELECT {AUTHORITY_COLUMNS}
        FROM pki_authorities
        WHERE (($1::uuid IS NULL
                AND tenant_id IS NULL
                AND kind = 'platform_leaf_issuer')
            OR ($1::uuid IS NOT NULL
                AND tenant_id = $1
                AND kind = 'tenant_intermediate'))
          AND status = 'active'
          AND issuance_enabled = true
          AND not_before <= now()
          AND not_after > now()
        "#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(tenant_id)
        .fetch_one(executor)
        .await
        .map_err(db_err)
}

/// Select and lock the active issuer used by one issuance transaction.
///
/// The share lock prevents a lifecycle transition from retiring the authority
/// after policy validation but before the issuer-bound credential commits.
pub async fn lock_active_leaf_issuer_for_scope(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError> {
    let query = format!(
        r#"
        SELECT {AUTHORITY_COLUMNS}
        FROM pki_authorities
        WHERE (($1::uuid IS NULL
                AND tenant_id IS NULL
                AND kind = 'platform_leaf_issuer')
            OR ($1::uuid IS NOT NULL
                AND tenant_id = $1
                AND kind = 'tenant_intermediate'))
          AND status = 'active'
          AND issuance_enabled = true
          AND not_before <= now()
          AND not_after > now()
        FOR SHARE
        "#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => {
                AppError::not_found("no active issuing authority is available for the entity scope")
            }
            other => AppError::Database(other),
        })
}

/// Hold a shared lock while an already-issued certificate is used as renewal
/// authentication. Lifecycle transitions may wait, but they cannot revoke or
/// retire the presented issuer between validation and renewal commit.
pub async fn lock_authority_for_certificate_authentication(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    let query = format!(
        r#"
        SELECT {AUTHORITY_COLUMNS}
        FROM pki_authorities
        WHERE id = $1
        FOR SHARE
        "#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(authority_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_err)
}

/// Backward-compatible tenant-only selector for current call sites.
pub async fn active_tenant_leaf_issuer(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    active_leaf_issuer_for_scope(pool, Some(tenant_id)).await
}

pub async fn fetch_active_tenant_leaf_issuer<'e, E>(
    executor: E,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    fetch_active_leaf_issuer_for_scope(executor, Some(tenant_id)).await
}

pub async fn list_tenant_authorities(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<AuthorityRecord>, AppError> {
    let query = format!(
        r#"
        SELECT {AUTHORITY_COLUMNS}
        FROM pki_authorities
        WHERE tenant_id = $1
        ORDER BY version DESC, created_at DESC
        "#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)
}

/// Return only non-secret metadata needed to validate the encrypted CA provider
/// before the process starts serving. Private-key columns are deliberately not
/// selected, so startup validation cannot preload tenant keys.
pub async fn encrypted_key_requirements(
    pool: &PgPool,
) -> Result<Vec<EncryptedKeyRequirement>, AppError> {
    sqlx::query_as::<_, EncryptedKeyRequirement>(
        r#"SELECT DISTINCT key_encryption_key_id, encryption_algorithm
           FROM pki_authorities
           WHERE key_backend = 'encrypted_database'
           ORDER BY key_encryption_key_id, encryption_algorithm"#,
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// Return PKCS#11-backed authorities for fail-closed startup validation. The
/// selected rows contain public certificate metadata and opaque references;
/// they cannot contain encrypted or plaintext private-key bytes by constraint.
pub async fn pkcs11_authorities(pool: &PgPool) -> Result<Vec<AuthorityRecord>, AppError> {
    let query = format!(
        "SELECT {AUTHORITY_COLUMNS} FROM pki_authorities WHERE key_backend = 'pkcs11' ORDER BY id"
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

pub async fn kms_authority_count(pool: &PgPool) -> Result<i64, AppError> {
    sqlx::query_scalar("SELECT count(*) FROM pki_authorities WHERE key_backend = 'kms'")
        .fetch_one(pool)
        .await
        .map_err(db_err)
}

pub struct PendingAuthorityInsert<'a> {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub parent_id: Uuid,
    pub kind: AuthorityKind,
    pub version: i32,
    pub subject: &'a str,
    pub csr_pem: &'a str,
    pub provisioning_mode: &'a str,
    pub key: &'a ManagedAuthorityKey,
}

pub struct CompletedAuthority {
    pub subject: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub subject_key_id: String,
    pub authority_key_id: Option<String>,
    pub certificate_pem: String,
    pub chain_pem: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

pub async fn lock_provisioning(tx: &mut Transaction<'_, Postgres>) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PROVISIONING_ADVISORY_LOCK_ID)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub async fn lock_active_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM tenants WHERE id = $1 AND status = 'active' AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn authority_by_id_for_update(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    let query = format!("SELECT {AUTHORITY_COLUMNS} FROM pki_authorities WHERE id = $1 FOR UPDATE");
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(authority_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_err)
}

pub async fn authority_by_fingerprint(
    tx: &mut Transaction<'_, Postgres>,
    fingerprint_sha256: &str,
) -> Result<Option<AuthorityRecord>, AppError> {
    let query =
        format!("SELECT {AUTHORITY_COLUMNS} FROM pki_authorities WHERE fingerprint_sha256 = $1");
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(fingerprint_sha256)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)
}

pub async fn next_authority_version(
    tx: &mut Transaction<'_, Postgres>,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<i32, AppError> {
    sqlx::query_scalar(
        r#"SELECT COALESCE(MAX(version), 0) + 1
           FROM pki_authorities
           WHERE kind = $1 AND tenant_id IS NOT DISTINCT FROM $2"#,
    )
    .bind(kind)
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)
}

pub async fn pending_authority_for_scope(
    tx: &mut Transaction<'_, Postgres>,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<Option<AuthorityRecord>, AppError> {
    let query = format!(
        r#"SELECT {AUTHORITY_COLUMNS}
           FROM pki_authorities
           WHERE kind = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status IN ('provisioning', 'pending_signature')
           ORDER BY version DESC
           LIMIT 1
           FOR UPDATE"#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(kind)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)
}

pub async fn active_authority_for_scope(
    tx: &mut Transaction<'_, Postgres>,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<Option<AuthorityRecord>, AppError> {
    let query = format!(
        r#"SELECT {AUTHORITY_COLUMNS}
           FROM pki_authorities
           WHERE kind = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status = 'active'
             AND not_before <= now()
             AND not_after > now()
           ORDER BY version DESC
           LIMIT 1
           FOR UPDATE"#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(kind)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)
}

pub async fn active_root(tx: &mut Transaction<'_, Postgres>) -> Result<AuthorityRecord, AppError> {
    active_authority_for_scope(tx, AuthorityKind::Root, None)
        .await?
        .ok_or_else(|| AppError::not_found("no active root authority"))
}

pub async fn active_platform_intermediate(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<AuthorityRecord, AppError> {
    active_authority_for_scope(tx, AuthorityKind::PlatformIntermediate, None)
        .await?
        .ok_or_else(|| AppError::not_found("no active platform intermediate authority"))
}

pub async fn insert_root_authority(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    version: i32,
    completed: &CompletedAuthority,
) -> Result<AuthorityRecord, AppError> {
    sqlx::query(
        r#"INSERT INTO pki_authorities (
               id, kind, version, status, issuance_enabled, subject,
               serial_number, fingerprint_sha256, subject_key_id,
               authority_key_id, certificate_pem, chain_pem, not_before,
               not_after, key_backend, provisioning_mode, activated_at
           ) VALUES (
               $1, 'root', $2, 'active', false, $3,
               $4, $5, $6, $7, $8, $9, $10, $11,
               'public_only', 'imported', now()
           )"#,
    )
    .bind(id)
    .bind(version)
    .bind(&completed.subject)
    .bind(&completed.serial_number)
    .bind(&completed.fingerprint_sha256)
    .bind(&completed.subject_key_id)
    .bind(&completed.authority_key_id)
    .bind(&completed.certificate_pem)
    .bind(&completed.chain_pem)
    .bind(completed.not_before)
    .bind(completed.not_after)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    authority_by_id_for_update(tx, id).await
}

pub async fn insert_pending_authority(
    tx: &mut Transaction<'_, Postgres>,
    input: &PendingAuthorityInsert<'_>,
) -> Result<AuthorityRecord, AppError> {
    let key = input.key.columns();
    sqlx::query(
        r#"INSERT INTO pki_authorities (
               id, tenant_id, parent_id, kind, version, status,
               issuance_enabled, subject, key_backend, key_reference,
               encrypted_private_key, private_key_nonce, wrapped_dek,
               wrapped_dek_nonce, key_encryption_key_id, encryption_algorithm,
               provisioning_mode, csr_pem
           ) VALUES (
               $1, $2, $3, $4, $5, 'pending_signature',
               false, $6, $7, $8, $9,
               $10, $11, $12, $13, $14, $15, $16
           )"#,
    )
    .bind(input.id)
    .bind(input.tenant_id)
    .bind(input.parent_id)
    .bind(input.kind)
    .bind(input.version)
    .bind(input.subject)
    .bind(key.backend)
    .bind(key.key_reference)
    .bind(key.encrypted_private_key)
    .bind(key.private_key_nonce)
    .bind(key.wrapped_dek)
    .bind(key.wrapped_dek_nonce)
    .bind(key.key_encryption_key_id)
    .bind(key.encryption_algorithm)
    .bind(input.provisioning_mode)
    .bind(input.csr_pem)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    authority_by_id_for_update(tx, input.id).await
}

pub async fn activate_authority(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
    completed: &CompletedAuthority,
    issuance_enabled: bool,
    discovery: Option<&DiscoveryUrls>,
) -> Result<AuthorityRecord, AppError> {
    let (ocsp_url, ca_issuers_url, crl_distribution_point_url) = discovery
        .map(|urls| {
            (
                urls.ocsp_url.clone(),
                urls.ca_issuers_url.clone(),
                urls.crl_distribution_point_url.clone(),
            )
        })
        .unwrap_or((None, None, None));
    sqlx::query(
        r#"UPDATE pki_authorities
           SET status = 'active', issuance_enabled = $2, subject = $3,
               serial_number = $4, fingerprint_sha256 = $5,
               subject_key_id = $6, authority_key_id = $7,
               certificate_pem = $8, chain_pem = $9, not_before = $10,
               not_after = $11, failure_reason = NULL, activated_at = now(),
               ocsp_url = COALESCE($12, ocsp_url),
               ca_issuers_url = COALESCE($13, ca_issuers_url),
               crl_distribution_point_url = COALESCE($14, crl_distribution_point_url),
               updated_at = now()
           WHERE id = $1 AND status = 'pending_signature'"#,
    )
    .bind(authority_id)
    .bind(issuance_enabled)
    .bind(&completed.subject)
    .bind(&completed.serial_number)
    .bind(&completed.fingerprint_sha256)
    .bind(&completed.subject_key_id)
    .bind(&completed.authority_key_id)
    .bind(&completed.certificate_pem)
    .bind(&completed.chain_pem)
    .bind(completed.not_before)
    .bind(completed.not_after)
    .bind(ocsp_url)
    .bind(ca_issuers_url)
    .bind(crl_distribution_point_url)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    authority_by_id_for_update(tx, authority_id).await
}

pub async fn mark_authority_failed(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
    reason: &str,
) -> Result<AuthorityRecord, AppError> {
    sqlx::query(
        r#"UPDATE pki_authorities
           SET status = 'failed', issuance_enabled = false,
               failure_reason = $2, updated_at = now()
           WHERE id = $1 AND status IN ('provisioning', 'pending_signature')"#,
    )
    .bind(authority_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    authority_by_id_for_update(tx, authority_id).await
}

pub async fn retire_other_active_authorities(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"UPDATE pki_authorities
           SET status = 'retiring', issuance_enabled = false,
               retiring_at = now(), updated_at = now()
           WHERE id <> $1
             AND kind = $2
             AND tenant_id IS NOT DISTINCT FROM $3
             AND status = 'active'
           RETURNING id"#,
    )
    .bind(authority_id)
    .bind(kind)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)
}

pub async fn transition_authority(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
    from: AuthorityStatus,
    to: AuthorityStatus,
) -> Result<AuthorityRecord, AppError> {
    let result = sqlx::query(
        r#"UPDATE pki_authorities
           SET status = $3,
               issuance_enabled = false,
               retiring_at = CASE WHEN $3 = 'retiring' THEN COALESCE(retiring_at, now()) ELSE retiring_at END,
               retired_at = CASE WHEN $3 = 'retired' THEN COALESCE(retired_at, now()) ELSE retired_at END,
               updated_at = now()
           WHERE id = $1 AND status = $2"#,
    )
    .bind(authority_id)
    .bind(from)
    .bind(to)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    if result.rows_affected() != 1 {
        return Err(AppError::conflict("authority lifecycle state changed"));
    }
    authority_by_id_for_update(tx, authority_id).await
}

pub async fn list_authorities(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
) -> Result<Vec<AuthorityRecord>, AppError> {
    let query = format!(
        r#"SELECT {AUTHORITY_COLUMNS}
           FROM pki_authorities
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
           ORDER BY tenant_id NULLS FIRST, kind, version DESC"#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

pub async fn trust_bundle_authorities(pool: &PgPool) -> Result<Vec<AuthorityRecord>, AppError> {
    let query = format!(
        r#"SELECT {AUTHORITY_COLUMNS}
           FROM pki_authorities
           WHERE status IN ('active', 'retiring', 'retired')
             AND certificate_pem IS NOT NULL
             AND chain_pem IS NOT NULL
           ORDER BY CASE kind WHEN 'root' THEN 0 ELSE 1 END,
                    tenant_id NULLS FIRST, kind, version DESC"#
    );
    sqlx::query_as::<_, AuthorityRecord>(&query)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}
