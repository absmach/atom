use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::error::{db_err, AppError};

use super::AuthorityRecord;

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
