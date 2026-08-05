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
    sqlx::query_as::<_, AuthorityRecord>(&format!(
        "SELECT {AUTHORITY_COLUMNS} FROM pki_authorities WHERE id = $1"
    ))
    .bind(authority_id)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

/// Return the one tenant intermediate that may receive new leaf issuance.
///
/// Rotation keeps old versions in `retiring`/`retired` state, so callers must
/// use this selector rather than ordering all tenant authorities themselves.
pub async fn active_tenant_leaf_issuer(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    fetch_active_tenant_leaf_issuer(pool, tenant_id).await
}

pub async fn fetch_active_tenant_leaf_issuer<'e, E>(
    executor: E,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, AuthorityRecord>(&format!(
        r#"
        SELECT {AUTHORITY_COLUMNS}
        FROM pki_authorities
        WHERE tenant_id = $1
          AND kind = 'tenant_intermediate'
          AND status = 'active'
          AND issuance_enabled = true
          AND not_before <= now()
          AND not_after > now()
        "#
    ))
    .bind(tenant_id)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub async fn list_tenant_authorities(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<AuthorityRecord>, AppError> {
    sqlx::query_as::<_, AuthorityRecord>(&format!(
        r#"
        SELECT {AUTHORITY_COLUMNS}
        FROM pki_authorities
        WHERE tenant_id = $1
        ORDER BY version DESC, created_at DESC
        "#
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)
}
