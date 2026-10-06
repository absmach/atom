mod postgres;
mod sqlite;

use crate::db::Database;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{db::DbTransaction, error::AppError};

use super::{
    key_provider::ManagedAuthorityKey, AuthorityKeyBackend, AuthorityKind, AuthorityRecord,
    AuthorityStatus,
};

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

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LeafIssuerReadiness {
    pub active_count: i64,
    #[sqlx(try_from = "crate::db::TextList")]
    pub active_backends: Vec<AuthorityKeyBackend>,
}

pub async fn authority_by_id(
    pool: &Database,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    fetch_authority_by_id(pool, authority_id).await
}

pub async fn fetch_authority_by_id<'e, E>(
    executor: E,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::fetch_authority_by_id(conn, authority_id).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::fetch_authority_by_id(conn, authority_id).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::fetch_authority_by_id(conn, authority_id).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::fetch_authority_by_id(conn, authority_id).await
        }
    }
}

/// Return the active leaf issuer for a stored entity scope.
///
/// Tenant entities use their tenant intermediate. Global entities use the one
/// active platform leaf issuer. Callers derive this scope from the stored entity;
/// public requests never choose an issuer.
pub async fn active_leaf_issuer_for_scope(
    pool: &Database,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError> {
    fetch_active_leaf_issuer_for_scope(pool, tenant_id).await
}

pub async fn fetch_active_leaf_issuer_for_scope<'e, E>(
    executor: E,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    match executor.into_target() {
        crate::db::Target::PoolPostgres(conn) => {
            postgres::fetch_active_leaf_issuer_for_scope(conn, tenant_id).await
        }
        crate::db::Target::ConnectionPostgres(conn) => {
            postgres::fetch_active_leaf_issuer_for_scope(conn, tenant_id).await
        }
        crate::db::Target::PoolSqlite(conn) => {
            sqlite::fetch_active_leaf_issuer_for_scope(conn, tenant_id).await
        }
        crate::db::Target::ConnectionSqlite(conn) => {
            sqlite::fetch_active_leaf_issuer_for_scope(conn, tenant_id).await
        }
    }
}

/// Select and lock the active issuer used by one issuance transaction.
///
/// The share lock prevents a lifecycle transition from retiring the authority
/// after policy validation but before the issuer-bound credential commits.
pub async fn lock_active_leaf_issuer_for_scope(
    tx: &mut DbTransaction<'_>,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::lock_active_leaf_issuer_for_scope(conn, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_active_leaf_issuer_for_scope(conn, tenant_id).await
        }
    }
}

/// Hold a shared lock while an already-issued certificate is used as renewal
/// authentication. Lifecycle transitions may wait, but they cannot revoke or
/// retire the presented issuer between validation and renewal commit.
pub async fn lock_authority_for_certificate_authentication(
    tx: &mut DbTransaction<'_>,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::lock_authority_for_certificate_authentication(conn, authority_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::lock_authority_for_certificate_authentication(conn, authority_id).await
        }
    }
}

/// Backward-compatible tenant-only selector for current call sites.
pub async fn active_tenant_leaf_issuer(
    pool: &Database,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    active_leaf_issuer_for_scope(pool, Some(tenant_id)).await
}

pub async fn fetch_active_tenant_leaf_issuer<'e, E>(
    executor: E,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    fetch_active_leaf_issuer_for_scope(executor, Some(tenant_id)).await
}

/// Return the active issuer count and the key backends used by authorities that
/// can issue leaves now. Readiness ignores provisioning and historical rows,
/// while an active-but-disabled or out-of-window issuer remains an error. The
/// single non-secret snapshot avoids both a second query and a cross-query race.
pub async fn leaf_issuer_readiness(pool: &Database) -> Result<LeafIssuerReadiness, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::leaf_issuer_readiness(pool).await,
        Database::Sqlite(db) => sqlite::leaf_issuer_readiness(&db.pool).await,
    }
}

pub async fn list_tenant_authorities(
    pool: &Database,
    tenant_id: Uuid,
) -> Result<Vec<AuthorityRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_tenant_authorities(pool, tenant_id).await,
        Database::Sqlite(db) => sqlite::list_tenant_authorities(&db.pool, tenant_id).await,
    }
}

/// Return only non-secret metadata needed to validate the encrypted CA provider
/// before the process starts serving. Private-key columns are deliberately not
/// selected, so startup validation cannot preload tenant keys.
pub async fn encrypted_key_requirements(
    pool: &Database,
) -> Result<Vec<EncryptedKeyRequirement>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::encrypted_key_requirements(pool).await,
        Database::Sqlite(db) => sqlite::encrypted_key_requirements(&db.pool).await,
    }
}

/// Return PKCS#11-backed authorities for fail-closed startup validation. The
/// selected rows contain public certificate metadata and opaque references;
/// they cannot contain encrypted or plaintext private-key bytes by constraint.
pub async fn pkcs11_authorities(pool: &Database) -> Result<Vec<AuthorityRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::pkcs11_authorities(pool).await,
        Database::Sqlite(db) => sqlite::pkcs11_authorities(&db.pool).await,
    }
}

pub async fn kms_authority_count(pool: &Database) -> Result<i64, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::kms_authority_count(pool).await,
        Database::Sqlite(db) => sqlite::kms_authority_count(&db.pool).await,
    }
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

pub async fn lock_provisioning(tx: &mut DbTransaction<'_>) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_provisioning(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_provisioning(conn).await,
    }
}

pub async fn lock_active_tenant(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
) -> Result<(), AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_active_tenant(conn, tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_active_tenant(conn, tenant_id).await,
    }
}

pub async fn authority_by_id_for_update(
    tx: &mut DbTransaction<'_>,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::authority_by_id_for_update(conn, authority_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::authority_by_id_for_update(conn, authority_id).await,
    }
}

pub async fn authority_by_fingerprint(
    tx: &mut DbTransaction<'_>,
    fingerprint_sha256: &str,
) -> Result<Option<AuthorityRecord>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::authority_by_fingerprint(conn, fingerprint_sha256).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::authority_by_fingerprint(conn, fingerprint_sha256).await
        }
    }
}

pub async fn next_authority_version(
    tx: &mut DbTransaction<'_>,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<i32, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::next_authority_version(conn, kind, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::next_authority_version(conn, kind, tenant_id).await,
    }
}

pub async fn pending_authority_for_scope(
    tx: &mut DbTransaction<'_>,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<Option<AuthorityRecord>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::pending_authority_for_scope(conn, kind, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::pending_authority_for_scope(conn, kind, tenant_id).await
        }
    }
}

pub async fn active_authority_for_scope(
    tx: &mut DbTransaction<'_>,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<Option<AuthorityRecord>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::active_authority_for_scope(conn, kind, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::active_authority_for_scope(conn, kind, tenant_id).await
        }
    }
}

pub async fn active_root(tx: &mut DbTransaction<'_>) -> Result<AuthorityRecord, AppError> {
    active_authority_for_scope(tx, AuthorityKind::Root, None)
        .await?
        .ok_or_else(|| AppError::not_found("no active root authority"))
}

pub async fn active_platform_intermediate(
    tx: &mut DbTransaction<'_>,
) -> Result<AuthorityRecord, AppError> {
    active_authority_for_scope(tx, AuthorityKind::PlatformIntermediate, None)
        .await?
        .ok_or_else(|| AppError::not_found("no active platform intermediate authority"))
}

pub async fn insert_root_authority(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    version: i32,
    completed: &CompletedAuthority,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_root_authority(conn, id, version, completed).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_root_authority(conn, id, version, completed).await
        }
    }
}

pub struct ActiveAuthorityInsert<'a> {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub parent_id: Uuid,
    pub kind: AuthorityKind,
    pub version: i32,
    pub provisioning_mode: &'a str,
    pub issuance_enabled: bool,
    pub key: &'a ManagedAuthorityKey,
    pub completed: &'a CompletedAuthority,
    pub discovery: Option<&'a DiscoveryUrls>,
}

/// Insert an already-active authority whose certificate was supplied by the
/// operator (bring-your-own) rather than produced by the internal
/// CSR/import round-trip. Used by config-driven bootstraps that persist a
/// pre-signed authority together with its encrypted private key.
pub async fn insert_active_authority(
    tx: &mut DbTransaction<'_>,
    input: &ActiveAuthorityInsert<'_>,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::insert_active_authority(conn, input).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_active_authority(conn, input).await,
    }
}

pub async fn insert_pending_authority(
    tx: &mut DbTransaction<'_>,
    input: &PendingAuthorityInsert<'_>,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::insert_pending_authority(conn, input).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_pending_authority(conn, input).await,
    }
}

pub async fn activate_authority(
    tx: &mut DbTransaction<'_>,
    authority_id: Uuid,
    completed: &CompletedAuthority,
    issuance_enabled: bool,
    discovery: Option<&DiscoveryUrls>,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::activate_authority(conn, authority_id, completed, issuance_enabled, discovery)
                .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::activate_authority(conn, authority_id, completed, issuance_enabled, discovery)
                .await
        }
    }
}

pub async fn mark_authority_failed(
    tx: &mut DbTransaction<'_>,
    authority_id: Uuid,
    reason: &str,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::mark_authority_failed(conn, authority_id, reason).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::mark_authority_failed(conn, authority_id, reason).await
        }
    }
}

pub async fn retire_other_active_authorities(
    tx: &mut DbTransaction<'_>,
    authority_id: Uuid,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::retire_other_active_authorities(conn, authority_id, kind, tenant_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::retire_other_active_authorities(conn, authority_id, kind, tenant_id).await
        }
    }
}

pub async fn transition_authority(
    tx: &mut DbTransaction<'_>,
    authority_id: Uuid,
    from: AuthorityStatus,
    to: AuthorityStatus,
) -> Result<AuthorityRecord, AppError> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::transition_authority(conn, authority_id, from, to).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::transition_authority(conn, authority_id, from, to).await
        }
    }
}

pub async fn list_authorities(
    pool: &Database,
    tenant_id: Option<Uuid>,
) -> Result<Vec<AuthorityRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_authorities(pool, tenant_id).await,
        Database::Sqlite(db) => sqlite::list_authorities(&db.pool, tenant_id).await,
    }
}

pub async fn trust_bundle_authorities(pool: &Database) -> Result<Vec<AuthorityRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::trust_bundle_authorities(pool).await,
        Database::Sqlite(db) => sqlite::trust_bundle_authorities(&db.pool).await,
    }
}
