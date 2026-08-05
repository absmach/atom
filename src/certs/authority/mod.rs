use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod repo;

/// Position of a CA in Atom's managed trust hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    /// Trust anchor. Production root private keys remain offline, so an Atom row
    /// normally uses [`AuthorityKeyBackend::PublicOnly`].
    Root,
    /// Optional online CA used to automate tenant-intermediate provisioning.
    PlatformIntermediate,
    /// Tenant-scoped CA that signs leaf credentials for one tenant only.
    TenantIntermediate,
}

impl AuthorityKind {
    pub fn can_issue_leaf_credentials(self) -> bool {
        matches!(self, Self::TenantIntermediate)
    }
}

/// Lifecycle state of a CA version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Provisioning,
    PendingSignature,
    Active,
    Retiring,
    Retired,
    Revoked,
    Expired,
    Failed,
}

/// Where the private signing key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKeyBackend {
    /// Certificate metadata only; no signing key is available to Atom.
    PublicOnly,
    /// Envelope-encrypted CA key material stored in Postgres.
    EncryptedDatabase,
    /// Operator-managed file reference. Intended for migration and development.
    File,
    /// PKCS#11 object reference in an HSM or software token.
    Pkcs11,
    /// Cloud or remote KMS signing-key reference.
    Kms,
}

impl AuthorityKeyBackend {
    pub fn can_sign(self) -> bool {
        !matches!(self, Self::PublicOnly)
    }
}

/// Persisted CA metadata. Private-key columns are intentionally represented as
/// opaque encrypted bytes; plaintext key material must never enter this model.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorityRecord {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub kind: AuthorityKind,
    pub version: i32,
    pub status: AuthorityStatus,
    pub issuance_enabled: bool,
    pub subject: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub subject_key_id: Option<String>,
    pub authority_key_id: Option<String>,
    pub certificate_pem: String,
    pub chain_pem: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub key_backend: AuthorityKeyBackend,
    pub key_reference: Option<String>,
    pub encrypted_private_key: Option<Vec<u8>>,
    pub private_key_nonce: Option<Vec<u8>>,
    pub wrapped_dek: Option<Vec<u8>>,
    pub wrapped_dek_nonce: Option<Vec<u8>>,
    pub key_encryption_key_id: Option<String>,
    pub encryption_algorithm: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub retiring_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
}

impl AuthorityRecord {
    /// Whether this CA is currently eligible for new leaf issuance.
    ///
    /// Database constraints enforce the static shape. This method additionally
    /// checks the validity window, so callers fail closed if lifecycle status and
    /// wall-clock validity diverge.
    pub fn can_issue_leaves_at(&self, now: DateTime<Utc>) -> bool {
        self.kind.can_issue_leaf_credentials()
            && self.status == AuthorityStatus::Active
            && self.issuance_enabled
            && self.key_backend.can_sign()
            && self.not_before <= now
            && now < self.not_after
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorityInvariantError {
    #[error("root authority must be global and parentless")]
    RootScope,
    #[error("platform intermediate must be global and have a parent")]
    PlatformIntermediateScope,
    #[error("tenant intermediate must belong to one tenant and have a parent")]
    TenantIntermediateScope,
    #[error("only an active tenant intermediate with a signing backend may issue leaves")]
    LeafIssuance,
}

/// Validate hierarchy fields before opening a database transaction. The same
/// invariants are repeated as CHECK constraints so every write path, including
/// migrations and operator SQL, fails closed.
pub fn validate_authority_shape(
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
    parent_id: Option<Uuid>,
) -> Result<(), AuthorityInvariantError> {
    match kind {
        AuthorityKind::Root if tenant_id.is_none() && parent_id.is_none() => Ok(()),
        AuthorityKind::Root => Err(AuthorityInvariantError::RootScope),
        AuthorityKind::PlatformIntermediate if tenant_id.is_none() && parent_id.is_some() => Ok(()),
        AuthorityKind::PlatformIntermediate => {
            Err(AuthorityInvariantError::PlatformIntermediateScope)
        }
        AuthorityKind::TenantIntermediate if tenant_id.is_some() && parent_id.is_some() => Ok(()),
        AuthorityKind::TenantIntermediate => Err(AuthorityInvariantError::TenantIntermediateScope),
    }
}

pub fn validate_leaf_issuance(
    kind: AuthorityKind,
    status: AuthorityStatus,
    backend: AuthorityKeyBackend,
    issuance_enabled: bool,
) -> Result<(), AuthorityInvariantError> {
    if !issuance_enabled
        || (kind.can_issue_leaf_credentials()
            && status == AuthorityStatus::Active
            && backend.can_sign())
    {
        return Ok(());
    }
    Err(AuthorityInvariantError::LeafIssuance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_shape_is_fail_closed() {
        let tenant_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();

        assert!(validate_authority_shape(AuthorityKind::Root, None, None).is_ok());
        assert_eq!(
            validate_authority_shape(AuthorityKind::Root, Some(tenant_id), None),
            Err(AuthorityInvariantError::RootScope)
        );
        assert!(validate_authority_shape(
            AuthorityKind::PlatformIntermediate,
            None,
            Some(parent_id)
        )
        .is_ok());
        assert!(validate_authority_shape(
            AuthorityKind::TenantIntermediate,
            Some(tenant_id),
            Some(parent_id)
        )
        .is_ok());
        assert_eq!(
            validate_authority_shape(AuthorityKind::TenantIntermediate, None, Some(parent_id)),
            Err(AuthorityInvariantError::TenantIntermediateScope)
        );
    }

    #[test]
    fn leaf_issuance_requires_an_active_tenant_signer() {
        assert!(validate_leaf_issuance(
            AuthorityKind::TenantIntermediate,
            AuthorityStatus::Active,
            AuthorityKeyBackend::EncryptedDatabase,
            true
        )
        .is_ok());
        assert_eq!(
            validate_leaf_issuance(
                AuthorityKind::PlatformIntermediate,
                AuthorityStatus::Active,
                AuthorityKeyBackend::EncryptedDatabase,
                true
            ),
            Err(AuthorityInvariantError::LeafIssuance)
        );
        assert_eq!(
            validate_leaf_issuance(
                AuthorityKind::TenantIntermediate,
                AuthorityStatus::Active,
                AuthorityKeyBackend::PublicOnly,
                true
            ),
            Err(AuthorityInvariantError::LeafIssuance)
        );
        assert!(validate_leaf_issuance(
            AuthorityKind::Root,
            AuthorityStatus::Retired,
            AuthorityKeyBackend::PublicOnly,
            false
        )
        .is_ok());
    }
}
