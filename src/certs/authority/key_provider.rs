//! Atom-owned CA signing boundary.
//!
//! The encrypted-database provider implemented here is deliberately independent
//! of certificate issuance. Later providers (PKCS#11, KMS, or the legacy file
//! bridge) can implement [`AuthorityKeyProvider`] without changing public APIs.

use std::fmt;

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{config::PkiCaKeyConfig, crypto, error::AppError, metrics};

use super::{repo, AuthorityKeyBackend, AuthorityRecord};

const PROVIDER_NAME: &str = "encrypted_database";
const ENCRYPTION_ALGORITHM: &str = crypto::AEAD_ALG;
const DEK_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKeyAlgorithm {
    EcdsaP256Sha256,
}

impl AuthorityKeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa_p256_sha256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySignatureAlgorithm {
    EcdsaP256Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityKeyContext {
    pub authority_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub version: i32,
}

impl AuthorityKeyContext {
    fn aad(self, purpose: &'static str) -> Vec<u8> {
        let tenant = self
            .tenant_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "global".to_string());
        format!(
            "atom:pki:authority-key:v1:{purpose}:{}:{tenant}:{}",
            self.authority_id, self.version
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKeyProviderStatus {
    Ready,
    Unconfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityKeyProviderHealth {
    pub backend: AuthorityKeyBackend,
    pub status: AuthorityKeyProviderStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityKeyMetadata {
    pub backend: AuthorityKeyBackend,
    pub key_algorithm: AuthorityKeyAlgorithm,
    pub key_encryption_key_id: String,
    pub encryption_algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityPublicKey {
    pub algorithm: AuthorityKeyAlgorithm,
    /// SubjectPublicKeyInfo DER. This is public material.
    pub subject_public_key_info_der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySignature {
    pub algorithm: AuthoritySignatureAlgorithm,
    /// ASN.1 DER encoded ECDSA signature. This is not private-key material.
    pub bytes: Vec<u8>,
}

/// Opaque database representation of one encrypted CA key.
///
/// It intentionally does not implement `Serialize`. Its custom `Debug` omits
/// ciphertext, nonces, wrapped DEKs, and external key references.
pub struct EncryptedAuthorityKey {
    pub(crate) encrypted_private_key: Vec<u8>,
    pub(crate) private_key_nonce: Vec<u8>,
    pub(crate) wrapped_dek: Vec<u8>,
    pub(crate) wrapped_dek_nonce: Vec<u8>,
    pub(crate) key_encryption_key_id: String,
    pub(crate) encryption_algorithm: String,
    key_algorithm: AuthorityKeyAlgorithm,
    destroyed: bool,
}

impl fmt::Debug for EncryptedAuthorityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedAuthorityKey")
            .field("backend", &AuthorityKeyBackend::EncryptedDatabase)
            .field("key_algorithm", &self.key_algorithm)
            .field("key_encryption_key_id", &self.key_encryption_key_id)
            .field("encryption_algorithm", &self.encryption_algorithm)
            .field("destroyed", &self.destroyed)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl Drop for EncryptedAuthorityKey {
    fn drop(&mut self) {
        self.encrypted_private_key.zeroize();
        self.private_key_nonce.zeroize();
        self.wrapped_dek.zeroize();
        self.wrapped_dek_nonce.zeroize();
    }
}

impl EncryptedAuthorityKey {
    pub fn from_authority(authority: &AuthorityRecord) -> Result<Self, AuthorityKeyProviderError> {
        if authority.key_backend != AuthorityKeyBackend::EncryptedDatabase {
            return Err(AuthorityKeyProviderError::WrongBackend);
        }
        Self::from_columns(
            authority.encrypted_private_key.clone(),
            authority.private_key_nonce.clone(),
            authority.wrapped_dek.clone(),
            authority.wrapped_dek_nonce.clone(),
            authority.key_encryption_key_id.clone(),
            authority.encryption_algorithm.clone(),
        )
    }

    fn from_columns(
        encrypted_private_key: Option<Vec<u8>>,
        private_key_nonce: Option<Vec<u8>>,
        wrapped_dek: Option<Vec<u8>>,
        wrapped_dek_nonce: Option<Vec<u8>>,
        key_encryption_key_id: Option<String>,
        encryption_algorithm: Option<String>,
    ) -> Result<Self, AuthorityKeyProviderError> {
        Ok(Self {
            encrypted_private_key: required(encrypted_private_key, "encrypted_private_key")?,
            private_key_nonce: required(private_key_nonce, "private_key_nonce")?,
            wrapped_dek: required(wrapped_dek, "wrapped_dek")?,
            wrapped_dek_nonce: required(wrapped_dek_nonce, "wrapped_dek_nonce")?,
            key_encryption_key_id: required(key_encryption_key_id, "key_encryption_key_id")?,
            encryption_algorithm: required(encryption_algorithm, "encryption_algorithm")?,
            key_algorithm: AuthorityKeyAlgorithm::EcdsaP256Sha256,
            destroyed: false,
        })
    }

    pub fn metadata(&self) -> AuthorityKeyMetadata {
        AuthorityKeyMetadata {
            backend: AuthorityKeyBackend::EncryptedDatabase,
            key_algorithm: self.key_algorithm,
            key_encryption_key_id: self.key_encryption_key_id.clone(),
            encryption_algorithm: self.encryption_algorithm.clone(),
        }
    }

    fn ensure_usable(&self) -> Result<(), AuthorityKeyProviderError> {
        if self.destroyed {
            return Err(AuthorityKeyProviderError::Destroyed);
        }
        if self.encryption_algorithm != ENCRYPTION_ALGORITHM {
            return Err(AuthorityKeyProviderError::UnsupportedEncryptionAlgorithm);
        }
        Ok(())
    }

    fn destroy(&mut self) {
        self.encrypted_private_key.zeroize();
        self.encrypted_private_key.clear();
        self.private_key_nonce.zeroize();
        self.private_key_nonce.clear();
        self.wrapped_dek.zeroize();
        self.wrapped_dek.clear();
        self.wrapped_dek_nonce.zeroize();
        self.wrapped_dek_nonce.clear();
        self.destroyed = true;
    }
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, AuthorityKeyProviderError> {
    value.ok_or(AuthorityKeyProviderError::MissingField(field))
}

#[derive(Debug)]
pub struct GeneratedAuthorityKey<K> {
    pub public_key: AuthorityPublicKey,
    pub key: K,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorityKeyProviderError {
    #[error("CA key provider is not configured")]
    Unconfigured,
    #[error("authority key belongs to a different provider backend")]
    WrongBackend,
    #[error("encrypted authority key is missing {0}")]
    MissingField(&'static str),
    #[error("encrypted authority key uses an unavailable CA KEK id")]
    KeyEncryptionKeyIdMismatch,
    #[error("encrypted authority key uses an unsupported encryption algorithm")]
    UnsupportedEncryptionAlgorithm,
    #[error("authority key uses an unsupported signing algorithm")]
    UnsupportedKeyAlgorithm,
    #[error("authority key cryptographic operation failed")]
    CryptographicFailure,
    #[error("authority key has been destroyed")]
    Destroyed,
}

/// Provider-neutral CA key operations. Certificate services depend on this
/// interface rather than database encryption, PKCS#11, KMS, or file details.
pub trait AuthorityKeyProvider: Send + Sync {
    /// Provider-owned opaque handle. File, PKCS#11, and KMS implementations can
    /// use their own handle without exposing it to certificate services.
    type Key;

    fn backend(&self) -> AuthorityKeyBackend;
    fn health(&self) -> AuthorityKeyProviderHealth;
    fn generate(
        &self,
        context: AuthorityKeyContext,
        algorithm: AuthorityKeyAlgorithm,
    ) -> Result<GeneratedAuthorityKey<Self::Key>, AuthorityKeyProviderError>;
    fn public_key(
        &self,
        context: AuthorityKeyContext,
        key: &Self::Key,
    ) -> Result<AuthorityPublicKey, AuthorityKeyProviderError>;
    fn sign(
        &self,
        context: AuthorityKeyContext,
        key: &Self::Key,
        message: &[u8],
    ) -> Result<AuthoritySignature, AuthorityKeyProviderError>;
    fn retire(&self, key: &Self::Key) -> Result<(), AuthorityKeyProviderError>;
    fn destroy(&self, key: &mut Self::Key) -> Result<(), AuthorityKeyProviderError>;
}

#[derive(Clone)]
pub struct EncryptedDatabaseKeyProvider {
    config: PkiCaKeyConfig,
}

impl fmt::Debug for EncryptedDatabaseKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedDatabaseKeyProvider")
            .field("backend", &AuthorityKeyBackend::EncryptedDatabase)
            .field("configured", &self.config.key_encryption_key.is_some())
            .field("key_encryption_key_id", &self.config.key_encryption_key_id)
            .finish()
    }
}

impl EncryptedDatabaseKeyProvider {
    pub fn new(config: PkiCaKeyConfig) -> Self {
        Self { config }
    }

    fn kek(&self, key_id: &str) -> Result<&[u8], AuthorityKeyProviderError> {
        if key_id != self.config.key_encryption_key_id {
            return Err(AuthorityKeyProviderError::KeyEncryptionKeyIdMismatch);
        }
        self.config
            .key_encryption_key
            .as_ref()
            .map(|key| key.expose())
            .ok_or(AuthorityKeyProviderError::Unconfigured)
    }

    fn encrypt_generated_key(
        &self,
        context: AuthorityKeyContext,
        key_algorithm: AuthorityKeyAlgorithm,
        private_key: &[u8],
    ) -> Result<EncryptedAuthorityKey, AuthorityKeyProviderError> {
        let kek = self.kek(&self.config.key_encryption_key_id)?;
        let mut dek = Zeroizing::new(vec![0_u8; DEK_LEN]);
        OsRng.fill_bytes(dek.as_mut_slice());

        let private = crypto::encrypt(dek.as_slice(), &context.aad("private-key"), private_key)
            .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
        let wrapped = crypto::encrypt(kek, &context.aad("wrapped-dek"), dek.as_slice())
            .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;

        Ok(EncryptedAuthorityKey {
            encrypted_private_key: private.ciphertext,
            private_key_nonce: private.nonce,
            wrapped_dek: wrapped.ciphertext,
            wrapped_dek_nonce: wrapped.nonce,
            key_encryption_key_id: self.config.key_encryption_key_id.clone(),
            encryption_algorithm: ENCRYPTION_ALGORITHM.to_string(),
            key_algorithm,
            destroyed: false,
        })
    }

    fn decrypt_signing_key(
        &self,
        context: AuthorityKeyContext,
        key: &EncryptedAuthorityKey,
    ) -> Result<SigningKey, AuthorityKeyProviderError> {
        key.ensure_usable()?;
        if key.key_algorithm != AuthorityKeyAlgorithm::EcdsaP256Sha256 {
            return Err(AuthorityKeyProviderError::UnsupportedKeyAlgorithm);
        }
        let kek = self.kek(&key.key_encryption_key_id)?;
        let dek = Zeroizing::new(
            crypto::decrypt(
                kek,
                &context.aad("wrapped-dek"),
                &key.wrapped_dek,
                &key.wrapped_dek_nonce,
            )
            .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?,
        );
        if dek.len() != DEK_LEN {
            return Err(AuthorityKeyProviderError::CryptographicFailure);
        }
        let private_key = Zeroizing::new(
            crypto::decrypt(
                dek.as_slice(),
                &context.aad("private-key"),
                &key.encrypted_private_key,
                &key.private_key_nonce,
            )
            .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?,
        );
        SigningKey::from_pkcs8_der(private_key.as_slice())
            .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)
    }

    fn observe<T>(
        operation: &'static str,
        result: Result<T, AuthorityKeyProviderError>,
    ) -> Result<T, AuthorityKeyProviderError> {
        let outcome = if result.is_ok() { "success" } else { "error" };
        metrics::record_pki_key_provider_operation(PROVIDER_NAME, operation, outcome);
        result
    }

    fn validate_requirement(
        &self,
        requirement: &repo::EncryptedKeyRequirement,
    ) -> Result<(), AuthorityKeyProviderError> {
        if requirement.encryption_algorithm != ENCRYPTION_ALGORITHM {
            return Err(AuthorityKeyProviderError::UnsupportedEncryptionAlgorithm);
        }
        self.kek(&requirement.key_encryption_key_id).map(|_| ())
    }
}

impl AuthorityKeyProvider for EncryptedDatabaseKeyProvider {
    type Key = EncryptedAuthorityKey;

    fn backend(&self) -> AuthorityKeyBackend {
        AuthorityKeyBackend::EncryptedDatabase
    }

    fn health(&self) -> AuthorityKeyProviderHealth {
        AuthorityKeyProviderHealth {
            backend: self.backend(),
            status: if self.config.key_encryption_key.is_some() {
                AuthorityKeyProviderStatus::Ready
            } else {
                AuthorityKeyProviderStatus::Unconfigured
            },
        }
    }

    fn generate(
        &self,
        context: AuthorityKeyContext,
        algorithm: AuthorityKeyAlgorithm,
    ) -> Result<GeneratedAuthorityKey<Self::Key>, AuthorityKeyProviderError> {
        let result = (|| {
            if algorithm != AuthorityKeyAlgorithm::EcdsaP256Sha256 {
                return Err(AuthorityKeyProviderError::UnsupportedKeyAlgorithm);
            }
            let signing_key = SigningKey::random(&mut OsRng);
            let private_key = signing_key
                .to_pkcs8_der()
                .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
            let public_key = signing_key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
            let private_key = Zeroizing::new(private_key.as_bytes().to_vec());
            let encrypted_key =
                self.encrypt_generated_key(context, algorithm, private_key.as_slice())?;
            Ok(GeneratedAuthorityKey {
                public_key: AuthorityPublicKey {
                    algorithm,
                    subject_public_key_info_der: public_key.as_bytes().to_vec(),
                },
                key: encrypted_key,
            })
        })();
        Self::observe("generate", result)
    }

    fn public_key(
        &self,
        context: AuthorityKeyContext,
        key: &EncryptedAuthorityKey,
    ) -> Result<AuthorityPublicKey, AuthorityKeyProviderError> {
        let result = (|| {
            let signing_key = self.decrypt_signing_key(context, key)?;
            let public_key = signing_key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
            Ok(AuthorityPublicKey {
                algorithm: key.key_algorithm,
                subject_public_key_info_der: public_key.as_bytes().to_vec(),
            })
        })();
        Self::observe("public_key", result)
    }

    fn sign(
        &self,
        context: AuthorityKeyContext,
        key: &EncryptedAuthorityKey,
        message: &[u8],
    ) -> Result<AuthoritySignature, AuthorityKeyProviderError> {
        let result = (|| {
            let signing_key = self.decrypt_signing_key(context, key)?;
            let signature: Signature = signing_key.sign(message);
            Ok(AuthoritySignature {
                algorithm: AuthoritySignatureAlgorithm::EcdsaP256Sha256,
                bytes: signature.to_der().as_bytes().to_vec(),
            })
        })();
        Self::observe("sign", result)
    }

    fn retire(&self, key: &EncryptedAuthorityKey) -> Result<(), AuthorityKeyProviderError> {
        // Retired issuer keys must remain usable for CRL/OCSP until retention
        // ends. Lifecycle state lives on the authority; the encrypted provider
        // therefore validates but intentionally retains the key material.
        let result = key.ensure_usable();
        Self::observe("retire", result)
    }

    fn destroy(&self, key: &mut EncryptedAuthorityKey) -> Result<(), AuthorityKeyProviderError> {
        let result = (|| {
            key.ensure_usable()?;
            key.destroy();
            Ok(())
        })();
        Self::observe("destroy", result)
    }
}

/// Validate provider metadata without loading or decrypting any CA private key.
/// A CA KEK is optional while every authority is `public_only`, but startup
/// fails closed as soon as an encrypted authority requires it.
pub async fn validate_startup(pool: &PgPool, config: &PkiCaKeyConfig) -> Result<(), AppError> {
    let requirements = repo::encrypted_key_requirements(pool).await?;
    if requirements.is_empty() {
        return Ok(());
    }

    let provider = EncryptedDatabaseKeyProvider::new(config.clone());
    requirements
        .iter()
        .try_for_each(|requirement| provider.validate_requirement(requirement))
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))?;

    tracing::info!(
        provider = PROVIDER_NAME,
        configurations = requirements.len(),
        "PKI CA key provider metadata validated"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use p256::{
        ecdsa::{signature::Verifier, Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
    };

    use crate::config::SecretBytes;

    use super::*;

    fn config(byte: u8, id: &str) -> PkiCaKeyConfig {
        PkiCaKeyConfig {
            key_encryption_key: Some(SecretBytes::new(vec![byte; DEK_LEN]).expect("test CA KEK")),
            key_encryption_key_id: id.to_string(),
        }
    }

    fn context() -> AuthorityKeyContext {
        AuthorityKeyContext {
            authority_id: Uuid::new_v4(),
            tenant_id: Some(Uuid::new_v4()),
            version: 1,
        }
    }

    fn generated(
        provider: &EncryptedDatabaseKeyProvider,
        context: AuthorityKeyContext,
    ) -> GeneratedAuthorityKey<EncryptedAuthorityKey> {
        provider
            .generate(context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
            .expect("generate")
    }

    fn public_only_root() -> AuthorityRecord {
        let now = chrono::Utc::now();
        AuthorityRecord {
            id: Uuid::new_v4(),
            tenant_id: None,
            parent_id: None,
            kind: super::super::AuthorityKind::Root,
            version: 1,
            status: super::super::AuthorityStatus::Active,
            issuance_enabled: false,
            subject: "CN=offline root".to_string(),
            serial_number: Some("01".to_string()),
            fingerprint_sha256: Some("00".repeat(32)),
            subject_key_id: None,
            authority_key_id: None,
            certificate_pem: Some("public certificate".to_string()),
            chain_pem: Some("public chain".to_string()),
            not_before: Some(now),
            not_after: Some(now + chrono::Duration::days(1)),
            key_backend: AuthorityKeyBackend::PublicOnly,
            key_reference: None,
            encrypted_private_key: None,
            private_key_nonce: None,
            wrapped_dek: None,
            wrapped_dek_nonce: None,
            key_encryption_key_id: None,
            encryption_algorithm: None,
            provisioning_mode: "imported".to_string(),
            csr_pem: None,
            failure_reason: None,
            ocsp_url: None,
            ca_issuers_url: None,
            crl_distribution_point_url: None,
            created_at: now,
            updated_at: now,
            activated_at: Some(now),
            retiring_at: None,
            retired_at: None,
        }
    }

    #[test]
    fn generated_key_signs_and_public_key_verifies() {
        let provider = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let context = context();
        let generated = generated(&provider, context);
        let message = b"certificate-tbs";

        let signature = provider
            .sign(context, &generated.key, message)
            .expect("sign");
        let public = provider
            .public_key(context, &generated.key)
            .expect("public key");
        assert_eq!(public, generated.public_key);

        let verifying_key = VerifyingKey::from_public_key_der(&public.subject_public_key_info_der)
            .expect("public key DER");
        let signature = Signature::from_der(&signature.bytes).expect("signature DER");
        verifying_key
            .verify(message, &signature)
            .expect("independent verification");
    }

    #[test]
    fn aad_binds_authority_tenant_and_version() {
        let provider = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let context = context();
        let generated = generated(&provider, context);

        for wrong_context in [
            AuthorityKeyContext {
                authority_id: Uuid::new_v4(),
                ..context
            },
            AuthorityKeyContext {
                tenant_id: Some(Uuid::new_v4()),
                ..context
            },
            AuthorityKeyContext {
                version: context.version + 1,
                ..context
            },
        ] {
            assert_eq!(
                provider
                    .sign(wrong_context, &generated.key, b"message")
                    .expect_err("AAD mismatch"),
                AuthorityKeyProviderError::CryptographicFailure
            );
        }
    }

    #[test]
    fn wrong_kek_and_key_id_fail_closed() {
        let context = context();
        let original = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let generated = generated(&original, context);

        let wrong_key = EncryptedDatabaseKeyProvider::new(config(8, "ca:v1"));
        assert_eq!(
            wrong_key
                .sign(context, &generated.key, b"message")
                .expect_err("wrong key"),
            AuthorityKeyProviderError::CryptographicFailure
        );

        let rotated_id = EncryptedDatabaseKeyProvider::new(config(7, "ca:v2"));
        assert_eq!(
            rotated_id
                .sign(context, &generated.key, b"message")
                .expect_err("unavailable old key id"),
            AuthorityKeyProviderError::KeyEncryptionKeyIdMismatch
        );
    }

    #[test]
    fn corrupted_ciphertext_and_unsupported_algorithm_fail_closed() {
        let provider = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let context = context();
        let mut generated = generated(&provider, context);
        generated.key.encrypted_private_key[0] ^= 0xff;
        assert_eq!(
            provider
                .sign(context, &generated.key, b"message")
                .expect_err("corruption"),
            AuthorityKeyProviderError::CryptographicFailure
        );

        generated.key.encryption_algorithm = "unsupported".to_string();
        assert_eq!(
            provider
                .sign(context, &generated.key, b"message")
                .expect_err("algorithm"),
            AuthorityKeyProviderError::UnsupportedEncryptionAlgorithm
        );
    }

    #[test]
    fn missing_fields_and_public_only_backend_fail_closed() {
        assert_eq!(
            EncryptedAuthorityKey::from_columns(
                None,
                Some(vec![0; 12]),
                Some(vec![1]),
                Some(vec![0; 12]),
                Some("ca:v1".to_string()),
                Some(ENCRYPTION_ALGORITHM.to_string()),
            )
            .expect_err("missing field"),
            AuthorityKeyProviderError::MissingField("encrypted_private_key")
        );

        assert!(!AuthorityKeyBackend::PublicOnly.can_sign());
        assert_eq!(
            EncryptedAuthorityKey::from_authority(&public_only_root())
                .expect_err("public-only root cannot produce a signing handle"),
            AuthorityKeyProviderError::WrongBackend
        );
    }

    #[test]
    fn restart_loading_uses_only_persisted_encrypted_columns() {
        let context = context();
        let first_process = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let generated = generated(&first_process, context);
        let persisted = &generated.key;

        let loaded = EncryptedAuthorityKey::from_columns(
            Some(persisted.encrypted_private_key.clone()),
            Some(persisted.private_key_nonce.clone()),
            Some(persisted.wrapped_dek.clone()),
            Some(persisted.wrapped_dek_nonce.clone()),
            Some(persisted.key_encryption_key_id.clone()),
            Some(persisted.encryption_algorithm.clone()),
        )
        .expect("load persisted key");
        let restarted_process = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        restarted_process
            .sign(context, &loaded, b"after restart")
            .expect("sign after restart");
    }

    #[test]
    fn secret_material_is_not_debugged_or_serialized() {
        let provider = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let generated = generated(&provider, context());
        let ciphertext = hex::encode(&generated.key.encrypted_private_key);
        let wrapped_dek = hex::encode(&generated.key.wrapped_dek);
        let debug = format!("{:?}", generated.key);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&ciphertext));
        assert!(!debug.contains(&wrapped_dek));

        let serialized =
            serde_json::to_string(&generated.key.metadata()).expect("safe metadata serialization");
        assert!(!serialized.contains(&ciphertext));
        assert!(!serialized.contains(&wrapped_dek));
    }

    #[test]
    fn retirement_retains_key_but_destruction_zeroizes_handle() {
        let provider = EncryptedDatabaseKeyProvider::new(config(7, "ca:v1"));
        let context = context();
        let mut generated = generated(&provider, context);
        provider.retire(&generated.key).expect("retire retains key");
        provider
            .sign(context, &generated.key, b"crl")
            .expect("retired key remains usable for artifacts");

        provider.destroy(&mut generated.key).expect("destroy");
        assert_eq!(
            provider
                .sign(context, &generated.key, b"message")
                .expect_err("destroyed key"),
            AuthorityKeyProviderError::Destroyed
        );
    }

    #[test]
    fn missing_ca_kek_is_healthy_only_for_unused_provider() {
        let provider = EncryptedDatabaseKeyProvider::new(PkiCaKeyConfig::default());
        assert_eq!(
            provider.health().status,
            AuthorityKeyProviderStatus::Unconfigured
        );
        assert_eq!(
            provider
                .validate_requirement(&repo::EncryptedKeyRequirement {
                    key_encryption_key_id: "local-ca:v1".to_string(),
                    encryption_algorithm: ENCRYPTION_ALGORITHM.to_string(),
                })
                .expect_err("encrypted row requires CA KEK"),
            AuthorityKeyProviderError::Unconfigured
        );
    }
}
