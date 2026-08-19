use std::{collections::HashSet, ops::Deref};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKey, SecretKey,
};
use rand::{rngs::OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyIdMethod, KeyUsagePurpose,
    PublicKeyData, SerialNumber, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256,
};
use ring::digest;
use sqlx::{PgPool, Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::{extensions::ParsedExtension, pem::parse_x509_pem, prelude::X509Certificate};
use zeroize::Zeroizing;

use crate::{config::PkiCaKeyConfig, error::AppError};

use super::{
    key_provider::{
        AuthorityKeyAlgorithm, AuthorityKeyContext, AuthorityKeyProvider, ManagedAuthorityKey,
        ManagedAuthorityKeyProvider,
    },
    repo, AuthorityKind, AuthorityRecord, AuthorityStatus,
};

const CA_CLOCK_SKEW_SECS: i64 = 300;
const AUTOMATED_CA_TTL_DAYS: i64 = 365;

#[derive(Debug)]
pub struct AuthorityImportOutcome {
    pub authority: AuthorityRecord,
    pub validation_error: Option<String>,
    pub replaced_authorities: Vec<Uuid>,
}

impl AuthorityImportOutcome {
    pub fn succeeded(&self) -> bool {
        self.validation_error.is_none()
    }
}

#[derive(Debug)]
pub struct AuthorityMutationOutcome<T> {
    pub value: T,
    pub changed: bool,
    generated_key: Option<GeneratedAuthorityKeyGuard>,
}

impl<T> AuthorityMutationOutcome<T> {
    fn unchanged(value: T) -> Self {
        Self {
            value,
            changed: false,
            generated_key: None,
        }
    }

    fn changed(value: T) -> Self {
        Self {
            value,
            changed: true,
            generated_key: None,
        }
    }

    fn with_generated_key(value: T, generated_key: GeneratedAuthorityKeyGuard) -> Self {
        Self {
            value,
            changed: true,
            generated_key: Some(generated_key),
        }
    }

    /// Transfer ownership of a newly generated provider key to the committed
    /// authority row. Until this is called, dropping the outcome destroys the
    /// key so a failed or rolled-back transaction cannot orphan token objects.
    pub fn commit_generated_key(&mut self) {
        if let Some(mut generated_key) = self.generated_key.take() {
            generated_key.disarm();
        }
    }
}

impl<T> Deref for AuthorityMutationOutcome<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[derive(Debug)]
struct GeneratedAuthorityKeyGuard {
    provider: ManagedAuthorityKeyProvider,
    context: AuthorityKeyContext,
    key: Option<ManagedAuthorityKey>,
}

impl GeneratedAuthorityKeyGuard {
    fn new(
        provider: ManagedAuthorityKeyProvider,
        context: AuthorityKeyContext,
        key: ManagedAuthorityKey,
    ) -> Self {
        Self {
            provider,
            context,
            key: Some(key),
        }
    }

    fn provider(&self) -> &ManagedAuthorityKeyProvider {
        &self.provider
    }

    fn key(&self) -> &ManagedAuthorityKey {
        self.key
            .as_ref()
            .expect("generated authority key guard is armed")
    }

    fn disarm(&mut self) {
        self.key = None;
    }
}

impl Drop for GeneratedAuthorityKeyGuard {
    fn drop(&mut self) {
        let Some(mut key) = self.key.take() else {
            return;
        };
        if let Err(error) = self.provider.destroy(self.context, &mut key) {
            tracing::error!(
                provider = ?self.provider.backend(),
                authority_id = %self.context.authority_id,
                error = %error,
                "failed to remove uncommitted authority key"
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBundle {
    pub pem: String,
    pub version: String,
}

#[derive(Debug)]
struct ParsedAuthorityCertificate {
    der: Vec<u8>,
    pem: String,
    subject: String,
    common_name: String,
    serial_number: String,
    fingerprint_sha256: String,
    subject_public_key_info: Vec<u8>,
    subject_key_id: Vec<u8>,
    authority_key_id: Option<Vec<u8>>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    path_len_constraint: Option<u32>,
    digital_signature: bool,
}

struct ProviderSigningKey<'a> {
    provider: &'a ManagedAuthorityKeyProvider,
    context: AuthorityKeyContext,
    key: &'a ManagedAuthorityKey,
    raw_public_key: Vec<u8>,
}

impl ProviderSigningKey<'_> {
    fn new<'a>(
        provider: &'a ManagedAuthorityKeyProvider,
        context: AuthorityKeyContext,
        key: &'a ManagedAuthorityKey,
    ) -> Result<ProviderSigningKey<'a>, AppError> {
        let public = provider
            .public_key(context, key)
            .map_err(key_provider_error)?;
        let public_key = PublicKey::from_public_key_der(&public.subject_public_key_info_der)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid authority public key")))?;
        Ok(ProviderSigningKey {
            provider,
            context,
            key,
            raw_public_key: public_key.to_encoded_point(false).as_bytes().to_vec(),
        })
    }
}

impl PublicKeyData for ProviderSigningKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.raw_public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for ProviderSigningKey<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.provider
            .sign(self.context, self.key, msg)
            .map(|signature| signature.bytes)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

pub async fn import_root_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    certificate_pem: &str,
) -> Result<AuthorityRecord, AppError> {
    Ok(import_root_mutation_in_tx(tx, certificate_pem).await?.value)
}

pub async fn import_root_mutation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    certificate_pem: &str,
) -> Result<AuthorityMutationOutcome<AuthorityRecord>, AppError> {
    repo::lock_provisioning(tx).await?;
    let parsed = parse_authority_certificate(certificate_pem)?;
    validate_root_certificate(&parsed)?;

    if let Some(existing) = repo::authority_by_fingerprint(tx, &parsed.fingerprint_sha256).await? {
        if existing.kind == AuthorityKind::Root {
            return Ok(AuthorityMutationOutcome::unchanged(existing));
        }
        return Err(AppError::conflict(
            "certificate fingerprint already belongs to another authority",
        ));
    }

    let version = repo::next_authority_version(tx, AuthorityKind::Root, None).await?;
    let completed = completed_authority(&parsed, &parsed.pem);
    let authority = repo::insert_root_authority(tx, Uuid::new_v4(), version, &completed).await?;
    Ok(AuthorityMutationOutcome::changed(authority))
}

/// Persist a bring-your-own platform intermediate CA: an operator-supplied
/// certificate already signed by the configured root, together with its
/// PKCS#8 or SEC1 PEM-encoded EC private key. The key is wrapped by the
/// encrypted-database provider before it hits the row. Idempotent by
/// certificate fingerprint.
pub async fn import_platform_intermediate_mutation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<AuthorityMutationOutcome<AuthorityRecord>, AppError> {
    repo::lock_provisioning(tx).await?;
    let parsed = parse_authority_certificate(certificate_pem)?;
    validate_ca_shape(AuthorityKind::PlatformIntermediate, &parsed)?;

    let parent = repo::active_root(tx).await?;
    ensure_parent_available(&parent)?;

    // Idempotency: replaying the same certificate against a previous import
    // returns the existing active row without wrapping the key again.
    if let Some(existing) = repo::authority_by_fingerprint(tx, &parsed.fingerprint_sha256).await? {
        if existing.kind == AuthorityKind::PlatformIntermediate {
            return Ok(AuthorityMutationOutcome::unchanged(existing));
        }
        return Err(AppError::conflict(
            "certificate fingerprint already belongs to another authority",
        ));
    }

    // Verify chain: cert's AKI matches root's SKI and its issuer DN matches
    // the root's subject DN, and the parent actually signed it.
    let parent_pem = parent
        .certificate_pem
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent certificate is missing")))?;
    let parsed_parent = parse_authority_certificate(parent_pem)?;
    if parent.fingerprint_sha256.as_deref() != Some(&parsed_parent.fingerprint_sha256) {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored parent certificate metadata does not match its certificate"
        )));
    }
    let (_, child) = x509_parser::parse_x509_certificate(&parsed.der)
        .map_err(|_| AppError::bad_request("invalid platform intermediate certificate"))?;
    let (_, issuer) = x509_parser::parse_x509_certificate(&parsed_parent.der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid parent certificate")))?;
    if child.issuer() != issuer.subject() {
        return Err(AppError::bad_request(
            "platform intermediate issuer does not match the configured root subject",
        ));
    }
    child
        .verify_signature(Some(issuer.public_key()))
        .map_err(|_| {
            AppError::bad_request("platform intermediate is not signed by the configured root")
        })?;
    if parsed.authority_key_id.as_deref() != Some(parsed_parent.subject_key_id.as_slice()) {
        return Err(AppError::bad_request(
            "platform intermediate authority key identifier does not match root subject key identifier",
        ));
    }
    if parsed.not_before < parsed_parent.not_before || parsed.not_after > parsed_parent.not_after {
        return Err(AppError::bad_request(
            "platform intermediate validity exceeds root validity",
        ));
    }

    // Decode private key PEM to PKCS#8 DER (support PKCS#8 and SEC1 EC forms).
    let pkcs8_der = decode_private_key_pem(private_key_pem)?;

    // Verify the private key matches the certificate's public key.
    use p256::pkcs8::DecodePrivateKey as _;
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der.as_slice())
        .map_err(|_| AppError::bad_request("platform intermediate private key is invalid"))?;
    let key_public_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to encode imported public key")))?;
    if key_public_der.as_bytes() != parsed.subject_public_key_info.as_slice() {
        return Err(AppError::bad_request(
            "platform intermediate private key does not match the supplied certificate",
        ));
    }

    // Wrap and persist through the encrypted-database provider regardless of
    // the runtime provisioning backend. PKCS#11 tokens generate non-exportable
    // keys inside the HSM and refuse `import_pkcs8`, so bring-your-own material
    // must always land in the encrypted-database store.
    let authority_id = Uuid::new_v4();
    let version =
        repo::next_authority_version(tx, AuthorityKind::PlatformIntermediate, None).await?;
    let context = AuthorityKeyContext {
        authority_id,
        tenant_id: None,
        version,
    };
    let mut import_keys = ca_keys.clone();
    import_keys.provisioning_backend = crate::config::PkiCaProvisioningBackend::EncryptedDatabase;
    let provider =
        ManagedAuthorityKeyProvider::for_provisioning(&import_keys).map_err(key_provider_error)?;
    let generated = provider
        .import_pkcs8(
            context,
            AuthorityKeyAlgorithm::EcdsaP256Sha256,
            pkcs8_der.as_slice(),
        )
        .map_err(key_provider_error)?;
    let generated_key = GeneratedAuthorityKeyGuard::new(provider, context, generated.key);

    let subject = authority_common_name(AuthorityKind::PlatformIntermediate, None, version)?;
    let parent_chain = parent
        .chain_pem
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent authority has no chain")))?;
    let chain_pem = format!("{}{}", parsed.pem, parent_chain);
    let completed = completed_authority(&parsed, &chain_pem);
    let discovery = discovery_urls_for(AuthorityKind::PlatformIntermediate, authority_id, ca_keys);

    // A subsequent bootstrap with a fresh certificate replaces the previous
    // active platform intermediate. The unique-active index would otherwise
    // reject the insert; retiring the older row also preserves audit history
    // and lets any in-flight issuance continue against the retired issuer.
    let _replaced = repo::retire_other_active_authorities(
        tx,
        authority_id,
        AuthorityKind::PlatformIntermediate,
        None,
    )
    .await?;
    let record = repo::insert_active_authority(
        tx,
        &repo::ActiveAuthorityInsert {
            id: authority_id,
            tenant_id: None,
            parent_id: parent.id,
            kind: AuthorityKind::PlatformIntermediate,
            version,
            subject: &subject,
            provisioning_mode: "config_bootstrap",
            issuance_enabled: AuthorityKind::PlatformIntermediate.can_issue_leaf_credentials(),
            key: generated_key.key(),
            completed: &completed,
            discovery: discovery.as_ref(),
        },
    )
    .await?;

    Ok(AuthorityMutationOutcome::with_generated_key(
        record,
        generated_key,
    ))
}

/// Decode a PEM-encoded EC private key to its PKCS#8 DER representation.
/// Accepts both `-----BEGIN PRIVATE KEY-----` (PKCS#8) and
/// `-----BEGIN EC PRIVATE KEY-----` (SEC1) forms; other labels are rejected.
fn decode_private_key_pem(pem: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    use p256::pkcs8::DecodePrivateKey;
    // Skip any leading PEM blocks that aren't the private key itself
    // (openssl-generated files may prepend "EC PARAMETERS" ahead of the key).
    let key_pem = find_private_key_block(pem)
        .ok_or_else(|| AppError::bad_request("no PEM private key block was found"))?;
    if key_pem.contains("-----BEGIN PRIVATE KEY-----") {
        let secret = SecretKey::from_pkcs8_pem(&key_pem)
            .map_err(|_| AppError::bad_request("invalid PKCS#8 private key PEM"))?;
        let der = secret
            .to_pkcs8_der()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to re-encode PKCS#8 key")))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    } else if key_pem.contains("-----BEGIN EC PRIVATE KEY-----") {
        let secret = SecretKey::from_sec1_pem(&key_pem)
            .map_err(|_| AppError::bad_request("invalid SEC1 EC private key PEM"))?;
        let der = secret
            .to_pkcs8_der()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to convert SEC1 to PKCS#8")))?;
        Ok(Zeroizing::new(der.as_bytes().to_vec()))
    } else {
        Err(AppError::bad_request(
            "platform intermediate private key must be PKCS#8 or SEC1 EC PEM",
        ))
    }
}

fn find_private_key_block(pem: &str) -> Option<String> {
    for label in [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ] {
        if let Some(start) = pem.find(label) {
            let end_label = label.replace("BEGIN", "END");
            if let Some(end) = pem[start..].find(&end_label) {
                let stop = start + end + end_label.len();
                return Some(pem[start..stop].to_string());
            }
        }
    }
    None
}

pub async fn begin_tenant_authority_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> Result<AuthorityMutationOutcome<AuthorityRecord>, AppError> {
    begin_tenant_authority_mutation_in_tx(tx, ca_keys, tenant_id).await
}

pub async fn begin_tenant_authority_mutation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> Result<AuthorityMutationOutcome<AuthorityRecord>, AppError> {
    repo::lock_provisioning(tx).await?;
    repo::lock_active_tenant(tx, tenant_id).await?;
    if let Some(existing) =
        repo::pending_authority_for_scope(tx, AuthorityKind::TenantIntermediate, Some(tenant_id))
            .await?
    {
        if existing.provisioning_mode == "offline" {
            return Ok(AuthorityMutationOutcome::unchanged(existing));
        }
        return Err(AppError::conflict(
            "authority provisioning already exists for this scope",
        ));
    }

    let parent = repo::active_root(tx).await?;
    ensure_parent_available(&parent)?;
    let (authority, generated_key) = create_pending_authority(
        tx,
        ca_keys,
        AuthorityKind::TenantIntermediate,
        Some(tenant_id),
        &parent,
        "offline",
    )
    .await?;
    Ok(AuthorityMutationOutcome::with_generated_key(
        authority,
        generated_key,
    ))
}

pub async fn provision_tenant_automatically_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> Result<AuthorityMutationOutcome<AuthorityImportOutcome>, AppError> {
    provision_tenant_automatically_mutation_in_tx(tx, ca_keys, tenant_id).await
}

pub async fn provision_tenant_automatically_mutation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> Result<AuthorityMutationOutcome<AuthorityImportOutcome>, AppError> {
    repo::lock_provisioning(tx).await?;
    repo::lock_active_tenant(tx, tenant_id).await?;

    if let Some(active) =
        repo::active_authority_for_scope(tx, AuthorityKind::TenantIntermediate, Some(tenant_id))
            .await?
    {
        return Ok(AuthorityMutationOutcome::unchanged(
            AuthorityImportOutcome {
                authority: active,
                validation_error: None,
                replaced_authorities: Vec::new(),
            },
        ));
    }
    if let Some(existing) =
        repo::pending_authority_for_scope(tx, AuthorityKind::TenantIntermediate, Some(tenant_id))
            .await?
    {
        return Err(AppError::conflict(format!(
            "authority {} is already waiting for an offline signature",
            existing.id
        )));
    }

    let parent = repo::active_platform_intermediate(tx).await?;
    ensure_parent_available(&parent)?;
    let (pending, generated_key) = create_pending_authority(
        tx,
        ca_keys,
        AuthorityKind::TenantIntermediate,
        Some(tenant_id),
        &parent,
        "automated",
    )
    .await?;
    let certificate_pem = sign_pending_authority(ca_keys, &pending, &parent)?;
    let outcome = import_signed_authority_locked(tx, ca_keys, pending, &certificate_pem).await?;
    Ok(AuthorityMutationOutcome::with_generated_key(
        outcome,
        generated_key,
    ))
}

async fn import_signed_authority_locked(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    authority: AuthorityRecord,
    certificate_pem: &str,
) -> Result<AuthorityImportOutcome, AppError> {
    if authority.kind == AuthorityKind::Root {
        return Err(AppError::bad_request(
            "root certificates use the root import operation",
        ));
    }

    if authority.status == AuthorityStatus::Active {
        let parsed = parse_authority_certificate(certificate_pem)?;
        if authority.fingerprint_sha256.as_deref() == Some(&parsed.fingerprint_sha256) {
            return Ok(AuthorityImportOutcome {
                authority,
                validation_error: None,
                replaced_authorities: Vec::new(),
            });
        }
        return Err(AppError::conflict("authority is already active"));
    }
    if authority.status == AuthorityStatus::Failed {
        return Err(AppError::conflict(
            "failed authority rows are retained; start a new provisioning version",
        ));
    }
    if authority.status != AuthorityStatus::PendingSignature {
        return Err(AppError::conflict(
            "authority is not waiting for a signed certificate",
        ));
    }

    let parsed = match parse_authority_certificate(certificate_pem) {
        Ok(parsed) => parsed,
        Err(error) => {
            let reason = error.to_string();
            let failed = repo::mark_authority_failed(tx, authority.id, &reason).await?;
            return Ok(AuthorityImportOutcome {
                authority: failed,
                validation_error: Some(reason),
                replaced_authorities: Vec::new(),
            });
        }
    };

    let parent_id = authority
        .parent_id
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("managed CA has no parent")))?;
    let parent = repo::authority_by_id_for_update(tx, parent_id).await?;
    let validation = validate_imported_authority(ca_keys, &authority, &parent, &parsed);
    if let Err(error) = validation {
        let reason = error.to_string();
        let failed = repo::mark_authority_failed(tx, authority.id, &reason).await?;
        return Ok(AuthorityImportOutcome {
            authority: failed,
            validation_error: Some(reason),
            replaced_authorities: Vec::new(),
        });
    }

    if let Some(existing) = repo::authority_by_fingerprint(tx, &parsed.fingerprint_sha256).await? {
        if existing.id != authority.id {
            let reason = "certificate was already imported for another authority".to_string();
            let failed = repo::mark_authority_failed(tx, authority.id, &reason).await?;
            return Ok(AuthorityImportOutcome {
                authority: failed,
                validation_error: Some(reason),
                replaced_authorities: Vec::new(),
            });
        }
    }

    let parent_chain = parent
        .chain_pem
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent authority has no chain")))?;
    let chain_pem = format!("{}{}", parsed.pem, parent_chain);
    let completed = completed_authority(&parsed, &chain_pem);
    let replaced = repo::retire_other_active_authorities(
        tx,
        authority.id,
        authority.kind,
        authority.tenant_id,
    )
    .await?;
    let discovery = discovery_urls_for(authority.kind, authority.id, ca_keys);
    let active = repo::activate_authority(
        tx,
        authority.id,
        &completed,
        authority.kind.can_issue_leaf_credentials(),
        discovery.as_ref(),
    )
    .await?;
    Ok(AuthorityImportOutcome {
        authority: active,
        validation_error: None,
        replaced_authorities: replaced,
    })
}

/// Derive per-authority publication routes from the deployment's public base
/// URL. Only leaf-issuing kinds need them at activation — `PkiIssuer::from_
/// managed_authority` requires all three and it is only ever loaded for
/// leaf-issuing authorities. Returns `None` when the deployment did not
/// configure a base URL (legacy manual-SQL workflow).
fn discovery_urls_for(
    kind: AuthorityKind,
    authority_id: Uuid,
    ca_keys: &PkiCaKeyConfig,
) -> Option<repo::DiscoveryUrls> {
    if !kind.can_issue_leaf_credentials() {
        return None;
    }
    let base = ca_keys.artifact_base_url.as_deref()?.trim_end_matches('/');
    Some(repo::DiscoveryUrls {
        ocsp_url: Some(format!("{base}/certs/issuers/{authority_id}/ocsp")),
        ca_issuers_url: Some(format!("{base}/certs/trust-bundle.pem")),
        crl_distribution_point_url: Some(format!("{base}/certs/issuers/{authority_id}/crl")),
    })
}

pub async fn begin_retirement_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    Ok(begin_retirement_mutation_in_tx(tx, ca_keys, authority_id)
        .await?
        .value)
}

pub async fn begin_retirement_mutation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    authority_id: Uuid,
) -> Result<AuthorityMutationOutcome<AuthorityRecord>, AppError> {
    repo::lock_provisioning(tx).await?;
    let authority = repo::authority_by_id_for_update(tx, authority_id).await?;
    if authority.kind == AuthorityKind::Root {
        return Err(AppError::bad_request(
            "root authority retirement is an offline trust-anchor operation",
        ));
    }
    if authority.status == AuthorityStatus::Retiring {
        return Ok(AuthorityMutationOutcome::unchanged(authority));
    }
    if authority.status != AuthorityStatus::Active {
        return Err(AppError::conflict("only an active authority can retire"));
    }
    if authority.key_backend.can_sign() {
        let provider = ManagedAuthorityKeyProvider::for_authority(ca_keys, &authority)
            .map_err(key_provider_error)?;
        let key = ManagedAuthorityKey::from_authority(&authority).map_err(key_provider_error)?;
        provider
            .retire(authority_key_context(&authority), &key)
            .map_err(key_provider_error)?;
    }
    let authority = repo::transition_authority(
        tx,
        authority_id,
        AuthorityStatus::Active,
        AuthorityStatus::Retiring,
    )
    .await?;
    Ok(AuthorityMutationOutcome::changed(authority))
}

pub async fn complete_retirement_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    Ok(complete_retirement_mutation_in_tx(tx, authority_id)
        .await?
        .value)
}

pub async fn complete_retirement_mutation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
) -> Result<AuthorityMutationOutcome<AuthorityRecord>, AppError> {
    repo::lock_provisioning(tx).await?;
    let authority = repo::authority_by_id_for_update(tx, authority_id).await?;
    if authority.status == AuthorityStatus::Retired {
        return Ok(AuthorityMutationOutcome::unchanged(authority));
    }
    let authority = repo::transition_authority(
        tx,
        authority_id,
        AuthorityStatus::Retiring,
        AuthorityStatus::Retired,
    )
    .await?;
    Ok(AuthorityMutationOutcome::changed(authority))
}

pub async fn trust_bundle(pool: &PgPool) -> Result<TrustBundle, AppError> {
    let authorities = repo::trust_bundle_authorities(pool).await?;
    let mut seen = HashSet::new();
    let mut certificates = Vec::new();
    for authority in authorities {
        let chain = authority
            .chain_pem
            .as_deref()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("authority chain is missing")))?;
        let mut remaining = chain.as_bytes();
        while !remaining.iter().all(|byte| byte.is_ascii_whitespace()) {
            let (rest, pem) = parse_x509_pem(remaining)
                .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid authority chain")))?;
            if pem.label != "CERTIFICATE" {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "authority chain contains non-certificate material"
                )));
            }
            let fingerprint = hex::encode(digest::digest(&digest::SHA256, &pem.contents));
            if seen.insert(fingerprint) {
                certificates.push(pem_encode_certificate(&pem.contents));
            }
            remaining = rest;
        }
    }
    let pem = certificates.concat();
    let version = hex::encode(digest::digest(&digest::SHA256, pem.as_bytes()));
    Ok(TrustBundle { pem, version })
}

async fn create_pending_authority(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
    parent: &AuthorityRecord,
    provisioning_mode: &str,
) -> Result<(AuthorityRecord, GeneratedAuthorityKeyGuard), AppError> {
    let version = repo::next_authority_version(tx, kind, tenant_id).await?;
    let authority_id = Uuid::new_v4();
    let context = AuthorityKeyContext {
        authority_id,
        tenant_id,
        version,
    };
    let provider =
        ManagedAuthorityKeyProvider::for_provisioning(ca_keys).map_err(key_provider_error)?;
    let generated = provider
        .generate(context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
        .map_err(key_provider_error)?;
    let generated_key = GeneratedAuthorityKeyGuard::new(provider, context, generated.key);
    let signing_key =
        ProviderSigningKey::new(generated_key.provider(), context, generated_key.key())?;
    let subject = authority_common_name(kind, tenant_id, version)?;
    let params = ca_certificate_params(kind, &subject)?;
    let csr = params
        .serialize_request(&signing_key)
        .map_err(rcgen_error)?;
    let csr_pem = csr.pem().map_err(rcgen_error)?;
    let inserted = repo::insert_pending_authority(
        tx,
        &repo::PendingAuthorityInsert {
            id: authority_id,
            tenant_id,
            parent_id: parent.id,
            kind,
            version,
            subject: &subject,
            csr_pem: &csr_pem,
            provisioning_mode,
            key: generated_key.key(),
        },
    )
    .await?;
    Ok((inserted, generated_key))
}

fn sign_pending_authority(
    ca_keys: &PkiCaKeyConfig,
    authority: &AuthorityRecord,
    parent: &AuthorityRecord,
) -> Result<String, AppError> {
    let child_provider = ManagedAuthorityKeyProvider::for_authority(ca_keys, authority)
        .map_err(key_provider_error)?;
    let child_key = ManagedAuthorityKey::from_authority(authority).map_err(key_provider_error)?;
    let child_context = authority_key_context(authority);
    let child_signing_key = ProviderSigningKey::new(&child_provider, child_context, &child_key)?;

    let parent_provider =
        ManagedAuthorityKeyProvider::for_authority(ca_keys, parent).map_err(key_provider_error)?;
    let parent_key = ManagedAuthorityKey::from_authority(parent).map_err(key_provider_error)?;
    let parent_context = authority_key_context(parent);
    let parent_signing_key =
        ProviderSigningKey::new(&parent_provider, parent_context, &parent_key)?;
    let parent_pem = parent
        .certificate_pem
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent certificate is missing")))?;
    let issuer = Issuer::from_ca_cert_pem(parent_pem, &parent_signing_key).map_err(rcgen_error)?;

    let mut params = ca_certificate_params(authority.kind, &authority.subject)?;
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    let parent_not_before = to_offset(
        parent
            .not_before
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent validity is missing")))?,
    )?;
    let parent_not_after = to_offset(
        parent
            .not_after
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent validity is missing")))?,
    )?;
    params.not_before = (now - Duration::seconds(CA_CLOCK_SKEW_SECS)).max(parent_not_before);
    params.not_after = (now + Duration::days(AUTOMATED_CA_TTL_DAYS)).min(parent_not_after);
    if params.not_after <= now {
        return Err(AppError::bad_request("parent authority is expired"));
    }
    let mut serial = [0_u8; 16];
    OsRng.fill_bytes(&mut serial);
    params.serial_number = Some(SerialNumber::from(serial.to_vec()));
    let certificate = params
        .signed_by(&child_signing_key, &issuer)
        .map_err(rcgen_error)?;
    Ok(certificate.pem())
}

fn validate_imported_authority(
    ca_keys: &PkiCaKeyConfig,
    authority: &AuthorityRecord,
    parent: &AuthorityRecord,
    certificate: &ParsedAuthorityCertificate,
) -> Result<(), AppError> {
    ensure_parent_available(parent)?;
    validate_ca_shape(authority.kind, certificate)?;
    let expected_cn =
        authority_common_name(authority.kind, authority.tenant_id, authority.version)?;
    if certificate.common_name != expected_cn || authority.subject != expected_cn {
        return Err(AppError::bad_request(
            "signed authority subject does not match the intended scope",
        ));
    }

    let provider = ManagedAuthorityKeyProvider::for_authority(ca_keys, authority)
        .map_err(key_provider_error)?;
    let key = ManagedAuthorityKey::from_authority(authority).map_err(key_provider_error)?;
    let public = provider
        .public_key(authority_key_context(authority), &key)
        .map_err(key_provider_error)?;
    if public.subject_public_key_info_der != certificate.subject_public_key_info {
        return Err(AppError::bad_request(
            "signed authority certificate does not match the generated key",
        ));
    }

    let parent_pem = parent
        .certificate_pem
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("parent certificate is missing")))?;
    let parsed_parent = parse_authority_certificate(parent_pem)?;
    validate_ca_shape(parent.kind, &parsed_parent)?;
    if parent.fingerprint_sha256.as_deref() != Some(&parsed_parent.fingerprint_sha256) {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored parent certificate metadata does not match its certificate"
        )));
    }
    let (_, child) = x509_parser::parse_x509_certificate(&certificate.der)
        .map_err(|_| AppError::bad_request("invalid signed authority certificate"))?;
    let (_, issuer) = x509_parser::parse_x509_certificate(&parsed_parent.der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid parent certificate")))?;
    if child.issuer() != issuer.subject() {
        return Err(AppError::bad_request(
            "authority certificate issuer does not match its intended parent",
        ));
    }
    child
        .verify_signature(Some(issuer.public_key()))
        .map_err(|_| {
            AppError::bad_request("authority certificate has the wrong parent signature")
        })?;
    if certificate.authority_key_id.as_deref() != Some(parsed_parent.subject_key_id.as_slice()) {
        return Err(AppError::bad_request(
            "authority key identifier does not match parent subject key identifier",
        ));
    }
    if certificate.not_before < parsed_parent.not_before
        || certificate.not_after > parsed_parent.not_after
    {
        return Err(AppError::bad_request(
            "authority validity exceeds parent validity",
        ));
    }
    Ok(())
}

fn validate_root_certificate(certificate: &ParsedAuthorityCertificate) -> Result<(), AppError> {
    validate_ca_shape(AuthorityKind::Root, certificate)?;
    let (_, root) = x509_parser::parse_x509_certificate(&certificate.der)
        .map_err(|_| AppError::bad_request("invalid root certificate"))?;
    if root.issuer() != root.subject() {
        return Err(AppError::bad_request(
            "root certificate must be self-issued",
        ));
    }
    root.verify_signature(None)
        .map_err(|_| AppError::bad_request("root certificate is not self-signed"))?;
    if certificate
        .authority_key_id
        .as_deref()
        .is_some_and(|aki| aki != certificate.subject_key_id.as_slice())
    {
        return Err(AppError::bad_request(
            "root authority key identifier does not match its subject key identifier",
        ));
    }
    Ok(())
}

fn validate_ca_shape(
    kind: AuthorityKind,
    certificate: &ParsedAuthorityCertificate,
) -> Result<(), AppError> {
    let now = Utc::now();
    if certificate.not_before > now + chrono::Duration::seconds(CA_CLOCK_SKEW_SECS) {
        return Err(AppError::bad_request(
            "authority certificate is not yet valid",
        ));
    }
    if certificate.not_after <= now {
        return Err(AppError::bad_request("authority certificate is expired"));
    }
    if kind.can_issue_leaf_credentials() && !certificate.digital_signature {
        return Err(AppError::bad_request(
            "leaf-issuing authority key usage must include digitalSignature",
        ));
    }
    match kind {
        AuthorityKind::TenantIntermediate | AuthorityKind::PlatformLeafIssuer
            if certificate.path_len_constraint != Some(0) =>
        {
            Err(AppError::bad_request(
                "leaf-issuing authority must have pathLenConstraint=0",
            ))
        }
        AuthorityKind::PlatformIntermediate
            if certificate
                .path_len_constraint
                .is_some_and(|path_len| path_len < 1) =>
        {
            Err(AppError::bad_request(
                "platform intermediate must permit one subordinate CA level",
            ))
        }
        AuthorityKind::Root
            if certificate
                .path_len_constraint
                .is_some_and(|path_len| path_len < 2) =>
        {
            Err(AppError::bad_request(
                "root authority must permit the platform and tenant intermediate levels",
            ))
        }
        AuthorityKind::Root
        | AuthorityKind::PlatformIntermediate
        | AuthorityKind::PlatformLeafIssuer
        | AuthorityKind::TenantIntermediate => Ok(()),
    }
}

fn parse_authority_certificate(
    certificate_pem: &str,
) -> Result<ParsedAuthorityCertificate, AppError> {
    let (remaining, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| AppError::bad_request("invalid authority certificate PEM"))?;
    if pem.label != "CERTIFICATE" || !remaining.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(AppError::bad_request(
            "authority import accepts exactly one certificate and no private key material",
        ));
    }
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|_| AppError::bad_request("invalid authority certificate"))?;
    let basic = cert
        .tbs_certificate
        .basic_constraints()
        .map_err(|_| AppError::bad_request("invalid authority basic constraints"))?
        .ok_or_else(|| {
            AppError::bad_request("authority certificate is missing basic constraints")
        })?;
    if !basic.value.ca {
        return Err(AppError::bad_request(
            "authority certificate must have CA=true",
        ));
    }
    let usage = cert
        .tbs_certificate
        .key_usage()
        .map_err(|_| AppError::bad_request("invalid authority key usage"))?
        .ok_or_else(|| AppError::bad_request("authority certificate is missing key usage"))?;
    if !usage.value.key_cert_sign() || !usage.value.crl_sign() {
        return Err(AppError::bad_request(
            "authority key usage must include keyCertSign and cRLSign",
        ));
    }

    let mut subject_key_id = None;
    let mut authority_key_id = None;
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(key_id) => {
                if subject_key_id.is_some() {
                    return Err(AppError::bad_request(
                        "authority certificate has duplicate subject key identifiers",
                    ));
                }
                subject_key_id = Some(key_id.0.to_vec());
            }
            ParsedExtension::AuthorityKeyIdentifier(key_id) => {
                if authority_key_id.is_some() {
                    return Err(AppError::bad_request(
                        "authority certificate has duplicate authority key identifiers",
                    ));
                }
                authority_key_id = key_id.key_identifier.as_ref().map(|value| value.0.to_vec());
            }
            ParsedExtension::UnsupportedExtension { .. } if extension.critical => {
                return Err(AppError::bad_request(
                    "authority certificate has an unsupported critical extension",
                ));
            }
            ParsedExtension::ParseError { .. } => {
                return Err(AppError::bad_request(
                    "authority certificate has a malformed extension",
                ));
            }
            _ => {}
        }
    }
    let subject_key_id = subject_key_id
        .filter(|key_id| !key_id.is_empty())
        .ok_or_else(|| {
            AppError::bad_request("authority certificate is missing subject key identifier")
        })?;
    let common_name = certificate_common_name(&cert)?;
    let not_before = DateTime::<Utc>::from_timestamp(cert.validity().not_before.timestamp(), 0)
        .ok_or_else(|| AppError::bad_request("invalid authority notBefore"))?;
    let not_after = DateTime::<Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| AppError::bad_request("invalid authority notAfter"))?;
    let serial_number = normalize_serial(&cert.tbs_certificate.raw_serial_as_string())?;
    let fingerprint_sha256 = hex::encode(digest::digest(&digest::SHA256, &pem.contents));
    Ok(ParsedAuthorityCertificate {
        der: pem.contents.clone(),
        pem: pem_encode_certificate(&pem.contents),
        subject: cert.subject().to_string(),
        common_name,
        serial_number,
        fingerprint_sha256,
        subject_public_key_info: cert.public_key().raw.to_vec(),
        subject_key_id,
        authority_key_id,
        not_before,
        not_after,
        path_len_constraint: basic.value.path_len_constraint,
        digital_signature: usage.value.digital_signature(),
    })
}

fn certificate_common_name(certificate: &X509Certificate<'_>) -> Result<String, AppError> {
    let mut names = certificate.subject().iter_common_name();
    let name = names
        .next()
        .ok_or_else(|| AppError::bad_request("authority subject must contain one common name"))?
        .as_str()
        .map_err(|_| AppError::bad_request("authority common name is not valid UTF-8"))?
        .to_string();
    if names.next().is_some() {
        return Err(AppError::bad_request(
            "authority subject must contain exactly one common name",
        ));
    }
    Ok(name)
}

fn ca_certificate_params(
    kind: AuthorityKind,
    common_name: &str,
) -> Result<CertificateParams, AppError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(rcgen_error)?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let path_len = match kind {
        AuthorityKind::PlatformIntermediate => 1,
        AuthorityKind::PlatformLeafIssuer | AuthorityKind::TenantIntermediate => 0,
        AuthorityKind::Root => {
            return Err(AppError::bad_request(
                "Atom never generates a production root key or root CSR",
            ))
        }
    };
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if kind.can_issue_leaf_credentials() {
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    }
    params.key_identifier_method = KeyIdMethod::Sha256;
    Ok(params)
}

fn authority_common_name(
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
    version: i32,
) -> Result<String, AppError> {
    Ok(match kind {
        AuthorityKind::Root => format!("Atom Root CA v{version}"),
        AuthorityKind::PlatformIntermediate => format!("Atom Platform Intermediate CA v{version}"),
        AuthorityKind::PlatformLeafIssuer => format!("Atom Platform Leaf Issuer v{version}"),
        AuthorityKind::TenantIntermediate => format!(
            "Atom Tenant {} Intermediate CA v{version}",
            tenant_id.ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("tenant authority has no tenant"))
            })?
        ),
    })
}

fn completed_authority(
    certificate: &ParsedAuthorityCertificate,
    chain_pem: &str,
) -> repo::CompletedAuthority {
    repo::CompletedAuthority {
        subject: certificate.subject.clone(),
        serial_number: certificate.serial_number.clone(),
        fingerprint_sha256: certificate.fingerprint_sha256.clone(),
        subject_key_id: hex::encode(&certificate.subject_key_id),
        authority_key_id: certificate.authority_key_id.as_ref().map(hex::encode),
        certificate_pem: certificate.pem.clone(),
        chain_pem: chain_pem.to_string(),
        not_before: certificate.not_before,
        not_after: certificate.not_after,
    }
}

fn authority_key_context(authority: &AuthorityRecord) -> AuthorityKeyContext {
    AuthorityKeyContext {
        authority_id: authority.id,
        tenant_id: authority.tenant_id,
        version: authority.version,
    }
}

fn ensure_parent_available(parent: &AuthorityRecord) -> Result<(), AppError> {
    if parent.status != AuthorityStatus::Active {
        return Err(AppError::bad_request("parent authority is not active"));
    }
    let now = Utc::now();
    if parent.not_before.is_none_or(|not_before| not_before > now) {
        return Err(AppError::bad_request("parent authority is not yet valid"));
    }
    if parent.not_after.is_none_or(|not_after| now >= not_after) {
        return Err(AppError::bad_request("parent authority is expired"));
    }
    Ok(())
}

fn normalize_serial(value: &str) -> Result<String, AppError> {
    let normalized = value
        .chars()
        .filter(|character| *character != ':' && !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if normalized.is_empty() || hex::decode(&normalized).is_err() {
        return Err(AppError::bad_request("invalid authority serial number"));
    }
    let normalized = normalized.trim_start_matches('0');
    Ok(if normalized.is_empty() {
        "0".to_string()
    } else {
        normalized.to_string()
    })
}

fn pem_encode_certificate(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend(chunk.iter().map(|byte| char::from(*byte)));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn to_offset(value: DateTime<Utc>) -> Result<OffsetDateTime, AppError> {
    OffsetDateTime::from_unix_timestamp(value.timestamp())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid authority timestamp")))
}

fn key_provider_error(error: impl std::fmt::Display) -> AppError {
    AppError::Internal(anyhow::anyhow!("CA key provider operation failed: {error}"))
}

fn rcgen_error(error: rcgen::Error) -> AppError {
    AppError::Internal(anyhow::anyhow!(
        "authority certificate operation failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};

    use super::*;

    fn test_ca_params(common_name: &str, path_len: u8) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.key_identifier_method = KeyIdMethod::Sha256;
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(30);
        params
    }

    #[test]
    fn root_import_rejects_private_key_or_extra_pem_material() {
        let key = KeyPair::generate().expect("key");
        let certificate = test_ca_params("Root", 2)
            .self_signed(&key)
            .expect("certificate");
        let with_key = format!("{}{}", certificate.pem(), key.serialize_pem());
        let error = parse_authority_certificate(&with_key).expect_err("extra material");
        assert!(error.to_string().contains("exactly one certificate"));
    }

    #[test]
    fn leaf_issuer_requires_path_length_zero() {
        let key = KeyPair::generate().expect("key");
        let certificate = test_ca_params("Leaf Issuer", 1)
            .self_signed(&key)
            .expect("certificate");
        let parsed = parse_authority_certificate(&certificate.pem()).expect("parse");
        let error =
            validate_ca_shape(AuthorityKind::PlatformLeafIssuer, &parsed).expect_err("path length");
        assert!(error.to_string().contains("pathLenConstraint=0"));
    }

    #[test]
    fn root_requires_the_full_configured_ca_depth() {
        let key = KeyPair::generate().expect("key");
        let certificate = test_ca_params("Shallow Root", 1)
            .self_signed(&key)
            .expect("certificate");
        let parsed = parse_authority_certificate(&certificate.pem()).expect("parse");
        let error = validate_root_certificate(&parsed).expect_err("insufficient path length");
        assert!(error
            .to_string()
            .contains("platform and tenant intermediate levels"));
    }

    #[test]
    fn missing_ca_or_key_usages_fail_closed() {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "Not CA");
        params.is_ca = IsCa::ExplicitNoCa;
        let certificate = params.self_signed(&key).expect("certificate");
        assert!(parse_authority_certificate(&certificate.pem())
            .expect_err("CA=false")
            .to_string()
            .contains("CA=true"));

        let key = KeyPair::generate().expect("key");
        let mut params = test_ca_params("Missing Usage", 0);
        params.key_usages.clear();
        let certificate = params.self_signed(&key).expect("certificate");
        assert!(parse_authority_certificate(&certificate.pem())
            .expect_err("missing usage")
            .to_string()
            .contains("missing key usage"));
    }
}
