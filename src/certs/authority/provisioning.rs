use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePublicKey,
    PublicKey,
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
use x509_parser::{
    extensions::ParsedExtension,
    pem::parse_x509_pem,
    prelude::X509Certificate,
};

use crate::{config::PkiCaKeyConfig, error::AppError};

use super::{
    key_provider::{
        AuthorityKeyAlgorithm, AuthorityKeyContext, AuthorityKeyProvider,
        EncryptedAuthorityKey, EncryptedDatabaseKeyProvider,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBundle {
    pub pem: String,
    pub version: String,
}

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
}

struct ProviderSigningKey<'a> {
    provider: &'a EncryptedDatabaseKeyProvider,
    context: AuthorityKeyContext,
    key: &'a EncryptedAuthorityKey,
    raw_public_key: Vec<u8>,
}

impl ProviderSigningKey<'_> {
    fn new<'a>(
        provider: &'a EncryptedDatabaseKeyProvider,
        context: AuthorityKeyContext,
        key: &'a EncryptedAuthorityKey,
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
    repo::lock_provisioning(tx).await?;
    let parsed = parse_authority_certificate(certificate_pem)?;
    validate_root_certificate(&parsed)?;

    if let Some(existing) =
        repo::authority_by_fingerprint(tx, &parsed.fingerprint_sha256).await?
    {
        if existing.kind == AuthorityKind::Root {
            return Ok(existing);
        }
        return Err(AppError::conflict(
            "certificate fingerprint already belongs to another authority",
        ));
    }

    let version = repo::next_authority_version(tx, AuthorityKind::Root, None).await?;
    let completed = completed_authority(&parsed, &parsed.pem);
    repo::insert_root_authority(tx, Uuid::new_v4(), version, &completed).await
}

pub async fn begin_tenant_authority_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    begin_offline_authority_in_tx(
        tx,
        ca_keys,
        AuthorityKind::TenantIntermediate,
        Some(tenant_id),
    )
    .await
}

pub async fn begin_platform_leaf_issuer_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
) -> Result<AuthorityRecord, AppError> {
    begin_offline_authority_in_tx(tx, ca_keys, AuthorityKind::PlatformLeafIssuer, None).await
}

pub async fn begin_platform_intermediate_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
) -> Result<AuthorityRecord, AppError> {
    begin_offline_authority_in_tx(tx, ca_keys, AuthorityKind::PlatformIntermediate, None).await
}

async fn begin_offline_authority_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    kind: AuthorityKind,
    tenant_id: Option<Uuid>,
) -> Result<AuthorityRecord, AppError> {
    repo::lock_provisioning(tx).await?;
    if let Some(tenant_id) = tenant_id {
        repo::lock_active_tenant(tx, tenant_id).await?;
    }
    if let Some(existing) = repo::pending_authority_for_scope(tx, kind, tenant_id).await? {
        if existing.provisioning_mode == "offline" {
            return Ok(existing);
        }
        return Err(AppError::conflict(
            "authority provisioning already exists for this scope",
        ));
    }

    let parent = repo::active_root(tx).await?;
    ensure_parent_available(&parent)?;
    create_pending_authority(tx, ca_keys, kind, tenant_id, &parent, "offline").await
}

pub async fn provision_tenant_automatically_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> Result<AuthorityImportOutcome, AppError> {
    repo::lock_provisioning(tx).await?;
    repo::lock_active_tenant(tx, tenant_id).await?;

    if let Some(active) = repo::active_authority_for_scope(
        tx,
        AuthorityKind::TenantIntermediate,
        Some(tenant_id),
    )
    .await?
    {
        return Ok(AuthorityImportOutcome {
            authority: active,
            validation_error: None,
            replaced_authorities: Vec::new(),
        });
    }
    if let Some(existing) = repo::pending_authority_for_scope(
        tx,
        AuthorityKind::TenantIntermediate,
        Some(tenant_id),
    )
    .await?
    {
        return Err(AppError::conflict(format!(
            "authority {} is already waiting for an offline signature",
            existing.id
        )));
    }

    let parent = repo::active_platform_intermediate(tx).await?;
    ensure_parent_available(&parent)?;
    let pending = create_pending_authority(
        tx,
        ca_keys,
        AuthorityKind::TenantIntermediate,
        Some(tenant_id),
        &parent,
        "automated",
    )
    .await?;
    let certificate_pem = sign_pending_authority(ca_keys, &pending, &parent)?;
    import_signed_authority_locked(tx, ca_keys, pending, &certificate_pem).await
}

pub async fn import_signed_authority_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    authority_id: Uuid,
    certificate_pem: &str,
) -> Result<AuthorityImportOutcome, AppError> {
    repo::lock_provisioning(tx).await?;
    let authority = repo::authority_by_id_for_update(tx, authority_id).await?;
    import_signed_authority_locked(tx, ca_keys, authority, certificate_pem).await
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

    if let Some(existing) =
        repo::authority_by_fingerprint(tx, &parsed.fingerprint_sha256).await?
    {
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
    let active = repo::activate_authority(
        tx,
        authority.id,
        &completed,
        authority.kind.can_issue_leaf_credentials(),
    )
    .await?;
    Ok(AuthorityImportOutcome {
        authority: active,
        validation_error: None,
        replaced_authorities: replaced,
    })
}

pub async fn begin_retirement_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    ca_keys: &PkiCaKeyConfig,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    repo::lock_provisioning(tx).await?;
    let authority = repo::authority_by_id_for_update(tx, authority_id).await?;
    if authority.kind == AuthorityKind::Root {
        return Err(AppError::bad_request(
            "root authority retirement is an offline trust-anchor operation",
        ));
    }
    if authority.status == AuthorityStatus::Retiring {
        return Ok(authority);
    }
    if authority.status != AuthorityStatus::Active {
        return Err(AppError::conflict("only an active authority can retire"));
    }
    if authority.key_backend.can_sign() {
        let provider = EncryptedDatabaseKeyProvider::new(ca_keys.clone());
        let key = EncryptedAuthorityKey::from_authority(&authority).map_err(key_provider_error)?;
        provider.retire(&key).map_err(key_provider_error)?;
    }
    repo::transition_authority(
        tx,
        authority_id,
        AuthorityStatus::Active,
        AuthorityStatus::Retiring,
    )
    .await
}

pub async fn complete_retirement_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
) -> Result<AuthorityRecord, AppError> {
    repo::lock_provisioning(tx).await?;
    let authority = repo::authority_by_id_for_update(tx, authority_id).await?;
    if authority.status == AuthorityStatus::Retired {
        return Ok(authority);
    }
    repo::transition_authority(
        tx,
        authority_id,
        AuthorityStatus::Retiring,
        AuthorityStatus::Retired,
    )
    .await
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
) -> Result<AuthorityRecord, AppError> {
    let version = repo::next_authority_version(tx, kind, tenant_id).await?;
    let authority_id = Uuid::new_v4();
    let context = AuthorityKeyContext {
        authority_id,
        tenant_id,
        version,
    };
    let provider = EncryptedDatabaseKeyProvider::new(ca_keys.clone());
    let generated = provider
        .generate(context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
        .map_err(key_provider_error)?;
    let signing_key = ProviderSigningKey::new(&provider, context, &generated.key)?;
    let subject = authority_common_name(kind, tenant_id, version)?;
    let params = ca_certificate_params(kind, &subject)?;
    let csr = params
        .serialize_request(&signing_key)
        .map_err(rcgen_error)?;
    let csr_pem = csr.pem().map_err(rcgen_error)?;
    repo::insert_pending_authority(
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
            key: &generated.key,
        },
    )
    .await
}

fn sign_pending_authority(
    ca_keys: &PkiCaKeyConfig,
    authority: &AuthorityRecord,
    parent: &AuthorityRecord,
) -> Result<String, AppError> {
    let provider = EncryptedDatabaseKeyProvider::new(ca_keys.clone());
    let child_key = EncryptedAuthorityKey::from_authority(authority).map_err(key_provider_error)?;
    let child_context = authority_key_context(authority);
    let child_signing_key = ProviderSigningKey::new(&provider, child_context, &child_key)?;

    let parent_key = EncryptedAuthorityKey::from_authority(parent).map_err(key_provider_error)?;
    let parent_context = authority_key_context(parent);
    let parent_signing_key = ProviderSigningKey::new(&provider, parent_context, &parent_key)?;
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

    let provider = EncryptedDatabaseKeyProvider::new(ca_keys.clone());
    let key = EncryptedAuthorityKey::from_authority(authority).map_err(key_provider_error)?;
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
    let (_, child) = x509_parser::parse_x509_certificate(&certificate.der)
        .map_err(|_| AppError::bad_request("invalid signed authority certificate"))?;
    let (_, issuer) = x509_parser::parse_x509_certificate(&parsed_parent.der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid parent certificate")))?;
    child
        .verify_signature(Some(issuer.public_key()))
        .map_err(|_| AppError::bad_request("authority certificate has the wrong parent signature"))?;
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
        return Err(AppError::bad_request("authority certificate is not yet valid"));
    }
    if certificate.not_after <= now {
        return Err(AppError::bad_request("authority certificate is expired"));
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
            if certificate.path_len_constraint.is_some_and(|path_len| path_len < 1) =>
        {
            Err(AppError::bad_request(
                "platform intermediate must permit one subordinate CA level",
            ))
        }
        AuthorityKind::Root
        | AuthorityKind::PlatformIntermediate
        | AuthorityKind::PlatformLeafIssuer
        | AuthorityKind::TenantIntermediate => Ok(()),
    }
}

fn parse_authority_certificate(certificate_pem: &str) -> Result<ParsedAuthorityCertificate, AppError> {
    let (remaining, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| AppError::bad_request("invalid authority certificate PEM"))?;
    if pem.label != "CERTIFICATE"
        || !remaining.iter().all(|byte| byte.is_ascii_whitespace())
    {
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
        .ok_or_else(|| AppError::bad_request("authority certificate is missing basic constraints"))?;
    if !basic.value.ca {
        return Err(AppError::bad_request("authority certificate must have CA=true"));
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
        .ok_or_else(|| AppError::bad_request("authority certificate is missing subject key identifier"))?;
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

fn ca_certificate_params(kind: AuthorityKind, common_name: &str) -> Result<CertificateParams, AppError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(rcgen_error)?;
    params.distinguished_name.push(DnType::CommonName, common_name);
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
        authority_key_id: certificate
            .authority_key_id
            .as_ref()
            .map(hex::encode),
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
    if !parent.not_before.is_some_and(|not_before| not_before <= now) {
        return Err(AppError::bad_request("parent authority is not yet valid"));
    }
    if !parent.not_after.is_some_and(|not_after| now < not_after) {
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
    AppError::Internal(anyhow::anyhow!("authority certificate operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};

    use super::*;

    fn test_ca_params(common_name: &str, path_len: u8) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
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
        let error = validate_ca_shape(AuthorityKind::PlatformLeafIssuer, &parsed)
            .expect_err("path length");
        assert!(error.to_string().contains("pathLenConstraint=0"));
    }

    #[test]
    fn missing_ca_or_key_usages_fail_closed() {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "Not CA");
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
