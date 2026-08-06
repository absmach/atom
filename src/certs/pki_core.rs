//! Atom-owned certificate construction and validation.
//!
//! Callers provide stored profile and subject records plus opaque issuer
//! material.  No rcgen or x509-parser type crosses this module's public API.

use std::{collections::HashSet, fmt, net::IpAddr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::DecodePublicKey, PublicKey};
use rcgen::{
    CertificateParams, CertificateRevocationListParams, CertificateSigningRequestParams,
    CrlDistributionPoint, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, RsaKeySize, SanType, SerialNumber, SignatureAlgorithm,
    SigningKey, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
};
use ring::{digest, rand, rand::SecureRandom};
use time::{Duration, OffsetDateTime};
use url::Url;
use x509_parser::{
    certification_request::X509CertificationRequest,
    pem::parse_x509_pem,
    prelude::{FromDer, ParsedExtension, X509Certificate},
};
use yasna::{models::ObjectIdentifier, Tag};
use zeroize::Zeroizing;

use crate::{config::PkiCaKeyConfig, error::AppError};

use super::authority::{
    key_provider::{
        AuthorityKeyContext, AuthorityKeyProvider, AuthorityKeyProviderError,
        EncryptedAuthorityKey, EncryptedDatabaseKeyProvider,
    },
    AuthorityKeyBackend, AuthorityRecord,
};
use super::profile::{
    CertificateProfile, ExtendedKeyUsage, KeyAlgorithm, KeyUsage, SanRule, SanRuleMode,
    StoredSubject,
};

const LEAF_CLOCK_SKEW_SECONDS: i64 = 300;
const AIA_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
const OCSP_ACCESS_METHOD_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
const CA_ISSUERS_ACCESS_METHOD_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];

enum PkiSigningKey {
    Local(KeyPair),
    EncryptedDatabase {
        provider: EncryptedDatabaseKeyProvider,
        context: AuthorityKeyContext,
        key: EncryptedAuthorityKey,
        raw_public_key: Vec<u8>,
    },
}

impl PublicKeyData for PkiSigningKey {
    fn der_bytes(&self) -> &[u8] {
        match self {
            Self::Local(key) => key.der_bytes(),
            Self::EncryptedDatabase { raw_public_key, .. } => raw_public_key,
        }
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        match self {
            Self::Local(key) => key.algorithm(),
            Self::EncryptedDatabase { .. } => &PKCS_ECDSA_P256_SHA256,
        }
    }
}

impl SigningKey for PkiSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            Self::Local(key) => key.sign(message),
            Self::EncryptedDatabase {
                provider,
                context,
                key,
                ..
            } => provider
                .sign(*context, key, message)
                .map(|signature| signature.bytes)
                .map_err(|_| rcgen::Error::RemoteKeyError),
        }
    }
}

pub struct PkiIssuer {
    certificate_pem: String,
    chain_pem: String,
    signing_key: PkiSigningKey,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    ocsp_url: String,
    ca_issuers_url: String,
    crl_distribution_point_url: String,
}

/// Restricted signing surface for retained publication artifacts. Unlike a
/// leaf issuer, this type carries no discovery URLs and cannot be passed to
/// certificate issuance helpers.
pub struct PkiArtifactSigner {
    certificate_pem: String,
    signing_key: PkiSigningKey,
}

struct ManagedAuthorityMaterial {
    certificate_pem: String,
    chain_pem: String,
    signing_key: PkiSigningKey,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl fmt::Debug for PkiIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkiIssuer")
            .field("certificate_present", &true)
            .field("chain_present", &true)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("ocsp_url", &self.ocsp_url)
            .field("ca_issuers_url", &self.ca_issuers_url)
            .field(
                "crl_distribution_point_url",
                &self.crl_distribution_point_url,
            )
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl PkiIssuer {
    /// Build an opaque issuer and validate its key, CA constraints, chain, and
    /// artifact-discovery routes before it can be used for signing.
    pub fn from_pem(
        certificate_pem: &str,
        private_key_pem: &str,
        chain_pem: &str,
        ocsp_url: &str,
        ca_issuers_url: &str,
        crl_distribution_point_url: &str,
    ) -> Result<Self, AppError> {
        validate_route(ocsp_url, "OCSP")?;
        validate_route(ca_issuers_url, "CA issuers")?;
        validate_route(crl_distribution_point_url, "CRL distribution point")?;

        let certificate_der = one_certificate_der(certificate_pem, "issuer certificate")?;
        let (_, certificate) = x509_parser::parse_x509_certificate(&certificate_der)
            .map_err(|_| AppError::bad_request("invalid issuer certificate"))?;
        validate_issuer_certificate(&certificate)?;
        validate_chain(&certificate_der, chain_pem)?;

        let key_pair = KeyPair::from_pem(private_key_pem)
            .map_err(|_| AppError::bad_request("invalid issuer private key"))?;
        let public_key_der = parse_x509_pem(key_pair.public_key_pem().as_bytes())
            .map(|(_, pem)| pem.contents)
            .map_err(|_| AppError::bad_request("invalid issuer key public component"))?;
        if public_key_der != certificate.public_key().raw {
            return Err(AppError::bad_request(
                "issuer private key does not match issuer certificate",
            ));
        }

        let not_before = certificate.validity().not_before.to_datetime();
        let not_after = certificate.validity().not_after.to_datetime();
        Ok(Self {
            certificate_pem: pem_encode_certificate(&certificate_der),
            chain_pem: chain_pem.to_string(),
            signing_key: PkiSigningKey::Local(key_pair),
            not_before,
            not_after,
            ocsp_url: ocsp_url.to_string(),
            ca_issuers_url: ca_issuers_url.to_string(),
            crl_distribution_point_url: crl_distribution_point_url.to_string(),
        })
    }

    /// Load an active managed issuer without materializing a plaintext CA key.
    /// The provider decrypts only inside each signing operation and immediately
    /// drops its ephemeral signing-key value afterwards.
    pub fn from_managed_authority(
        authority: &AuthorityRecord,
        ca_keys: &PkiCaKeyConfig,
    ) -> Result<Self, AppError> {
        if !authority.can_issue_leaves_at(Utc::now()) {
            return Err(AppError::bad_request(
                "issuing authority is not active and valid for leaf issuance",
            ));
        }
        let ocsp_url = required_authority_field(authority.ocsp_url.as_deref(), "OCSP URL")?;
        let ca_issuers_url =
            required_authority_field(authority.ca_issuers_url.as_deref(), "CA issuers URL")?;
        let crl_distribution_point_url = required_authority_field(
            authority.crl_distribution_point_url.as_deref(),
            "CRL distribution point URL",
        )?;
        validate_route(ocsp_url, "OCSP")?;
        validate_route(ca_issuers_url, "CA issuers")?;
        validate_route(crl_distribution_point_url, "CRL distribution point")?;
        let material = managed_authority_material(authority, ca_keys)?;

        Ok(Self {
            certificate_pem: material.certificate_pem,
            chain_pem: material.chain_pem,
            signing_key: material.signing_key,
            not_before: material.not_before,
            not_after: material.not_after,
            ocsp_url: ocsp_url.to_string(),
            ca_issuers_url: ca_issuers_url.to_string(),
            crl_distribution_point_url: crl_distribution_point_url.to_string(),
        })
    }
}

impl PkiArtifactSigner {
    /// Load a retained managed leaf issuer for CRL/OCSP signing. Discovery
    /// routes are deliberately not required: old issuers must keep publishing
    /// even if they predate the route metadata migration.
    pub fn from_managed_authority(
        authority: &AuthorityRecord,
        ca_keys: &PkiCaKeyConfig,
    ) -> Result<Self, AppError> {
        let now = Utc::now();
        if !authority.kind.can_issue_leaf_credentials()
            || !matches!(
                authority.status,
                super::authority::AuthorityStatus::Active
                    | super::authority::AuthorityStatus::Retiring
                    | super::authority::AuthorityStatus::Retired
            )
            || !authority
                .not_before
                .is_some_and(|not_before| not_before <= now)
            || !authority.not_after.is_some_and(|not_after| now < not_after)
        {
            return Err(AppError::bad_request(
                "authority is not eligible for artifact signing",
            ));
        }
        let material = managed_authority_material(authority, ca_keys)?;
        Ok(Self {
            certificate_pem: material.certificate_pem,
            signing_key: material.signing_key,
        })
    }

    pub fn sign_crl(&self, params: CertificateRevocationListParams) -> Result<Vec<u8>, AppError> {
        let signer = Issuer::from_ca_cert_pem(&self.certificate_pem, &self.signing_key)
            .map_err(core_encoding_error)?;
        let crl = params.signed_by(&signer).map_err(core_encoding_error)?;
        Ok(crl.der().to_vec())
    }
}

fn managed_authority_material(
    authority: &AuthorityRecord,
    ca_keys: &PkiCaKeyConfig,
) -> Result<ManagedAuthorityMaterial, AppError> {
    if authority.key_backend != AuthorityKeyBackend::EncryptedDatabase {
        return Err(AppError::Internal(anyhow::anyhow!(
            "managed authority key backend is not available"
        )));
    }
    let certificate_pem =
        required_authority_field(authority.certificate_pem.as_deref(), "certificate")?;
    let chain_pem = required_authority_field(authority.chain_pem.as_deref(), "chain")?;
    let certificate_der = one_certificate_der(certificate_pem, "issuer certificate")?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&certificate_der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("stored invalid issuer certificate")))?;
    validate_issuer_certificate(&certificate)?;
    validate_chain(&certificate_der, chain_pem)?;

    let fingerprint = hex::encode(digest::digest(&digest::SHA256, &certificate_der));
    if authority.fingerprint_sha256.as_deref() != Some(&fingerprint)
        || authority.not_before.map(|value| value.timestamp())
            != Some(certificate.validity().not_before.timestamp())
        || authority.not_after.map(|value| value.timestamp())
            != Some(certificate.validity().not_after.timestamp())
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored issuer metadata does not match its certificate"
        )));
    }

    let context = AuthorityKeyContext {
        authority_id: authority.id,
        tenant_id: authority.tenant_id,
        version: authority.version,
    };
    let provider = EncryptedDatabaseKeyProvider::new(ca_keys.clone());
    let key =
        EncryptedAuthorityKey::from_authority(authority).map_err(managed_key_provider_error)?;
    let public = provider
        .public_key(context, &key)
        .map_err(managed_key_provider_error)?;
    if public.subject_public_key_info_der != certificate.public_key().raw {
        return Err(AppError::Internal(anyhow::anyhow!(
            "managed authority key does not match its certificate"
        )));
    }
    let public_key = PublicKey::from_public_key_der(&public.subject_public_key_info_der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid managed authority key")))?;
    let raw_public_key = public_key.to_encoded_point(false).as_bytes().to_vec();
    let not_before = certificate.validity().not_before.to_datetime();
    let not_after = certificate.validity().not_after.to_datetime();

    Ok(ManagedAuthorityMaterial {
        certificate_pem: pem_encode_certificate(&certificate_der),
        chain_pem: chain_pem.to_string(),
        signing_key: PkiSigningKey::EncryptedDatabase {
            provider,
            context,
            key,
            raw_public_key,
        },
        not_before,
        not_after,
    })
}

#[derive(Debug, Clone)]
pub struct IssueFromCsr<'a> {
    pub csr_pem: &'a str,
    pub requested_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    pub chain_pem: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub identity_uri: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub profile_id: uuid::Uuid,
    pub profile_name: String,
    pub renewal_threshold_seconds: u64,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
}

/// A freshly generated CSR and its one-time private key. The private material
/// is deliberately non-cloneable, redacted from Debug, and zeroized on drop.
pub struct GeneratedLeafRequest {
    csr_pem: String,
    private_key_pem: Zeroizing<String>,
}

impl fmt::Debug for GeneratedLeafRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedLeafRequest")
            .field("csr_present", &true)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl GeneratedLeafRequest {
    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }

    pub fn into_private_key_pem(self) -> Zeroizing<String> {
        self.private_key_pem
    }
}

/// Generate a leaf key using the first Atom-supported algorithm/size in the
/// stored profile. Profile order is the preference order; callers cannot
/// select or override it.
pub fn generate_leaf_request(
    profile: &CertificateProfile,
) -> Result<GeneratedLeafRequest, AppError> {
    let key_pair = generate_profile_key_pair(profile)?;
    let csr_pem = CertificateParams::default()
        .serialize_request(&key_pair)
        .and_then(|request| request.pem())
        .map_err(core_encoding_error)?;
    let private_key_pem = Zeroizing::new(key_pair.serialize_pem());
    Ok(GeneratedLeafRequest {
        csr_pem,
        private_key_pem,
    })
}

fn generate_profile_key_pair(profile: &CertificateProfile) -> Result<KeyPair, AppError> {
    for rule in &profile.permitted_key_algorithms {
        for size in &rule.sizes {
            let generated = match (rule.algorithm, *size) {
                (KeyAlgorithm::Ecdsa, 256) => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
                (KeyAlgorithm::Ecdsa, 384) => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384),
                (KeyAlgorithm::Ed25519, 255) => KeyPair::generate_for(&PKCS_ED25519),
                (KeyAlgorithm::Rsa, 2048) => {
                    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
                }
                (KeyAlgorithm::Rsa, 3072) => {
                    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072)
                }
                (KeyAlgorithm::Rsa, 4096) => {
                    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_4096)
                }
                _ => continue,
            };
            return generated.map_err(|_| {
                AppError::Internal(anyhow::anyhow!(
                    "stored client profile key algorithm is unavailable for generation"
                ))
            });
        }
    }
    Err(AppError::Internal(anyhow::anyhow!(
        "stored client profile has no supported generated-key algorithm"
    )))
}

struct ParsedCsr {
    params: CertificateSigningRequestParams,
    algorithm: KeyAlgorithm,
    key_size: u16,
}

struct ApprovedSans {
    rcgen: Vec<SanType>,
    dns_names: Vec<String>,
    ip_addresses: Vec<IpAddr>,
    identity_uri: String,
}

pub fn issue_from_csr_at(
    profile: &CertificateProfile,
    subject: &StoredSubject,
    issuer: &PkiIssuer,
    input: IssueFromCsr<'_>,
    now: DateTime<Utc>,
) -> Result<IssuedCertificate, AppError> {
    let parsed = parse_and_verify_csr(input.csr_pem)?;
    validate_key_policy(profile, parsed.algorithm, parsed.key_size)?;
    validate_requested_extensions(profile, &parsed.params.params)?;

    let identity_uri = canonical_identity_uri(profile, subject)?;
    let approved_sans = approve_sans(
        profile,
        subject,
        &identity_uri,
        &parsed.params.params.subject_alt_names,
    )?;
    let ttl = input
        .requested_ttl_seconds
        .unwrap_or(profile.default_ttl_seconds);
    if ttl == 0 || ttl > profile.maximum_ttl_seconds {
        return Err(AppError::bad_request(
            "requested certificate TTL exceeds the stored profile ceiling",
        ));
    }

    // X.509 validity is encoded at whole-second precision. Canonicalizing here
    // makes the value validated after encoding exactly the value returned.
    let now = OffsetDateTime::from_unix_timestamp(now.timestamp())
        .map_err(|_| AppError::bad_request("invalid certificate timestamp"))?;
    if now < issuer.not_before || now >= issuer.not_after {
        return Err(AppError::bad_request(
            "issuing authority is not currently valid",
        ));
    }
    let not_before = (now - Duration::seconds(LEAF_CLOCK_SKEW_SECONDS)).max(issuer.not_before);
    let not_after = now
        .checked_add(Duration::seconds(i64::try_from(ttl).map_err(|_| {
            AppError::bad_request("requested certificate TTL is too large")
        })?))
        .ok_or_else(|| AppError::bad_request("requested certificate validity is invalid"))?;
    if not_after > issuer.not_after {
        return Err(AppError::bad_request(
            "requested certificate validity exceeds issuing authority validity",
        ));
    }

    let serial = random_serial()?;
    let serial_number = hex::encode(serial.to_bytes());
    let mut params = CertificateParams::default();
    params.serial_number = Some(serial);
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, subject.entity_id().to_string());
    params.subject_alt_names = approved_sans.rcgen;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = profile
        .key_usages
        .iter()
        .copied()
        .map(rcgen_key_usage)
        .collect();
    params.extended_key_usages = profile
        .extended_key_usages
        .iter()
        .copied()
        .map(rcgen_extended_key_usage)
        .collect();
    params.use_authority_key_identifier_extension = true;
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![issuer.crl_distribution_point_url.clone()],
    }];
    params.custom_extensions = vec![aia_extension(&issuer.ocsp_url, &issuer.ca_issuers_url)];

    // Requested subject, validity, basic constraints, KU, EKU, and extensions
    // are intentionally discarded.  Only the verified public key is retained.
    let signing_request = CertificateSigningRequestParams {
        params,
        public_key: parsed.params.public_key,
    };
    let signer = Issuer::from_ca_cert_pem(&issuer.certificate_pem, &issuer.signing_key)
        .map_err(core_encoding_error)?;
    let certificate = signing_request
        .signed_by(&signer)
        .map_err(core_encoding_error)?;
    let certificate_der = certificate.der().to_vec();
    validate_issued_certificate(
        &certificate_der,
        &issuer.certificate_pem,
        subject,
        profile,
        &approved_sans.identity_uri,
        not_before,
        not_after,
    )?;
    let fingerprint_sha256 =
        hex::encode(digest::digest(&digest::SHA256, &certificate_der).as_ref());

    Ok(IssuedCertificate {
        certificate_pem: certificate.pem(),
        certificate_der,
        chain_pem: issuer.chain_pem.clone(),
        serial_number,
        fingerprint_sha256,
        identity_uri: approved_sans.identity_uri,
        not_before: to_chrono(not_before)?,
        not_after: to_chrono(not_after)?,
        profile_id: profile.id,
        profile_name: profile.name.clone(),
        renewal_threshold_seconds: profile.renewal_threshold_seconds,
        dns_names: approved_sans.dns_names,
        ip_addresses: approved_sans.ip_addresses,
    })
}

pub fn issue_from_csr(
    profile: &CertificateProfile,
    subject: &StoredSubject,
    issuer: &PkiIssuer,
    input: IssueFromCsr<'_>,
) -> Result<IssuedCertificate, AppError> {
    issue_from_csr_at(profile, subject, issuer, input, Utc::now())
}

fn parse_and_verify_csr(csr_pem: &str) -> Result<ParsedCsr, AppError> {
    let (remaining, pem) = parse_x509_pem(csr_pem.as_bytes())
        .map_err(|_| AppError::bad_request("malformed certificate signing request"))?;
    if !remaining.iter().all(u8::is_ascii_whitespace)
        || !matches!(
            pem.label.as_str(),
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST"
        )
    {
        return Err(AppError::bad_request(
            "certificate signing request must contain exactly one CSR",
        ));
    }
    let (_, independently_parsed) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|_| AppError::bad_request("malformed certificate signing request"))?;
    independently_parsed
        .verify_signature()
        .map_err(|_| AppError::bad_request("invalid certificate signing request signature"))?;

    let subject_pki = &independently_parsed.certification_request_info.subject_pki;
    let algorithm_oid = subject_pki.algorithm.algorithm.to_id_string();
    let (algorithm, key_size) = match algorithm_oid.as_str() {
        "1.2.840.10045.2.1" => (
            KeyAlgorithm::Ecdsa,
            u16::try_from(
                subject_pki
                    .parsed()
                    .map_err(|_| AppError::bad_request("invalid CSR public key"))?
                    .key_size(),
            )
            .map_err(|_| AppError::bad_request("invalid CSR key size"))?,
        ),
        "1.2.840.113549.1.1.1" => (
            KeyAlgorithm::Rsa,
            u16::try_from(
                subject_pki
                    .parsed()
                    .map_err(|_| AppError::bad_request("invalid CSR public key"))?
                    .key_size(),
            )
            .map_err(|_| AppError::bad_request("invalid CSR key size"))?,
        ),
        "1.3.101.112" => (KeyAlgorithm::Ed25519, 255),
        _ => return Err(AppError::bad_request("unsupported CSR key algorithm")),
    };
    if key_size == 0 {
        return Err(AppError::bad_request("invalid CSR key size"));
    }

    let params = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|_| AppError::bad_request("invalid certificate signing request"))?;
    Ok(ParsedCsr {
        params,
        algorithm,
        key_size,
    })
}

fn validate_key_policy(
    profile: &CertificateProfile,
    algorithm: KeyAlgorithm,
    key_size: u16,
) -> Result<(), AppError> {
    if profile
        .permitted_key_algorithms
        .iter()
        .any(|rule| rule.algorithm == algorithm && rule.sizes.contains(&key_size))
    {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "CSR key algorithm or size is not permitted by the stored profile",
        ))
    }
}

fn validate_requested_extensions(
    profile: &CertificateProfile,
    requested: &CertificateParams,
) -> Result<(), AppError> {
    if matches!(requested.is_ca, IsCa::Ca(_)) {
        return Err(AppError::bad_request("CSR cannot request CA capability"));
    }
    for usage in &requested.key_usages {
        let requested_usage = match usage {
            KeyUsagePurpose::DigitalSignature => KeyUsage::DigitalSignature,
            KeyUsagePurpose::ContentCommitment => KeyUsage::ContentCommitment,
            KeyUsagePurpose::KeyEncipherment => KeyUsage::KeyEncipherment,
            KeyUsagePurpose::DataEncipherment => KeyUsage::DataEncipherment,
            KeyUsagePurpose::KeyAgreement => KeyUsage::KeyAgreement,
            KeyUsagePurpose::KeyCertSign | KeyUsagePurpose::CrlSign => {
                return Err(AppError::bad_request(
                    "CSR cannot request certificate or CRL signing capability",
                ))
            }
            _ => {
                return Err(AppError::bad_request(
                    "CSR requested an unsupported key usage",
                ))
            }
        };
        if !profile.key_usages.contains(&requested_usage) {
            return Err(AppError::bad_request(
                "CSR key usage is not permitted by the stored profile",
            ));
        }
    }
    for usage in &requested.extended_key_usages {
        let requested_usage = match usage {
            ExtendedKeyUsagePurpose::ServerAuth => ExtendedKeyUsage::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth => ExtendedKeyUsage::ClientAuth,
            ExtendedKeyUsagePurpose::CodeSigning => ExtendedKeyUsage::CodeSigning,
            ExtendedKeyUsagePurpose::EmailProtection => ExtendedKeyUsage::EmailProtection,
            ExtendedKeyUsagePurpose::TimeStamping => ExtendedKeyUsage::TimeStamping,
            ExtendedKeyUsagePurpose::OcspSigning => ExtendedKeyUsage::OcspSigning,
            ExtendedKeyUsagePurpose::Any | ExtendedKeyUsagePurpose::Other(_) => {
                return Err(AppError::bad_request(
                    "CSR requested an arbitrary extended key usage",
                ))
            }
        };
        if !profile.extended_key_usages.contains(&requested_usage) {
            return Err(AppError::bad_request(
                "CSR extended key usage is not permitted by the stored profile",
            ));
        }
    }
    Ok(())
}

fn approve_sans(
    profile: &CertificateProfile,
    subject: &StoredSubject,
    identity_uri: &str,
    requested: &[SanType],
) -> Result<ApprovedSans, AppError> {
    let mut sans = Vec::new();
    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();
    let mut seen = HashSet::new();

    for san in requested {
        match san {
            SanType::DnsName(name) => {
                let value = name.to_string().to_ascii_lowercase();
                enforce_san_rule(&profile.san_policy.dns, &value, subject, "DNS")?;
                if seen.insert(format!("dns:{value}")) {
                    sans.push(SanType::DnsName(
                        value
                            .clone()
                            .try_into()
                            .map_err(|_| AppError::bad_request("invalid DNS SAN"))?,
                    ));
                    dns_names.push(value);
                }
            }
            SanType::IpAddress(address) => {
                let value = address.to_string();
                enforce_san_rule(&profile.san_policy.ip, &value, subject, "IP")?;
                if seen.insert(format!("ip:{value}")) {
                    sans.push(SanType::IpAddress(*address));
                    ip_addresses.push(*address);
                }
            }
            SanType::Rfc822Name(address) => {
                let value = address.to_string().to_ascii_lowercase();
                enforce_san_rule(&profile.san_policy.email, &value, subject, "email")?;
                if seen.insert(format!("email:{value}")) {
                    sans.push(SanType::Rfc822Name(
                        value
                            .try_into()
                            .map_err(|_| AppError::bad_request("invalid email SAN"))?,
                    ));
                }
            }
            SanType::URI(uri) => {
                if uri.as_str() != identity_uri {
                    return Err(AppError::bad_request(
                        "CSR cannot substitute the canonical identity URI",
                    ));
                }
            }
            SanType::OtherName(_) => {
                return Err(AppError::bad_request(
                    "CSR requested an unsupported subject alternative name",
                ))
            }
            _ => {
                return Err(AppError::bad_request(
                    "CSR requested an unsupported subject alternative name",
                ))
            }
        }
    }

    sans.push(SanType::URI(identity_uri.to_string().try_into().map_err(
        |_| AppError::Internal(anyhow::anyhow!("generated identity URI is invalid")),
    )?));
    Ok(ApprovedSans {
        rcgen: sans,
        dns_names,
        ip_addresses,
        identity_uri: identity_uri.to_string(),
    })
}

fn enforce_san_rule(
    rule: &SanRule,
    requested: &str,
    subject: &StoredSubject,
    label: &str,
) -> Result<(), AppError> {
    let allowed = match rule.mode {
        SanRuleMode::Deny | SanRuleMode::Identity => false,
        SanRuleMode::Allowlist => rule
            .values
            .iter()
            .any(|value| value.eq_ignore_ascii_case(requested)),
        SanRuleMode::EntityTemplate => rule.values.iter().any(|template| {
            render_template(template, subject)
                .is_ok_and(|value| value.eq_ignore_ascii_case(requested))
        }),
    };
    if allowed {
        Ok(())
    } else {
        Err(AppError::bad_request(format!(
            "{label} SAN is outside the stored profile policy"
        )))
    }
}

fn canonical_identity_uri(
    profile: &CertificateProfile,
    subject: &StoredSubject,
) -> Result<String, AppError> {
    render_template(&profile.identity_uri_template, subject)
}

fn render_template(template: &str, subject: &StoredSubject) -> Result<String, AppError> {
    let scope = subject
        .tenant_id()
        .map(|tenant_id| format!("tenant:{tenant_id}:"))
        .unwrap_or_default();
    let mut value = template
        .replace("{scope}", &scope)
        .replace("{entity_id}", &subject.entity_id().to_string());
    if value.contains("{tenant_id}") {
        let tenant_id = subject
            .tenant_id()
            .ok_or_else(|| AppError::bad_request("SAN template requires a tenant-owned subject"))?;
        value = value.replace("{tenant_id}", &tenant_id.to_string());
    }
    if value.contains('{') || value.contains('}') {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored certificate profile contains an unknown template variable"
        )));
    }
    Ok(value)
}

fn aia_extension(ocsp_url: &str, ca_issuers_url: &str) -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            for (method, location) in [
                (OCSP_ACCESS_METHOD_OID, ocsp_url),
                (CA_ISSUERS_ACCESS_METHOD_OID, ca_issuers_url),
            ] {
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(method));
                    writer
                        .next()
                        .write_tagged_implicit(Tag::context(6), |writer| {
                            writer.write_ia5_string(location);
                        });
                });
            }
        });
    });
    CustomExtension::from_oid_content(AIA_OID, content)
}

fn validate_issued_certificate(
    certificate_der: &[u8],
    issuer_pem: &str,
    subject: &StoredSubject,
    profile: &CertificateProfile,
    identity_uri: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<(), AppError> {
    let issuer_der = one_certificate_der(issuer_pem, "issuer certificate")?;
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("issued invalid certificate")))?;
    let (_, issuer) = x509_parser::parse_x509_certificate(&issuer_der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("stored invalid issuer certificate")))?;
    if certificate.issuer() != issuer.subject() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "issued certificate has the wrong issuer"
        )));
    }
    certificate
        .verify_signature(Some(issuer.public_key()))
        .map_err(|_| AppError::Internal(anyhow::anyhow!("issued certificate signature failed")))?;
    if certificate.tbs_certificate.is_ca() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "PKI core emitted a CA certificate for a leaf profile"
        )));
    }
    let expected_common_name = subject.entity_id().to_string();
    let common_names = certificate
        .subject()
        .iter_common_name()
        .filter_map(|name| name.as_str().ok())
        .collect::<Vec<_>>();
    if common_names != [expected_common_name.as_str()] {
        return Err(AppError::Internal(anyhow::anyhow!(
            "issued certificate subject is not canonical"
        )));
    }
    let actual_not_before = certificate.validity().not_before.to_datetime();
    let actual_not_after = certificate.validity().not_after.to_datetime();
    if actual_not_before != not_before || actual_not_after != not_after {
        return Err(AppError::Internal(anyhow::anyhow!(
            "issued certificate validity does not match the bounded request"
        )));
    }

    let mut found_identity = false;
    let mut aia = false;
    let mut cdp = false;
    for extension in certificate.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => {
                found_identity = names.general_names.iter().any(|name| {
                    matches!(name, x509_parser::extensions::GeneralName::URI(uri) if *uri == identity_uri)
                });
            }
            ParsedExtension::AuthorityInfoAccess(_) => aia = true,
            ParsedExtension::CRLDistributionPoints(_) => cdp = true,
            ParsedExtension::BasicConstraints(constraints) if constraints.ca => {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "issued certificate contains CA basic constraints"
                )))
            }
            ParsedExtension::KeyUsage(usage) if usage.key_cert_sign() || usage.crl_sign() => {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "issued certificate contains CA key usages"
                )))
            }
            _ => {}
        }
    }
    if !found_identity || !aia || !cdp {
        return Err(AppError::Internal(anyhow::anyhow!(
            "issued certificate is missing mandatory PKI extensions"
        )));
    }
    if profile.basic_constraints.ca || profile.basic_constraints.path_len.is_some() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored leaf profile has invalid basic constraints"
        )));
    }
    Ok(())
}

fn validate_issuer_certificate(certificate: &X509Certificate<'_>) -> Result<(), AppError> {
    if !certificate.tbs_certificate.is_ca() {
        return Err(AppError::bad_request("issuing certificate is not a CA"));
    }
    let usage = certificate
        .tbs_certificate
        .key_usage()
        .map_err(|_| AppError::bad_request("invalid issuer key usage"))?
        .ok_or_else(|| AppError::bad_request("issuer is missing key usage"))?;
    if !usage.value.key_cert_sign() {
        return Err(AppError::bad_request(
            "issuer key usage does not permit certificate signing",
        ));
    }
    Ok(())
}

fn validate_chain(issuer_der: &[u8], chain_pem: &str) -> Result<(), AppError> {
    let chain = certificate_chain_der(chain_pem)?;
    if chain.is_empty() || chain[0] != issuer_der {
        return Err(AppError::bad_request(
            "issuer chain must begin with the issuing certificate",
        ));
    }
    for pair in chain.windows(2) {
        let (_, child) = x509_parser::parse_x509_certificate(&pair[0])
            .map_err(|_| AppError::bad_request("invalid issuer chain certificate"))?;
        let (_, parent) = x509_parser::parse_x509_certificate(&pair[1])
            .map_err(|_| AppError::bad_request("invalid issuer chain certificate"))?;
        validate_issuer_certificate(&child)?;
        validate_issuer_certificate(&parent)?;
        if child.issuer() != parent.subject() {
            return Err(AppError::bad_request("issuer chain names do not link"));
        }
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|_| AppError::bad_request("issuer chain signature verification failed"))?;
        if child.validity().not_before < parent.validity().not_before
            || child.validity().not_after > parent.validity().not_after
        {
            return Err(AppError::bad_request(
                "issuer chain validity exceeds its parent",
            ));
        }
    }
    let (_, root) = x509_parser::parse_x509_certificate(
        chain
            .last()
            .ok_or_else(|| AppError::bad_request("issuer chain is empty"))?,
    )
    .map_err(|_| AppError::bad_request("invalid issuer root certificate"))?;
    if root.issuer() != root.subject() {
        return Err(AppError::bad_request(
            "issuer chain is not anchored by a root",
        ));
    }
    validate_issuer_certificate(&root)?;
    root.verify_signature(None)
        .map_err(|_| AppError::bad_request("issuer chain root is not self-signed"))?;
    Ok(())
}

fn certificate_chain_der(chain_pem: &str) -> Result<Vec<Vec<u8>>, AppError> {
    let mut remaining = chain_pem.as_bytes();
    let mut certificates = Vec::new();
    while !remaining.iter().all(u8::is_ascii_whitespace) {
        let (rest, pem) = parse_x509_pem(remaining)
            .map_err(|_| AppError::bad_request("invalid issuer chain PEM"))?;
        if pem.label != "CERTIFICATE" {
            return Err(AppError::bad_request(
                "issuer chain contains non-certificate material",
            ));
        }
        certificates.push(pem.contents);
        remaining = rest;
    }
    Ok(certificates)
}

fn one_certificate_der(pem: &str, label: &str) -> Result<Vec<u8>, AppError> {
    let (remaining, pem) = parse_x509_pem(pem.as_bytes())
        .map_err(|_| AppError::bad_request(format!("invalid {label} PEM")))?;
    if pem.label != "CERTIFICATE" || !remaining.iter().all(u8::is_ascii_whitespace) {
        return Err(AppError::bad_request(format!(
            "{label} must contain exactly one certificate"
        )));
    }
    Ok(pem.contents)
}

fn validate_route(value: &str, label: &str) -> Result<(), AppError> {
    let url =
        Url::parse(value).map_err(|_| AppError::bad_request(format!("invalid {label} URL")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(AppError::bad_request(format!("invalid {label} URL")));
    }
    Ok(())
}

fn required_authority_field<'a>(value: Option<&'a str>, label: &str) -> Result<&'a str, AppError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("managed authority {label} is missing")))
}

fn managed_key_provider_error(error: AuthorityKeyProviderError) -> AppError {
    AppError::Internal(anyhow::anyhow!(
        "managed authority key provider failed: {error}"
    ))
}

fn rcgen_key_usage(usage: KeyUsage) -> KeyUsagePurpose {
    match usage {
        KeyUsage::DigitalSignature => KeyUsagePurpose::DigitalSignature,
        KeyUsage::ContentCommitment => KeyUsagePurpose::ContentCommitment,
        KeyUsage::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
        KeyUsage::DataEncipherment => KeyUsagePurpose::DataEncipherment,
        KeyUsage::KeyAgreement => KeyUsagePurpose::KeyAgreement,
    }
}

fn rcgen_extended_key_usage(usage: ExtendedKeyUsage) -> ExtendedKeyUsagePurpose {
    match usage {
        ExtendedKeyUsage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsage::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsage::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsage::EmailProtection => ExtendedKeyUsagePurpose::EmailProtection,
        ExtendedKeyUsage::TimeStamping => ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsage::OcspSigning => ExtendedKeyUsagePurpose::OcspSigning,
    }
}

fn random_serial() -> Result<SerialNumber, AppError> {
    let mut bytes = [0_u8; 16];
    rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("failed to generate serial number")))?;
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    Ok(SerialNumber::from(bytes.to_vec()))
}

fn to_chrono(value: OffsetDateTime) -> Result<DateTime<Utc>, AppError> {
    DateTime::<Utc>::from_timestamp(value.unix_timestamp(), value.nanosecond())
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("invalid certificate timestamp")))
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

fn core_encoding_error(error: rcgen::Error) -> AppError {
    AppError::Internal(anyhow::anyhow!(
        "PKI core certificate encoding failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::profile::{KeyAlgorithmRule, LeafBasicConstraints, SanPolicy};

    fn profile(ekus: Vec<ExtendedKeyUsage>) -> CertificateProfile {
        CertificateProfile {
            id: uuid::Uuid::new_v4(),
            tenant_id: None,
            base_profile_id: None,
            name: "test".into(),
            permitted_key_algorithms: vec![KeyAlgorithmRule {
                algorithm: KeyAlgorithm::Ecdsa,
                sizes: vec![256],
            }],
            default_ttl_seconds: 3600,
            maximum_ttl_seconds: 7200,
            renewal_threshold_seconds: 600,
            key_usages: vec![KeyUsage::DigitalSignature],
            extended_key_usages: ekus,
            san_policy: SanPolicy {
                dns: SanRule {
                    mode: SanRuleMode::Deny,
                    values: vec![],
                },
                ip: SanRule {
                    mode: SanRuleMode::Deny,
                    values: vec![],
                },
                email: SanRule {
                    mode: SanRuleMode::Deny,
                    values: vec![],
                },
                uri: SanRule {
                    mode: SanRuleMode::Identity,
                    values: vec![],
                },
            },
            identity_uri_template: "urn:atom:{scope}entity:{entity_id}".into(),
            basic_constraints: LeafBasicConstraints {
                ca: false,
                path_len: None,
            },
        }
    }

    #[test]
    fn arbitrary_requested_eku_is_rejected() {
        let profile = profile(vec![ExtendedKeyUsage::ClientAuth]);
        let mut requested = CertificateParams::default();
        requested.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        assert!(validate_requested_extensions(&profile, &requested).is_err());
    }

    #[test]
    fn ca_requested_usages_are_rejected() {
        let profile = profile(vec![ExtendedKeyUsage::ClientAuth]);
        let mut requested = CertificateParams::default();
        requested.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        assert!(validate_requested_extensions(&profile, &requested).is_err());
    }

    #[test]
    fn generated_request_uses_profile_algorithm_and_redacts_key() {
        let mut profile = profile(vec![ExtendedKeyUsage::ClientAuth]);
        profile.permitted_key_algorithms = vec![KeyAlgorithmRule {
            algorithm: KeyAlgorithm::Ecdsa,
            sizes: vec![384],
        }];

        let generated = generate_leaf_request(&profile).unwrap();
        let debug = format!("{generated:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("PRIVATE KEY"));

        let parsed = parse_and_verify_csr(generated.csr_pem()).unwrap();
        assert_eq!(parsed.algorithm, KeyAlgorithm::Ecdsa);
        assert_eq!(parsed.key_size, 384);
        let private_key = generated.into_private_key_pem();
        let key_pair = KeyPair::from_pem(private_key.as_str()).unwrap();
        assert!(std::ptr::eq(key_pair.algorithm(), &PKCS_ECDSA_P384_SHA384));
    }
}
