use chrono::{DateTime, Utc};
use const_oid::{db::rfc6960::ID_PKIX_OCSP_NONCE, ObjectIdentifier};
use der::{
    asn1::{BitString, GeneralizedTime, Null, OctetString},
    Decode, Encode,
};
use rcgen::{
    CertificateParams, CertificateRevocationListParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SanType, SerialNumber, SigningKey,
};
use ring::{digest, rand, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use spki::AlgorithmIdentifierOwned;
use sqlx::Acquire;
use std::{fs, time::Instant};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_cert::{
    ext::{pkix::CrlReason as X509CrlReason, Extension},
    Certificate as X509Certificate,
};
use x509_ocsp::{
    ext::Nonce, BasicOcspResponse, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
    OcspResponseStatus, ResponderId, ResponseData, RevokedInfo, SingleResponse, Version,
};
use x509_parser::pem::parse_x509_pem;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::{CertsCaMode, Config},
    error::AppError,
    identity,
};

use super::{
    authority::{repo as authority_repo, AuthorityKind, AuthorityRecord, AuthorityStatus},
    pki_core, profile, repo,
};

const CRL_REGEN_LOCK_ID: i64 = 0x0041_544f_4d43_524c;
const ISSUER_CRL_LOCK_DOMAIN: i64 = 0x504b_4939_4352_4c00;
const LEAF_CLOCK_SKEW_SECS: i64 = 300;
const CRL_TTL_HOURS: i64 = 24;
const SERIAL_INSERT_ATTEMPTS: usize = 3;
pub const OCSP_REQUEST_MAX_BYTES: usize = 16 * 1024;
const OCSP_MAX_SINGLE_REQUESTS: usize = 16;
const OCSP_VALIDITY_SECONDS: i64 = 300;
pub const RUNTIME_CERTIFICATE_DER_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct IssueCertificate {
    pub entity_id: Uuid,
    pub ttl_secs: Option<u64>,
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IssueCertificateFromCsr {
    pub entity_id: Uuid,
    pub ttl_secs: Option<u64>,
    pub csr_pem: String,
}

#[derive(Debug, Clone)]
pub struct IssueCertificateFromCsrV2 {
    pub entity_id: Uuid,
    pub ttl_secs: Option<u64>,
    pub csr_pem: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct IssueGeneratedCertificateV2 {
    pub entity_id: Uuid,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RenewCertificate {
    pub serial_number: String,
    pub ttl_secs: Option<u64>,
    pub revoke_old: bool,
}

#[derive(Debug, Clone)]
pub enum RenewalKeySource {
    Csr(String),
    Generated,
}

impl RenewalKeySource {
    pub(crate) fn mode(&self) -> &'static str {
        match self {
            Self::Csr(_) => "csr",
            Self::Generated => "generated",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenewCertificateV2 {
    pub credential_id: Uuid,
    pub ttl_secs: Option<u64>,
    pub key_source: RenewalKeySource,
    pub revoke_old: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct ResolveCertificateV2 {
    pub certificate_der: Option<Vec<u8>>,
    pub fingerprint_sha256: Option<String>,
    pub issuer_fingerprint_sha256: Option<String>,
    pub serial_number: Option<String>,
    pub expected_tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy)]
pub enum CertificateRenewalAuthorization {
    Operator {
        actor_entity_id: Option<Uuid>,
        expected_entity_id: Uuid,
        expected_tenant_id: Option<Uuid>,
    },
    PresentedCertificate {
        credential_id: Uuid,
    },
}

#[derive(Debug, Clone)]
pub enum CertificateRevocationSelector {
    CredentialId(Uuid),
    FingerprintSha256(String),
    IssuerSerial {
        issuer_id: Uuid,
        serial_number: String,
    },
}

impl CertificateRevocationSelector {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CredentialId(_) => "credential_id",
            Self::FingerprintSha256(_) => "fingerprint_sha256",
            Self::IssuerSerial { .. } => "issuer_serial",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RevokeCertificateV2 {
    pub selector: CertificateRevocationSelector,
    pub reason: Option<String>,
    pub actor_entity_id: Option<Uuid>,
    pub expected_entity_id: Uuid,
    pub expected_tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct CertificateRevocationResult {
    pub certificate: CertificateRecord,
    pub issuer_fingerprint_sha256: Option<String>,
    pub reason: String,
    pub actor_entity_id: Option<Uuid>,
    pub revoked_at: DateTime<Utc>,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone)]
pub struct BulkCertificateRevocationResult {
    pub count: usize,
    pub credential_ids: Vec<Uuid>,
    pub issuer_ids: Vec<Uuid>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CrlArtifact {
    pub der: Vec<u8>,
    pub sha256: String,
    pub crl_number: i64,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub certificate_pem: String,
    #[serde(default)]
    pub chain_pem: Option<String>,
    pub subject: Value,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub issuer_kind: String,
    pub issuer_subject: String,
    pub issuer_serial_number: String,
    pub issuer_fingerprint_sha256: String,
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub profile_id: Option<Uuid>,
    #[serde(default)]
    pub profile_name: Option<String>,
    #[serde(default)]
    pub identity_uri: Option<String>,
    #[serde(default)]
    pub renewed_from_credential_id: Option<Uuid>,
    #[serde(default)]
    pub renewal_threshold_seconds: Option<u64>,
    #[serde(default)]
    pub renewal_due_at: Option<DateTime<Utc>>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issued_from_csr: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateRecord {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub serial_number: String,
    pub status: String,
    pub certificate_pem: String,
    pub chain_pem: Option<String>,
    pub subject: Value,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub fingerprint_sha256: String,
    pub profile_id: Option<Uuid>,
    pub profile_name: Option<String>,
    pub identity_uri: Option<String>,
    pub renewed_from_credential_id: Option<Uuid>,
    pub renewal_threshold_seconds: Option<u64>,
    pub renewal_due_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

pub use repo::CertificateListFilter;

#[derive(Debug, Clone)]
pub struct CertificateListPage {
    pub items: Vec<CertificateRecord>,
    pub total: i64,
}

pub struct OneTimePrivateKey(Zeroizing<String>);

impl OneTimePrivateKey {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for OneTimePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OneTimePrivateKey([REDACTED])")
    }
}

#[derive(Debug)]
pub struct IssuedCertificate {
    pub certificate: CertificateRecord,
    pub private_key_pem: Option<OneTimePrivateKey>,
    pub chain_pem: Option<String>,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone)]
pub struct CertificateIdentity {
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

pub struct CertificateIssuer {
    issuer_kind: &'static str,
    chain_pem: String,
    issuer_subject: String,
    issuer_serial_number: String,
    issuer_fingerprint_sha256: String,
    issuer_not_after: DateTime<Utc>,
    issuer: Issuer<'static, KeyPair>,
    key_pair: KeyPair,
    certificate_der: Vec<u8>,
}

struct PersistCertificate {
    entity_id: Uuid,
    serial_number: String,
    certificate_pem: String,
    subject: Value,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    issued_from_csr: bool,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

struct CertificateInfo {
    pem: String,
    der: Vec<u8>,
    subject: String,
    serial_number: String,
    fingerprint_sha256: String,
    not_after: DateTime<Utc>,
    public_key_der: Vec<u8>,
}

pub fn load_file_issuer_if_enabled(config: &Config) -> Result<Option<CertificateIssuer>, AppError> {
    if !config.certs_enabled {
        return Ok(None);
    }
    validate_file_issuer_config(config)?;
    let issuer = match config.certs_ca_mode {
        CertsCaMode::FileIntermediateIssuer => load_intermediate_file_issuer(config)?,
        CertsCaMode::FileRootIssuer => load_root_file_issuer(config)?,
    };
    tracing::info!(
        mode = config.certs_ca_mode.as_str(),
        issuer_fingerprint_sha256 = issuer.issuer_fingerprint_sha256,
        "certificate file issuer loaded"
    );
    Ok(Some(issuer))
}

fn load_intermediate_file_issuer(config: &Config) -> Result<CertificateIssuer, AppError> {
    let root_path = require_config_path(
        config.certs_root_ca_cert_path.as_deref(),
        "ATOM_CERTS_ROOT_CA_CERT_PATH",
    )?;
    let intermediate_path = require_config_path(
        config.certs_intermediate_ca_cert_path.as_deref(),
        "ATOM_CERTS_INTERMEDIATE_CA_CERT_PATH",
    )?;
    let key_path = require_config_path(
        config.certs_intermediate_ca_key_path.as_deref(),
        "ATOM_CERTS_INTERMEDIATE_CA_KEY_PATH",
    )?;
    let root = load_ca_cert(root_path, "root CA")?;
    let intermediate = load_ca_cert(intermediate_path, "intermediate CA")?;
    verify_signed_by(
        &intermediate,
        &root,
        "intermediate CA is not signed by root CA",
    )?;
    let mut key_pem = read_required_file(key_path, "intermediate CA private key")?;
    let issuer = build_issuer(
        "intermediate",
        format!("{}{}", intermediate.pem, root.pem),
        intermediate,
        &key_pem,
    )?;
    key_pem.zeroize();
    Ok(issuer)
}

fn load_root_file_issuer(config: &Config) -> Result<CertificateIssuer, AppError> {
    let root_path = require_config_path(
        config.certs_root_ca_cert_path.as_deref(),
        "ATOM_CERTS_ROOT_CA_CERT_PATH",
    )?;
    let key_path = require_config_path(
        config.certs_root_ca_key_path.as_deref(),
        "ATOM_CERTS_ROOT_CA_KEY_PATH",
    )?;
    let root = load_ca_cert(root_path, "root CA")?;
    verify_self_signed(&root, "root CA is not self-signed")?;
    let mut key_pem = read_required_file(key_path, "root CA private key")?;
    let issuer = build_issuer("root", root.pem.clone(), root, &key_pem)?;
    key_pem.zeroize();
    Ok(issuer)
}

fn build_issuer(
    issuer_kind: &'static str,
    chain_pem: String,
    cert: CertificateInfo,
    key_pem: &str,
) -> Result<CertificateIssuer, AppError> {
    let key_pair = KeyPair::from_pem(key_pem).map_err(rcgen_err)?;
    ensure_key_matches_cert(&key_pair, &cert)?;
    let issuer =
        Issuer::from_ca_cert_pem(&cert.pem, KeyPair::from_pem(key_pem).map_err(rcgen_err)?)
            .map_err(rcgen_err)?;
    Ok(CertificateIssuer {
        issuer_kind,
        chain_pem,
        issuer_subject: cert.subject,
        issuer_serial_number: cert.serial_number,
        issuer_fingerprint_sha256: cert.fingerprint_sha256,
        issuer_not_after: cert.not_after,
        issuer,
        key_pair,
        certificate_der: cert.der,
    })
}

fn read_required_file(path: &str, label: &str) -> Result<String, AppError> {
    fs::read_to_string(path)
        .map_err(|err| AppError::bad_request(format!("failed to read {label} file {path}: {err}")))
}

fn load_ca_cert(path: &str, label: &str) -> Result<CertificateInfo, AppError> {
    let pem = read_required_file(path, label)?;
    let der = certificate_der_from_pem(&pem)
        .map_err(|_| AppError::bad_request(format!("invalid {label} PEM at {path}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|_| AppError::bad_request(format!("invalid {label} certificate at {path}")))?;
    if !cert.tbs_certificate.is_ca() {
        return Err(AppError::bad_request(format!(
            "{label} must be a CA certificate"
        )));
    }
    let key_usage = cert
        .tbs_certificate
        .key_usage()
        .map_err(|_| AppError::bad_request(format!("invalid {label} key usage")))?
        .map(|usage| *usage.value);
    if let Some(usage) = key_usage {
        if !usage.key_cert_sign() || !usage.crl_sign() {
            return Err(AppError::bad_request(format!(
                "{label} key usage must allow certificate and CRL signing"
            )));
        }
    }
    let not_after = DateTime::<Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| AppError::bad_request(format!("invalid {label} notAfter timestamp")))?;
    if not_after <= Utc::now() {
        return Err(AppError::bad_request(format!("{label} is expired")));
    }
    let subject = cert.subject().to_string();
    let serial_number = normalize_serial(&cert.tbs_certificate.raw_serial_as_string())?;
    let public_key_der = cert.public_key().raw.to_vec();
    let fingerprint = digest::digest(&digest::SHA256, &der);
    Ok(CertificateInfo {
        pem,
        der,
        subject,
        serial_number,
        fingerprint_sha256: hex::encode(fingerprint.as_ref()),
        not_after,
        public_key_der,
    })
}

fn verify_signed_by(
    cert: &CertificateInfo,
    issuer: &CertificateInfo,
    message: &str,
) -> Result<(), AppError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert.der)
        .map_err(|_| AppError::bad_request("invalid issuer certificate"))?;
    let (_, parsed_issuer) = x509_parser::parse_x509_certificate(&issuer.der)
        .map_err(|_| AppError::bad_request("invalid root certificate"))?;
    parsed
        .verify_signature(Some(parsed_issuer.public_key()))
        .map_err(|_| AppError::bad_request(message))
}

fn verify_self_signed(cert: &CertificateInfo, message: &str) -> Result<(), AppError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert.der)
        .map_err(|_| AppError::bad_request("invalid root certificate"))?;
    parsed
        .verify_signature(None)
        .map_err(|_| AppError::bad_request(message))
}

fn ensure_key_matches_cert(key_pair: &KeyPair, cert: &CertificateInfo) -> Result<(), AppError> {
    let public_key_pem = key_pair.public_key_pem();
    let public_key_der = parse_x509_pem(public_key_pem.as_bytes())
        .map(|(_, pem)| pem.contents)
        .map_err(|_| AppError::bad_request("invalid issuer private key public component"))?;
    if public_key_der != cert.public_key_der {
        return Err(AppError::bad_request(
            "issuer private key does not match issuer certificate",
        ));
    }
    Ok(())
}

pub async fn issue_certificate(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: IssueCertificate,
) -> Result<IssuedCertificate, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "issuance").await?;
    let issued = issue_certificate_in_tx(&mut tx, config, issuer, input).await?;
    commit_lifecycle_transaction(tx, issued, "issuance").await
}

/// The caller owns the commit, so an audited caller can bind issuance and its
/// `certificate.issue` event into one transaction via
/// [`crate::audit::commit_with_audit`].
pub async fn issue_certificate_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: IssueCertificate,
) -> Result<IssuedCertificate, AppError> {
    let result = issue_certificate_in_tx_inner(tx, config, issuer, input).await;
    record_lifecycle_precommit_failure("issuance", &result);
    result
}

async fn issue_certificate_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: IssueCertificate,
) -> Result<IssuedCertificate, AppError> {
    let loaded = require_issuer(config, issuer)?;
    repo::entity_tenant_id(&mut **tx, input.entity_id).await?;
    let ttl = leaf_ttl(config, input.ttl_secs)?;
    let now = OffsetDateTime::now_utc();
    let not_before = now - Duration::seconds(LEAF_CLOCK_SKEW_SECS);
    let not_after = now + Duration::seconds(ttl as i64);
    ensure_issuer_covers_leaf(loaded, not_after)?;
    let common_name = input
        .common_name
        .clone()
        .unwrap_or_else(|| input.entity_id.to_string());
    let san_names = input
        .dns_names
        .iter()
        .chain(input.ip_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();

    for attempt in 0..SERIAL_INSERT_ATTEMPTS {
        let serial = random_serial()?;
        let serial_number = serial_to_string(&serial);
        let mut params = CertificateParams::new(san_names.clone()).map_err(rcgen_err)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.clone());
        params.serial_number = Some(serial);
        params.not_before = not_before;
        params.not_after = not_after;
        params.use_authority_key_identifier_extension = true;
        params.key_usages.clear();
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        params.extended_key_usages.clear();
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        let key_pair = KeyPair::generate().map_err(rcgen_err)?;
        let cert = params
            .signed_by(&key_pair, &loaded.issuer)
            .map_err(rcgen_err)?;
        let private_key_pem = OneTimePrivateKey::new(key_pair.serialize_pem());
        // Each attempt runs in a nested transaction (a SAVEPOINT): a serial
        // collision aborts the current (sub)transaction in Postgres, so without
        // one, retrying would run against — and the caller would later commit —
        // a poisoned transaction.
        let mut attempt_tx = tx.begin().await.map_err(AppError::Database)?;
        let outcome = persist_certificate(
            &mut attempt_tx,
            loaded,
            PersistCertificate {
                entity_id: input.entity_id,
                serial_number,
                certificate_pem: cert.pem(),
                subject: json!({"common_name": common_name}),
                dns_names: input.dns_names.clone(),
                ip_addresses: input.ip_addresses.clone(),
                issued_from_csr: false,
                not_before: to_chrono(not_before)?,
                not_after: to_chrono(not_after)?,
            },
        )
        .await;
        match outcome {
            Ok(record) => {
                attempt_tx.commit().await.map_err(AppError::Database)?;
                return Ok(IssuedCertificate {
                    certificate: record,
                    private_key_pem: Some(private_key_pem),
                    chain_pem: Some(loaded.chain_pem.clone()),
                    idempotent_replay: false,
                });
            }
            Err(err) if is_unique_violation(&err) && attempt + 1 < SERIAL_INSERT_ATTEMPTS => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
            }
            Err(err) => {
                return Err(err);
            }
        }
    }

    Err(AppError::conflict(
        "failed to allocate a unique certificate serial number",
    ))
}

pub async fn issue_certificate_from_csr(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: IssueCertificateFromCsr,
) -> Result<IssuedCertificate, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "issuance").await?;
    let issued = issue_certificate_from_csr_in_tx(&mut tx, config, issuer, input).await?;
    commit_lifecycle_transaction(tx, issued, "issuance").await
}

/// See [`issue_certificate_in_tx`] — the caller owns the commit.
pub async fn issue_certificate_from_csr_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: IssueCertificateFromCsr,
) -> Result<IssuedCertificate, AppError> {
    let result = issue_certificate_from_csr_in_tx_inner(tx, config, issuer, input).await;
    record_lifecycle_precommit_failure("issuance", &result);
    result
}

async fn issue_certificate_from_csr_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: IssueCertificateFromCsr,
) -> Result<IssuedCertificate, AppError> {
    let loaded = require_issuer(config, issuer)?;
    repo::entity_tenant_id(&mut **tx, input.entity_id).await?;
    let ttl = leaf_ttl(config, input.ttl_secs)?;
    let now = OffsetDateTime::now_utc();
    let not_before = now - Duration::seconds(LEAF_CLOCK_SKEW_SECS);
    let not_after = now + Duration::seconds(ttl as i64);
    ensure_issuer_covers_leaf(loaded, not_after)?;
    let mut csr_template = CertificateSigningRequestParams::from_pem(&input.csr_pem)
        .map_err(|_| AppError::bad_request("invalid CSR"))?;
    force_leaf_csr_params(&mut csr_template.params);
    let (dns_names, ip_addresses) = san_metadata(&csr_template.params);
    let subject = json!({"csr_subject": format!("{:?}", csr_template.params.distinguished_name)});

    for attempt in 0..SERIAL_INSERT_ATTEMPTS {
        let serial = random_serial()?;
        let serial_number = serial_to_string(&serial);
        let mut csr = csr_template.clone();
        csr.params.serial_number = Some(serial);
        csr.params.not_before = not_before;
        csr.params.not_after = not_after;
        let cert = csr.signed_by(&loaded.issuer).map_err(rcgen_err)?;
        // Each attempt runs in a nested transaction (a SAVEPOINT): a serial
        // collision aborts the current (sub)transaction in Postgres, so without
        // one, retrying would run against — and the caller would later commit —
        // a poisoned transaction.
        let mut attempt_tx = tx.begin().await.map_err(AppError::Database)?;
        let outcome = persist_certificate(
            &mut attempt_tx,
            loaded,
            PersistCertificate {
                entity_id: input.entity_id,
                serial_number,
                certificate_pem: cert.pem(),
                subject: subject.clone(),
                dns_names: dns_names.clone(),
                ip_addresses: ip_addresses.clone(),
                issued_from_csr: true,
                not_before: to_chrono(not_before)?,
                not_after: to_chrono(not_after)?,
            },
        )
        .await;
        match outcome {
            Ok(record) => {
                attempt_tx.commit().await.map_err(AppError::Database)?;
                return Ok(IssuedCertificate {
                    certificate: record,
                    private_key_pem: None,
                    chain_pem: Some(loaded.chain_pem.clone()),
                    idempotent_replay: false,
                });
            }
            Err(err) if is_unique_violation(&err) && attempt + 1 < SERIAL_INSERT_ATTEMPTS => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
            }
            Err(err) => return Err(err),
        }
    }

    Err(AppError::conflict(
        "failed to allocate a unique certificate serial number",
    ))
}

/// Explicitly versioned, managed-issuer CSR path introduced by PR-005.
///
/// `authorized_tenant_id` is produced by the transport authorization layer;
/// it is not a public request field.  Rechecking it after locking the entity
/// closes the authorization-to-issuance race without accepting caller scope.
pub async fn issue_certificate_from_csr_v2(
    pool: &sqlx::PgPool,
    config: &Config,
    authorized_tenant_id: Option<Uuid>,
    input: IssueCertificateFromCsrV2,
) -> Result<IssuedCertificate, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "issuance").await?;
    let issued =
        issue_certificate_from_csr_v2_in_tx(&mut tx, config, authorized_tenant_id, input).await?;
    commit_lifecycle_transaction(tx, issued, "issuance").await
}

/// Managed CSR issuance using only the caller's existing transaction and
/// nested savepoints for serial retries.
pub async fn issue_certificate_from_csr_v2_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    authorized_tenant_id: Option<Uuid>,
    input: IssueCertificateFromCsrV2,
) -> Result<IssuedCertificate, AppError> {
    let result =
        issue_certificate_from_csr_v2_in_tx_inner(tx, config, authorized_tenant_id, input).await;
    record_lifecycle_precommit_failure("issuance", &result);
    result
}

async fn issue_certificate_from_csr_v2_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    authorized_tenant_id: Option<Uuid>,
    input: IssueCertificateFromCsrV2,
) -> Result<IssuedCertificate, AppError> {
    validate_idempotency_key(&input.idempotency_key)?;
    let (_, stored_tenant_id) = identity::repo::lock_active_entity(tx, input.entity_id)
        .await?
        .ok_or_else(|| AppError::not_found("entity not found"))?;
    if stored_tenant_id != authorized_tenant_id {
        return Err(AppError::Forbidden);
    }
    let subject = profile::load_subject(&mut **tx, input.entity_id).await?;
    if subject.tenant_id() != stored_tenant_id {
        return Err(AppError::Internal(anyhow::anyhow!(
            "locked entity scope changed during certificate issuance"
        )));
    }

    let request_key_hash = issuance_request_key_hash(&input.idempotency_key);
    let request_fingerprint =
        issuance_request_fingerprint(input.entity_id, input.ttl_secs, input.csr_pem.as_bytes());
    let request_id = match repo::claim_certificate_issuance_request(
        tx,
        input.entity_id,
        &request_key_hash,
        &request_fingerprint,
    )
    .await?
    {
        repo::CertificateIssuanceRequestClaim::New { request_id } => request_id,
        repo::CertificateIssuanceRequestClaim::Replay { credential_id } => {
            let certificate =
                record_from_row(repo::fetch_certificate_by_id(&mut **tx, credential_id).await?)?;
            return Ok(IssuedCertificate {
                chain_pem: certificate.chain_pem.clone(),
                certificate,
                private_key_pem: None,
                idempotent_replay: true,
            });
        }
    };

    let certificate_profile = profile::resolve_for_subject_in_tx(tx, &subject, "client").await?;
    let authority = authority_repo::lock_active_leaf_issuer_for_scope(tx, stored_tenant_id).await?;
    validate_issuer_scope(&authority, stored_tenant_id)?;
    let issuer = pki_core::PkiIssuer::from_managed_authority(&authority, &config.pki_ca_keys)?;

    for attempt in 0..SERIAL_INSERT_ATTEMPTS {
        let issued = pki_core::issue_from_csr(
            &certificate_profile,
            &subject,
            &issuer,
            pki_core::IssueFromCsr {
                csr_pem: &input.csr_pem,
                requested_ttl_seconds: input.ttl_secs,
            },
        )?;
        let chain_pem = issued.chain_pem.clone();
        let mut attempt_tx = tx.begin().await.map_err(AppError::Database)?;
        let outcome = persist_managed_certificate(
            &mut attempt_tx,
            input.entity_id,
            &authority,
            issued,
            true,
            None,
        )
        .await;
        match outcome {
            Ok(certificate) => {
                repo::complete_certificate_issuance_request(
                    &mut attempt_tx,
                    request_id,
                    certificate.credential_id,
                )
                .await?;
                attempt_tx.commit().await.map_err(AppError::Database)?;
                return Ok(IssuedCertificate {
                    certificate,
                    private_key_pem: None,
                    chain_pem: Some(chain_pem),
                    idempotent_replay: false,
                });
            }
            Err(error) if is_unique_violation(&error) => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
                if attempt + 1 == SERIAL_INSERT_ATTEMPTS {
                    return Err(AppError::conflict(
                        "failed to allocate a unique certificate serial number",
                    ));
                }
            }
            Err(error) => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
                return Err(error);
            }
        }
    }

    Err(AppError::conflict(
        "failed to allocate a unique certificate serial number",
    ))
}

/// Explicitly versioned managed generated-key bootstrap. The feature gate is
/// off by default until per-issuer revocation publication is complete.
pub async fn issue_generated_certificate_v2_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    authorized_tenant_id: Option<Uuid>,
    input: IssueGeneratedCertificateV2,
) -> Result<IssuedCertificate, AppError> {
    let result =
        issue_generated_certificate_v2_in_tx_inner(tx, config, authorized_tenant_id, input).await;
    record_lifecycle_precommit_failure("issuance", &result);
    result
}

async fn issue_generated_certificate_v2_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    authorized_tenant_id: Option<Uuid>,
    input: IssueGeneratedCertificateV2,
) -> Result<IssuedCertificate, AppError> {
    if !config.pki_generated_key_issuance_enabled {
        return Err(AppError::Forbidden);
    }

    let (_, stored_tenant_id) = identity::repo::lock_active_entity(tx, input.entity_id)
        .await?
        .ok_or_else(|| AppError::not_found("entity not found"))?;
    if stored_tenant_id != authorized_tenant_id {
        return Err(AppError::Forbidden);
    }
    let subject = profile::load_subject(&mut **tx, input.entity_id).await?;
    if subject.tenant_id() != stored_tenant_id {
        return Err(AppError::Internal(anyhow::anyhow!(
            "locked entity scope changed during certificate issuance"
        )));
    }

    let certificate_profile = profile::resolve_for_subject_in_tx(tx, &subject, "client").await?;
    let authority = authority_repo::lock_active_leaf_issuer_for_scope(tx, stored_tenant_id).await?;
    validate_issuer_scope(&authority, stored_tenant_id)?;
    let issuer = pki_core::PkiIssuer::from_managed_authority(&authority, &config.pki_ca_keys)?;
    let mut generated = Some(pki_core::generate_leaf_request(&certificate_profile)?);

    for attempt in 0..SERIAL_INSERT_ATTEMPTS {
        let csr_pem = generated
            .as_ref()
            .map(pki_core::GeneratedLeafRequest::csr_pem)
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!(
                    "generated leaf key was consumed before issuance completed"
                ))
            })?;
        let issued = pki_core::issue_from_csr(
            &certificate_profile,
            &subject,
            &issuer,
            pki_core::IssueFromCsr {
                csr_pem,
                requested_ttl_seconds: input.ttl_secs,
            },
        )?;
        let chain_pem = issued.chain_pem.clone();
        let mut attempt_tx = tx.begin().await.map_err(AppError::Database)?;
        let outcome = persist_managed_certificate(
            &mut attempt_tx,
            input.entity_id,
            &authority,
            issued,
            false,
            None,
        )
        .await;
        match outcome {
            Ok(certificate) => {
                attempt_tx.commit().await.map_err(AppError::Database)?;
                return Ok(IssuedCertificate {
                    certificate,
                    private_key_pem: Some(OneTimePrivateKey::from_zeroizing(
                        generated
                            .take()
                            .ok_or_else(|| {
                                AppError::Internal(anyhow::anyhow!(
                                    "generated leaf key was already consumed"
                                ))
                            })?
                            .into_private_key_pem(),
                    )),
                    chain_pem: Some(chain_pem),
                    idempotent_replay: false,
                });
            }
            Err(error) if is_unique_violation(&error) => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
                if attempt + 1 == SERIAL_INSERT_ATTEMPTS {
                    return Err(AppError::conflict(
                        "failed to allocate a unique certificate serial number",
                    ));
                }
            }
            Err(error) => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
                return Err(error);
            }
        }
    }

    Err(AppError::conflict(
        "failed to allocate a unique certificate serial number",
    ))
}

pub async fn renew_certificate(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: RenewCertificate,
) -> Result<IssuedCertificate, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "renewal").await?;
    let issued = renew_certificate_in_tx(&mut tx, config, issuer, input).await?;
    commit_lifecycle_transaction(tx, issued, "renewal").await
}

/// See [`issue_certificate_in_tx`] — the caller owns the commit. Renewal issues
/// a replacement and (optionally) revokes the old certificate, so binding both
/// to one transaction also stops a renewal from half-applying.
pub async fn renew_certificate_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: RenewCertificate,
) -> Result<IssuedCertificate, AppError> {
    let result = renew_certificate_in_tx_inner(tx, config, issuer, input).await;
    record_lifecycle_precommit_failure("renewal", &result);
    result
}

async fn renew_certificate_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    input: RenewCertificate,
) -> Result<IssuedCertificate, AppError> {
    let serial = normalize_serial(&input.serial_number)?;
    let old = record_from_row(repo::legacy_certificate_by_serial(&mut **tx, &serial).await?)?;
    if old.status == "revoked" {
        return Err(AppError::bad_request("cannot renew a revoked certificate"));
    }
    let issued = issue_certificate_in_tx_inner(
        tx,
        config,
        issuer,
        IssueCertificate {
            entity_id: old.entity_id,
            ttl_secs: input.ttl_secs,
            common_name: old
                .subject
                .get("common_name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            dns_names: old.dns_names.clone(),
            ip_addresses: old.ip_addresses.clone(),
        },
    )
    .await?;
    if input.revoke_old {
        revoke_certificate_in_tx_inner(tx, &serial, Some("superseded".into())).await?;
    }
    Ok(issued)
}

pub async fn renew_certificate_v2(
    pool: &sqlx::PgPool,
    config: &Config,
    authorization: CertificateRenewalAuthorization,
    input: RenewCertificateV2,
) -> Result<IssuedCertificate, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "renewal").await?;
    let issued = renew_certificate_v2_in_tx(&mut tx, config, authorization, input).await?;
    commit_lifecycle_transaction(tx, issued, "renewal").await
}

/// Exact-credential, issuer-aware renewal. Operator authorization is bound to
/// the entity and tenant observed before the transaction; certificate
/// authorization is bound to the exact credential that authenticated the
/// caller. The transport never supplies tenant, entity, issuer, or profile.
pub async fn renew_certificate_v2_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    authorization: CertificateRenewalAuthorization,
    input: RenewCertificateV2,
) -> Result<IssuedCertificate, AppError> {
    let result = renew_certificate_v2_in_tx_inner(tx, config, authorization, input).await;
    record_lifecycle_precommit_failure("renewal", &result);
    result
}

async fn renew_certificate_v2_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
    authorization: CertificateRenewalAuthorization,
    input: RenewCertificateV2,
) -> Result<IssuedCertificate, AppError> {
    validate_idempotency_key(&input.idempotency_key)?;
    if matches!(&input.key_source, RenewalKeySource::Generated)
        && !config.pki_generated_key_issuance_enabled
    {
        return Err(AppError::Forbidden);
    }

    let old = repo::lock_certificate_by_id(tx, input.credential_id).await?;
    let (_, stored_tenant_id) = identity::repo::lock_active_entity(tx, old.entity_id)
        .await?
        .ok_or_else(|| AppError::not_found("entity not found"))?;
    if old.tenant_id != stored_tenant_id {
        return Err(AppError::Internal(anyhow::anyhow!(
            "locked certificate scope changed during renewal"
        )));
    }
    validate_renewal_authorization(&old, authorization)?;

    let old_metadata = metadata_from_value(&old.metadata)?;
    let now = Utc::now();
    if matches!(
        authorization,
        CertificateRenewalAuthorization::PresentedCertificate { .. }
    ) {
        validate_renewal_source(tx, &old, &old_metadata, authorization, now).await?;
    }

    let key_mode = input.key_source.mode();
    let request_key_hash = renewal_request_key_hash(&input.idempotency_key);
    let request_fingerprint = renewal_request_fingerprint(
        input.credential_id,
        input.ttl_secs,
        input.revoke_old,
        key_mode,
        match &input.key_source {
            RenewalKeySource::Csr(csr_pem) => csr_pem.as_bytes(),
            RenewalKeySource::Generated => &[],
        },
    );
    let renewal_id = match repo::claim_certificate_renewal(
        tx,
        input.credential_id,
        &request_key_hash,
        &request_fingerprint,
        key_mode,
    )
    .await?
    {
        repo::CertificateRenewalRequestClaim::New { renewal_id } => renewal_id,
        repo::CertificateRenewalRequestClaim::Replay { credential_id } => {
            let certificate =
                record_from_row(repo::fetch_certificate_by_id(&mut **tx, credential_id).await?)?;
            if certificate.renewed_from_credential_id != Some(input.credential_id) {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "stored certificate renewal link is inconsistent"
                )));
            }
            return Ok(IssuedCertificate {
                chain_pem: certificate.chain_pem.clone(),
                certificate,
                private_key_pem: None,
                idempotent_replay: true,
            });
        }
    };

    if matches!(
        authorization,
        CertificateRenewalAuthorization::Operator { .. }
    ) {
        validate_renewal_source(tx, &old, &old_metadata, authorization, now).await?;
    }

    let subject = profile::load_subject(&mut **tx, old.entity_id).await?;
    if subject.tenant_id() != stored_tenant_id {
        return Err(AppError::Internal(anyhow::anyhow!(
            "locked entity scope changed during certificate renewal"
        )));
    }
    let certificate_profile = profile::resolve_for_subject_in_tx(tx, &subject, "client").await?;
    let authority = authority_repo::lock_active_leaf_issuer_for_scope(tx, stored_tenant_id).await?;
    validate_issuer_scope(&authority, stored_tenant_id)?;
    let issuer = pki_core::PkiIssuer::from_managed_authority(&authority, &config.pki_ca_keys)?;
    let (csr_pem, mut generated) = match input.key_source {
        RenewalKeySource::Csr(csr_pem) => (csr_pem, None),
        RenewalKeySource::Generated => {
            let generated = pki_core::generate_leaf_request(&certificate_profile)?;
            (generated.csr_pem().to_string(), Some(generated))
        }
    };

    for attempt in 0..SERIAL_INSERT_ATTEMPTS {
        let issued = pki_core::issue_from_csr(
            &certificate_profile,
            &subject,
            &issuer,
            pki_core::IssueFromCsr {
                csr_pem: &csr_pem,
                requested_ttl_seconds: input.ttl_secs,
            },
        )?;
        let chain_pem = issued.chain_pem.clone();
        let mut attempt_tx = tx.begin().await.map_err(AppError::Database)?;
        let outcome = persist_managed_certificate(
            &mut attempt_tx,
            old.entity_id,
            &authority,
            issued,
            key_mode == "csr",
            Some(old.id),
        )
        .await;
        match outcome {
            Ok(certificate) => {
                if input.revoke_old {
                    let actor_entity_id = match authorization {
                        CertificateRenewalAuthorization::Operator {
                            actor_entity_id, ..
                        } => actor_entity_id,
                        CertificateRenewalAuthorization::PresentedCertificate { .. } => {
                            Some(old.entity_id)
                        }
                    };
                    let metadata = revocation_metadata(
                        old.metadata.clone(),
                        "superseded",
                        actor_entity_id,
                        Utc::now(),
                    );
                    if !repo::revoke_certificate_if_active(&mut attempt_tx, old.id, metadata)
                        .await?
                    {
                        return Err(AppError::conflict(
                            "renewal source revocation state changed concurrently",
                        ));
                    }
                }
                repo::complete_certificate_renewal(
                    &mut attempt_tx,
                    renewal_id,
                    certificate.credential_id,
                )
                .await?;
                attempt_tx.commit().await.map_err(AppError::Database)?;
                let private_key_pem = generated
                    .take()
                    .map(pki_core::GeneratedLeafRequest::into_private_key_pem)
                    .map(OneTimePrivateKey::from_zeroizing);
                return Ok(IssuedCertificate {
                    certificate,
                    private_key_pem,
                    chain_pem: Some(chain_pem),
                    idempotent_replay: false,
                });
            }
            Err(error) if is_unique_violation(&error) => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
                if attempt + 1 == SERIAL_INSERT_ATTEMPTS {
                    return Err(AppError::conflict(
                        "failed to allocate a unique certificate serial number",
                    ));
                }
            }
            Err(error) => {
                attempt_tx.rollback().await.map_err(AppError::Database)?;
                return Err(error);
            }
        }
    }

    Err(AppError::conflict(
        "failed to allocate a unique certificate serial number",
    ))
}

/// Resolve a certificate's renewal window from its stored profile snapshot,
/// falling back to the referenced/effective profile for pre-PR-007 rows.
pub async fn certificate_renewal_due_at(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
) -> Result<DateTime<Utc>, AppError> {
    let row = repo::certificate_by_id(pool, credential_id).await?;
    let metadata = metadata_from_value(&row.metadata)?;
    if let Some(due_at) = metadata.renewal_due_at {
        return Ok(due_at);
    }
    let threshold_seconds = if let Some(value) = metadata.renewal_threshold_seconds {
        value
    } else if let Some(profile_id) = metadata.profile_id {
        profile::profile_by_id(pool, profile_id)
            .await?
            .renewal_threshold_seconds()
    } else {
        let subject = profile::load_subject(pool, row.entity_id).await?;
        profile::resolve_for_subject(pool, &subject, "client")
            .await?
            .renewal_threshold_seconds()
    };
    renewal_due_at(metadata.not_before, metadata.not_after, threshold_seconds)
}

pub async fn revoke_certificate(
    pool: &sqlx::PgPool,
    serial_number: &str,
    reason: Option<String>,
) -> Result<CertificateRecord, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "revocation").await?;
    let record = revoke_certificate_in_tx(&mut tx, serial_number, reason).await?;
    commit_lifecycle_transaction(tx, record, "revocation").await
}

/// See [`issue_certificate_in_tx`] — the caller owns the commit. The revocation
/// and the CRL dirty flag were previously two independent pool writes; running
/// them in one transaction means a published `certificate.revoke` can never
/// describe a CRL that was never marked stale.
pub async fn revoke_certificate_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    serial_number: &str,
    reason: Option<String>,
) -> Result<CertificateRecord, AppError> {
    let result = revoke_certificate_in_tx_inner(tx, serial_number, reason).await;
    record_lifecycle_precommit_failure("revocation", &result);
    result
}

async fn revoke_certificate_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    serial_number: &str,
    reason: Option<String>,
) -> Result<CertificateRecord, AppError> {
    let serial = normalize_serial(serial_number)?;
    let current = repo::legacy_certificate_by_serial(&mut **tx, &serial).await?;
    if current.issuer_id.is_some() {
        return Err(AppError::bad_request(
            "managed certificate revocation requires an exact v2 selector",
        ));
    }
    let result = revoke_certificate_v2_in_tx_inner(
        tx,
        RevokeCertificateV2 {
            selector: CertificateRevocationSelector::CredentialId(current.id),
            reason,
            actor_entity_id: None,
            expected_entity_id: current.entity_id,
            expected_tenant_id: current.tenant_id,
        },
    )
    .await?;
    Ok(result.certificate)
}

pub async fn certificate_by_revocation_selector(
    pool: &sqlx::PgPool,
    selector: &CertificateRevocationSelector,
) -> Result<CertificateRecord, AppError> {
    let row = match selector {
        CertificateRevocationSelector::CredentialId(credential_id) => {
            repo::certificate_by_id(pool, *credential_id).await?
        }
        CertificateRevocationSelector::FingerprintSha256(fingerprint) => {
            let fingerprint = validated_fingerprint(fingerprint)?;
            repo::certificate_by_fingerprint(pool, &fingerprint).await?
        }
        CertificateRevocationSelector::IssuerSerial {
            issuer_id,
            serial_number,
        } => {
            let serial = normalize_serial(serial_number)?;
            repo::certificate_by_issuer_serial(pool, *issuer_id, &serial).await?
        }
    };
    record_from_row(row)
}

pub async fn revoke_certificate_v2(
    pool: &sqlx::PgPool,
    input: RevokeCertificateV2,
) -> Result<CertificateRevocationResult, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "revocation").await?;
    let result = revoke_certificate_v2_in_tx(&mut tx, input).await?;
    commit_lifecycle_transaction(tx, result, "revocation").await
}

/// Revoke one exact certificate. The row lock makes first-write semantics and
/// idempotent replay deterministic. The database trigger records immutable
/// revocation evidence and dirties only this certificate's issuer artifacts in
/// the same transaction.
pub async fn revoke_certificate_v2_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: RevokeCertificateV2,
) -> Result<CertificateRevocationResult, AppError> {
    let result = revoke_certificate_v2_in_tx_inner(tx, input).await;
    record_lifecycle_precommit_failure("revocation", &result);
    result
}

async fn revoke_certificate_v2_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: RevokeCertificateV2,
) -> Result<CertificateRevocationResult, AppError> {
    let current = match &input.selector {
        CertificateRevocationSelector::CredentialId(credential_id) => {
            repo::lock_certificate_by_id(tx, *credential_id).await?
        }
        CertificateRevocationSelector::FingerprintSha256(fingerprint) => {
            let fingerprint = validated_fingerprint(fingerprint)?;
            repo::lock_certificate_by_fingerprint(tx, &fingerprint).await?
        }
        CertificateRevocationSelector::IssuerSerial {
            issuer_id,
            serial_number,
        } => {
            let serial = normalize_serial(serial_number)?;
            repo::lock_certificate_by_issuer_serial(tx, *issuer_id, &serial).await?
        }
    };
    if current.entity_id != input.expected_entity_id
        || current.tenant_id != input.expected_tenant_id
    {
        return Err(AppError::Forbidden);
    }

    if current.status == "revoked" {
        let revocation = repo::certificate_revocation_by_id(&mut **tx, current.id).await?;
        return Ok(CertificateRevocationResult {
            certificate: record_from_row(current)?,
            issuer_fingerprint_sha256: revocation.issuer_fingerprint_sha256,
            reason: revocation.reason,
            actor_entity_id: revocation.actor_entity_id,
            revoked_at: revocation.revoked_at,
            idempotent_replay: true,
        });
    }
    if current.status != "active" {
        return Err(AppError::Unauthorized("certificate is not active".into()));
    }

    let reason = normalize_revocation_reason(input.reason.as_deref())?;
    let now = Utc::now();
    let metadata = revocation_metadata(
        current.metadata.clone(),
        &reason,
        input.actor_entity_id,
        now,
    );
    if !repo::revoke_certificate_if_active(tx, current.id, metadata).await? {
        return Err(AppError::conflict(
            "certificate revocation state changed concurrently",
        ));
    }
    let revocation = repo::certificate_revocation_by_id(&mut **tx, current.id).await?;
    let certificate = record_from_row(repo::fetch_certificate_by_id(&mut **tx, current.id).await?)?;
    Ok(CertificateRevocationResult {
        certificate,
        issuer_fingerprint_sha256: revocation.issuer_fingerprint_sha256,
        reason: revocation.reason,
        actor_entity_id: revocation.actor_entity_id,
        revoked_at: revocation.revoked_at,
        idempotent_replay: false,
    })
}

pub async fn revoke_entity_certificates(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    reason: Option<String>,
) -> Result<usize, AppError> {
    let mut tx = begin_lifecycle_transaction(pool, "revocation").await?;
    let count = revoke_entity_certificates_in_tx(&mut tx, entity_id, reason).await?;
    commit_lifecycle_transaction(tx, count, "revocation").await
}

/// See [`revoke_certificate_in_tx`] — the caller owns the commit. Revoking an
/// entity's certificates was a write per certificate plus a CRL flag, none of
/// them atomic with each other; one transaction makes the reported count and
/// the published event describe the same committed state.
pub async fn revoke_entity_certificates_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    reason: Option<String>,
) -> Result<usize, AppError> {
    Ok(
        revoke_entity_certificates_v2_in_tx(tx, entity_id, reason, None)
            .await?
            .count,
    )
}

pub async fn revoke_entity_certificates_v2_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    reason: Option<String>,
    actor_entity_id: Option<Uuid>,
) -> Result<BulkCertificateRevocationResult, AppError> {
    let result =
        revoke_entity_certificates_v2_in_tx_inner(tx, entity_id, reason, actor_entity_id).await;
    record_lifecycle_precommit_failure("revocation", &result);
    result
}

async fn revoke_entity_certificates_v2_in_tx_inner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    reason: Option<String>,
    actor_entity_id: Option<Uuid>,
) -> Result<BulkCertificateRevocationResult, AppError> {
    // Serializes explicit entity-wide revocation with issuance paths, which
    // also lock the active entity before inserting a certificate.
    identity::repo::lock_active_entity(tx, entity_id)
        .await?
        .ok_or_else(|| AppError::not_found("entity not found"))?;
    let reason = normalize_revocation_reason(reason.as_deref().or(Some("entity_revoked")))?;
    let certs = repo::active_entity_certificates(&mut **tx, entity_id).await?;
    let mut credential_ids = Vec::with_capacity(certs.len());
    let mut issuer_ids = Vec::new();
    for cert in certs {
        let metadata = revocation_metadata(cert.metadata, &reason, actor_entity_id, Utc::now());
        if repo::revoke_certificate_if_active(tx, cert.id, metadata).await? {
            credential_ids.push(cert.id);
            if let Some(issuer_id) = cert.issuer_id {
                if !issuer_ids.contains(&issuer_id) {
                    issuer_ids.push(issuer_id);
                }
            }
        }
    }
    Ok(BulkCertificateRevocationResult {
        count: credential_ids.len(),
        credential_ids,
        issuer_ids,
        reason,
    })
}

pub async fn legacy_certificate_by_serial(
    pool: &sqlx::PgPool,
    serial_number: &str,
) -> Result<CertificateRecord, AppError> {
    repo::legacy_certificate_by_serial(pool, &normalize_serial(serial_number)?)
        .await
        .and_then(record_from_row)
}

/// Backward-compatible alias for the legacy file-issuer management lookup.
/// New managed paths must use an exact credential, fingerprint, or issuer pair.
pub async fn certificate_by_serial(
    pool: &sqlx::PgPool,
    serial_number: &str,
) -> Result<CertificateRecord, AppError> {
    legacy_certificate_by_serial(pool, serial_number).await
}

pub async fn certificate_by_id(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
) -> Result<CertificateRecord, AppError> {
    repo::certificate_by_id(pool, credential_id)
        .await
        .and_then(record_from_row)
}

pub async fn list_certificates(
    pool: &sqlx::PgPool,
    entity_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    status: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<Vec<CertificateRecord>, AppError> {
    let status = status.map(validate_certificate_status).transpose()?;
    let rows = repo::list_certificates(
        pool,
        entity_id,
        tenant_id,
        status.as_deref(),
        limit.clamp(1, 100),
        offset.max(0),
    )
    .await?;
    rows.into_iter().map(record_from_row).collect()
}

pub async fn list_certificates_filtered(
    pool: &sqlx::PgPool,
    mut filter: CertificateListFilter,
) -> Result<CertificateListPage, AppError> {
    filter.status = filter.status.map(validate_certificate_status).transpose()?;
    if let (Some(from), Some(before)) = (&filter.expires_from, &filter.expires_before) {
        if from >= before {
            return Err(AppError::bad_request(
                "expires_from must be earlier than expires_before",
            ));
        }
    }
    filter.limit = filter.limit.clamp(1, 100);
    filter.offset = filter.offset.max(0);
    let total = repo::count_certificates(pool, &filter).await?;
    let rows = repo::list_certificates_filtered(pool, &filter).await?;
    Ok(CertificateListPage {
        items: rows
            .into_iter()
            .map(record_from_row)
            .collect::<Result<Vec<_>, _>>()?,
        total,
    })
}

pub fn ca_chain(config: &Config, issuer: Option<&CertificateIssuer>) -> Result<String, AppError> {
    Ok(require_issuer(config, issuer)?.chain_pem.clone())
}

pub async fn generate_crl(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
) -> Result<Vec<u8>, AppError> {
    let loaded = require_issuer(config, issuer)?;
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CRL_REGEN_LOCK_ID)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    let state = repo::crl_state_tx(&mut tx, &loaded.issuer_fingerprint_sha256).await?;
    let now_chrono = Utc::now();
    if let Some(cached) = cached_crl_artifact(&state, &loaded.issuer_fingerprint_sha256, now_chrono)
    {
        tx.commit().await.map_err(AppError::Database)?;
        crate::metrics::record_pki_crl("legacy", cached.der.len(), None);
        return Ok(cached.der);
    }

    let generation_started = Instant::now();
    let revoked = repo::revoked_certificates(pool, &loaded.issuer_fingerprint_sha256).await?;
    let revoked_certs = revoked
        .into_iter()
        .map(|cert| {
            let metadata = metadata_from_value(&cert.metadata)?;
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from(serial_bytes(&cert.identifier)?),
                revocation_time: to_offset(metadata.revoked_at.unwrap_or_else(Utc::now))?,
                reason_code: Some(RevocationReason::Unspecified),
                invalidity_date: None,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let now = OffsetDateTime::now_utc();
    let next_update = now + Duration::hours(CRL_TTL_HOURS);
    let crl_number = state.crl_number + 1;
    let crl = CertificateRevocationListParams {
        this_update: now,
        next_update,
        crl_number: SerialNumber::from(crl_number as u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&loaded.issuer)
    .map_err(rcgen_err)?;
    let crl_der = crl.der().as_ref().to_vec();
    let crl_sha256 = sha256_hex(&crl_der);
    repo::store_crl_tx(
        &mut tx,
        &loaded.issuer_fingerprint_sha256,
        crl_number,
        &crl_der,
        &crl_sha256,
        to_chrono(now)?,
        to_chrono(next_update)?,
    )
    .await?;
    tx.commit().await.map_err(AppError::Database)?;
    crate::metrics::record_pki_crl("legacy", crl_der.len(), Some(generation_started.elapsed()));
    Ok(crl_der)
}

/// Generate or return a validator-ready CRL for one managed leaf issuer.
/// Clean cache reads avoid the signing lock; dirty/missing/expired/corrupt
/// entries serialize on an issuer-derived advisory lock and recheck state.
pub async fn issuer_crl(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer_id: Uuid,
) -> Result<CrlArtifact, AppError> {
    let authority = authority_repo::authority_by_id(pool, issuer_id).await?;
    validate_crl_authority_role(&authority)?;
    let now = Utc::now();
    let fingerprint = authority
        .fingerprint_sha256
        .as_deref()
        .ok_or_else(|| AppError::not_found("issuer has no published certificate"))?;
    let cached = match repo::issuer_crl_state(pool, issuer_id).await? {
        Some(state) => cached_crl_artifact(&state, fingerprint, now),
        None => None,
    };
    if let Some(cached) = cached {
        validate_crl_authority_retention(&authority, true, now)?;
        crate::metrics::record_pki_crl("managed", cached.der.len(), None);
        return Ok(cached);
    }
    validate_crl_authority_retention(&authority, false, now)?;

    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let lock_id = issuer_crl_lock_id(issuer_id);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    // Hold the authority lifecycle row stable until signing and persistence
    // commit. Retirement remains allowed for later requests, while revocation
    // or expiry cannot race this publication operation.
    let authority =
        authority_repo::lock_authority_for_certificate_authentication(&mut tx, issuer_id).await?;
    validate_crl_authority_role(&authority)?;
    let now = Utc::now();
    validate_crl_authority_retention(&authority, false, now)?;
    let fingerprint = authority
        .fingerprint_sha256
        .as_deref()
        .ok_or_else(|| AppError::not_found("issuer has no published certificate"))?;
    let state = repo::issuer_crl_state_tx(&mut tx, issuer_id, fingerprint).await?;
    if let Some(cached) = cached_crl_artifact(&state, fingerprint, now) {
        tx.commit().await.map_err(AppError::Database)?;
        crate::metrics::record_pki_crl("managed", cached.der.len(), None);
        return Ok(cached);
    }

    let generation_started = Instant::now();
    let revoked_certs = repo::issuer_revocations_tx(&mut tx, issuer_id)
        .await?
        .into_iter()
        .map(|entry| {
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from(serial_bytes(&entry.serial_number)?),
                revocation_time: to_offset(entry.revoked_at)?,
                reason_code: Some(crl_revocation_reason(&entry.reason)),
                invalidity_date: None,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let crl_number = state
        .crl_number
        .checked_add(1)
        .filter(|number| *number > 0)
        .ok_or_else(|| AppError::conflict("issuer CRL number is exhausted"))?;
    let this_update = OffsetDateTime::from_unix_timestamp(now.timestamp())
        .map_err(|_| AppError::bad_request("invalid CRL timestamp"))?;
    let desired_next_update = this_update + Duration::hours(CRL_TTL_HOURS);
    let issuer_not_after = authority
        .not_after
        .ok_or_else(|| AppError::not_found("issuer has no validity window"))?;
    let issuer_not_after = to_offset(issuer_not_after)?;
    let next_update = desired_next_update.min(issuer_not_after);
    if next_update <= this_update {
        return Err(AppError::not_found("issuer is expired"));
    }
    let signer =
        pki_core::PkiArtifactSigner::from_managed_authority(&authority, &config.pki_ca_keys)?;
    let crl_der = signer.sign_crl(CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(crl_number as u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    })?;
    let crl_sha256 = sha256_hex(&crl_der);
    let this_update = to_chrono(this_update)?;
    let next_update = to_chrono(next_update)?;
    repo::store_issuer_crl_tx(
        &mut tx,
        issuer_id,
        crl_number,
        &crl_der,
        &crl_sha256,
        this_update,
        next_update,
    )
    .await?;
    tx.commit().await.map_err(AppError::Database)?;
    crate::metrics::record_pki_crl("managed", crl_der.len(), Some(generation_started.elapsed()));
    Ok(CrlArtifact {
        der: crl_der,
        sha256: crl_sha256,
        crl_number,
        this_update,
        next_update,
        cache_hit: false,
    })
}

pub async fn ocsp_response(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    request_der: &[u8],
) -> Result<Vec<u8>, AppError> {
    let loaded = require_issuer(config, issuer)?;
    let request = parse_ocsp_request(request_der)?;
    let nonce = request_nonce(&request)?;
    let now = Utc::now();
    let next_update =
        (now + chrono::Duration::seconds(OCSP_VALIDITY_SECONDS)).min(loaded.issuer_not_after);
    if next_update <= now {
        return Err(AppError::not_found("legacy OCSP issuer is expired"));
    }
    let this_update = ocsp_time(now)?;
    let next_update = ocsp_time(next_update)?;
    let mut responses = Vec::with_capacity(request.tbs_request.request_list.len());
    for one in &request.tbs_request.request_list {
        let issuer_matches = certid_issuer_matches(&one.req_cert, &loaded.certificate_der)?;
        let status = if issuer_matches {
            let serial = serial_from_ocsp_request(&one.req_cert)?;
            match repo::legacy_certificate_by_serial(pool, &serial).await {
                Ok(cert) if cert.status == "active" => CertStatus::good(),
                Ok(cert) => {
                    let metadata = metadata_from_value(&cert.metadata)?;
                    let revoked_at = metadata.revoked_at.unwrap_or_else(Utc::now);
                    CertStatus::revoked(RevokedInfo {
                        revocation_time: ocsp_time(revoked_at)?,
                        revocation_reason: Some(ocsp_revocation_reason(
                            metadata
                                .revocation_reason
                                .as_deref()
                                .unwrap_or("unspecified"),
                        )),
                    })
                }
                Err(AppError::NotFound(_)) => CertStatus::unknown(),
                Err(err) => return Err(err),
            }
        } else {
            CertStatus::unknown()
        };
        responses.push(SingleResponse {
            cert_id: one.req_cert.clone(),
            cert_status: status,
            this_update,
            next_update: Some(next_update),
            single_extensions: None,
        });
    }
    let certificate_chain = certificate_chain_from_pem(&loaded.chain_pem)?;
    encode_signed_ocsp(
        certificate_chain,
        responses,
        nonce.as_deref(),
        this_update,
        |response_data_der| {
            let algorithm = pki_core::pki_signature_algorithm(loaded.key_pair.algorithm())?;
            let signature = loaded.key_pair.sign(response_data_der).map_err(rcgen_err)?;
            Ok((algorithm, signature))
        },
    )
}

/// Build an issuer-scoped OCSP response from the exact issuer/serial identity.
/// The request is parsed before issuer lookup so malformed input has identical
/// behavior for known and unknown route identifiers.
pub async fn issuer_ocsp_response(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer_id: Uuid,
    request_der: &[u8],
) -> Result<Vec<u8>, AppError> {
    let request = parse_ocsp_request(request_der)?;
    let nonce = request_nonce(&request)?;
    let authority = authority_repo::authority_by_id(pool, issuer_id).await?;
    validate_ocsp_authority(&authority, Utc::now())?;
    let signer =
        pki_core::PkiArtifactSigner::from_managed_authority(&authority, &config.pki_ca_keys)
            .map_err(|error| {
                AppError::Internal(anyhow::anyhow!(
                    "managed OCSP signer is unavailable: {error}"
                ))
            })?;
    let certificate_chain = signer.certificate_chain_der().map_err(|error| {
        AppError::Internal(anyhow::anyhow!(
            "managed OCSP signer chain is unavailable: {error}"
        ))
    })?;
    let issuer_der = certificate_chain
        .first()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("managed OCSP issuer chain is empty")))?;
    let now = Utc::now();
    let issuer_not_after = authority
        .not_after
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("managed OCSP issuer has no expiry")))?;
    let next_update =
        (now + chrono::Duration::seconds(OCSP_VALIDITY_SECONDS)).min(issuer_not_after);
    if next_update <= now {
        return Err(AppError::not_found("OCSP responder is unavailable"));
    }
    let this_update = ocsp_time(now)?;
    let next_update = ocsp_time(next_update)?;
    let mut responses = Vec::with_capacity(request.tbs_request.request_list.len());
    for one in &request.tbs_request.request_list {
        let issuer_matches = certid_issuer_matches(&one.req_cert, issuer_der)?;
        let cert_status = if issuer_matches {
            let serial = serial_from_ocsp_request(&one.req_cert)?;
            managed_ocsp_status(pool, issuer_id, &serial).await?
        } else {
            // A CertID for another issuer is deliberately indistinguishable
            // from an unissued serial under this public responder.
            CertStatus::unknown()
        };
        responses.push(SingleResponse {
            cert_id: one.req_cert.clone(),
            cert_status,
            this_update,
            next_update: Some(next_update),
            single_extensions: None,
        });
    }
    encode_signed_ocsp(
        certificate_chain,
        responses,
        nonce.as_deref(),
        this_update,
        |response_data_der| {
            let signature = signer.sign_ocsp_response_data(response_data_der)?;
            let algorithm = signature.algorithm();
            Ok((algorithm, signature.into_bytes()))
        },
    )
}

/// Deprecated runtime compatibility resolver for the legacy file issuer.
///
/// Serial-only resolution is safe solely inside the `issuer_id IS NULL`
/// namespace, which retains a dedicated unique index. Managed certificates are
/// intentionally invisible here and must use [`resolve_certificate_identity_v2`].
pub async fn resolve_certificate_identity(
    pool: &sqlx::PgPool,
    serial_number: &str,
    fingerprint_sha256: Option<&str>,
) -> Result<CertificateIdentity, AppError> {
    let serial = normalize_serial(serial_number)?;
    let record = repo::runtime_legacy_certificate_by_serial(pool, &serial).await?;
    if let Some(expected) = fingerprint_sha256 {
        let expected = validated_fingerprint(expected)?;
        if expected != runtime_stored_fingerprint(&record)? {
            return Err(AppError::Unauthorized(
                "certificate fingerprint mismatch".into(),
            ));
        }
    }
    runtime_identity_from_row(record, None)
}

/// Authoritative, issuer-aware certificate resolver. Every supplied selector
/// is independently verified and, when more than one is present, all selectors
/// must identify the same credential.
pub async fn resolve_certificate_identity_v2(
    pool: &sqlx::PgPool,
    input: ResolveCertificateV2,
) -> Result<CertificateIdentity, AppError> {
    let der_fingerprint = input
        .certificate_der
        .as_deref()
        .map(runtime_der_fingerprint)
        .transpose()?;
    let supplied_fingerprint = input
        .fingerprint_sha256
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(validated_fingerprint)
        .transpose()?;
    if let (Some(derived), Some(supplied)) = (&der_fingerprint, &supplied_fingerprint) {
        if derived != supplied {
            return Err(runtime_selector_mismatch());
        }
    }
    let fingerprint = der_fingerprint.or(supplied_fingerprint);

    let issuer_fingerprint = input
        .issuer_fingerprint_sha256
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(validated_fingerprint)
        .transpose()?;
    let serial = input
        .serial_number
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(normalize_serial)
        .transpose()?;
    let issuer_serial = match (issuer_fingerprint, serial) {
        (Some(issuer_fingerprint), Some(serial)) => Some((issuer_fingerprint, serial)),
        (None, None) => None,
        _ => {
            return Err(AppError::bad_request(
                "issuer_fingerprint_sha256 and serial_number must be supplied together",
            ))
        }
    };

    if fingerprint.is_none() && issuer_serial.is_none() {
        return Err(AppError::bad_request(
            "provide certificate_der, fingerprint_sha256, or issuer fingerprint plus serial",
        ));
    }

    let record = match (fingerprint.as_deref(), issuer_serial.as_ref()) {
        (Some(fingerprint), None) => {
            repo::runtime_certificate_by_fingerprint(pool, fingerprint).await?
        }
        (None, Some((issuer_fingerprint, serial))) => {
            repo::runtime_certificate_by_issuer_fingerprint_serial(pool, issuer_fingerprint, serial)
                .await?
        }
        (Some(fingerprint), Some((issuer_fingerprint, serial))) => {
            let by_fingerprint = repo::runtime_certificate_by_fingerprint(pool, fingerprint).await;
            let by_issuer = repo::runtime_certificate_by_issuer_fingerprint_serial(
                pool,
                issuer_fingerprint,
                serial,
            )
            .await;
            match by_fingerprint {
                Ok(by_fingerprint) => match by_issuer {
                    Ok(by_issuer) if by_fingerprint.id == by_issuer.id => by_fingerprint,
                    Ok(_) | Err(AppError::NotFound(_)) => return Err(runtime_selector_mismatch()),
                    Err(error) => return Err(error),
                },
                Err(AppError::NotFound(_)) => match by_issuer {
                    Ok(_) | Err(AppError::NotFound(_)) => return Err(runtime_selector_mismatch()),
                    Err(error) => return Err(error),
                },
                Err(error) => return Err(error),
            }
        }
        (None, None) => {
            return Err(AppError::bad_request(
                "certificate resolver selector is missing",
            ))
        }
    };

    runtime_identity_from_row(record, input.expected_tenant_id)
}

fn runtime_der_fingerprint(certificate_der: &[u8]) -> Result<String, AppError> {
    if certificate_der.is_empty() {
        return Err(AppError::bad_request("certificate_der must not be empty"));
    }
    if certificate_der.len() > RUNTIME_CERTIFICATE_DER_MAX_BYTES {
        return Err(AppError::payload_too_large(format!(
            "certificate_der exceeds {} bytes",
            RUNTIME_CERTIFICATE_DER_MAX_BYTES
        )));
    }
    let (remaining, _) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| AppError::bad_request("invalid X.509 certificate DER"))?;
    if !remaining.is_empty() {
        return Err(AppError::bad_request(
            "certificate_der contains trailing data",
        ));
    }
    Ok(hex::encode(
        digest::digest(&digest::SHA256, certificate_der).as_ref(),
    ))
}

fn runtime_stored_fingerprint(
    record: &repo::RuntimeCertificateCredential,
) -> Result<String, AppError> {
    let value = record
        .metadata
        .get("fingerprint_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Unauthorized("certificate fingerprint is unavailable".into()))?;
    validated_fingerprint(value)
        .map_err(|_| AppError::Unauthorized("certificate fingerprint is invalid".into()))
}

fn runtime_identity_from_row(
    record: repo::RuntimeCertificateCredential,
    expected_tenant_id: Option<Uuid>,
) -> Result<CertificateIdentity, AppError> {
    if record.credential_status != "active" {
        return Err(AppError::Unauthorized(
            "certificate credential is not active".into(),
        ));
    }
    let now = Utc::now();
    let expires_at = record
        .expires_at
        .ok_or_else(|| AppError::Unauthorized("certificate has no expiry".into()))?;
    if expires_at <= now {
        return Err(AppError::Unauthorized("certificate expired".into()));
    }
    runtime_stored_fingerprint(&record)?;

    if record.entity_status != "active" || record.entity_deleted_at.is_some() {
        return Err(AppError::Unauthorized(
            "certificate entity is not active".into(),
        ));
    }
    if record.tenant_id.is_some()
        && (record.tenant_status.as_deref() != Some("active") || record.tenant_deleted_at.is_some())
    {
        return Err(AppError::Unauthorized(
            "certificate tenant is not active".into(),
        ));
    }
    if expected_tenant_id.is_some() && expected_tenant_id != record.tenant_id {
        return Err(AppError::Forbidden);
    }

    if record.issuer_id.is_some() {
        let issuer_enabled = match record.issuer_status.as_deref() {
            Some("active") => record.issuer_issuance_enabled == Some(true),
            Some("retiring" | "retired") => true,
            _ => false,
        };
        if !issuer_enabled {
            return Err(AppError::Unauthorized(
                "certificate issuer is not enabled for verification".into(),
            ));
        }
        if record
            .issuer_not_before
            .is_none_or(|not_before| not_before > now)
            || record
                .issuer_not_after
                .is_none_or(|not_after| not_after <= now)
        {
            return Err(AppError::Unauthorized(
                "certificate issuer is outside its validity period".into(),
            ));
        }
    }

    Ok(CertificateIdentity {
        entity_id: record.entity_id,
        tenant_id: record.tenant_id,
        credential_id: record.id,
        issuer_id: record.issuer_id,
        expires_at,
        status: record.credential_status,
    })
}

fn runtime_selector_mismatch() -> AppError {
    AppError::Unauthorized("certificate selectors do not identify the same credential".into())
}

pub fn normalize_serial(serial_number: &str) -> Result<String, AppError> {
    let normalized = serial_number
        .chars()
        .filter(|ch| *ch != ':' && !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if normalized.is_empty() || normalized.len() % 2 != 0 || hex::decode(&normalized).is_err() {
        return Err(AppError::bad_request("invalid certificate serial number"));
    }
    Ok(normalized)
}

fn validated_fingerprint(value: &str) -> Result<String, AppError> {
    let normalized = normalize_fingerprint(value);
    if normalized.len() != 64 || hex::decode(&normalized).is_err() {
        return Err(AppError::bad_request(
            "invalid certificate SHA-256 fingerprint",
        ));
    }
    Ok(normalized)
}

fn normalize_revocation_reason(value: Option<&str>) -> Result<String, AppError> {
    let reason = value.unwrap_or("unspecified").trim().to_ascii_lowercase();
    if reason.is_empty()
        || reason.len() > 64
        || !reason
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(AppError::bad_request(
            "revocation reason must be a 1-64 character reason code",
        ));
    }
    Ok(reason)
}

fn revocation_metadata(
    mut metadata: Value,
    reason: &str,
    actor_entity_id: Option<Uuid>,
    revoked_at: DateTime<Utc>,
) -> Value {
    metadata["revoked_at"] = json!(revoked_at);
    metadata["revocation_reason"] = json!(reason);
    metadata["revoked_by_entity_id"] = json!(actor_entity_id);
    metadata
}

fn validate_file_issuer_config(config: &Config) -> Result<(), AppError> {
    if config.certs_leaf_default_ttl_secs > config.certs_leaf_max_ttl_secs {
        return Err(AppError::bad_request(
            "ATOM_CERTS_LEAF_DEFAULT_TTL_SECS must be less than or equal to ATOM_CERTS_LEAF_MAX_TTL_SECS",
        ));
    }
    match config.certs_ca_mode {
        CertsCaMode::FileIntermediateIssuer => {
            require_config_path(
                config.certs_root_ca_cert_path.as_deref(),
                "ATOM_CERTS_ROOT_CA_CERT_PATH",
            )?;
            require_config_path(
                config.certs_intermediate_ca_cert_path.as_deref(),
                "ATOM_CERTS_INTERMEDIATE_CA_CERT_PATH",
            )?;
            require_config_path(
                config.certs_intermediate_ca_key_path.as_deref(),
                "ATOM_CERTS_INTERMEDIATE_CA_KEY_PATH",
            )?;
        }
        CertsCaMode::FileRootIssuer => {
            require_config_path(
                config.certs_root_ca_cert_path.as_deref(),
                "ATOM_CERTS_ROOT_CA_CERT_PATH",
            )?;
            require_config_path(
                config.certs_root_ca_key_path.as_deref(),
                "ATOM_CERTS_ROOT_CA_KEY_PATH",
            )?;
        }
    }
    Ok(())
}

fn require_config_path<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, AppError> {
    value
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| AppError::bad_request(format!("{name} must be set")))
}

fn require_issuer<'a>(
    config: &Config,
    issuer: Option<&'a CertificateIssuer>,
) -> Result<&'a CertificateIssuer, AppError> {
    if !config.certs_enabled {
        return Err(AppError::bad_request("certificate support is disabled"));
    }
    if let Some(issuer) = issuer {
        Ok(issuer)
    } else {
        Err(AppError::Internal(anyhow::anyhow!(
            "certificate file issuer is not loaded"
        )))
    }
}

async fn persist_certificate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    issuer: &CertificateIssuer,
    input: PersistCertificate,
) -> Result<CertificateRecord, AppError> {
    let fingerprint_sha256 = certificate_fingerprint_sha256(&input.certificate_pem)?;
    let metadata = CertificateMetadata {
        certificate_pem: input.certificate_pem,
        chain_pem: Some(issuer.chain_pem.clone()),
        subject: input.subject,
        dns_names: input.dns_names,
        ip_addresses: input.ip_addresses,
        issuer_kind: issuer.issuer_kind.to_string(),
        issuer_subject: issuer.issuer_subject.clone(),
        issuer_serial_number: issuer.issuer_serial_number.clone(),
        issuer_fingerprint_sha256: issuer.issuer_fingerprint_sha256.clone(),
        fingerprint_sha256,
        profile_id: None,
        profile_name: None,
        identity_uri: None,
        renewed_from_credential_id: None,
        renewal_threshold_seconds: None,
        renewal_due_at: None,
        not_before: input.not_before,
        not_after: input.not_after,
        issued_from_csr: input.issued_from_csr,
        revoked_at: None,
        revocation_reason: None,
    };
    if identity::repo::lock_active_entity(tx, input.entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::not_found("entity not found"));
    }
    let id = repo::insert_certificate_credential(
        tx,
        input.entity_id,
        &input.serial_number,
        serde_json::to_value(metadata).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?,
        input.not_after,
    )
    .await?;
    // Read inside the transaction: re-reading after a commit would let a
    // transient failure report an already-issued certificate as an error.
    record_from_row(repo::fetch_certificate_by_id(&mut **tx, id).await?)
}

async fn persist_managed_certificate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    authority: &AuthorityRecord,
    issued: pki_core::IssuedCertificate,
    issued_from_csr: bool,
    renewed_from_credential_id: Option<Uuid>,
) -> Result<CertificateRecord, AppError> {
    let issuer_serial_number = authority.serial_number.clone().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("managed issuer serial number is missing"))
    })?;
    let issuer_fingerprint_sha256 = authority.fingerprint_sha256.clone().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("managed issuer fingerprint is missing"))
    })?;
    let renewal_due_at = renewal_due_at(
        issued.not_before,
        issued.not_after,
        issued.renewal_threshold_seconds,
    )?;
    let metadata = CertificateMetadata {
        certificate_pem: issued.certificate_pem,
        chain_pem: Some(issued.chain_pem),
        subject: json!({
            "common_name": entity_id,
            "identity_uri": issued.identity_uri.clone(),
        }),
        dns_names: issued.dns_names,
        ip_addresses: issued
            .ip_addresses
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
        issuer_kind: authority_kind_name(authority.kind).to_string(),
        issuer_subject: authority.subject.clone(),
        issuer_serial_number,
        issuer_fingerprint_sha256,
        fingerprint_sha256: issued.fingerprint_sha256,
        profile_id: Some(issued.profile_id),
        profile_name: Some(issued.profile_name),
        identity_uri: Some(issued.identity_uri),
        renewed_from_credential_id,
        renewal_threshold_seconds: Some(issued.renewal_threshold_seconds),
        renewal_due_at: Some(renewal_due_at),
        not_before: issued.not_before,
        not_after: issued.not_after,
        issued_from_csr,
        revoked_at: None,
        revocation_reason: None,
    };
    let id = repo::insert_managed_certificate_credential(
        tx,
        entity_id,
        authority.id,
        &issued.serial_number,
        serde_json::to_value(metadata).map_err(|error| {
            AppError::Internal(anyhow::anyhow!(
                "failed to encode certificate metadata: {error}"
            ))
        })?,
        issued.not_after,
    )
    .await?;
    record_from_row(repo::fetch_certificate_by_id(&mut **tx, id).await?)
}

fn record_from_row(row: repo::CertificateCredential) -> Result<CertificateRecord, AppError> {
    let metadata = metadata_from_value(&row.metadata)?;
    Ok(CertificateRecord {
        credential_id: row.id,
        issuer_id: row.issuer_id,
        entity_id: row.entity_id,
        tenant_id: row.tenant_id,
        serial_number: row.identifier,
        status: row.status,
        certificate_pem: metadata.certificate_pem,
        chain_pem: metadata.chain_pem,
        subject: metadata.subject,
        dns_names: metadata.dns_names,
        ip_addresses: metadata.ip_addresses,
        fingerprint_sha256: metadata.fingerprint_sha256,
        profile_id: metadata.profile_id,
        profile_name: metadata.profile_name,
        identity_uri: metadata.identity_uri,
        renewed_from_credential_id: metadata.renewed_from_credential_id,
        renewal_threshold_seconds: metadata.renewal_threshold_seconds,
        renewal_due_at: metadata.renewal_due_at,
        expires_at: row.expires_at,
        created_at: row.created_at,
        revoked_at: metadata.revoked_at,
        revocation_reason: metadata.revocation_reason,
    })
}

fn validate_issuer_scope(
    authority: &AuthorityRecord,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let matches = match tenant_id {
        Some(tenant_id) => {
            authority.kind == AuthorityKind::TenantIntermediate
                && authority.tenant_id == Some(tenant_id)
        }
        None => {
            authority.kind == AuthorityKind::PlatformLeafIssuer && authority.tenant_id.is_none()
        }
    };
    if matches {
        Ok(())
    } else {
        Err(AppError::Internal(anyhow::anyhow!(
            "selected issuing authority does not match the locked entity scope"
        )))
    }
}

fn authority_kind_name(kind: AuthorityKind) -> &'static str {
    match kind {
        AuthorityKind::Root => "root",
        AuthorityKind::PlatformIntermediate => "platform_intermediate",
        AuthorityKind::PlatformLeafIssuer => "platform_leaf_issuer",
        AuthorityKind::TenantIntermediate => "tenant_intermediate",
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "idempotency key must contain 1 to 256 non-control UTF-8 bytes",
        ));
    }
    Ok(())
}

fn issuance_request_key_hash(value: &str) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"atom:pki:csr-issuance-key:v1\0");
    context.update(value.as_bytes());
    hex::encode(context.finish())
}

fn issuance_request_fingerprint(entity_id: Uuid, ttl_secs: Option<u64>, csr_pem: &[u8]) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"atom:pki:csr-issuance-request:v1\0");
    context.update(entity_id.as_bytes());
    match ttl_secs {
        Some(ttl) => {
            context.update(&[1]);
            context.update(&ttl.to_be_bytes());
        }
        None => context.update(&[0]),
    }
    context.update(csr_pem);
    hex::encode(context.finish())
}

fn validate_renewal_authorization(
    old: &repo::CertificateCredential,
    authorization: CertificateRenewalAuthorization,
) -> Result<(), AppError> {
    let authorized = match authorization {
        CertificateRenewalAuthorization::Operator {
            actor_entity_id: _,
            expected_entity_id,
            expected_tenant_id,
        } => old.entity_id == expected_entity_id && old.tenant_id == expected_tenant_id,
        CertificateRenewalAuthorization::PresentedCertificate { credential_id } => {
            old.id == credential_id
        }
    };
    if authorized {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn validate_renewal_source(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    old: &repo::CertificateCredential,
    metadata: &CertificateMetadata,
    authorization: CertificateRenewalAuthorization,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    if old.status == "revoked" {
        return match authorization {
            CertificateRenewalAuthorization::Operator { .. } => {
                Err(AppError::bad_request("cannot renew a revoked certificate"))
            }
            CertificateRenewalAuthorization::PresentedCertificate { .. } => {
                Err(AppError::Unauthorized("certificate revoked".into()))
            }
        };
    }
    if old.status != "active" {
        return Err(AppError::Unauthorized("certificate is not active".into()));
    }
    let expires_at = old
        .expires_at
        .ok_or_else(|| AppError::bad_request("cannot renew a certificate without an expiry"))?;

    if matches!(
        authorization,
        CertificateRenewalAuthorization::Operator { .. }
    ) {
        // An explicitly authorized operator is the recovery path for an
        // expired (but never revoked) subject certificate.
        return Ok(());
    }

    if metadata.not_before > now {
        return Err(AppError::Unauthorized(
            "certificate is not yet valid".into(),
        ));
    }
    if expires_at <= now {
        return Err(AppError::Unauthorized("certificate expired".into()));
    }

    if let Some(issuer_id) = old.issuer_id {
        let issuer = authority_repo::lock_authority_for_certificate_authentication(tx, issuer_id)
            .await
            .map_err(|_| AppError::Unauthorized("certificate issuer is unavailable".into()))?;
        let scope_matches = match old.tenant_id {
            Some(tenant_id) => {
                issuer.kind == AuthorityKind::TenantIntermediate
                    && issuer.tenant_id == Some(tenant_id)
            }
            None => issuer.kind == AuthorityKind::PlatformLeafIssuer && issuer.tenant_id.is_none(),
        };
        let issuer_is_current = matches!(
            (issuer.not_before.as_ref(), issuer.not_after.as_ref()),
            (Some(not_before), Some(not_after)) if not_before <= &now && &now < not_after
        );
        if !scope_matches
            || !issuer_is_current
            || !matches!(
                issuer.status,
                AuthorityStatus::Active | AuthorityStatus::Retiring
            )
        {
            return Err(AppError::Unauthorized(
                "certificate issuer is not trusted for renewal".into(),
            ));
        }
    }
    Ok(())
}

fn renewal_due_at(
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    threshold_seconds: u64,
) -> Result<DateTime<Utc>, AppError> {
    if threshold_seconds == 0 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored certificate renewal threshold is invalid"
        )));
    }
    let threshold = i64::try_from(threshold_seconds).map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "stored certificate renewal threshold is too large"
        ))
    })?;
    let due_at = not_after
        .checked_sub_signed(chrono::Duration::seconds(threshold))
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "stored certificate renewal window is invalid"
            ))
        })?;
    Ok(due_at.max(not_before))
}

fn renewal_request_key_hash(value: &str) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"atom:pki:certificate-renewal-key:v1\0");
    context.update(value.as_bytes());
    hex::encode(context.finish())
}

fn renewal_request_fingerprint(
    credential_id: Uuid,
    ttl_secs: Option<u64>,
    revoke_old: bool,
    key_mode: &str,
    request_material: &[u8],
) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"atom:pki:certificate-renewal-request:v1\0");
    context.update(credential_id.as_bytes());
    match ttl_secs {
        Some(ttl) => {
            context.update(&[1]);
            context.update(&ttl.to_be_bytes());
        }
        None => context.update(&[0]),
    }
    context.update(&[u8::from(revoke_old)]);
    context.update(&(key_mode.len() as u64).to_be_bytes());
    context.update(key_mode.as_bytes());
    context.update(&(request_material.len() as u64).to_be_bytes());
    context.update(request_material);
    hex::encode(context.finish())
}

fn metadata_from_value(value: &Value) -> Result<CertificateMetadata, AppError> {
    serde_json::from_value(value.clone())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid certificate metadata")))
}

fn leaf_ttl(config: &Config, ttl_secs: Option<u64>) -> Result<u64, AppError> {
    let ttl = ttl_secs.unwrap_or(config.certs_leaf_default_ttl_secs);
    if ttl == 0 {
        return Err(AppError::bad_request(
            "certificate TTL must be greater than zero",
        ));
    }
    if ttl > config.certs_leaf_max_ttl_secs {
        return Err(AppError::bad_request(format!(
            "certificate TTL exceeds ATOM_CERTS_LEAF_MAX_TTL_SECS ({})",
            config.certs_leaf_max_ttl_secs
        )));
    }
    Ok(ttl)
}

fn validate_certificate_status(status: String) -> Result<String, AppError> {
    match status.as_str() {
        "active" | "revocation_pending" | "revoked" => Ok(status),
        _ => Err(AppError::bad_request(
            "certificate status must be active, revocation_pending, or revoked",
        )),
    }
}

fn ensure_issuer_covers_leaf(
    issuer: &CertificateIssuer,
    leaf_not_after: OffsetDateTime,
) -> Result<(), AppError> {
    let leaf_not_after = to_chrono(leaf_not_after)?;
    if leaf_not_after > issuer.issuer_not_after {
        return Err(AppError::bad_request(
            "requested certificate validity exceeds active issuer CA validity",
        ));
    }
    Ok(())
}

fn force_leaf_csr_params(params: &mut CertificateParams) {
    params.is_ca = IsCa::NoCa;
    params.key_usages.clear();
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    params.extended_key_usages.clear();
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.name_constraints = None;
    params.custom_extensions.clear();
    params.use_authority_key_identifier_extension = true;
}

fn san_metadata(params: &CertificateParams) -> (Vec<String>, Vec<String>) {
    let dns_names = params
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            SanType::DnsName(name) => Some(name.to_string()),
            SanType::Rfc822Name(_)
            | SanType::URI(_)
            | SanType::IpAddress(_)
            | SanType::OtherName(_)
            | _ => None,
        })
        .collect::<Vec<_>>();
    let ip_addresses = params
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            SanType::IpAddress(ip) => Some(ip.to_string()),
            SanType::Rfc822Name(_)
            | SanType::DnsName(_)
            | SanType::URI(_)
            | SanType::OtherName(_)
            | _ => None,
        })
        .collect::<Vec<_>>();
    (dns_names, ip_addresses)
}

fn certificate_fingerprint_sha256(certificate_pem: &str) -> Result<String, AppError> {
    let der = certificate_der_from_pem(certificate_pem)?;
    let fingerprint = digest::digest(&digest::SHA256, &der);
    Ok(hex::encode(fingerprint.as_ref()))
}

fn certificate_der_from_pem(certificate_pem: &str) -> Result<Vec<u8>, AppError> {
    parse_x509_pem(certificate_pem.as_bytes())
        .map(|(_, pem)| pem.contents)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid certificate PEM")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OcspHashAlgorithm {
    Sha1,
    Sha256,
}

const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

fn parse_ocsp_request(request_der: &[u8]) -> Result<OcspRequest, AppError> {
    if request_der.is_empty() {
        return Err(AppError::bad_request("empty OCSP request"));
    }
    if request_der.len() > OCSP_REQUEST_MAX_BYTES {
        return Err(AppError::payload_too_large("OCSP request is too large"));
    }
    let request = OcspRequest::from_der(request_der)
        .map_err(|_| AppError::bad_request("malformed OCSP request"))?;
    if request.tbs_request.request_list.is_empty()
        || request.tbs_request.request_list.len() > OCSP_MAX_SINGLE_REQUESTS
    {
        return Err(AppError::bad_request(
            "OCSP request must contain between one and sixteen CertIDs",
        ));
    }
    for one in &request.tbs_request.request_list {
        if let Some(extensions) = &one.single_request_extensions {
            for extension in extensions {
                if extension.extn_id == ID_PKIX_OCSP_NONCE || extension.critical {
                    return Err(AppError::bad_request(
                        "unsupported OCSP single-request extension",
                    ));
                }
            }
        }
        // Resolve the algorithm while the request is still in the bounded
        // validation phase. This rejects unsupported hashes before any issuer
        // or certificate lookup can reveal state.
        ocsp_hash_algorithm(&one.req_cert)?;
    }
    if let Some(extensions) = &request.tbs_request.request_extensions {
        for extension in extensions {
            if extension.extn_id != ID_PKIX_OCSP_NONCE && extension.critical {
                return Err(AppError::bad_request(
                    "unsupported critical OCSP request extension",
                ));
            }
        }
    }
    Ok(request)
}

fn request_nonce(request: &OcspRequest) -> Result<Option<Vec<u8>>, AppError> {
    let Some(extensions) = &request.tbs_request.request_extensions else {
        return Ok(None);
    };
    let mut nonce = None;
    for extension in extensions
        .iter()
        .filter(|extension| extension.extn_id == ID_PKIX_OCSP_NONCE)
    {
        if nonce.is_some() {
            return Err(AppError::bad_request("duplicate OCSP nonce extension"));
        }
        let decoded = Nonce::from_der(extension.extn_value.as_bytes())
            .map_err(|_| AppError::bad_request("malformed OCSP nonce extension"))?;
        let bytes = decoded.0.as_bytes();
        if !(1..=32).contains(&bytes.len()) {
            return Err(AppError::bad_request(
                "OCSP nonce must contain between one and thirty-two bytes",
            ));
        }
        nonce = Some(bytes.to_vec());
    }
    Ok(nonce)
}

fn ocsp_hash_algorithm(certid: &x509_ocsp::CertId) -> Result<OcspHashAlgorithm, AppError> {
    let parameters_supported = match &certid.hash_algorithm.parameters {
        None => true,
        Some(parameters) => parameters
            .to_der()
            .map(|encoded| encoded.as_slice() == [0x05, 0x00])
            .unwrap_or(false),
    };
    if !parameters_supported {
        return Err(AppError::bad_request(
            "unsupported OCSP hash algorithm parameters",
        ));
    }
    match certid.hash_algorithm.oid {
        SHA1_OID => Ok(OcspHashAlgorithm::Sha1),
        SHA256_OID => Ok(OcspHashAlgorithm::Sha256),
        _ => Err(AppError::bad_request("unsupported OCSP CertID hash")),
    }
}

fn issuer_hashes_from_der(
    certificate_der: &[u8],
    algorithm: OcspHashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let (_, cert) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid issuer certificate DER")))?;
    let digest_algorithm = match algorithm {
        OcspHashAlgorithm::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        OcspHashAlgorithm::Sha256 => &digest::SHA256,
    };
    let name_hash = digest::digest(digest_algorithm, cert.tbs_certificate.subject.as_raw())
        .as_ref()
        .to_vec();
    let key_hash = digest::digest(
        digest_algorithm,
        cert.tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    )
    .as_ref()
    .to_vec();
    Ok((name_hash, key_hash))
}

fn certid_issuer_matches(certid: &x509_ocsp::CertId, issuer_der: &[u8]) -> Result<bool, AppError> {
    let algorithm = ocsp_hash_algorithm(certid)?;
    let (issuer_name_hash, issuer_key_hash) = issuer_hashes_from_der(issuer_der, algorithm)?;
    Ok(certid.issuer_name_hash.as_bytes() == issuer_name_hash
        && certid.issuer_key_hash.as_bytes() == issuer_key_hash)
}

fn serial_from_ocsp_request(certid: &x509_ocsp::CertId) -> Result<String, AppError> {
    let serial = certid.serial_number.as_bytes();
    if serial.is_empty() {
        return Err(AppError::bad_request("invalid certificate serial number"));
    }
    normalize_serial(&hex::encode(serial))
}

fn validate_ocsp_authority(
    authority: &AuthorityRecord,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let lifecycle_retained = matches!(
        authority.status,
        AuthorityStatus::Active | AuthorityStatus::Retiring | AuthorityStatus::Retired
    );
    if !authority.kind.can_issue_leaf_credentials()
        || !lifecycle_retained
        || !authority.key_backend.can_sign()
        || authority
            .not_before
            .is_none_or(|not_before| not_before > now)
        || authority.not_after.is_none_or(|not_after| not_after <= now)
    {
        return Err(AppError::not_found("OCSP responder is unavailable"));
    }
    Ok(())
}

async fn managed_ocsp_status(
    pool: &sqlx::PgPool,
    issuer_id: Uuid,
    serial_number: &str,
) -> Result<CertStatus, AppError> {
    let certificate = match repo::certificate_by_issuer_serial(pool, issuer_id, serial_number).await
    {
        Ok(certificate) => certificate,
        Err(AppError::NotFound(_)) => return Ok(CertStatus::unknown()),
        Err(error) => return Err(error),
    };
    match certificate.status.as_str() {
        "active" => Ok(CertStatus::good()),
        "revoked" => {
            let revocation = repo::certificate_revocation_by_id(pool, certificate.id)
                .await
                .map_err(|error| {
                    AppError::Internal(anyhow::anyhow!(
                        "revoked certificate has no immutable revocation record: {error}"
                    ))
                })?;
            if revocation.issuer_id != Some(issuer_id) || revocation.serial_number != serial_number
            {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "certificate revocation record does not match its issuer identity"
                )));
            }
            Ok(CertStatus::revoked(RevokedInfo {
                revocation_time: ocsp_time(revocation.revoked_at)?,
                revocation_reason: Some(ocsp_revocation_reason(&revocation.reason)),
            }))
        }
        _ => Ok(CertStatus::unknown()),
    }
}

fn ocsp_revocation_reason(reason: &str) -> X509CrlReason {
    match reason {
        "key_compromise" => X509CrlReason::KeyCompromise,
        "ca_compromise" => X509CrlReason::CaCompromise,
        "affiliation_changed" => X509CrlReason::AffiliationChanged,
        "superseded" => X509CrlReason::Superseded,
        "cessation_of_operation" => X509CrlReason::CessationOfOperation,
        "certificate_hold" => X509CrlReason::CertificateHold,
        "remove_from_crl" => X509CrlReason::RemoveFromCRL,
        "privilege_withdrawn" => X509CrlReason::PrivilegeWithdrawn,
        "aa_compromise" => X509CrlReason::AaCompromise,
        _ => X509CrlReason::Unspecified,
    }
}

fn should_regenerate_crl(state: &repo::CrlState, now: DateTime<Utc>) -> bool {
    state.dirty
        || state.crl_der.is_none()
        || state
            .next_update
            .map(|next_update| next_update <= now)
            .unwrap_or(true)
}

fn cached_crl_artifact(
    state: &repo::CrlState,
    issuer_fingerprint_sha256: &str,
    now: DateTime<Utc>,
) -> Option<CrlArtifact> {
    if should_regenerate_crl(state, now) {
        return None;
    }
    if state.issuer_fingerprint_sha256 != issuer_fingerprint_sha256 {
        return None;
    }
    let der = state.crl_der.as_ref()?;
    let sha256 = state.crl_sha256.as_ref()?;
    if sha256_hex(der) != *sha256 {
        return None;
    }
    let Ok((remaining, _)) = x509_parser::parse_x509_crl(der) else {
        return None;
    };
    if !remaining.is_empty() {
        return None;
    }
    Some(CrlArtifact {
        der: der.clone(),
        sha256: sha256.clone(),
        crl_number: state.crl_number,
        this_update: state.this_update?,
        next_update: state.next_update?,
        cache_hit: true,
    })
}

fn validate_crl_authority_role(authority: &AuthorityRecord) -> Result<(), AppError> {
    if authority.kind.can_issue_leaf_credentials() {
        Ok(())
    } else {
        Err(AppError::not_found(
            "authority role does not publish leaf certificate CRLs",
        ))
    }
}

fn validate_crl_authority_retention(
    authority: &AuthorityRecord,
    serving_cached: bool,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let status_allowed = matches!(
        authority.status,
        AuthorityStatus::Active | AuthorityStatus::Retiring | AuthorityStatus::Retired
    );
    let expired = authority.status == AuthorityStatus::Expired
        || authority
            .not_after
            .map(|not_after| not_after <= now)
            .unwrap_or(true);
    if serving_cached
        && (status_allowed || authority.status == AuthorityStatus::Expired)
        && authority.status != AuthorityStatus::Revoked
    {
        return Ok(());
    }
    if status_allowed && !expired {
        Ok(())
    } else {
        Err(AppError::not_found(
            "authority has no publishable CRL for this lifecycle state",
        ))
    }
}

fn issuer_crl_lock_id(issuer_id: Uuid) -> i64 {
    let bytes = issuer_id.as_bytes();
    let first = i64::from_be_bytes(bytes[..8].try_into().expect("UUID first half"));
    let second = i64::from_be_bytes(bytes[8..].try_into().expect("UUID second half"));
    first ^ second ^ ISSUER_CRL_LOCK_DOMAIN
}

fn crl_revocation_reason(reason: &str) -> RevocationReason {
    match reason {
        "key_compromise" => RevocationReason::KeyCompromise,
        "ca_compromise" => RevocationReason::CaCompromise,
        "affiliation_changed" => RevocationReason::AffiliationChanged,
        "superseded" => RevocationReason::Superseded,
        "cessation_of_operation" => RevocationReason::CessationOfOperation,
        "certificate_hold" => RevocationReason::CertificateHold,
        "remove_from_crl" => RevocationReason::RemoveFromCrl,
        "privilege_withdrawn" => RevocationReason::PrivilegeWithdrawn,
        "aa_compromise" => RevocationReason::AaCompromise,
        _ => RevocationReason::Unspecified,
    }
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, value).as_ref())
}

fn is_unique_violation(err: &AppError) -> bool {
    matches!(
        err,
        AppError::Database(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505")
    )
}

async fn begin_lifecycle_transaction<'a>(
    pool: &'a sqlx::PgPool,
    operation: &'static str,
) -> Result<sqlx::Transaction<'a, sqlx::Postgres>, AppError> {
    match pool.begin().await {
        Ok(tx) => Ok(tx),
        Err(error) => {
            crate::metrics::record_pki_lifecycle_operation(operation, "failure");
            Err(AppError::Database(error))
        }
    }
}

async fn commit_lifecycle_transaction<T>(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    value: T,
    operation: &'static str,
) -> Result<T, AppError> {
    let result = tx.commit().await;
    record_lifecycle_commit(operation, &result);
    result.map(|_| value).map_err(AppError::Database)
}

fn record_lifecycle_precommit_failure<T>(
    operation: &'static str,
    result: &Result<T, AppError>,
) {
    if result.is_err() {
        crate::metrics::record_pki_lifecycle_operation(operation, "failure");
    }
}

/// Record an operation only after the owner of a transaction has observed its
/// final commit result. Transactional transports use this after their audit +
/// mutation commit; `_in_tx` helpers record only pre-commit failures.
pub(crate) fn record_lifecycle_commit<T, E>(
    operation: &'static str,
    result: &Result<T, E>,
) {
    crate::metrics::record_pki_lifecycle_operation(
        operation,
        if result.is_ok() { "success" } else { "failure" },
    );
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

fn serial_to_string(serial: &SerialNumber) -> String {
    hex::encode(serial.to_bytes())
}

fn serial_bytes(serial_number: &str) -> Result<Vec<u8>, AppError> {
    hex::decode(normalize_serial(serial_number)?)
        .map_err(|_| AppError::bad_request("invalid certificate serial number"))
}

fn to_chrono(value: OffsetDateTime) -> Result<DateTime<Utc>, AppError> {
    DateTime::<Utc>::from_timestamp(value.unix_timestamp(), value.nanosecond())
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("invalid certificate timestamp")))
}

fn to_offset(value: DateTime<Utc>) -> Result<OffsetDateTime, AppError> {
    OffsetDateTime::from_unix_timestamp(value.timestamp())
        .map(|time| time + Duration::nanoseconds(value.timestamp_subsec_nanos() as i64))
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid certificate timestamp")))
}

fn ocsp_time(value: DateTime<Utc>) -> Result<OcspGeneralizedTime, AppError> {
    let seconds = u64::try_from(value.timestamp())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid OCSP timestamp")))?;
    GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map(OcspGeneralizedTime)
        .map_err(der_err)
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != ':' && !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn certificate_chain_from_pem(chain_pem: &str) -> Result<Vec<Vec<u8>>, AppError> {
    let mut remaining = chain_pem.as_bytes();
    let mut certificates = Vec::new();
    while !remaining.iter().all(u8::is_ascii_whitespace) {
        let (rest, pem) = parse_x509_pem(remaining)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid OCSP signer chain PEM")))?;
        if pem.label != "CERTIFICATE" {
            return Err(AppError::Internal(anyhow::anyhow!(
                "OCSP signer chain contains non-certificate material"
            )));
        }
        certificates.push(pem.contents);
        remaining = rest;
    }
    if certificates.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "OCSP signer chain is empty"
        )));
    }
    Ok(certificates)
}

fn encode_signed_ocsp<F>(
    certificate_chain_der: Vec<Vec<u8>>,
    responses: Vec<SingleResponse>,
    nonce: Option<&[u8]>,
    produced_at: OcspGeneralizedTime,
    sign: F,
) -> Result<Vec<u8>, AppError>
where
    F: FnOnce(&[u8]) -> Result<(pki_core::PkiSignatureAlgorithm, Vec<u8>), AppError>,
{
    let certificates = certificate_chain_der
        .iter()
        .map(|certificate_der| {
            X509Certificate::from_der(certificate_der).map_err(|_| {
                AppError::Internal(anyhow::anyhow!(
                    "OCSP signer chain contains invalid certificate DER"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let responder_name = certificates
        .first()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("OCSP signer chain is empty")))?
        .tbs_certificate
        .subject
        .clone();
    let response_extensions = if let Some(nonce) = nonce {
        let nonce_der = Nonce::new(nonce.to_vec())
            .map_err(der_err)?
            .to_der()
            .map_err(der_err)?;
        Some(vec![Extension {
            extn_id: ID_PKIX_OCSP_NONCE,
            critical: false,
            extn_value: OctetString::new(nonce_der).map_err(der_err)?,
        }])
    } else {
        None
    };
    let response_data = ResponseData {
        version: Version::default(),
        responder_id: ResponderId::ByName(responder_name),
        produced_at,
        responses,
        response_extensions,
    };
    let response_data_der = response_data.to_der().map_err(der_err)?;
    let (algorithm, signature) = sign(&response_data_der)?;
    let basic = BasicOcspResponse {
        tbs_response_data: response_data,
        signature_algorithm: ocsp_signature_algorithm_identifier(algorithm),
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
        certs: Some(certificates),
    };
    OcspResponse::successful(basic)
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)
}

fn ocsp_signature_algorithm_identifier(
    algorithm: pki_core::PkiSignatureAlgorithm,
) -> AlgorithmIdentifierOwned {
    use pki_core::PkiSignatureAlgorithm;

    let (oid, rsa_parameters) = match algorithm {
        PkiSignatureAlgorithm::RsaPkcs1Sha256 => {
            (ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"), true)
        }
        PkiSignatureAlgorithm::RsaPkcs1Sha384 => {
            (ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"), true)
        }
        PkiSignatureAlgorithm::RsaPkcs1Sha512 => {
            (ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"), true)
        }
        PkiSignatureAlgorithm::EcdsaSha256 => {
            (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), false)
        }
        PkiSignatureAlgorithm::EcdsaSha384 => {
            (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), false)
        }
        PkiSignatureAlgorithm::EcdsaSha512 => {
            (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"), false)
        }
        PkiSignatureAlgorithm::Ed25519 => (ObjectIdentifier::new_unwrap("1.3.101.112"), false),
    };
    AlgorithmIdentifierOwned {
        oid,
        parameters: rsa_parameters.then(|| Null.into()),
    }
}

fn rcgen_err(err: rcgen::Error) -> AppError {
    AppError::Internal(anyhow::anyhow!("certificate error: {err}"))
}

fn der_err(error: der::Error) -> AppError {
    AppError::Internal(anyhow::anyhow!("OCSP DER error: {error}"))
}

pub fn unsuccessful_ocsp(status: OcspResponseStatus) -> Result<Vec<u8>, AppError> {
    OcspResponse {
        response_status: status,
        response_bytes: None,
    }
    .to_der()
    .map_err(der_err)
}

#[cfg(test)]
mod tests {
    use rcgen::BasicConstraints;
    use std::{fs, path::PathBuf};

    use super::*;

    fn config() -> Config {
        Config {
            certs_enabled: true,
            certs_ca_mode: crate::config::CertsCaMode::FileIntermediateIssuer,
            ..Config::for_tests()
        }
    }

    struct TestCaFiles {
        _dir: PathBuf,
        root_cert_path: PathBuf,
        root_key_path: PathBuf,
        intermediate_cert_path: PathBuf,
        intermediate_key_path: PathBuf,
    }

    fn ca_params_for_test(common_name: &str, valid_for_secs: i64) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc() - Duration::seconds(60);
        params.not_after = OffsetDateTime::now_utc() + Duration::seconds(valid_for_secs);
        params
    }

    fn leaf_params_for_test(common_name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.not_before = OffsetDateTime::now_utc() - Duration::seconds(60);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(1);
        params
    }

    fn test_ca_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("atom-service-certs-{label}-{}", Uuid::new_v4()))
    }

    fn write_ca_files(
        label: &str,
        root_valid_secs: i64,
        intermediate_valid_secs: i64,
    ) -> TestCaFiles {
        let dir = test_ca_dir(label);
        fs::create_dir_all(&dir).expect("ca dir");
        let root_key = KeyPair::generate().expect("root key");
        let root_key_pem = root_key.serialize_pem();
        let root_params = ca_params_for_test("Atom Test Root", root_valid_secs);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let root_issuer = Issuer::new(root_params, root_key);

        let intermediate_key = KeyPair::generate().expect("intermediate key");
        let intermediate_cert =
            ca_params_for_test("Atom Test Intermediate", intermediate_valid_secs)
                .signed_by(&intermediate_key, &root_issuer)
                .expect("intermediate cert");

        let root_cert_path = dir.join("root-ca.crt");
        let root_key_path = dir.join("root-ca.key");
        let intermediate_cert_path = dir.join("intermediate-ca.crt");
        let intermediate_key_path = dir.join("intermediate-ca.key");
        fs::write(&root_cert_path, root_cert.pem()).expect("write root cert");
        fs::write(&root_key_path, root_key_pem).expect("write root key");
        fs::write(&intermediate_cert_path, intermediate_cert.pem())
            .expect("write intermediate cert");
        fs::write(&intermediate_key_path, intermediate_key.serialize_pem())
            .expect("write intermediate key");

        TestCaFiles {
            _dir: dir,
            root_cert_path,
            root_key_path,
            intermediate_cert_path,
            intermediate_key_path,
        }
    }

    fn config_for_intermediate(files: &TestCaFiles) -> Config {
        let mut cfg = config();
        cfg.certs_ca_mode = crate::config::CertsCaMode::FileIntermediateIssuer;
        cfg.certs_root_ca_cert_path = Some(files.root_cert_path.to_string_lossy().into_owned());
        cfg.certs_intermediate_ca_cert_path =
            Some(files.intermediate_cert_path.to_string_lossy().into_owned());
        cfg.certs_intermediate_ca_key_path =
            Some(files.intermediate_key_path.to_string_lossy().into_owned());
        cfg
    }

    fn config_for_root(files: &TestCaFiles) -> Config {
        let mut cfg = config();
        cfg.certs_ca_mode = crate::config::CertsCaMode::FileRootIssuer;
        cfg.certs_root_ca_cert_path = Some(files.root_cert_path.to_string_lossy().into_owned());
        cfg.certs_root_ca_key_path = Some(files.root_key_path.to_string_lossy().into_owned());
        cfg
    }

    fn issuer_load_err(cfg: &Config) -> AppError {
        match load_file_issuer_if_enabled(cfg) {
            Ok(_) => panic!("expected issuer load failure"),
            Err(err) => err,
        }
    }

    #[test]
    fn normalizes_serial_numbers() {
        assert_eq!(normalize_serial("AA:bb 01").unwrap(), "aabb01");
        assert!(normalize_serial("not-hex").is_err());
    }

    #[test]
    fn missing_file_paths_fail_startup() {
        let err = issuer_load_err(&config());
        assert!(err
            .to_string()
            .contains("ATOM_CERTS_ROOT_CA_CERT_PATH must be set"));
    }

    #[test]
    fn root_file_issuer_loads_and_publishes_root_chain() {
        let files = write_ca_files("root-loads", 86_400, 86_400);
        let cfg = config_for_root(&files);
        let issuer = load_file_issuer_if_enabled(&cfg).unwrap().unwrap();
        let chain = ca_chain(&cfg, Some(&issuer)).unwrap();

        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 1);
    }

    #[test]
    fn intermediate_file_issuer_publishes_intermediate_then_root_chain() {
        let files = write_ca_files("intermediate-chain", 86_400, 86_400);
        let cfg = config_for_intermediate(&files);
        let issuer = load_file_issuer_if_enabled(&cfg).unwrap().unwrap();
        let chain = ca_chain(&cfg, Some(&issuer)).unwrap();

        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        let first_der = parse_x509_pem(chain.as_bytes()).unwrap().1.contents;
        let (_, first_cert) = x509_parser::parse_x509_certificate(&first_der).unwrap();
        assert!(first_cert.subject().to_string().contains("Intermediate"));
    }

    #[test]
    fn intermediate_private_key_must_match_certificate() {
        let files = write_ca_files("key-mismatch", 86_400, 86_400);
        fs::write(
            &files.intermediate_key_path,
            KeyPair::generate().unwrap().serialize_pem(),
        )
        .expect("replace intermediate key");
        let err = issuer_load_err(&config_for_intermediate(&files));

        assert!(err
            .to_string()
            .contains("issuer private key does not match issuer certificate"));
    }

    #[test]
    fn intermediate_must_be_signed_by_root() {
        let files = write_ca_files("bad-chain", 86_400, 86_400);
        let unrelated_key = KeyPair::generate().expect("unrelated key");
        let unrelated_cert = ca_params_for_test("Unrelated Intermediate", 86_400)
            .self_signed(&unrelated_key)
            .expect("unrelated cert");
        fs::write(&files.intermediate_cert_path, unrelated_cert.pem()).expect("replace cert");
        fs::write(&files.intermediate_key_path, unrelated_key.serialize_pem())
            .expect("replace key");
        let err = issuer_load_err(&config_for_intermediate(&files));

        assert!(err
            .to_string()
            .contains("intermediate CA is not signed by root CA"));
    }

    #[test]
    fn expired_ca_certificate_fails_startup() {
        let files = write_ca_files("expired", -1, 86_400);
        let err = issuer_load_err(&config_for_intermediate(&files));

        assert!(err.to_string().contains("root CA is expired"));
    }

    #[test]
    fn non_ca_issuer_certificate_fails_startup() {
        let files = write_ca_files("not-ca", 86_400, 86_400);
        let key = KeyPair::generate().expect("leaf key");
        let cert = leaf_params_for_test("not-a-ca")
            .self_signed(&key)
            .expect("leaf cert");
        fs::write(&files.root_cert_path, cert.pem()).expect("replace root cert");
        fs::write(&files.root_key_path, key.serialize_pem()).expect("replace root key");
        let err = issuer_load_err(&config_for_root(&files));

        assert!(err.to_string().contains("root CA must be a CA certificate"));
    }

    #[test]
    fn leaf_validity_cannot_exceed_file_issuer_validity() {
        let files = write_ca_files("issuer-validity", 86_400, 60);
        let cfg = config_for_intermediate(&files);
        let issuer = load_file_issuer_if_enabled(&cfg).unwrap().unwrap();
        let err =
            ensure_issuer_covers_leaf(&issuer, OffsetDateTime::now_utc() + Duration::hours(1))
                .unwrap_err();

        assert!(err
            .to_string()
            .contains("exceeds active issuer CA validity"));
    }

    #[test]
    fn certificate_fingerprint_uses_der_not_pem_text() {
        let key = KeyPair::generate().expect("key");
        let mut params =
            CertificateParams::new(vec!["device.example".to_string()]).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "device.example");
        let cert = params.self_signed(&key).expect("cert");
        let pem = cert.pem();
        let fingerprint = certificate_fingerprint_sha256(&pem).expect("fingerprint");
        let der = certificate_der_from_pem(&pem).expect("der");
        let expected = digest::digest(&digest::SHA256, &der);
        let pem_text_hash = digest::digest(&digest::SHA256, pem.as_bytes());

        assert_eq!(fingerprint, hex::encode(expected.as_ref()));
        assert_ne!(fingerprint, hex::encode(pem_text_hash.as_ref()));
    }

    #[test]
    fn leaf_ttl_rejects_values_above_max() {
        let cfg = config();
        assert_eq!(leaf_ttl(&cfg, Some(60)).unwrap(), 60);
        let err = leaf_ttl(&cfg, Some(cfg.certs_leaf_max_ttl_secs + 1)).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn csr_params_are_forced_to_leaf_client_auth() {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        force_leaf_csr_params(&mut params);

        assert!(matches!(params.is_ca, IsCa::NoCa));
        assert_eq!(
            params.key_usages,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment
            ]
        );
        assert_eq!(
            params.extended_key_usages,
            vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth
            ]
        );
    }

    #[test]
    fn ocsp_issuer_hashes_must_match_intermediate() {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Atom Test Intermediate");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).expect("cert");
        let der = certificate_der_from_pem(&cert.pem()).expect("der");
        for (algorithm, oid) in [
            (OcspHashAlgorithm::Sha1, SHA1_OID),
            (OcspHashAlgorithm::Sha256, SHA256_OID),
        ] {
            let (name_hash, key_hash) = issuer_hashes_from_der(&der, algorithm).expect("hashes");
            let serial = [1, 2, 3, 4];
            let good = x509_ocsp::CertId {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid,
                    parameters: Some(Null.into()),
                },
                issuer_name_hash: OctetString::new(name_hash).expect("name hash"),
                issuer_key_hash: OctetString::new(key_hash.clone()).expect("key hash"),
                serial_number: x509_cert::serial_number::SerialNumber::new(&serial)
                    .expect("serial"),
            };
            let bad = x509_ocsp::CertId {
                issuer_name_hash: OctetString::new(vec![0; key_hash.len()]).expect("bad hash"),
                ..good.clone()
            };

            assert!(certid_issuer_matches(&good, &der).unwrap());
            assert!(!certid_issuer_matches(&bad, &der).unwrap());
        }
    }

    #[test]
    fn crl_cache_regenerates_only_when_dirty_missing_or_expired() {
        let now = Utc::now();
        let fresh = repo::CrlState {
            issuer_fingerprint_sha256: "a".repeat(64),
            crl_number: 1,
            crl_der: Some(vec![1, 2, 3]),
            crl_sha256: Some(sha256_hex(&[1, 2, 3])),
            this_update: Some(now),
            next_update: Some(now + chrono::Duration::hours(1)),
            dirty: false,
        };
        assert!(!should_regenerate_crl(&fresh, now));

        let mut dirty = fresh.clone();
        dirty.dirty = true;
        assert!(should_regenerate_crl(&dirty, now));

        let mut missing = fresh.clone();
        missing.crl_der = None;
        assert!(should_regenerate_crl(&missing, now));

        let mut expired = fresh;
        expired.next_update = Some(now - chrono::Duration::seconds(1));
        assert!(should_regenerate_crl(&expired, now));
    }

    #[test]
    fn crl_reason_codes_follow_rfc_5280_values() {
        assert_eq!(
            crl_revocation_reason("key_compromise"),
            RevocationReason::KeyCompromise
        );
        assert_eq!(
            crl_revocation_reason("ca_compromise"),
            RevocationReason::CaCompromise
        );
        assert_eq!(
            crl_revocation_reason("affiliation_changed"),
            RevocationReason::AffiliationChanged
        );
        assert_eq!(
            crl_revocation_reason("superseded"),
            RevocationReason::Superseded
        );
        assert_eq!(
            crl_revocation_reason("cessation_of_operation"),
            RevocationReason::CessationOfOperation
        );
        assert_eq!(
            crl_revocation_reason("certificate_hold"),
            RevocationReason::CertificateHold
        );
        assert_eq!(
            crl_revocation_reason("remove_from_crl"),
            RevocationReason::RemoveFromCrl
        );
        assert_eq!(
            crl_revocation_reason("privilege_withdrawn"),
            RevocationReason::PrivilegeWithdrawn
        );
        assert_eq!(
            crl_revocation_reason("aa_compromise"),
            RevocationReason::AaCompromise
        );
        assert_eq!(
            crl_revocation_reason("operator_specific_reason"),
            RevocationReason::Unspecified
        );
    }

    #[test]
    fn one_time_private_key_debug_is_redacted() {
        let secret = "-----BEGIN PRIVATE KEY-----\ntest-secret\n-----END PRIVATE KEY-----";
        let key = OneTimePrivateKey::new(secret.to_string());
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(secret));
        assert!(!debug.contains("test-secret"));
    }
}
