use chrono::{DateTime, Datelike, Timelike, Utc};
use ocsp::{
    common::asn1::{GeneralizedTime, Oid},
    oid::{ALGO_SHA1_DOT, ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT, OCSP_RESPONSE_BASIC_DOT},
    request::OcspRequest,
    response::{
        CertStatus, CertStatusCode, CrlReason, OcspRespStatus, OcspResponse, OneResp, ResponderId,
        ResponseData, RevokedInfo,
    },
};
use rcgen::{
    CertificateParams, CertificateRevocationListParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SanType, SerialNumber, SigningKey,
};
use ring::{digest, rand, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroize;

use crate::{
    config::{CertsCaMode, Config},
    error::AppError,
};

use super::repo;

const CRL_REGEN_LOCK_ID: i64 = 0x0041_544f_4d43_524c;
const LEAF_CLOCK_SKEW_SECS: i64 = 300;
const CRL_TTL_HOURS: i64 = 24;
const SERIAL_INSERT_ATTEMPTS: usize = 3;

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
pub struct RenewCertificate {
    pub serial_number: String,
    pub ttl_secs: Option<u64>,
    pub revoke_old: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub certificate_pem: String,
    pub subject: Value,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub issuer_kind: String,
    pub issuer_subject: String,
    pub issuer_serial_number: String,
    pub issuer_fingerprint_sha256: String,
    pub fingerprint_sha256: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issued_from_csr: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateRecord {
    pub credential_id: Uuid,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub serial_number: String,
    pub status: String,
    pub certificate_pem: String,
    pub subject: Value,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub fingerprint_sha256: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub certificate: CertificateRecord,
    pub private_key_pem: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateIdentity {
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub credential_id: Uuid,
    pub expires_at: DateTime<Utc>,
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
    issuer_name_hash_sha1: Vec<u8>,
    issuer_key_hash_sha1: Vec<u8>,
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
    let (issuer_name_hash_sha1, issuer_key_hash_sha1) = issuer_sha1_hashes_from_der(&cert.der)?;
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
        issuer_name_hash_sha1,
        issuer_key_hash_sha1,
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
    let loaded = require_issuer(config, issuer)?;
    repo::entity_tenant_id(pool, input.entity_id).await?;
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
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        let key_pair = KeyPair::generate().map_err(rcgen_err)?;
        let cert = params
            .signed_by(&key_pair, &loaded.issuer)
            .map_err(rcgen_err)?;
        let mut private_key_pem = key_pair.serialize_pem();
        match persist_certificate(
            pool,
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
        .await
        {
            Ok(record) => {
                return Ok(IssuedCertificate {
                    certificate: record,
                    private_key_pem: Some(private_key_pem),
                });
            }
            Err(err) if is_unique_violation(&err) && attempt + 1 < SERIAL_INSERT_ATTEMPTS => {
                private_key_pem.zeroize();
            }
            Err(err) => {
                private_key_pem.zeroize();
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
    let loaded = require_issuer(config, issuer)?;
    repo::entity_tenant_id(pool, input.entity_id).await?;
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
        match persist_certificate(
            pool,
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
        .await
        {
            Ok(record) => {
                return Ok(IssuedCertificate {
                    certificate: record,
                    private_key_pem: None,
                });
            }
            Err(err) if is_unique_violation(&err) && attempt + 1 < SERIAL_INSERT_ATTEMPTS => {}
            Err(err) => return Err(err),
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
    let serial = normalize_serial(&input.serial_number)?;
    let old = certificate_by_serial(pool, &serial).await?;
    if old.status == "revoked" {
        return Err(AppError::bad_request("cannot renew a revoked certificate"));
    }
    let issued = issue_certificate(
        pool,
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
        revoke_certificate(pool, &serial, Some("superseded".into())).await?;
    }
    Ok(issued)
}

pub async fn revoke_certificate(
    pool: &sqlx::PgPool,
    serial_number: &str,
    reason: Option<String>,
) -> Result<CertificateRecord, AppError> {
    let serial = normalize_serial(serial_number)?;
    let current = repo::certificate_by_serial(pool, &serial).await?;
    let mut metadata = current.metadata.clone();
    let now = Utc::now();
    metadata["revoked_at"] = json!(now);
    metadata["revocation_reason"] = json!(reason.clone().unwrap_or_else(|| "unspecified".into()));
    repo::revoke_certificate(pool, current.id, metadata).await?;
    repo::mark_crl_dirty(pool).await?;
    certificate_by_serial(pool, &serial).await
}

pub async fn revoke_entity_certificates(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    reason: Option<String>,
) -> Result<usize, AppError> {
    let certs = repo::active_entity_certificates(pool, entity_id).await?;
    let count = certs.len();
    for cert in certs {
        let mut metadata = cert.metadata.clone();
        metadata["revoked_at"] = json!(Utc::now());
        metadata["revocation_reason"] =
            json!(reason.clone().unwrap_or_else(|| "entity_revoked".into()));
        repo::revoke_certificate(pool, cert.id, metadata).await?;
    }
    if count > 0 {
        repo::mark_crl_dirty(pool).await?;
    }
    Ok(count)
}

pub async fn certificate_by_serial(
    pool: &sqlx::PgPool,
    serial_number: &str,
) -> Result<CertificateRecord, AppError> {
    repo::certificate_by_serial(pool, &normalize_serial(serial_number)?)
        .await
        .and_then(record_from_row)
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
    if !should_regenerate_crl(&state, now_chrono) {
        if let Some(crl_der) = state.crl_der {
            tx.commit().await.map_err(AppError::Database)?;
            return Ok(crl_der);
        }
    }

    let revoked = repo::revoked_certificates(pool).await?;
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
    repo::store_crl_tx(
        &mut tx,
        &loaded.issuer_fingerprint_sha256,
        crl_number,
        &crl_der,
        to_chrono(now)?,
        to_chrono(next_update)?,
    )
    .await?;
    tx.commit().await.map_err(AppError::Database)?;
    Ok(crl_der)
}

pub async fn ocsp_response(
    pool: &sqlx::PgPool,
    config: &Config,
    issuer: Option<&CertificateIssuer>,
    request_der: &[u8],
) -> Result<Vec<u8>, AppError> {
    let loaded = require_issuer(config, issuer)?;
    let request = OcspRequest::parse(request_der)
        .map_err(|_| AppError::bad_request("invalid OCSP request"))?;
    let now = Utc::now();
    let this_update = generalized_time(now)?;
    let next_update = Some(generalized_time(now + chrono::Duration::hours(1))?);
    let mut one_responses = Vec::with_capacity(request.tbs_request.request_list.len());
    for one in &request.tbs_request.request_list {
        let issuer_matches = certid_issuer_matches(
            &one.certid,
            &loaded.issuer_name_hash_sha1,
            &loaded.issuer_key_hash_sha1,
        )?;
        let status = if issuer_matches {
            let serial = serial_from_ocsp_request(&one.certid.serial_num)?;
            match repo::certificate_by_serial(pool, &serial).await {
                Ok(cert) if cert.status == "active" => CertStatus::new(CertStatusCode::Good, None),
                Ok(cert) => {
                    let metadata = metadata_from_value(&cert.metadata)?;
                    let revoked_at = metadata.revoked_at.unwrap_or_else(Utc::now);
                    CertStatus::new(
                        CertStatusCode::Revoked,
                        Some(RevokedInfo::new(
                            generalized_time(revoked_at)?,
                            Some(CrlReason::OcspRevokeUnspecified),
                        )),
                    )
                }
                Err(AppError::NotFound(_)) => CertStatus::new(CertStatusCode::Unknown, None),
                Err(err) => return Err(err),
            }
        } else {
            CertStatus::new(CertStatusCode::Unknown, None)
        };
        one_responses.push(OneResp {
            cid: one.certid.clone(),
            cert_status: status,
            this_update,
            next_update,
            one_resp_ext: None,
        });
    }

    let responder = ResponderId::new_key_hash(&loaded.issuer_key_hash_sha1);
    let data = ResponseData::new(responder, this_update, one_responses, None);
    let data_der = data.to_der().map_err(ocsp_err)?;
    let signature = loaded.key_pair.sign(&data_der).map_err(rcgen_err)?;
    let oid = Oid::new_from_dot(ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT).map_err(ocsp_err)?;
    let response_type = Oid::new_from_dot(OCSP_RESPONSE_BASIC_DOT).map_err(ocsp_err)?;
    let basic = basic_ocsp_response_der(
        &data_der,
        &oid,
        &signature,
        &[loaded.certificate_der.as_slice()],
    )?;
    successful_ocsp_response_der(&response_type, &basic)
}

pub async fn resolve_certificate_identity(
    pool: &sqlx::PgPool,
    serial_number: &str,
    fingerprint_sha256: Option<&str>,
) -> Result<CertificateIdentity, AppError> {
    let record = certificate_by_serial(pool, serial_number).await?;
    if record.status != "active" {
        return Err(AppError::Unauthorized("certificate revoked".into()));
    }
    let expires_at = record
        .expires_at
        .ok_or_else(|| AppError::Unauthorized("certificate has no expiry".into()))?;
    if expires_at <= Utc::now() {
        return Err(AppError::Unauthorized("certificate expired".into()));
    }
    if let Some(expected) = fingerprint_sha256 {
        if normalize_fingerprint(expected) != normalize_fingerprint(&record.fingerprint_sha256) {
            return Err(AppError::Unauthorized(
                "certificate fingerprint mismatch".into(),
            ));
        }
    }
    repo::entity_tenant_id(pool, record.entity_id).await?;
    Ok(CertificateIdentity {
        entity_id: record.entity_id,
        tenant_id: record.tenant_id,
        credential_id: record.credential_id,
        expires_at,
    })
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
    pool: &sqlx::PgPool,
    issuer: &CertificateIssuer,
    input: PersistCertificate,
) -> Result<CertificateRecord, AppError> {
    let fingerprint_sha256 = certificate_fingerprint_sha256(&input.certificate_pem)?;
    let metadata = CertificateMetadata {
        certificate_pem: input.certificate_pem,
        subject: input.subject,
        dns_names: input.dns_names,
        ip_addresses: input.ip_addresses,
        issuer_kind: issuer.issuer_kind.to_string(),
        issuer_subject: issuer.issuer_subject.clone(),
        issuer_serial_number: issuer.issuer_serial_number.clone(),
        issuer_fingerprint_sha256: issuer.issuer_fingerprint_sha256.clone(),
        fingerprint_sha256,
        not_before: input.not_before,
        not_after: input.not_after,
        issued_from_csr: input.issued_from_csr,
        revoked_at: None,
        revocation_reason: None,
    };
    let id = repo::insert_certificate_credential(
        pool,
        input.entity_id,
        &input.serial_number,
        serde_json::to_value(metadata).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?,
        input.not_after,
    )
    .await?;
    certificate_by_id(pool, id).await
}

fn record_from_row(row: repo::CertificateCredential) -> Result<CertificateRecord, AppError> {
    let metadata = metadata_from_value(&row.metadata)?;
    Ok(CertificateRecord {
        credential_id: row.id,
        entity_id: row.entity_id,
        tenant_id: row.tenant_id,
        serial_number: row.identifier,
        status: row.status,
        certificate_pem: metadata.certificate_pem,
        subject: metadata.subject,
        dns_names: metadata.dns_names,
        ip_addresses: metadata.ip_addresses,
        fingerprint_sha256: metadata.fingerprint_sha256,
        expires_at: row.expires_at,
        created_at: row.created_at,
        revoked_at: metadata.revoked_at,
        revocation_reason: metadata.revocation_reason,
    })
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
        "active" | "revoked" => Ok(status),
        _ => Err(AppError::bad_request(
            "certificate status must be active or revoked",
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
    params.extended_key_usages.clear();
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

fn issuer_sha1_hashes_from_der(certificate_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let (_, cert) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid issuer certificate DER")))?;
    let name_hash = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        cert.tbs_certificate.subject.as_raw(),
    )
    .as_ref()
    .to_vec();
    let key_hash = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
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

fn certid_issuer_matches(
    certid: &ocsp::common::asn1::CertId,
    issuer_name_hash_sha1: &[u8],
    issuer_key_hash_sha1: &[u8],
) -> Result<bool, AppError> {
    let sha1 = Oid::new_from_dot(ALGO_SHA1_DOT).map_err(ocsp_err)?;
    Ok(certid.hash_algo == sha1
        && certid.issuer_name_hash == issuer_name_hash_sha1
        && certid.issuer_key_hash == issuer_key_hash_sha1)
}

fn serial_from_ocsp_request(serial: &[u8]) -> Result<String, AppError> {
    let trimmed = serial
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect::<Vec<_>>();
    if trimmed.is_empty() {
        return Err(AppError::bad_request("invalid certificate serial number"));
    }
    normalize_serial(&hex::encode(trimmed))
}

fn should_regenerate_crl(state: &repo::CrlState, now: DateTime<Utc>) -> bool {
    state.dirty
        || state.crl_der.is_none()
        || state
            .next_update
            .map(|next_update| next_update <= now)
            .unwrap_or(true)
}

fn is_unique_violation(err: &AppError) -> bool {
    matches!(
        err,
        AppError::Database(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505")
    )
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

fn generalized_time(value: DateTime<Utc>) -> Result<GeneralizedTime, AppError> {
    GeneralizedTime::new(
        value.year(),
        value.month(),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
    )
    .map_err(ocsp_err)
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != ':' && !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn basic_ocsp_response_der(
    response_data_der: &[u8],
    signature_oid: &Oid,
    signature: &[u8],
    certs: &[&[u8]],
) -> Result<Vec<u8>, AppError> {
    let mut body = response_data_der.to_vec();
    body.extend(signature_oid.to_der_with_null().map_err(ocsp_err)?);
    body.extend(der_bit_string(signature));
    if !certs.is_empty() {
        let cert_list = certs
            .iter()
            .flat_map(|cert| cert.iter().copied())
            .collect::<Vec<_>>();
        body.extend(der_tlv(0xa0, der_tlv(0x30, cert_list)));
    }
    Ok(der_tlv(0x30, body))
}

fn successful_ocsp_response_der(
    response_type: &Oid,
    basic_der: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut response_bytes = response_type.to_der_raw().map_err(ocsp_err)?;
    response_bytes.extend(der_tlv(0x04, basic_der.to_vec()));
    let mut body = vec![0x0a, 0x01, OcspRespStatus::Successful as u8];
    body.extend(der_tlv(0xa0, der_tlv(0x30, response_bytes)));
    Ok(der_tlv(0x30, body))
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(data.len() + 1);
    body.push(0);
    body.extend_from_slice(data);
    der_tlv(0x03, body)
}

fn der_tlv(tag: u8, value: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    out.extend(der_len(value.len()));
    out.extend(value);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len <= 127 {
        return vec![len as u8];
    }
    let bytes = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(0x80 | bytes.len() as u8);
    out.extend(bytes);
    out
}

fn rcgen_err(err: rcgen::Error) -> AppError {
    AppError::Internal(anyhow::anyhow!("certificate error: {err}"))
}

fn ocsp_err(err: ocsp::err::OcspError) -> AppError {
    AppError::Internal(anyhow::anyhow!("OCSP error: {err:?}"))
}

pub fn unsuccessful_ocsp(status: OcspRespStatus) -> Result<Vec<u8>, AppError> {
    OcspResponse::new_non_success(status)
        .map_err(ocsp_err)?
        .to_der()
        .map_err(ocsp_err)
}

#[cfg(test)]
mod tests {
    use ocsp::common::asn1::CertId;
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
        assert_eq!(params.key_usages, vec![KeyUsagePurpose::DigitalSignature]);
        assert_eq!(
            params.extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ClientAuth]
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
        let (name_hash, key_hash) = issuer_sha1_hashes_from_der(&der).expect("hashes");
        let oid = Oid::new_from_dot(ALGO_SHA1_DOT).expect("oid");
        let serial = vec![1, 2, 3, 4];
        let good = CertId::new(oid.clone(), &name_hash, &key_hash, &serial);
        let bad = CertId::new(oid, &[0; 20], &key_hash, &serial);

        assert!(certid_issuer_matches(&good, &name_hash, &key_hash).unwrap());
        assert!(!certid_issuer_matches(&bad, &name_hash, &key_hash).unwrap());
    }

    #[test]
    fn crl_cache_regenerates_only_when_dirty_missing_or_expired() {
        let now = Utc::now();
        let fresh = repo::CrlState {
            crl_number: 1,
            crl_der: Some(vec![1, 2, 3]),
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
}
