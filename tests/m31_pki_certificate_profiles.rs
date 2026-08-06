//! PR-004 stored-profile and PKI-core integration coverage.
//!
//! Requires PostgreSQL and OpenSSL. The CI database matrix runs this ignored
//! binary on a freshly migrated database.

mod common;

use std::{
    io::Write,
    process::{Command, Stdio},
};

use atom::certs::{
    pki_core::{issue_from_csr_at, IssueFromCsr, IssuedCertificate, PkiIssuer},
    profile::{self, CertificateProfile},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Timelike, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::{pem::parse_x509_pem, prelude::ParsedExtension};

const OCSP_URL: &str = "https://pki.example.test/issuers/test/ocsp";
const CA_ISSUERS_URL: &str = "https://pki.example.test/issuers/test/ca.der";
const CRL_URL: &str = "https://pki.example.test/issuers/test/crl.der";

#[tokio::test]
#[ignore]
async fn stored_profiles_and_pki_core_enforce_the_pr004_contract() {
    let pool = common::pool().await;
    let tenant_id = create_tenant(&pool).await;
    let tenant_entity_id = create_entity(&pool, Some(tenant_id), "tenant-subject").await;
    let global_entity_id = create_entity(&pool, None, "global-subject").await;
    let tenant_subject = profile::load_subject(&pool, tenant_entity_id)
        .await
        .unwrap();
    let global_subject = profile::load_subject(&pool, global_entity_id)
        .await
        .unwrap();

    let client = profile::resolve_for_subject(&pool, &tenant_subject, "client")
        .await
        .unwrap();
    let server = profile::resolve_for_subject(&pool, &tenant_subject, "server")
        .await
        .unwrap();
    assert_eq!(client.extended_key_usages.len(), 1);
    assert_eq!(server.extended_key_usages.len(), 1);

    let combined_id = insert_platform_profile(
        &pool,
        "combined",
        3600,
        7200,
        json!({
            "dns":{"mode":"deny","values":[]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
        &["digital_signature"],
        &["client_auth", "server_auth"],
    )
    .await;
    let combined = profile::resolve_for_subject(&pool, &tenant_subject, "combined")
        .await
        .unwrap();
    assert_eq!(combined.id, combined_id);

    let now = Utc::now().with_nanosecond(0).unwrap();
    let issuer = test_issuer(now, 30 * 24 * 60 * 60);
    let plain_csr = csr(|_| {});
    let client_cert = issue(&client, &tenant_subject, &issuer, &plain_csr, None, now).unwrap();
    let server_cert = issue(&server, &tenant_subject, &issuer, &plain_csr, None, now).unwrap();
    let combined_cert = issue(&combined, &tenant_subject, &issuer, &plain_csr, None, now).unwrap();

    assert_eku(&client_cert, true, false);
    assert_eku(&server_cert, false, true);
    assert_eku(&combined_cert, true, true);
    assert_eq!(
        client_cert.identity_uri,
        format!("urn:atom:tenant:{tenant_id}:entity:{tenant_entity_id}")
    );
    assert_discovery_extensions(&client_cert);

    let global_client = profile::resolve_for_subject(&pool, &global_subject, "client")
        .await
        .unwrap();
    let global_cert = issue(
        &global_client,
        &global_subject,
        &issuer,
        &plain_csr,
        None,
        now,
    )
    .unwrap();
    assert_eq!(
        global_cert.identity_uri,
        format!("urn:atom:entity:{global_entity_id}")
    );

    assert!(issue(&client, &tenant_subject, &issuer, "not a CSR", None, now).is_err());
    assert!(issue(
        &client,
        &tenant_subject,
        &issuer,
        &corrupt_csr_signature(&plain_csr),
        None,
        now
    )
    .is_err());

    let ca_csr = csr(|params| {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    });
    assert!(issue(&client, &tenant_subject, &issuer, &ca_csr, None, now).is_err());
    let ca_usage_csr = csr(|params| params.key_usages = vec![KeyUsagePurpose::KeyCertSign]);
    assert!(issue(&client, &tenant_subject, &issuer, &ca_usage_csr, None, now).is_err());

    let substituted_identity = csr(|params| {
        params.subject_alt_names = vec![SanType::URI(
            "urn:atom:tenant:attacker:entity:attacker"
                .try_into()
                .unwrap(),
        )];
    });
    assert!(issue(
        &client,
        &tenant_subject,
        &issuer,
        &substituted_identity,
        None,
        now
    )
    .is_err());
    let arbitrary_eku =
        csr(|params| params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth]);
    assert!(issue(&client, &tenant_subject, &issuer, &arbitrary_eku, None, now).is_err());

    let mut wrong_size_profile = client.clone();
    wrong_size_profile.permitted_key_algorithms[0].sizes = vec![384];
    assert!(issue(
        &wrong_size_profile,
        &tenant_subject,
        &issuer,
        &plain_csr,
        None,
        now
    )
    .is_err());

    insert_platform_profile(
        &pool,
        "dns_allowlist",
        3600,
        7200,
        json!({
            "dns":{"mode":"allowlist","values":["api.example.test","backup.example.test"]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
        &["digital_signature"],
        &["server_auth"],
    )
    .await;
    let dns_allowlist = profile::resolve_for_subject(&pool, &tenant_subject, "dns_allowlist")
        .await
        .unwrap();
    let allowed_dns_csr = csr(|params| {
        params.subject_alt_names = vec![SanType::DnsName("api.example.test".try_into().unwrap())]
    });
    let dns_allowlist_cert = issue(
        &dns_allowlist,
        &tenant_subject,
        &issuer,
        &allowed_dns_csr,
        None,
        now,
    )
    .unwrap();
    let outside_dns_csr = csr(|params| {
        params.subject_alt_names =
            vec![SanType::DnsName("outside.example.test".try_into().unwrap())]
    });
    assert!(issue(
        &dns_allowlist,
        &tenant_subject,
        &issuer,
        &outside_dns_csr,
        None,
        now
    )
    .is_err());

    insert_platform_profile(
        &pool,
        "dns_template",
        3600,
        7200,
        json!({
            "dns":{"mode":"entity_template","values":["{entity_id}.entities.example.test"]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
        &["digital_signature"],
        &["server_auth"],
    )
    .await;
    let dns_template = profile::resolve_for_subject(&pool, &tenant_subject, "dns_template")
        .await
        .unwrap();
    let expected_dns = format!("{tenant_entity_id}.entities.example.test");
    let template_csr = csr(|params| {
        params.subject_alt_names = vec![SanType::DnsName(expected_dns.clone().try_into().unwrap())]
    });
    let dns_template_cert = issue(
        &dns_template,
        &tenant_subject,
        &issuer,
        &template_csr,
        None,
        now,
    )
    .unwrap();
    assert_eq!(dns_template_cert.dns_names, [expected_dns]);
    let template_violation = csr(|params| {
        params.subject_alt_names = vec![SanType::DnsName(
            "another.entities.example.test".try_into().unwrap(),
        )]
    });
    assert!(issue(
        &dns_template,
        &tenant_subject,
        &issuer,
        &template_violation,
        None,
        now
    )
    .is_err());

    let ceiling_id = insert_platform_profile(
        &pool,
        "tenant_ceiling",
        3600,
        7200,
        json!({
            "dns":{"mode":"allowlist","values":["one.example.test","two.example.test"]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
        &["digital_signature"],
        &["server_auth"],
    )
    .await;
    let widened_ttl = insert_tenant_override(
        &pool,
        tenant_id,
        ceiling_id,
        3600,
        7201,
        json!({
            "dns":{"mode":"allowlist","values":["one.example.test"]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
    )
    .await;
    assert_check_violation(widened_ttl);
    let widened_san = insert_tenant_override(
        &pool,
        tenant_id,
        ceiling_id,
        1800,
        3600,
        json!({
            "dns":{"mode":"allowlist","values":["outside.example.test"]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
    )
    .await;
    assert_check_violation(widened_san);
    insert_tenant_override(
        &pool,
        tenant_id,
        ceiling_id,
        1800,
        3600,
        json!({
            "dns":{"mode":"allowlist","values":["one.example.test"]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }),
    )
    .await
    .unwrap();
    let tenant_override = profile::resolve_for_subject(&pool, &tenant_subject, "tenant_ceiling")
        .await
        .unwrap();
    assert_eq!(tenant_override.maximum_ttl_seconds, 3600);
    assert!(issue(
        &tenant_override,
        &tenant_subject,
        &issuer,
        &csr(|params| {
            params.subject_alt_names =
                vec![SanType::DnsName("one.example.test".try_into().unwrap())]
        }),
        Some(3601),
        now
    )
    .is_err());
    let tenant_override_cert = issue(
        &tenant_override,
        &tenant_subject,
        &issuer,
        &csr(|params| {
            params.subject_alt_names =
                vec![SanType::DnsName("one.example.test".try_into().unwrap())]
        }),
        Some(3600),
        now,
    )
    .unwrap();

    let boundary_issuer = test_issuer(now, 3600);
    let mut boundary_profile = client.clone();
    boundary_profile.default_ttl_seconds = 3600;
    boundary_profile.maximum_ttl_seconds = 3601;
    assert!(issue(
        &boundary_profile,
        &tenant_subject,
        &boundary_issuer,
        &plain_csr,
        Some(3600),
        now
    )
    .is_ok());
    assert!(issue(
        &boundary_profile,
        &tenant_subject,
        &boundary_issuer,
        &plain_csr,
        Some(3601),
        now
    )
    .is_err());

    // OpenSSL independently inspects every stored profile shape exercised by
    // this delivery, including the explicit client/server combination.
    for certificate in [
        &client_cert,
        &server_cert,
        &combined_cert,
        &global_cert,
        &dns_allowlist_cert,
        &dns_template_cert,
        &tenant_override_cert,
    ] {
        assert_openssl_profile(certificate);
    }
}

fn issue(
    profile: &CertificateProfile,
    subject: &profile::StoredSubject,
    issuer: &PkiIssuer,
    csr_pem: &str,
    ttl: Option<u64>,
    now: DateTime<Utc>,
) -> Result<IssuedCertificate, atom::error::AppError> {
    issue_from_csr_at(
        profile,
        subject,
        issuer,
        IssueFromCsr {
            csr_pem,
            requested_ttl_seconds: ttl,
        },
        now,
    )
}

fn test_issuer(now: DateTime<Utc>, validity_seconds: i64) -> PkiIssuer {
    let now = OffsetDateTime::from_unix_timestamp(now.timestamp()).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "PR-004 Test Issuer");
    params.serial_number = Some(SerialNumber::from(1_u64));
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::seconds(validity_seconds);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    let certificate = params.self_signed(&key).unwrap();
    let certificate_pem = certificate.pem();
    PkiIssuer::from_pem(
        &certificate_pem,
        &key.serialize_pem(),
        &certificate_pem,
        OCSP_URL,
        CA_ISSUERS_URL,
        CRL_URL,
    )
    .unwrap()
}

fn csr(mutate: impl FnOnce(&mut CertificateParams)) -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "untrusted request subject");
    mutate(&mut params);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

fn corrupt_csr_signature(csr_pem: &str) -> String {
    let (_, pem) = parse_x509_pem(csr_pem.as_bytes()).unwrap();
    let mut der = pem.contents;
    let last = der.last_mut().unwrap();
    *last ^= 0x01;
    pem_encode("CERTIFICATE REQUEST", &der)
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend(chunk.iter().map(|byte| char::from(*byte)));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn assert_eku(certificate: &IssuedCertificate, client: bool, server: bool) {
    let (_, parsed) = x509_parser::parse_x509_certificate(&certificate.certificate_der).unwrap();
    let eku = parsed.extended_key_usage().unwrap().unwrap();
    assert_eq!(eku.value.client_auth, client);
    assert_eq!(eku.value.server_auth, server);
}

fn assert_discovery_extensions(certificate: &IssuedCertificate) {
    let (_, parsed) = x509_parser::parse_x509_certificate(&certificate.certificate_der).unwrap();
    let mut found_aia = false;
    let mut found_cdp = false;
    for extension in parsed.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::AuthorityInfoAccess(access) => {
                let rendered = format!("{access:?}");
                assert!(rendered.contains(OCSP_URL));
                assert!(rendered.contains(CA_ISSUERS_URL));
                found_aia = true;
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                assert!(format!("{points:?}").contains(CRL_URL));
                found_cdp = true;
            }
            _ => {}
        }
    }
    assert!(found_aia && found_cdp);
}

fn assert_openssl_profile(certificate: &IssuedCertificate) {
    let mut child = Command::new("openssl")
        .args(["x509", "-noout", "-text"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("OpenSSL must be installed for mandatory PR-004 inspection");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(certificate.certificate_pem.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "OpenSSL inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(&certificate.identity_uri));
    assert!(text.contains(OCSP_URL));
    assert!(text.contains(CA_ISSUERS_URL));
    assert!(text.contains(CRL_URL));
    assert!(text.contains("CA:FALSE"));
}

async fn create_tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("pki-profile-{id}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn create_entity(pool: &PgPool, tenant_id: Option<Uuid>, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("{prefix}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_platform_profile(
    pool: &PgPool,
    name: &str,
    default_ttl: i64,
    maximum_ttl: i64,
    san_policy: Value,
    key_usages: &[&str],
    extended_key_usages: &[&str],
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO certificate_profiles (
            id, name, permitted_key_algorithms, default_ttl_seconds,
            maximum_ttl_seconds, renewal_threshold_seconds, key_usages,
            extended_key_usages, san_policy, identity_uri_template,
            basic_constraints
        ) VALUES (
            $1, $2, '[{"algorithm":"ecdsa","sizes":[256]}]'::jsonb,
            $3, $4, 600, $5, $6, $7,
            'urn:atom:{scope}entity:{entity_id}',
            '{"ca":false,"path_len":null}'::jsonb
        )
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(default_ttl)
    .bind(maximum_ttl)
    .bind(key_usages)
    .bind(extended_key_usages)
    .bind(san_policy)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_tenant_override(
    pool: &PgPool,
    tenant_id: Uuid,
    base_profile_id: Uuid,
    default_ttl: i64,
    maximum_ttl: i64,
    san_policy: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO certificate_profiles (
            id, tenant_id, base_profile_id, name, permitted_key_algorithms,
            default_ttl_seconds, maximum_ttl_seconds,
            renewal_threshold_seconds, key_usages, extended_key_usages,
            san_policy, identity_uri_template, basic_constraints
        ) VALUES (
            $1, $2, $3, 'tenant_ceiling',
            '[{"algorithm":"ecdsa","sizes":[256]}]'::jsonb,
            $4, $5, 300,
            ARRAY['digital_signature']::text[],
            ARRAY['server_auth']::text[], $6,
            'urn:atom:{scope}entity:{entity_id}',
            '{"ca":false,"path_len":null}'::jsonb
        )
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(base_profile_id)
    .bind(default_ttl)
    .bind(maximum_ttl)
    .bind(san_policy)
    .execute(pool)
    .await
    .map(|_| ())
}

fn assert_check_violation(result: Result<(), sqlx::Error>) {
    let error = result.expect_err("profile widening must fail");
    assert!(matches!(
        error,
        sqlx::Error::Database(ref database) if database.code().as_deref() == Some("23514")
    ));
}
