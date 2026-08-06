//! PR-010 per-issuer OCSP status, retention, bounds, and interoperability.
//!
//! Requires PostgreSQL and OpenSSL. CI runs this ignored binary against its own
//! freshly migrated database, single-threaded.

mod common;

use std::{fs, process::Command, time::Duration as StdDuration};

use atom::{
    certs::{
        authority::{provisioning, repo as authority_repo, AuthorityStatus},
        service,
    },
    config::{CertsCaMode, Config},
    routes::create_router,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use chrono::{DateTime, Utc};
use const_oid::{db::rfc6960::ID_PKIX_OCSP_NONCE, ObjectIdentifier};
use der::{
    asn1::{Null, OctetString},
    Decode, Encode,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA256,
    PKCS_ECDSA_P521_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384,
    PKCS_RSA_SHA512,
};
use ring::digest;
use spki::AlgorithmIdentifierOwned;
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::{
    ext::{pkix::CrlReason, Extension},
    serial_number::SerialNumber,
    Certificate as X509Certificate,
};
use x509_ocsp::{
    ext::Nonce, BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse,
    OcspResponseStatus, Request as OcspSingleRequest, TbsRequest,
};
use x509_parser::pem::parse_x509_pem;

const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ECDSA_SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Clone, Copy)]
enum RequestHash {
    Sha1,
    Sha256,
}

#[tokio::test]
#[ignore]
async fn per_issuer_ocsp_enforces_the_pr010_contract() {
    let pool = common::pool().await;
    let config = common::pki::managed_config(false, false);
    let root = common::pki::test_root("PR-010 Offline Root");
    let tenant_a = common::pki::create_tenant(&pool, "pki-ocsp-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-ocsp-b").await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-ocsp-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-ocsp-b").await;
    let issuer_a = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let issuer_b = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_b).await;
    let leaf_a = issue_managed(&pool, &config, tenant_a, entity_a, "leaf-a").await;
    let leaf_b = issue_managed(&pool, &config, tenant_b, entity_b, "leaf-b").await;
    let issuer_a_pem = issuer_a.certificate_pem.as_deref().unwrap();
    let issuer_b_pem = issuer_b.certificate_pem.as_deref().unwrap();

    // Both RFC-required SHA-1 CertIDs and reviewed SHA-256 CertIDs resolve to
    // good. The managed issuer currently supports ECDSA P-256, and the
    // response algorithm is derived from that key rather than hard-coded.
    let request_a_sha1 = ocsp_request(issuer_a_pem, &leaf_a.serial_number, RequestHash::Sha1, None);
    let request_a_sha256 = ocsp_request(
        issuer_a_pem,
        &leaf_a.serial_number,
        RequestHash::Sha256,
        None,
    );
    let good_a = service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request_a_sha1)
        .await
        .unwrap();
    assert_status(&good_a, CertStatus::good());
    let good_sha256 = service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request_a_sha256)
        .await
        .unwrap();
    assert_status(&good_sha256, CertStatus::good());
    let basic_good = basic_response(&good_a);
    assert_eq!(basic_good.signature_algorithm.oid, ECDSA_SHA256_OID);
    assert!(basic_good.signature_algorithm.parameters.is_none());
    assert_response_times(&basic_good);
    assert_direct_issuer_chain(&basic_good, issuer_a_pem, &root.pem);
    assert_openssl_ocsp(
        &good_a,
        issuer_a_pem,
        &leaf_a.certificate_pem,
        &root.pem,
        "good",
    );

    // Re-evaluation advances producedAt/thisUpdate and is not a cached replay.
    tokio::time::sleep(StdDuration::from_millis(1_100)).await;
    let fresh_a = service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request_a_sha1)
        .await
        .unwrap();
    let first_time = unix_seconds(basic_good.tbs_response_data.produced_at);
    let second_time = unix_seconds(basic_response(&fresh_a).tbs_response_data.produced_at);
    assert!(second_time > first_time);
    assert_ne!(fresh_a, good_a);

    // Unknown serials and requests whose issuer hashes target another CA are
    // signed `unknown` responses from the route issuer, never serial-only hits.
    let unknown_request = ocsp_request(issuer_a_pem, "0102030405060708", RequestHash::Sha1, None);
    let unknown = service::issuer_ocsp_response(&pool, &config, issuer_a.id, &unknown_request)
        .await
        .unwrap();
    assert_status(&unknown, CertStatus::unknown());
    let wrong_issuer = service::issuer_ocsp_response(&pool, &config, issuer_b.id, &request_a_sha1)
        .await
        .unwrap();
    assert_status(&wrong_issuer, CertStatus::unknown());

    // A valid 1..32-byte request nonce is echoed exactly once. Missing nonces
    // remain absent; duplicate, empty, oversized, or misplaced nonces fail.
    let nonce = (0_u8..32).collect::<Vec<_>>();
    let nonce_request = ocsp_request(
        issuer_a_pem,
        &leaf_a.serial_number,
        RequestHash::Sha1,
        Some(&nonce),
    );
    let nonce_response = service::issuer_ocsp_response(&pool, &config, issuer_a.id, &nonce_request)
        .await
        .unwrap();
    assert_eq!(
        basic_response(&nonce_response)
            .nonce()
            .unwrap()
            .0
            .as_bytes(),
        nonce
    );
    assert!(basic_response(&good_a).nonce().is_none());
    for invalid in [Vec::new(), vec![7; 33]] {
        let request = ocsp_request(
            issuer_a_pem,
            &leaf_a.serial_number,
            RequestHash::Sha1,
            Some(&invalid),
        );
        assert_bad_request(
            service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request).await,
        );
    }
    let mut duplicate_nonce = OcspRequest::from_der(&nonce_request).unwrap();
    duplicate_nonce
        .tbs_request
        .request_extensions
        .as_mut()
        .unwrap()
        .push(nonce_extension(&[9]));
    assert_bad_request(
        service::issuer_ocsp_response(
            &pool,
            &config,
            issuer_a.id,
            &duplicate_nonce.to_der().unwrap(),
        )
        .await,
    );
    let mut misplaced_nonce = OcspRequest::from_der(&request_a_sha1).unwrap();
    misplaced_nonce.tbs_request.request_list[0].single_request_extensions =
        Some(vec![nonce_extension(&[1, 2, 3])]);
    assert_bad_request(
        service::issuer_ocsp_response(
            &pool,
            &config,
            issuer_a.id,
            &misplaced_nonce.to_der().unwrap(),
        )
        .await,
    );

    // Malformed DER, unsupported hashes, unsupported algorithm parameters,
    // and an excessive number of SingleRequests all fail without lookup.
    assert_bad_request(
        service::issuer_ocsp_response(&pool, &config, issuer_a.id, &[0x30, 0x82, 0xff]).await,
    );
    let mut unsupported_hash = OcspRequest::from_der(&request_a_sha1).unwrap();
    unsupported_hash.tbs_request.request_list[0]
        .req_cert
        .hash_algorithm
        .oid = SHA384_OID;
    assert_bad_request(
        service::issuer_ocsp_response(
            &pool,
            &config,
            issuer_a.id,
            &unsupported_hash.to_der().unwrap(),
        )
        .await,
    );
    let mut unsupported_parameters = OcspRequest::from_der(&request_a_sha1).unwrap();
    unsupported_parameters.tbs_request.request_list[0]
        .req_cert
        .hash_algorithm
        .parameters = Some(der::asn1::Any::from_der(&[0x04, 0x01, 0x01]).unwrap());
    assert_bad_request(
        service::issuer_ocsp_response(
            &pool,
            &config,
            issuer_a.id,
            &unsupported_parameters.to_der().unwrap(),
        )
        .await,
    );
    let mut too_many = OcspRequest::from_der(&request_a_sha1).unwrap();
    too_many.tbs_request.request_list = vec![too_many.tbs_request.request_list[0].clone(); 17];
    assert_bad_request(
        service::issuer_ocsp_response(&pool, &config, issuer_a.id, &too_many.to_der().unwrap())
            .await,
    );

    // HTTP delivery is an RFC response with explicit no-store policy. Unknown
    // issuer identifiers are indistinguishable, malformed input is diagnosed
    // before issuer lookup, and transport size is bounded before allocation.
    let app = create_router(common::pki::graphql_state(pool.clone(), config.clone()));
    let http_good = post_ocsp(&app, issuer_a.id, request_a_sha1.clone()).await;
    assert_eq!(http_good.status(), StatusCode::OK);
    assert_eq!(
        http_good.headers()[header::CONTENT_TYPE],
        "application/ocsp-response"
    );
    assert_eq!(
        http_good.headers()[header::CACHE_CONTROL],
        "no-store, max-age=0"
    );
    assert_status(
        &to_bytes(http_good.into_body(), usize::MAX).await.unwrap(),
        CertStatus::good(),
    );
    let unknown_one = post_ocsp(&app, Uuid::new_v4(), request_a_sha1.clone()).await;
    let unknown_two = post_ocsp(&app, Uuid::new_v4(), request_a_sha1.clone()).await;
    let unknown_one_body = to_bytes(unknown_one.into_body(), usize::MAX).await.unwrap();
    let unknown_two_body = to_bytes(unknown_two.into_body(), usize::MAX).await.unwrap();
    assert_eq!(unknown_one_body, unknown_two_body);
    assert_response_status(&unknown_one_body, OcspResponseStatus::Unauthorized);
    let malformed_unknown = post_ocsp(&app, Uuid::new_v4(), vec![1, 2, 3]).await;
    assert_response_status(
        &to_bytes(malformed_unknown.into_body(), usize::MAX)
            .await
            .unwrap(),
        OcspResponseStatus::MalformedRequest,
    );
    let oversized = post_ocsp(
        &app,
        issuer_a.id,
        vec![0; service::OCSP_REQUEST_MAX_BYTES + 1],
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Simulate the same serial under two issuers (PR-011 later changes the
    // production uniqueness model). Exact issuer+serial lookup keeps A and B
    // independent even after A is revoked.
    sqlx::query("DROP INDEX idx_credentials_certificate_serial")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET identifier = $1 WHERE id = $2")
        .bind(&leaf_a.serial_number)
        .bind(leaf_b.credential_id)
        .execute(&pool)
        .await
        .unwrap();
    let duplicate_b_request =
        ocsp_request(issuer_b_pem, &leaf_a.serial_number, RequestHash::Sha1, None);
    let duplicate_b =
        service::issuer_ocsp_response(&pool, &config, issuer_b.id, &duplicate_b_request)
            .await
            .unwrap();
    assert_status(&duplicate_b, CertStatus::good());

    revoke(
        &pool,
        leaf_a.credential_id,
        entity_a,
        tenant_a,
        "key_compromise",
    )
    .await;
    let revoked_a = service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request_a_sha1)
        .await
        .unwrap();
    let basic_revoked = basic_response(&revoked_a);
    let revoked = match basic_revoked.tbs_response_data.responses[0].cert_status {
        CertStatus::Revoked(info) => info,
        ref other => panic!("expected revoked status, got {other:?}"),
    };
    assert_eq!(revoked.revocation_reason, Some(CrlReason::KeyCompromise));
    let (recorded_at, recorded_reason): (DateTime<Utc>, String) = sqlx::query_as(
        "SELECT revoked_at, reason FROM certificate_revocations WHERE credential_id = $1",
    )
    .bind(leaf_a.credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recorded_reason, "key_compromise");
    assert_eq!(
        unix_seconds(revoked.revocation_time) as i64,
        recorded_at.timestamp()
    );
    let duplicate_b_after_revoke =
        service::issuer_ocsp_response(&pool, &config, issuer_b.id, &duplicate_b_request)
            .await
            .unwrap();
    assert_status(&duplicate_b_after_revoke, CertStatus::good());

    // Rotation retains responder availability while the old authority is
    // retiring and after it is retired. No delegated responder is used: the
    // retained issuer key signs directly and its complete chain is embedded.
    let issuer_a_v2 = common::pki::rotate_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let old = authority_repo::authority_by_id(&pool, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(old.status, AuthorityStatus::Retiring);
    let retiring_response =
        service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request_a_sha1)
            .await
            .unwrap();
    assert_status(&retiring_response, CertStatus::revoked(revoked));
    let mut tx = pool.begin().await.unwrap();
    provisioning::complete_retirement_in_tx(&mut tx, issuer_a.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let retired_response =
        service::issuer_ocsp_response(&pool, &config, issuer_a.id, &request_a_sha1)
            .await
            .unwrap();
    assert_status(&retired_response, CertStatus::revoked(revoked));
    let new_leaf = issue_managed(&pool, &config, tenant_a, entity_a, "rotated").await;
    assert_eq!(new_leaf.issuer_id, Some(issuer_a_v2.id));
    let new_request = ocsp_request(
        issuer_a_v2.certificate_pem.as_deref().unwrap(),
        &new_leaf.serial_number,
        RequestHash::Sha1,
        None,
    );
    let new_response = service::issuer_ocsp_response(&pool, &config, issuer_a_v2.id, &new_request)
        .await
        .unwrap();
    assert_status(&new_response, CertStatus::good());
}

#[tokio::test]
#[ignore]
async fn legacy_ocsp_verifies_every_supported_issuer_key_algorithm() {
    let pool = common::pool().await;
    let cases: [(&SignatureAlgorithm, ObjectIdentifier); 9] = [
        (
            &PKCS_RSA_SHA256,
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        ),
        (
            &PKCS_RSA_SHA384,
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
        ),
        (
            &PKCS_RSA_SHA512,
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
        ),
        (&PKCS_ECDSA_P256_SHA256, ECDSA_SHA256_OID),
        (
            &PKCS_ECDSA_P384_SHA384,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        ),
        (
            &PKCS_ECDSA_P521_SHA256,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        ),
        (
            &PKCS_ECDSA_P521_SHA384,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        ),
        (
            &PKCS_ECDSA_P521_SHA512,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"),
        ),
        (&PKCS_ED25519, ObjectIdentifier::new_unwrap("1.3.101.112")),
    ];

    for (index, (algorithm, expected_oid)) in cases.into_iter().enumerate() {
        let directory =
            std::env::temp_dir().join(format!("atom-pr010-alg-{index}-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let key = KeyPair::generate_for(algorithm).unwrap();
        let key_pem = key.serialize_pem();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("PR-010 Algorithm {index}"));
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(1);
        let issuer_pem = params.self_signed(&key).unwrap().pem();
        let certificate_path = directory.join("issuer.pem");
        let key_path = directory.join("issuer.key");
        fs::write(&certificate_path, &issuer_pem).unwrap();
        fs::write(&key_path, key_pem).unwrap();

        let mut config = Config::for_tests();
        config.certs_enabled = true;
        config.certs_ca_mode = CertsCaMode::FileRootIssuer;
        config.certs_root_ca_cert_path = Some(certificate_path.to_string_lossy().into_owned());
        config.certs_root_ca_key_path = Some(key_path.to_string_lossy().into_owned());
        let issuer = service::load_file_issuer_if_enabled(&config)
            .unwrap()
            .unwrap();
        let request = ocsp_request(&issuer_pem, "010203", RequestHash::Sha1, None);
        let response = service::ocsp_response(&pool, &config, Some(&issuer), &request)
            .await
            .unwrap();
        let basic = basic_response(&response);
        assert_eq!(basic.signature_algorithm.oid, expected_oid);
        assert_status(&response, CertStatus::unknown());
        assert_openssl_serial_ocsp(&response, &issuer_pem, "010203");
        fs::remove_dir_all(directory).unwrap();
    }
}

async fn issue_managed(
    pool: &PgPool,
    config: &atom::config::Config,
    tenant_id: Uuid,
    entity_id: Uuid,
    label: &str,
) -> service::CertificateRecord {
    service::issue_certificate_from_csr_v2(
        pool,
        config,
        Some(tenant_id),
        service::IssueCertificateFromCsrV2 {
            entity_id,
            ttl_secs: Some(3600),
            csr_pem: csr(label),
            idempotency_key: format!("pr010-{label}-{}", Uuid::new_v4()),
        },
    )
    .await
    .unwrap()
    .certificate
}

async fn revoke(
    pool: &PgPool,
    credential_id: Uuid,
    entity_id: Uuid,
    tenant_id: Uuid,
    reason: &str,
) {
    service::revoke_certificate_v2(
        pool,
        service::RevokeCertificateV2 {
            selector: service::CertificateRevocationSelector::CredentialId(credential_id),
            reason: Some(reason.to_string()),
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_id,
            expected_tenant_id: Some(tenant_id),
        },
    )
    .await
    .unwrap();
}

fn csr(label: &str) -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, label);
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(2);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

fn ocsp_request(
    issuer_pem: &str,
    serial_hex: &str,
    hash: RequestHash,
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    let issuer_der = parse_x509_pem(issuer_pem.as_bytes()).unwrap().1.contents;
    let (_, issuer) = x509_parser::parse_x509_certificate(&issuer_der).unwrap();
    let (oid, digest_algorithm) = match hash {
        RequestHash::Sha1 => (SHA1_OID, &digest::SHA1_FOR_LEGACY_USE_ONLY),
        RequestHash::Sha256 => (SHA256_OID, &digest::SHA256),
    };
    let name_hash = digest::digest(digest_algorithm, issuer.tbs_certificate.subject.as_raw());
    let key_hash = digest::digest(
        digest_algorithm,
        issuer
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    );
    let cert_id = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(name_hash.as_ref().to_vec()).unwrap(),
        issuer_key_hash: OctetString::new(key_hash.as_ref().to_vec()).unwrap(),
        serial_number: SerialNumber::new(&hex::decode(serial_hex).unwrap()).unwrap(),
    };
    OcspRequest {
        tbs_request: TbsRequest {
            version: Default::default(),
            requestor_name: None,
            request_list: vec![OcspSingleRequest {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions: nonce.map(|nonce| vec![nonce_extension(nonce)]),
        },
        optional_signature: None,
    }
    .to_der()
    .unwrap()
}

fn nonce_extension(bytes: &[u8]) -> Extension {
    let encoded = Nonce::new(bytes.to_vec()).unwrap().to_der().unwrap();
    Extension {
        extn_id: ID_PKIX_OCSP_NONCE,
        critical: false,
        extn_value: OctetString::new(encoded).unwrap(),
    }
}

fn basic_response(response_der: &[u8]) -> BasicOcspResponse {
    let response = OcspResponse::from_der(response_der).unwrap();
    assert_eq!(response.response_status, OcspResponseStatus::Successful);
    BasicOcspResponse::from_der(response.response_bytes.unwrap().response.as_bytes()).unwrap()
}

fn assert_status(response_der: &[u8], expected: CertStatus) {
    let basic = basic_response(response_der);
    assert_eq!(basic.tbs_response_data.responses.len(), 1);
    assert_eq!(basic.tbs_response_data.responses[0].cert_status, expected);
}

fn assert_response_status(response_der: &[u8], expected: OcspResponseStatus) {
    let response = OcspResponse::from_der(response_der).unwrap();
    assert_eq!(response.response_status, expected);
    assert!(response.response_bytes.is_none());
}

fn assert_response_times(response: &BasicOcspResponse) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let produced_at = unix_seconds(response.tbs_response_data.produced_at);
    assert!(produced_at.abs_diff(now) <= 10);
    for single in &response.tbs_response_data.responses {
        let this_update = unix_seconds(single.this_update);
        let next_update = unix_seconds(single.next_update.unwrap());
        assert_eq!(this_update, produced_at);
        assert!(next_update > this_update);
        assert!(next_update - this_update <= 300);
    }
}

fn unix_seconds(time: x509_ocsp::OcspGeneralizedTime) -> u64 {
    time.0.to_unix_duration().as_secs()
}

fn assert_direct_issuer_chain(response: &BasicOcspResponse, issuer_pem: &str, root_pem: &str) {
    let certificates = response.certs.as_ref().expect("embedded responder chain");
    assert!(certificates.len() >= 2);
    let issuer_der = parse_x509_pem(issuer_pem.as_bytes()).unwrap().1.contents;
    let root_der = parse_x509_pem(root_pem.as_bytes()).unwrap().1.contents;
    assert_eq!(certificates.first().unwrap().to_der().unwrap(), issuer_der);
    assert_eq!(certificates.last().unwrap().to_der().unwrap(), root_der);
    let typed_issuer = X509Certificate::from_der(&issuer_der).unwrap();
    assert!(matches!(
        response.tbs_response_data.responder_id,
        x509_ocsp::ResponderId::ByName(ref name)
            if name == &typed_issuer.tbs_certificate.subject
    ));
}

async fn post_ocsp(app: &axum::Router, issuer_id: Uuid, body: Vec<u8>) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/certs/issuers/{issuer_id}/ocsp"))
                .header(header::CONTENT_TYPE, "application/ocsp-request")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn assert_bad_request<T>(result: Result<T, atom::error::AppError>) {
    assert!(matches!(result, Err(atom::error::AppError::BadRequest(_))));
}

fn assert_openssl_ocsp(
    response_der: &[u8],
    issuer_pem: &str,
    certificate_pem: &str,
    root_pem: &str,
    expected_status: &str,
) {
    let directory = std::env::temp_dir().join(format!("atom-pr010-ocsp-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let response_path = directory.join("response.der");
    let issuer_path = directory.join("issuer.pem");
    let certificate_path = directory.join("certificate.pem");
    let root_path = directory.join("root.pem");
    fs::write(&response_path, response_der).unwrap();
    fs::write(&issuer_path, issuer_pem).unwrap();
    fs::write(&certificate_path, certificate_pem).unwrap();
    fs::write(&root_path, root_pem).unwrap();
    let output = Command::new("openssl")
        .arg("ocsp")
        .arg("-respin")
        .arg(&response_path)
        .arg("-issuer")
        .arg(&issuer_path)
        .arg("-cert")
        .arg(&certificate_path)
        .arg("-CAfile")
        .arg(&root_path)
        .args(["-no_nonce", "-text"])
        .output()
        .expect("OpenSSL must be installed for PR-010 verification");
    fs::remove_dir_all(directory).unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "OpenSSL OCSP verification failed: {text}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains(&format!(": {expected_status}").to_ascii_lowercase()),
        "OpenSSL did not report {expected_status}: {text}"
    );
    assert!(
        text.to_ascii_lowercase().contains("response verify ok"),
        "OpenSSL did not independently verify the response: {text}"
    );
}

fn assert_openssl_serial_ocsp(response_der: &[u8], issuer_pem: &str, serial: &str) {
    let directory = std::env::temp_dir().join(format!("atom-pr010-serial-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let response_path = directory.join("response.der");
    let issuer_path = directory.join("issuer.pem");
    fs::write(&response_path, response_der).unwrap();
    fs::write(&issuer_path, issuer_pem).unwrap();
    let output = Command::new("openssl")
        .arg("ocsp")
        .arg("-respin")
        .arg(&response_path)
        .arg("-issuer")
        .arg(&issuer_path)
        .arg("-serial")
        .arg(format!("0x{serial}"))
        .arg("-CAfile")
        .arg(&issuer_path)
        .args(["-no_nonce", "-text"])
        .output()
        .expect("OpenSSL must be installed for PR-010 verification");
    fs::remove_dir_all(directory).unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "OpenSSL OCSP verification failed: {text}"
    );
    assert!(
        text.to_ascii_lowercase().contains("response verify ok"),
        "OpenSSL did not independently verify the response: {text}"
    );
}
