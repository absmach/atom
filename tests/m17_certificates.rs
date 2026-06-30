mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    certs::service,
    config::Config,
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use ocsp::{
    common::asn1::{CertId, Oid},
    oid::ALGO_SHA1_DOT,
    request::OneReq,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use ring::digest;
use sqlx::PgPool;
use std::{fs, path::PathBuf};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;

fn cert_config() -> Config {
    Config {
        certs_enabled: true,
        certs_ca_mode: atom::config::CertsCaMode::FileIntermediateIssuer,
        ..Config::for_tests()
    }
}

struct CertFixture {
    _dir: PathBuf,
    config: Config,
}

fn intermediate_fixture() -> CertFixture {
    let dir = test_ca_dir("intermediate");
    fs::create_dir_all(&dir).expect("create temp ca dir");

    let root_params = ca_params("Atom Test Root");
    let root_key = KeyPair::generate().expect("root key");
    let root_cert = root_params.self_signed(&root_key).expect("root cert");
    let root_issuer = Issuer::new(root_params, root_key);

    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let intermediate_cert = ca_params("Atom Test Intermediate")
        .signed_by(&intermediate_key, &root_issuer)
        .expect("intermediate cert");

    let root_cert_path = dir.join("root-ca.crt");
    let intermediate_cert_path = dir.join("intermediate-ca.crt");
    let intermediate_key_path = dir.join("intermediate-ca.key");
    fs::write(&root_cert_path, root_cert.pem()).expect("write root cert");
    fs::write(&intermediate_cert_path, intermediate_cert.pem()).expect("write intermediate cert");
    fs::write(&intermediate_key_path, intermediate_key.serialize_pem())
        .expect("write intermediate key");

    let mut config = cert_config();
    config.certs_ca_mode = atom::config::CertsCaMode::FileIntermediateIssuer;
    config.certs_root_ca_cert_path = Some(root_cert_path.to_string_lossy().into_owned());
    config.certs_intermediate_ca_cert_path =
        Some(intermediate_cert_path.to_string_lossy().into_owned());
    config.certs_intermediate_ca_key_path =
        Some(intermediate_key_path.to_string_lossy().into_owned());

    CertFixture { _dir: dir, config }
}

fn root_fixture() -> CertFixture {
    let dir = test_ca_dir("root");
    fs::create_dir_all(&dir).expect("create temp ca dir");

    let root_key = KeyPair::generate().expect("root key");
    let root_cert = ca_params("Atom Test Root")
        .self_signed(&root_key)
        .expect("root cert");

    let root_cert_path = dir.join("root-ca.crt");
    let root_key_path = dir.join("root-ca.key");
    fs::write(&root_cert_path, root_cert.pem()).expect("write root cert");
    fs::write(&root_key_path, root_key.serialize_pem()).expect("write root key");

    let mut config = cert_config();
    config.certs_ca_mode = atom::config::CertsCaMode::FileRootIssuer;
    config.certs_root_ca_cert_path = Some(root_cert_path.to_string_lossy().into_owned());
    config.certs_root_ca_key_path = Some(root_key_path.to_string_lossy().into_owned());

    CertFixture { _dir: dir, config }
}

fn test_ca_dir(kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!("atom-certs-{kind}-{}", Uuid::new_v4()))
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    params
}

fn state(
    pool: PgPool,
    config: Config,
    certificate_issuer: Option<service::CertificateIssuer>,
) -> AppState {
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        config,
        ActiveKeys {
            primary,
            standby: None,
        },
        certificate_issuer,
    )
}

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

#[tokio::test]
#[ignore]
async fn certificate_lifecycle_with_database() {
    let pool = common::pool().await;
    let fixture = intermediate_fixture();
    let cfg = fixture.config;
    let issuer = service::load_file_issuer_if_enabled(&cfg)
        .unwrap()
        .expect("issuer");
    let ca_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.certificate_authorities')::text")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(ca_table.is_none());

    let entity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, name, kind) VALUES ($1, $2, 'device')")
        .bind(entity_id)
        .bind(format!("cert-device-{entity_id}"))
        .execute(&pool)
        .await
        .unwrap();

    let issued = service::issue_certificate(
        &pool,
        &cfg,
        Some(&issuer),
        service::IssueCertificate {
            entity_id,
            ttl_secs: Some(3600),
            common_name: Some("cert-device".into()),
            dns_names: vec!["cert-device.local".into()],
            ip_addresses: vec![],
        },
    )
    .await
    .unwrap();
    assert!(issued.private_key_pem.is_some());
    let identity = service::resolve_certificate_identity(
        &pool,
        &issued.certificate.serial_number,
        Some(&issued.certificate.fingerprint_sha256),
    )
    .await
    .unwrap();
    assert_eq!(identity.entity_id, entity_id);

    let csr_pem = test_csr_pem();
    let csr_issued = service::issue_certificate_from_csr(
        &pool,
        &cfg,
        Some(&issuer),
        service::IssueCertificateFromCsr {
            entity_id,
            ttl_secs: Some(3600),
            csr_pem,
        },
    )
    .await
    .unwrap();
    assert!(csr_issued.private_key_pem.is_none());

    let renewed = service::renew_certificate(
        &pool,
        &cfg,
        Some(&issuer),
        service::RenewCertificate {
            serial_number: issued.certificate.serial_number.clone(),
            ttl_secs: Some(3600),
            revoke_old: false,
        },
    )
    .await
    .unwrap();
    assert_ne!(
        renewed.certificate.serial_number,
        issued.certificate.serial_number
    );

    let chain = service::ca_chain(&cfg, Some(&issuer)).unwrap();
    let good = service::ocsp_response(
        &pool,
        &cfg,
        Some(&issuer),
        &ocsp_request_for_serial(&chain, &issued.certificate.serial_number),
    )
    .await
    .unwrap();
    assert_ocsp_success(&good);

    service::revoke_certificate(
        &pool,
        &issued.certificate.serial_number,
        Some("test".into()),
    )
    .await
    .unwrap();
    assert!(
        service::resolve_certificate_identity(&pool, &issued.certificate.serial_number, None,)
            .await
            .is_err()
    );

    let revoked = service::ocsp_response(
        &pool,
        &cfg,
        Some(&issuer),
        &ocsp_request_for_serial(&chain, &issued.certificate.serial_number),
    )
    .await
    .unwrap();
    assert_ocsp_success(&revoked);

    let revoked_count =
        service::revoke_entity_certificates(&pool, entity_id, Some("entity".into()))
            .await
            .unwrap();
    assert!(revoked_count >= 2);

    let crl = service::generate_crl(&pool, &cfg, Some(&issuer))
        .await
        .unwrap();
    let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).unwrap();
    let serial = hex::decode(&issued.certificate.serial_number).unwrap();
    assert!(parsed_crl
        .iter_revoked_certificates()
        .any(|cert| cert.raw_serial() == serial.as_slice()));

    let unknown = service::ocsp_response(
        &pool,
        &cfg,
        Some(&issuer),
        &ocsp_request_for_serial(&chain, "0102030405060708"),
    )
    .await
    .unwrap();
    assert_ocsp_success(&unknown);
}

#[tokio::test]
#[ignore]
async fn root_file_issuer_can_issue_generated_certificate() {
    let pool = common::pool().await;
    let fixture = root_fixture();
    let cfg = fixture.config;
    let issuer = service::load_file_issuer_if_enabled(&cfg)
        .unwrap()
        .expect("issuer");

    let entity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, name, kind) VALUES ($1, $2, 'device')")
        .bind(entity_id)
        .bind(format!("root-cert-device-{entity_id}"))
        .execute(&pool)
        .await
        .unwrap();

    let issued = service::issue_certificate(
        &pool,
        &cfg,
        Some(&issuer),
        service::IssueCertificate {
            entity_id,
            ttl_secs: Some(3600),
            common_name: Some("root-cert-device".into()),
            dns_names: vec!["root-cert-device.local".into()],
            ip_addresses: vec![],
        },
    )
    .await
    .unwrap();

    assert!(issued.private_key_pem.is_some());
    assert!(service::ca_chain(&cfg, Some(&issuer))
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
#[ignore]
async fn graphql_entity_can_hold_password_and_certificate_credentials() {
    let pool = common::pool().await;
    let fixture = intermediate_fixture();
    let cfg = fixture.config;
    let issuer = service::load_file_issuer_if_enabled(&cfg)
        .unwrap()
        .expect("issuer");

    let entity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, name, kind) VALUES ($1, $2, 'device')")
        .bind(entity_id)
        .bind(format!("graphql-cert-device-{entity_id}"))
        .execute(&pool)
        .await
        .unwrap();

    let schema = build_schema(state(pool, cfg, Some(issuer)));

    let password = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPassword(entityId: "{entity_id}", password: "test-password-123")
            }}
            "#
        )))
        .await;
    assert!(password.errors.is_empty(), "{:?}", password.errors);
    assert_eq!(
        password.data.into_json().expect("json data")["createPassword"],
        true
    );

    let issued = schema
        .execute(authed(format!(
            r#"
            mutation {{
              issueCertificate(input: {{
                entityId: "{entity_id}",
                ttlSecs: 3600,
                commonName: "graphql-cert-device"
              }}) {{
                certificate {{
                  credentialId
                  serialNumber
                }}
                privateKeyPem
              }}
            }}
            "#
        )))
        .await;
    assert!(issued.errors.is_empty(), "{:?}", issued.errors);
    let issued_json = issued.data.into_json().expect("json data");
    let certificate_credential_id = issued_json["issueCertificate"]["certificate"]["credentialId"]
        .as_str()
        .expect("certificate credential id")
        .to_owned();
    assert!(issued_json["issueCertificate"]["privateKeyPem"]
        .as_str()
        .is_some());

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              credentials(entityId: "{entity_id}") {{
                items {{
                  id
                  kind
                  status
                }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    let credentials = data["credentials"]["items"]
        .as_array()
        .expect("credentials");

    assert!(credentials.iter().any(|credential| {
        credential["kind"] == "password" && credential["status"] == "active"
    }));
    assert!(credentials.iter().any(|credential| {
        credential["id"] == certificate_credential_id
            && credential["kind"] == "certificate"
            && credential["status"] == "active"
    }));
}

fn test_csr_pem() -> String {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["csr-device.local".into()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "csr-device");
    params.serialize_request(&key_pair).unwrap().pem().unwrap()
}

fn ocsp_request_for_serial(ca_chain_pem: &str, serial_hex: &str) -> Vec<u8> {
    let der = first_certificate_der(ca_chain_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let name_hash = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        cert.tbs_certificate.subject.as_raw(),
    );
    let key_hash = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        cert.tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    );
    let certid = CertId::new(
        Oid::new_from_dot(ALGO_SHA1_DOT).unwrap(),
        name_hash.as_ref(),
        key_hash.as_ref(),
        &hex::decode(serial_hex).unwrap(),
    );
    let one = OneReq {
        certid,
        one_req_ext: None,
    };
    let request_list = der_sequence(one.to_der().unwrap());
    let tbs_request = der_sequence(request_list);
    der_sequence(tbs_request)
}

fn first_certificate_der(pem: &str) -> Vec<u8> {
    parse_x509_pem(pem.as_bytes()).unwrap().1.contents
}

fn assert_ocsp_success(response: &[u8]) {
    assert!(response.starts_with(&[0x30]));
    assert!(response
        .windows(3)
        .any(|window| window == [0x0a, 0x01, 0x00]));
}

fn der_sequence(value: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(0x30);
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
