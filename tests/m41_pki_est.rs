//! PR-014b RFC 7030 interoperability and isolation coverage.
//!
//! Requires PostgreSQL, OpenSSL, and the independently maintained GlobalSign
//! EST client named by `ATOM_EST_CLIENT`. CI provisions all three and runs this
//! ignored binary against a freshly migrated database.

mod common;

use std::{
    env, fs,
    io::Cursor,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Output},
    sync::Arc,
};

use atom::{
    auth::AuthContext,
    certs::{
        authority::provisioning,
        enrollment::{service as enrollment, tls as enrollment_tls},
        profile::{KeyAlgorithm, KeyAlgorithmRule},
        service as certificate_service,
    },
    identity::service as identity_service,
    keys,
    state::AppState,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{CertificateParams, KeyPair};
use ring::digest;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command,
    time::{timeout, Duration},
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

const PASSWORD: &str = "est-interoperability-secret";

#[tokio::test]
#[ignore]
async fn est_adapter_interoperates_and_enforces_the_pr014b_contract() {
    let estclient = PathBuf::from(
        env::var_os("ATOM_EST_CLIENT")
            .expect("ATOM_EST_CLIENT must name the independent GlobalSign EST client"),
    );
    let pool = common::pool().await;
    let root = common::pki::test_root("PR-014b Offline Root");
    let tenant = common::pki::create_tenant(&pool, "pki-est").await;
    let other_tenant = common::pki::create_tenant(&pool, "pki-est-other").await;

    let directory = env::temp_dir().join(format!("atom-est-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_cert_path = directory.join("server.pem");
    let server_key_path = directory.join("server-key.pem");
    fs::write(&server_cert_path, server.cert.pem()).unwrap();
    fs::write(&server_key_path, server.signing_key.serialize_pem()).unwrap();

    let mut config = common::pki::managed_config(true, true);
    config.enrollment.enabled = true;
    config.enrollment.listen_addr = "127.0.0.1:0".into();
    config.enrollment.tls = Some(atom::config::EnrollmentTlsConfig {
        cert_path: server_cert_path.to_string_lossy().into_owned(),
        key_path: server_key_path.to_string_lossy().into_owned(),
    });
    config.enrollment.entity_rate_limit.max_requests = 100;
    config.enrollment.tenant_rate_limit.max_requests = 1_000;

    let issuer = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant).await;
    let other_issuer = {
        let mut tx = pool.begin().await.unwrap();
        let mut provisioned = provisioning::provision_tenant_automatically_in_tx(
            &mut tx,
            &config.pki_ca_keys,
            other_tenant,
        )
        .await
        .unwrap();
        assert!(
            provisioned.succeeded(),
            "{:?}",
            provisioned.validation_error
        );
        tx.commit().await.unwrap();
        provisioned.commit_generated_key();
        sqlx::query(
            r#"UPDATE pki_authorities
               SET ocsp_url = $2, ca_issuers_url = $3,
                   crl_distribution_point_url = $4
               WHERE id = $1"#,
        )
        .bind(provisioned.authority.id)
        .bind(common::pki::OCSP_URL)
        .bind(common::pki::CA_ISSUERS_URL)
        .bind(common::pki::CRL_URL)
        .execute(&pool)
        .await
        .unwrap();
        provisioned.value.authority
    };

    keys::bootstrap_if_needed(&pool, &config.signing_keys)
        .await
        .unwrap();
    let active_keys = keys::load_active_keys(&pool, &config.signing_keys)
        .await
        .unwrap();
    let state = AppState::new(pool.clone(), config.clone(), active_keys);
    let prepared = enrollment_tls::prepare(&state)
        .await
        .unwrap()
        .expect("enrollment enabled");
    let address = prepared.local_addr().unwrap();
    let server_name = format!("localhost:{}", address.port());
    let server_cert_pem = server.cert.pem();
    let server_task = tokio::spawn(enrollment_tls::serve(prepared, state.clone()));

    let entity = common::pki::create_entity(&pool, tenant, "est-client").await;
    identity_service::create_password(&pool, entity, PASSWORD)
        .await
        .unwrap();
    let other_entity = common::pki::create_entity(&pool, other_tenant, "est-other").await;
    identity_service::create_password(&pool, other_entity, PASSWORD)
        .await
        .unwrap();

    // An independent implementation parses the maintained-library CMS output
    // from /cacerts. Fingerprint sets must match PR-003's PEM source exactly.
    let cacerts_path = directory.join("cacerts.pem");
    assert_client_success(
        "cacerts",
        run_estclient(
            &estclient,
            vec![
                "cacerts".into(),
                "-server".into(),
                server_name.clone(),
                "-insecure".into(),
                "-out".into(),
                path_arg(&cacerts_path),
            ],
        )
        .await,
    );
    let trust_bundle = provisioning::trust_bundle(&pool).await.unwrap();
    assert_eq!(
        certificate_fingerprints(&fs::read_to_string(&cacerts_path).unwrap()),
        certificate_fingerprints(&trust_bundle.pem)
    );

    // csrattrs is the RFC 7030 AttrOrOID sequence for the profile selected by
    // the authenticated subject. The default client profile is precisely P-256.
    let basic = basic_authorization(entity, PASSWORD);
    let attrs = est_request(
        address,
        &server_cert_pem,
        None,
        "GET",
        "/.well-known/est/csrattrs",
        Some(&basic),
        None,
        &[],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(attrs.status, 200, "{}", attrs.body);
    assert!(attrs.headers.contains("content-type: application/csrattrs"));
    assert!(attrs.headers.contains("content-transfer-encoding: base64"));
    let requirements = enrollment::csr_requirements(
        &state,
        &AuthContext {
            entity_id: entity,
            tenant_id: Some(tenant),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        requirements,
        vec![KeyAlgorithmRule {
            algorithm: KeyAlgorithm::Ecdsa,
            sizes: vec![256],
        }]
    );
    assert_eq!(
        STANDARD.decode(attrs.body.trim()).unwrap(),
        STANDARD
            .decode("MCEwFQYHKoZIzj0CATEKBggqhkjOPQMBBwYIKoZIzj0EAwI=")
            .unwrap()
    );

    // The same independent client performs first enrollment using ordinary
    // HTTP Basic authentication backed by an Atom password credential.
    let (first_csr, first_key) = csr_and_key();
    let first_csr_path = directory.join("first.csr");
    let first_key_path = directory.join("first-key.pem");
    let first_cert_path = directory.join("first-cert.pem");
    fs::write(&first_csr_path, &first_csr).unwrap();
    fs::write(&first_key_path, &first_key).unwrap();
    assert_client_success(
        "simpleenroll",
        run_estclient(
            &estclient,
            authenticated_args(
                "enroll",
                &server_name,
                entity,
                &[
                    ("-csr", path_arg(&first_csr_path)),
                    ("-out", path_arg(&first_cert_path)),
                ],
            ),
        )
        .await,
    );
    assert_key_matches_certificate(&first_key_path, &first_cert_path);
    let first_id = latest_certificate_id(&pool, entity).await;
    let first = certificate_service::certificate_by_id(&pool, first_id)
        .await
        .unwrap();
    assert_eq!(first.entity_id, entity);
    assert_eq!(first.tenant_id, Some(tenant));
    assert_eq!(first.issuer_id, Some(issuer.id));
    assert_eq!(first.profile_name.as_deref(), Some("client"));
    assert_eq!(
        certificate_fingerprints(&first.certificate_pem),
        certificate_fingerprints(&fs::read_to_string(&first_cert_path).unwrap())
    );

    // Native and EST adapters reach the identical policy and issuer pipeline
    // for the same subject. Identity, profile, issuer, and encoded extensions
    // therefore agree even though serials and public keys necessarily differ.
    let native = enrollment::enroll(
        &state,
        AuthContext {
            entity_id: entity,
            tenant_id: Some(tenant),
            ..Default::default()
        },
        enrollment::EnrollmentInput {
            csr_pem: csr_and_key().0,
            ttl_secs: None,
            idempotency_key: "est-native-parity".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(native.issuer_id, first.issuer_id.unwrap());
    assert_eq!(native.profile_id, first.profile_id.unwrap());
    assert_eq!(native.profile_name, first.profile_name.as_deref().unwrap());
    assert_eq!(native.identity_uri, first.identity_uri.as_deref().unwrap());
    assert_eq!(
        profile_shape(&native.certificate_pem),
        profile_shape(&first.certificate_pem)
    );

    // Re-enrollment uses only the exact certificate being replaced at the TLS
    // layer. No bearer or Basic credential is supplied to this command.
    let first_chain_path = directory.join("first-chain.pem");
    fs::write(
        &first_chain_path,
        format!(
            "{}{}",
            fs::read_to_string(&first_cert_path).unwrap(),
            first.chain_pem.as_deref().unwrap()
        ),
    )
    .unwrap();
    let (renewed_csr, renewed_key) = csr_and_key();
    let renewed_csr_path = directory.join("renewed.csr");
    let renewed_key_path = directory.join("renewed-key.pem");
    let renewed_cert_path = directory.join("renewed-cert.pem");
    fs::write(&renewed_csr_path, &renewed_csr).unwrap();
    fs::write(&renewed_key_path, &renewed_key).unwrap();
    assert_client_success(
        "simplereenroll",
        run_estclient(
            &estclient,
            vec![
                "reenroll".into(),
                "-server".into(),
                server_name.clone(),
                "-insecure".into(),
                "-certs".into(),
                path_arg(&first_chain_path),
                "-key".into(),
                path_arg(&first_key_path),
                "-csr".into(),
                path_arg(&renewed_csr_path),
                "-out".into(),
                path_arg(&renewed_cert_path),
            ],
        )
        .await,
    );
    assert_key_matches_certificate(&renewed_key_path, &renewed_cert_path);
    let renewed_id = latest_certificate_id(&pool, entity).await;
    let renewed = certificate_service::certificate_by_id(&pool, renewed_id)
        .await
        .unwrap();
    assert_eq!(renewed.renewed_from_credential_id, Some(first_id));
    assert_eq!(renewed.issuer_id, first.issuer_id);
    assert_eq!(renewed.profile_id, first.profile_id);
    assert_eq!(renewed.identity_uri, first.identity_uri);

    // A request cannot acquire selectors through query parameters, headers, or
    // an EST additional path segment. Authentication always determines scope.
    let (other_csr, _) = csr_and_key();
    let selectors = vec![
        ("x-atom-tenant".into(), tenant.to_string()),
        ("x-atom-issuer".into(), issuer.id.to_string()),
        ("x-atom-profile".into(), "server".into()),
    ];
    let other_basic = basic_authorization(other_entity, PASSWORD);
    let other_reply = est_request(
        address,
        &server_cert_pem,
        None,
        "POST",
        &format!(
            "/.well-known/est/simpleenroll?tenant_id={tenant}&issuer_id={}&profile=server",
            issuer.id
        ),
        Some(&other_basic),
        Some("application/pkcs10"),
        STANDARD.encode(csr_der(&other_csr)).as_bytes(),
        &selectors,
    )
    .await
    .unwrap();
    assert_eq!(other_reply.status, 200, "{}", other_reply.body);
    let other = certificate_service::certificate_by_id(
        &pool,
        latest_certificate_id(&pool, other_entity).await,
    )
    .await
    .unwrap();
    assert_eq!(other.tenant_id, Some(other_tenant));
    assert_eq!(other.issuer_id, Some(other_issuer.id));
    assert_eq!(other.profile_name.as_deref(), Some("client"));
    let selected_path = est_request(
        address,
        &server_cert_pem,
        None,
        "POST",
        &format!("/.well-known/est/{tenant}/simpleenroll"),
        Some(&basic),
        Some("application/pkcs10"),
        STANDARD.encode(csr_der(&other_csr)).as_bytes(),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(selected_path.status, 404, "{}", selected_path.body);

    // Protocol errors are rejected before certificate issuance. A missing
    // client certificate cannot be replaced by proxy-controlled headers.
    assert_est_error(
        address,
        &server_cert_pem,
        &basic,
        "application/pkcs10",
        b"%%%",
        400,
    )
    .await;
    assert_est_error(
        address,
        &server_cert_pem,
        &basic,
        "application/pkcs10",
        STANDARD.encode(b"not a PKCS#10 request").as_bytes(),
        400,
    )
    .await;
    assert_est_error(
        address,
        &server_cert_pem,
        &basic,
        "application/octet-stream",
        STANDARD.encode(csr_der(&first_csr)).as_bytes(),
        415,
    )
    .await;
    let oversized = vec![b'A'; config.enrollment.max_csr_bytes * 4 / 3 + 20 * 1024];
    assert_est_error(
        address,
        &server_cert_pem,
        &basic,
        "application/pkcs10",
        &oversized,
        413,
    )
    .await;
    let no_peer = est_request(
        address,
        &server_cert_pem,
        None,
        "POST",
        "/.well-known/est/simplereenroll",
        None,
        Some("application/pkcs10"),
        STANDARD.encode(csr_der(&first_csr)).as_bytes(),
        &[("x-forwarded-client-cert".into(), "forged".into())],
    )
    .await
    .unwrap();
    assert_eq!(no_peer.status, 401, "{}", no_peer.body);
    assert!(
        no_peer
            .headers
            .to_ascii_lowercase()
            .contains("www-authenticate: basic"),
        "{}",
        no_peer.headers
    );

    // The independent client also parses serverkeygen's multipart response.
    // Each invocation returns a different PKCS#8 key exactly once, and no key
    // material is retained in the certificate credential metadata.
    let generated_cert_a = directory.join("generated-a.pem");
    let generated_key_a = directory.join("generated-a-key.pem");
    let generated_cert_b = directory.join("generated-b.pem");
    let generated_key_b = directory.join("generated-b-key.pem");
    for (label, cert_path, key_path) in [
        ("serverkeygen-a", &generated_cert_a, &generated_key_a),
        ("serverkeygen-b", &generated_cert_b, &generated_key_b),
    ] {
        assert_client_success(
            label,
            run_estclient(
                &estclient,
                authenticated_args(
                    "serverkeygen",
                    &server_name,
                    entity,
                    &[
                        ("-cn", "ignored-by-atom".into()),
                        ("-out", path_arg(cert_path)),
                        ("-keyout", path_arg(key_path)),
                    ],
                ),
            )
            .await,
        );
        assert_key_matches_certificate(key_path, cert_path);
    }
    let generated_key_a_pem = fs::read_to_string(&generated_key_a).unwrap();
    let generated_key_b_pem = fs::read_to_string(&generated_key_b).unwrap();
    assert_ne!(generated_key_a_pem, generated_key_b_pem);
    assert_ne!(
        fs::read_to_string(&generated_cert_a).unwrap(),
        fs::read_to_string(&generated_cert_b).unwrap()
    );
    let stored_metadata: Vec<String> = sqlx::query_scalar(
        "SELECT metadata::text FROM credentials WHERE entity_id = $1 AND kind = 'certificate'",
    )
    .bind(entity)
    .fetch_all(&pool)
    .await
    .unwrap();
    for key in [&generated_key_a_pem, &generated_key_b_pem] {
        let marker = private_key_marker(key);
        assert!(
            stored_metadata
                .iter()
                .all(|metadata| !metadata.contains(&marker)),
            "one-time private key material was persisted"
        );
    }

    // Lifecycle state in Atom remains authoritative after the TLS certificate
    // has passed cryptographic verification.
    certificate_service::revoke_certificate_v2(
        &pool,
        certificate_service::RevokeCertificateV2 {
            selector: certificate_service::CertificateRevocationSelector::CredentialId(first_id),
            reason: Some("superseded".into()),
            actor_entity_id: Some(entity),
            expected_entity_id: entity,
            expected_tenant_id: Some(tenant),
        },
    )
    .await
    .unwrap();
    let revoked_attempt = directory.join("revoked-attempt.pem");
    assert_client_failure(
        "revoked simplereenroll",
        run_estclient(
            &estclient,
            vec![
                "reenroll".into(),
                "-server".into(),
                server_name.clone(),
                "-insecure".into(),
                "-certs".into(),
                path_arg(&first_chain_path),
                "-key".into(),
                path_arg(&first_key_path),
                "-csr".into(),
                path_arg(&renewed_csr_path),
                "-out".into(),
                path_arg(&revoked_attempt),
            ],
        )
        .await,
    );

    let renewed_chain_path = directory.join("renewed-chain.pem");
    fs::write(
        &renewed_chain_path,
        format!(
            "{}{}",
            fs::read_to_string(&renewed_cert_path).unwrap(),
            renewed.chain_pem.as_deref().unwrap()
        ),
    )
    .unwrap();
    sqlx::query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(renewed_id)
        .execute(&pool)
        .await
        .unwrap();
    let expired_attempt = directory.join("expired-attempt.pem");
    assert_client_failure(
        "expired simplereenroll",
        run_estclient(
            &estclient,
            vec![
                "reenroll".into(),
                "-server".into(),
                server_name,
                "-insecure".into(),
                "-certs".into(),
                path_arg(&renewed_chain_path),
                "-key".into(),
                path_arg(&renewed_key_path),
                "-csr".into(),
                path_arg(&first_csr_path),
                "-out".into(),
                path_arg(&expired_attempt),
            ],
        )
        .await,
    );

    // Saturate this subject's persisted rate window without changing the
    // service configuration, then prove both remaining mutation adapters emit
    // structured failure observations on their service-error branches.
    sqlx::query(
        r#"UPDATE pki_enrollment_rate_windows
           SET request_count = $2
           WHERE scope_kind = 'entity' AND scope_id = $1"#,
    )
    .bind(entity)
    .bind(i64::from(config.enrollment.entity_rate_limit.max_requests))
    .execute(&pool)
    .await
    .unwrap();
    let encoded_csr = STANDARD.encode(csr_der(&first_csr));
    for operation in ["simpleenroll", "serverkeygen"] {
        let response = est_request(
            address,
            &server_cert_pem,
            None,
            "POST",
            &format!("/.well-known/est/{operation}"),
            Some(&basic),
            Some("application/pkcs10"),
            encoded_csr.as_bytes(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(response.status, 429, "{}", response.body);
    }

    for (event, mode, outcome, minimum) in [
        ("certificate.enroll", "first", "error", 1_i64),
        ("certificate.enroll", "serverkeygen", "error", 1_i64),
        ("certificate.reenroll", "reenroll", "deny", 2_i64),
    ] {
        let observed: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM event_outbox
               WHERE event = $1
                 AND payload->>'outcome' = $3
                 AND payload->'details'->>'transport' = 'est'
                 AND payload->'details'->>'mode' = $2"#,
        )
        .bind(event)
        .bind(mode)
        .bind(outcome)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            observed >= minimum,
            "EST {mode} mutation failures must be observed"
        );
    }

    server_task.abort();
    let _ = server_task.await;
    fs::remove_dir_all(directory).ok();
}

fn authenticated_args(
    command: &str,
    server: &str,
    entity_id: Uuid,
    options: &[(&str, String)],
) -> Vec<String> {
    let mut arguments = vec![
        command.into(),
        "-server".into(),
        server.into(),
        "-insecure".into(),
        "-user".into(),
        entity_id.to_string(),
        "-pass".into(),
        PASSWORD.into(),
    ];
    for (flag, value) in options {
        arguments.push((*flag).into());
        arguments.push(value.clone());
    }
    arguments
}

async fn run_estclient(binary: &Path, arguments: Vec<String>) -> Output {
    timeout(
        Duration::from_secs(30),
        Command::new(binary).args(arguments).output(),
    )
    .await
    .expect("independent EST client timed out")
    .expect("failed to start independent EST client")
}

fn assert_client_success(operation: &str, output: Output) -> Output {
    assert!(
        output.status.success(),
        "{operation} failed (status {}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn assert_client_failure(operation: &str, output: Output) {
    assert!(
        !output.status.success(),
        "{operation} unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

async fn latest_certificate_id(pool: &sqlx::PgPool, entity_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        r#"SELECT id
           FROM credentials
           WHERE entity_id = $1 AND kind = 'certificate'
           ORDER BY created_at DESC, id DESC
           LIMIT 1"#,
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn assert_key_matches_certificate(key: &Path, certificate: &Path) {
    let certificate_public_key = assert_client_success(
        "extract certificate public key",
        StdCommand::new("openssl")
            .args(["x509", "-pubkey", "-noout", "-in"])
            .arg(certificate)
            .output()
            .unwrap(),
    );
    let private_public_key = assert_client_success(
        "extract private-key public key",
        StdCommand::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(key)
            .output()
            .unwrap(),
    );
    assert_eq!(certificate_public_key.stdout, private_public_key.stdout);
}

fn certificate_fingerprints(pem: &str) -> Vec<String> {
    let mut fingerprints = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
        .map(|certificate| {
            let certificate = certificate.unwrap();
            hex::encode(digest::digest(&digest::SHA256, certificate.as_ref()))
        })
        .collect::<Vec<_>>();
    fingerprints.sort();
    fingerprints
}

fn private_key_marker(pem: &str) -> String {
    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let start = encoded.len().saturating_sub(48);
    encoded[start..].to_string()
}

fn csr_and_key() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    (csr, key.serialize_pem())
}

fn csr_der(csr_pem: &str) -> Vec<u8> {
    let (remaining, pem) = parse_x509_pem(csr_pem.as_bytes()).unwrap();
    assert!(remaining.iter().all(|byte| byte.is_ascii_whitespace()));
    assert_eq!(pem.label, "CERTIFICATE REQUEST");
    pem.contents
}

fn basic_authorization(entity_id: Uuid, password: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{entity_id}:{password}"))
    )
}

async fn assert_est_error(
    address: SocketAddr,
    server_certificate: &str,
    authorization: &str,
    content_type: &str,
    body: &[u8],
    expected_status: u16,
) {
    let response = est_request(
        address,
        server_certificate,
        None,
        "POST",
        "/.well-known/est/simpleenroll",
        Some(authorization),
        Some(content_type),
        body,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(response.status, expected_status, "{}", response.body);
}

#[derive(Clone)]
struct ClientIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

struct HttpReply {
    status: u16,
    headers: String,
    body: String,
}

#[allow(clippy::too_many_arguments)]
async fn est_request(
    address: SocketAddr,
    server_certificate: &str,
    client_identity: Option<&ClientIdentity>,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
    extra_headers: &[(String, String)],
) -> Result<HttpReply, String> {
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(server_certificate.as_bytes())) {
        roots
            .add(certificate.map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots);
    let client_config = match client_identity {
        Some(identity) => {
            let certificates =
                rustls_pemfile::certs(&mut Cursor::new(identity.certificate_pem.as_bytes()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
            let key =
                rustls_pemfile::private_key(&mut Cursor::new(identity.private_key_pem.as_bytes()))
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "client key missing".to_string())?;
            builder
                .with_client_auth_cert(certificates, key)
                .map_err(|error| error.to_string())?
        }
        None => builder.with_no_client_auth(),
    };

    let tcp = TcpStream::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost")
        .map_err(|error| error.to_string())?
        .to_owned();
    let mut stream = timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|error| error.to_string())?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(authorization) = authorization {
        request.push_str("Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    if let Some(content_type) = content_type {
        request.push_str("Content-Type: ");
        request.push_str(content_type);
        request.push_str("\r\n");
    }
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(body)
        .await
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .map_err(|_| "HTTP response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<HttpReply, String> {
    let marker = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "HTTP headers missing".to_string())?;
    let headers = String::from_utf8(response[..marker].to_vec()).map_err(|e| e.to_string())?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| "HTTP status missing".to_string())?;
    let raw_body = &response[marker + 4..];
    let body = if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked(raw_body)?
    } else {
        raw_body.to_vec()
    };
    Ok(HttpReply {
        status,
        headers: headers.to_ascii_lowercase(),
        body: String::from_utf8(body).map_err(|error| error.to_string())?,
    })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "chunk length missing".to_string())?;
        let size_text = std::str::from_utf8(&input[..line_end]).map_err(|e| e.to_string())?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap(), 16)
            .map_err(|error| error.to_string())?;
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err("malformed chunk".into());
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
    Ok(output)
}

fn parse_certificate(pem: &str) -> x509_parser::certificate::X509Certificate<'static> {
    let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
    let der: &'static [u8] = Box::leak(pem.contents.into_boxed_slice());
    x509_parser::parse_x509_certificate(der).unwrap().1
}

fn profile_shape(pem: &str) -> (bool, bool, bool, Vec<String>) {
    let certificate = parse_certificate(pem);
    let key_usage = certificate.key_usage().unwrap().unwrap();
    let extended = certificate.extended_key_usage().unwrap().unwrap();
    let basic = certificate.basic_constraints().unwrap().unwrap();
    let identity_uris = certificate
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) if uri.starts_with("urn:atom:") => Some((*uri).to_string()),
            _ => None,
        })
        .collect();
    (
        key_usage.value.digital_signature(),
        extended.value.client_auth,
        basic.value.ca,
        identity_uris,
    )
}
