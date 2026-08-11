//! PR-014 native subject enrollment and in-process mTLS re-enrollment.
//!
//! Requires PostgreSQL and OpenSSL. CI runs this ignored binary against its
//! own freshly migrated database.

mod common;

use std::{fs, io::Cursor, net::SocketAddr, sync::Arc};

use atom::{
    auth::AuthContext,
    certs::{
        enrollment::{service as enrollment, tls as enrollment_tls},
        service as certificate_service,
    },
    error::AppError,
    identity::{access_tokens, service as identity_service},
    keys,
    models::{
        enums::CredentialKind,
        token::{CreateAccessToken, CreateSharedKey},
    },
    state::AppState,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

#[tokio::test]
#[ignore]
async fn native_enrollment_enforces_the_pr014_contract() {
    let pool = common::pool().await;
    let root = common::pki::test_root("PR-014 Offline Root");
    let tenant = common::pki::create_tenant(&pool, "pki-enrollment").await;

    let directory = std::env::temp_dir().join(format!("atom-enrollment-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_cert_path = directory.join("server.pem");
    let server_key_path = directory.join("server-key.pem");
    fs::write(&server_cert_path, server.cert.pem()).unwrap();
    fs::write(&server_key_path, server.signing_key.serialize_pem()).unwrap();

    let mut config = common::pki::managed_config(false, true);
    config.certs_enabled = true;
    config.enrollment.enabled = true;
    config.enrollment.listen_addr = "127.0.0.1:0".into();
    config.enrollment.tls = Some(atom::config::EnrollmentTlsConfig {
        cert_path: server_cert_path.to_string_lossy().into_owned(),
        key_path: server_key_path.to_string_lossy().into_owned(),
    });
    config.enrollment.entity_rate_limit.max_requests = 100;
    config.enrollment.tenant_rate_limit.max_requests = 1_000;

    let issuer = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant).await;
    keys::bootstrap_if_needed(&pool, &config.signing_keys)
        .await
        .unwrap();
    let active_keys = keys::load_active_keys(&pool, &config.signing_keys)
        .await
        .unwrap();
    let state = AppState::new(pool.clone(), config.clone(), active_keys, None);
    let prepared = enrollment_tls::prepare(&state)
        .await
        .unwrap()
        .expect("enrollment enabled");
    let address = prepared.local_addr().unwrap();
    let server_cert_pem = server.cert.pem();
    let server_task = tokio::spawn(enrollment_tls::serve(prepared, state.clone()));

    // First enrollment via an access-token credential reaches the native
    // adapter and derives both entity and tenant from bearer authentication.
    let access_entity = common::pki::create_entity(&pool, tenant, "enroll-access").await;
    let access_token = access_tokens::create_access_token(
        &pool,
        &config.signing_keys,
        access_entity,
        CreateAccessToken {
            name: "enrollment bootstrap".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .unwrap();
    let (access_csr, access_key) = csr_and_key();
    let access_reply = native_request(
        address,
        &server_cert_pem,
        None,
        "/pki/enroll",
        Some(&access_token.token),
        &json!({
            "csr_pem": access_csr,
            "idempotency_key": "access-token-first"
        }),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(access_reply.status, 200, "{}", access_reply.body);
    let first = response_json(&access_reply);
    assert_eq!(uuid(&first, "entity_id"), access_entity);
    assert_eq!(uuid(&first, "tenant_id"), tenant);
    assert_eq!(uuid(&first, "issuer_id"), issuer.id);
    assert_eq!(first["profile_name"], "client");
    assert_eq!(first["renewal_threshold_seconds"], 86_400);
    let first_credential = uuid(&first, "credential_id");
    let first_certificate = first["certificate_pem"].as_str().unwrap().to_string();
    let first_chain = first["chain_pem"].as_str().unwrap().to_string();
    common::pki::assert_chain_with_openssl(&first_certificate, &first_chain, &root.pem);

    // Password and shared-key credentials authenticate through their normal
    // login flow, then the resulting sessions can bootstrap a certificate.
    let password_entity = common::pki::create_entity(&pool, tenant, "enroll-password").await;
    identity_service::create_password(&pool, password_entity, "password-enrollment-secret")
        .await
        .unwrap();
    let password_token = login_token(
        &state,
        password_entity,
        tenant,
        "password-enrollment-secret",
        CredentialKind::Password,
    )
    .await;
    assert_first_enrollment(
        address,
        &server_cert_pem,
        &password_token,
        password_entity,
        tenant,
        "password-first",
    )
    .await;

    let shared_entity = common::pki::create_entity(&pool, tenant, "enroll-shared").await;
    let shared = identity_service::create_shared_key(
        &pool,
        &config.signing_keys,
        shared_entity,
        CreateSharedKey {
            expires_at: None,
            description: Some("enrollment bootstrap".into()),
            key: None,
        },
    )
    .await
    .unwrap();
    let shared_token = login_token(
        &state,
        shared_entity,
        tenant,
        &shared.key,
        CredentialKind::SharedKey,
    )
    .await;
    assert_first_enrollment(
        address,
        &server_cert_pem,
        &shared_token,
        shared_entity,
        tenant,
        "shared-key-first",
    )
    .await;

    // The request schema has no subject or scope selector. Unknown subject or
    // tenant fields fail deserialization, while an untrusted requested CSR
    // subject is replaced by the authenticated Atom identity.
    let other_tenant = common::pki::create_tenant(&pool, "pki-enrollment-cross").await;
    let other_entity = common::pki::create_entity(&pool, other_tenant, "enroll-cross-tenant").await;
    let (untrusted_subject_csr, _) = csr_and_key();
    for forbidden_body in [
        json!({
            "csr_pem": untrusted_subject_csr.clone(),
            "idempotency_key": "self-scope-entity",
            "entity_id": other_entity
        }),
        json!({
            "csr_pem": untrusted_subject_csr,
            "idempotency_key": "self-scope-tenant",
            "tenant_id": other_tenant
        }),
    ] {
        let reply = native_request(
            address,
            &server_cert_pem,
            None,
            "/pki/enroll",
            Some(&access_token.token),
            &forbidden_body,
            &[],
        )
        .await
        .unwrap();
        assert!(matches!(reply.status, 400 | 422), "{}", reply.body);
    }
    let (_, parsed_first) = parse_certificate(&first_certificate);
    assert_eq!(
        parsed_first
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        access_entity.to_string()
    );

    // Re-enrollment has no bearer credential: the verified TLS leaf is mapped
    // through the runtime resolver to the exact certificate being replaced.
    let (renewal_csr, renewal_key) = csr_and_key();
    let renewal_body = json!({
        "csr_pem": renewal_csr,
        "idempotency_key": "mtls-reenrollment"
    });
    let client_identity = ClientIdentity {
        certificate_pem: format!("{first_certificate}{first_chain}"),
        private_key_pem: access_key.clone(),
    };
    let renewal_reply = native_request(
        address,
        &server_cert_pem,
        Some(&client_identity),
        "/pki/reenroll",
        None,
        &renewal_body,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(renewal_reply.status, 200, "{}", renewal_reply.body);
    let renewed = response_json(&renewal_reply);
    let renewed_credential = uuid(&renewed, "credential_id");
    assert_ne!(renewed_credential, first_credential);
    assert_eq!(uuid(&renewed, "entity_id"), access_entity);
    assert_eq!(uuid(&renewed, "issuer_id"), issuer.id);
    assert_eq!(renewed["profile_id"], first["profile_id"]);
    assert_eq!(renewed["renewal_threshold_seconds"], 86_400);

    let replay = native_request(
        address,
        &server_cert_pem,
        Some(&client_identity),
        "/pki/reenroll",
        None,
        &renewal_body,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(replay.status, 200, "{}", replay.body);
    let replay = response_json(&replay);
    assert_eq!(uuid(&replay, "credential_id"), renewed_credential);
    assert_eq!(replay["idempotent_replay"], true);

    // Headers never substitute for the connection-bound extension.
    let injected = native_request(
        address,
        &server_cert_pem,
        None,
        "/pki/reenroll",
        None,
        &json!({"csr_pem": csr_and_key().0, "idempotency_key": "header-injection"}),
        &[
            ("x-client-cert", "forged-certificate-assertion"),
            ("x-forwarded-client-cert", "forged-certificate-assertion"),
            ("ssl-client-cert", "forged-certificate-assertion"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(injected.status, 401, "{}", injected.body);
    let native_denial: (String, String) = sqlx::query_as(
        r#"SELECT payload->>'outcome', payload->'details'->>'transport'
           FROM event_outbox
           WHERE event = 'certificate.reenroll'
             AND payload->>'outcome' = 'deny'
             AND payload->'details'->>'transport' = 'native'
           ORDER BY created_at DESC
           LIMIT 1"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(native_denial.0, "deny");
    assert_eq!(native_denial.1, "native");

    // A certificate asserted in the TLS handshake but signed outside Atom's
    // trust bundle is rejected during the in-process handshake.
    let forged = rcgen::generate_simple_self_signed(vec!["forged.invalid".into()]).unwrap();
    let forged_identity = ClientIdentity {
        certificate_pem: forged.cert.pem(),
        private_key_pem: forged.signing_key.serialize_pem(),
    };
    let forged_result = native_request(
        address,
        &server_cert_pem,
        Some(&forged_identity),
        "/pki/reenroll",
        None,
        &json!({"csr_pem": csr_and_key().0, "idempotency_key": "forged-peer"}),
        &[],
    )
    .await;
    assert!(forged_result.is_err(), "forged peer completed TLS");

    // Revoked source credentials are denied even though their cryptographic
    // chains still verify at the listener.
    certificate_service::revoke_certificate_v2(
        &pool,
        certificate_service::RevokeCertificateV2 {
            selector: certificate_service::CertificateRevocationSelector::CredentialId(
                first_credential,
            ),
            reason: Some("superseded".into()),
            actor_entity_id: Some(access_entity),
            expected_entity_id: access_entity,
            expected_tenant_id: Some(tenant),
        },
    )
    .await
    .unwrap();
    assert_reenrollment_denied(address, &server_cert_pem, &client_identity, "revoked-peer").await;

    let renewed_identity = ClientIdentity {
        certificate_pem: format!(
            "{}{}",
            renewed["certificate_pem"].as_str().unwrap(),
            renewed["chain_pem"].as_str().unwrap()
        ),
        private_key_pem: renewal_key,
    };

    // Runtime lifecycle state remains authoritative after TLS verification.
    sqlx::query("UPDATE entities SET status = 'inactive' WHERE id = $1")
        .bind(access_entity)
        .execute(&pool)
        .await
        .unwrap();
    assert_reenrollment_denied(
        address,
        &server_cert_pem,
        &renewed_identity,
        "inactive-entity",
    )
    .await;
    sqlx::query("UPDATE entities SET status = 'active' WHERE id = $1")
        .bind(access_entity)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("UPDATE tenants SET status = 'frozen' WHERE id = $1")
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert_reenrollment_denied(
        address,
        &server_cert_pem,
        &renewed_identity,
        "frozen-tenant",
    )
    .await;
    sqlx::query("UPDATE tenants SET status = 'active' WHERE id = $1")
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();

    let original_fingerprint: String =
        sqlx::query_scalar("SELECT metadata->>'fingerprint_sha256' FROM credentials WHERE id = $1")
            .bind(renewed_credential)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE credentials SET metadata = jsonb_set(metadata, '{fingerprint_sha256}', to_jsonb($2::text)) WHERE id = $1",
    )
    .bind(renewed_credential)
    .bind("00".repeat(32))
    .execute(&pool)
    .await
    .unwrap();
    assert_reenrollment_denied(address, &server_cert_pem, &renewed_identity, "unknown-peer").await;
    sqlx::query(
        "UPDATE credentials SET metadata = jsonb_set(metadata, '{fingerprint_sha256}', to_jsonb($2::text)) WHERE id = $1",
    )
    .bind(renewed_credential)
    .bind(original_fingerprint)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(renewed_credential)
        .execute(&pool)
        .await
        .unwrap();
    assert_reenrollment_denied(address, &server_cert_pem, &renewed_identity, "expired-peer").await;

    // Documented recovery: the expired certificate is not accepted, but the
    // same subject's still-active non-certificate credential can enroll afresh.
    let recovery = native_request(
        address,
        &server_cert_pem,
        None,
        "/pki/enroll",
        Some(&access_token.token),
        &json!({"csr_pem": csr_and_key().0, "idempotency_key": "expired-recovery"}),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(recovery.status, 200, "{}", recovery.body);
    assert_eq!(uuid(&response_json(&recovery), "entity_id"), access_entity);

    // The native path and management path share the exact profile and issuer
    // pipeline, including X.509 KU/EKU/basic constraints and identity SAN.
    let management_entity =
        common::pki::create_entity(&pool, tenant, "enroll-management-parity").await;
    let management = certificate_service::issue_certificate_from_csr_v2(
        &pool,
        &config,
        Some(tenant),
        certificate_service::IssueCertificateFromCsrV2 {
            entity_id: management_entity,
            ttl_secs: None,
            csr_pem: csr_and_key().0,
            idempotency_key: "management-parity".into(),
        },
    )
    .await
    .unwrap()
    .certificate;
    assert_eq!(management.issuer_id, Some(issuer.id));
    assert_eq!(
        management.profile_id.unwrap().to_string(),
        first["profile_id"]
    );
    assert_eq!(management.profile_name.as_deref(), Some("client"));
    assert_eq!(
        profile_shape(&management.certificate_pem),
        profile_shape(&first_certificate)
    );
    let expected_threshold: i64 = sqlx::query_scalar(
        "SELECT renewal_threshold_seconds FROM certificate_profiles WHERE id = $1",
    )
    .bind(uuid(&first, "profile_id"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        first["renewal_threshold_seconds"].as_u64().unwrap(),
        expected_threshold as u64
    );

    // Global subjects select the platform leaf issuer, never a tenant CA.
    let platform_issuer = common::pki::provision_platform_leaf_issuer(&pool, &config, &root).await;
    let global_entity = common::pki::create_global_entity(&pool, "enroll-global").await;
    let global = enrollment::enroll(
        &state,
        AuthContext {
            entity_id: global_entity,
            tenant_id: None,
            ..Default::default()
        },
        enrollment::EnrollmentInput {
            csr_pem: csr_and_key().0,
            ttl_secs: None,
            idempotency_key: "global-enrollment".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(global.issuer_id, platform_issuer.id);
    assert!(global.tenant_id.is_none());

    // Malformed and oversized cryptographic input fails at the internal
    // boundary without invoking a second issuance implementation.
    let malformed = enrollment::enroll(
        &state,
        AuthContext {
            entity_id: shared_entity,
            tenant_id: Some(tenant),
            ..Default::default()
        },
        enrollment::EnrollmentInput {
            csr_pem: "not a CSR".into(),
            ttl_secs: None,
            idempotency_key: "malformed-csr".into(),
        },
    )
    .await;
    assert!(matches!(malformed, Err(AppError::BadRequest(_))));
    let oversized = enrollment::enroll(
        &state,
        AuthContext {
            entity_id: shared_entity,
            tenant_id: Some(tenant),
            ..Default::default()
        },
        enrollment::EnrollmentInput {
            csr_pem: "x".repeat(config.enrollment.max_csr_bytes + 1),
            ttl_secs: None,
            idempotency_key: "oversized-csr".into(),
        },
    )
    .await;
    assert!(matches!(oversized, Err(AppError::PayloadTooLarge(_))));

    // Durable per-entity limits reject the second request and expose a retry
    // interval. The tenant counter remains independently configured.
    let rate_entity = common::pki::create_entity(&pool, tenant, "enroll-rate").await;
    let mut rate_state = state.clone();
    rate_state.config.enrollment.entity_rate_limit.max_requests = 1;
    let rate_auth = AuthContext {
        entity_id: rate_entity,
        tenant_id: Some(tenant),
        ..Default::default()
    };
    enrollment::enroll(
        &rate_state,
        rate_auth.clone(),
        enrollment::EnrollmentInput {
            csr_pem: csr_and_key().0,
            ttl_secs: None,
            idempotency_key: "rate-first".into(),
        },
    )
    .await
    .unwrap();
    let limited = enrollment::enroll(
        &rate_state,
        rate_auth,
        enrollment::EnrollmentInput {
            csr_pem: csr_and_key().0,
            ttl_secs: None,
            idempotency_key: "rate-second".into(),
        },
    )
    .await;
    assert!(matches!(
        limited,
        Err(AppError::RateLimited {
            retry_after_secs: 1..,
            ..
        })
    ));
    let rate_count: i64 = sqlx::query_scalar(
        "SELECT request_count FROM pki_enrollment_rate_windows WHERE scope_kind = 'entity' AND scope_id = $1 ORDER BY window_start DESC LIMIT 1",
    )
    .bind(rate_entity)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rate_count, 1);

    sqlx::query(
        "DELETE FROM pki_enrollment_rate_windows WHERE scope_kind = 'tenant' AND scope_id = $1",
    )
    .bind(tenant)
    .execute(&pool)
    .await
    .unwrap();
    let tenant_rate_entity_a =
        common::pki::create_entity(&pool, tenant, "enroll-tenant-rate-a").await;
    let tenant_rate_entity_b =
        common::pki::create_entity(&pool, tenant, "enroll-tenant-rate-b").await;
    let mut tenant_rate_state = state.clone();
    tenant_rate_state
        .config
        .enrollment
        .tenant_rate_limit
        .max_requests = 1;
    enrollment::enroll(
        &tenant_rate_state,
        AuthContext {
            entity_id: tenant_rate_entity_a,
            tenant_id: Some(tenant),
            ..Default::default()
        },
        enrollment::EnrollmentInput {
            csr_pem: csr_and_key().0,
            ttl_secs: None,
            idempotency_key: "tenant-rate-first".into(),
        },
    )
    .await
    .unwrap();
    let tenant_limited = enrollment::enroll(
        &tenant_rate_state,
        AuthContext {
            entity_id: tenant_rate_entity_b,
            tenant_id: Some(tenant),
            ..Default::default()
        },
        enrollment::EnrollmentInput {
            csr_pem: csr_and_key().0,
            ttl_secs: None,
            idempotency_key: "tenant-rate-second".into(),
        },
    )
    .await;
    assert!(matches!(
        tenant_limited,
        Err(AppError::RateLimited {
            retry_after_secs: 1..,
            ..
        })
    ));

    // First enrollment, re-enrollment, and replay are separately observable;
    // only successful non-replay mutations produce outbox rows.
    assert!(audit_count(&pool, "certificate.enroll").await >= 4);
    assert_eq!(audit_count(&pool, "certificate.reenroll").await, 1);
    assert_eq!(audit_count(&pool, "certificate.reenroll_replayed").await, 1);
    assert_eq!(outbox_count(&pool, "certificate.reenroll").await, 1);

    server_task.abort();
    let _ = server_task.await;
    fs::remove_dir_all(directory).ok();
}

async fn login_token(
    state: &AppState,
    entity_id: Uuid,
    tenant_id: Uuid,
    secret: &str,
    kind: CredentialKind,
) -> String {
    let primary = state.keys.read().await.primary.clone();
    identity_service::login_credential_with_tenant(
        &state.pool,
        &state.config,
        &primary,
        identity_service::CredentialLoginRequest {
            identifier: &entity_id.to_string(),
            secret,
            tenant_id: Some(tenant_id),
            tenant_alias: None,
            kind,
        },
    )
    .await
    .unwrap()
    .token
}

async fn assert_first_enrollment(
    address: SocketAddr,
    server_certificate: &str,
    token: &str,
    entity_id: Uuid,
    tenant_id: Uuid,
    idempotency_key: &str,
) {
    let reply = native_request(
        address,
        server_certificate,
        None,
        "/pki/enroll",
        Some(token),
        &json!({"csr_pem": csr_and_key().0, "idempotency_key": idempotency_key}),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(reply.status, 200, "{}", reply.body);
    let response = response_json(&reply);
    assert_eq!(uuid(&response, "entity_id"), entity_id);
    assert_eq!(uuid(&response, "tenant_id"), tenant_id);
}

async fn assert_reenrollment_denied(
    address: SocketAddr,
    server_certificate: &str,
    identity: &ClientIdentity,
    key: &str,
) {
    let reply = native_request(
        address,
        server_certificate,
        Some(identity),
        "/pki/reenroll",
        None,
        &json!({"csr_pem": csr_and_key().0, "idempotency_key": key}),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(reply.status, 401, "{}", reply.body);
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

#[derive(Clone)]
struct ClientIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

struct HttpReply {
    status: u16,
    body: String,
}

async fn native_request(
    address: SocketAddr,
    server_certificate: &str,
    client_identity: Option<&ClientIdentity>,
    path: &str,
    bearer: Option<&str>,
    body: &Value,
    extra_headers: &[(&str, &str)],
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

    let body = serde_json::to_string(body).unwrap();
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(bearer) = bearer {
        request.push_str(&format!("Authorization: Bearer {bearer}\r\n"));
    }
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream
        .write_all(request.as_bytes())
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
        body: String::from_utf8(body).map_err(|error| error.to_string())?,
    })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "invalid chunk header".to_string())?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&input[..end])
                .map_err(|error| error.to_string())?
                .split(';')
                .next()
                .unwrap(),
            16,
        )
        .map_err(|error| error.to_string())?;
        input = &input[end + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 {
            return Err("truncated chunk".into());
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
    Ok(output)
}

fn response_json(reply: &HttpReply) -> Value {
    serde_json::from_str(&reply.body).unwrap()
}

fn uuid(value: &Value, field: &str) -> Uuid {
    value[field].as_str().unwrap().parse().unwrap()
}

fn parse_certificate(pem: &str) -> (Vec<u8>, x509_parser::certificate::X509Certificate<'_>) {
    let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
    // The owned DER is returned only for callers that need it; the parsed value
    // borrows from `pem`, so this helper cannot safely return both. Kept inline
    // through a deliberate leak in this test-only process.
    let der = pem.contents;
    let leaked: &'static [u8] = Box::leak(der.clone().into_boxed_slice());
    let (_, certificate) = x509_parser::parse_x509_certificate(leaked).unwrap();
    (der, certificate)
}

fn profile_shape(pem: &str) -> (bool, bool, bool, usize) {
    let (_, certificate) = parse_certificate(pem);
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
        .filter(|name| matches!(name, GeneralName::URI(uri) if uri.starts_with("urn:atom:")))
        .count();
    (
        key_usage.value.digital_signature(),
        extended.value.client_auth,
        basic.value.ca,
        identity_uris,
    )
}

async fn audit_count(pool: &sqlx::PgPool, event: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE event = $1")
        .bind(event)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn outbox_count(pool: &sqlx::PgPool, event: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_outbox
         WHERE event = $1 AND payload->>'outcome' = 'allow'",
    )
        .bind(event)
        .fetch_one(pool)
        .await
        .unwrap()
}
