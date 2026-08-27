//! DB-gated contract tests for the certificate runtime resolver v2.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m38_pki_runtime_resolver_v2 -- --ignored
//! ```

mod common;

use async_graphql::{Request as GraphqlRequest, Variables};
use atom::{
    auth::{encode_jwt, AuthContext},
    certs::service::{self, CertificateRecord, ResolveCertificateV2},
    error::AppError,
    graphql::build_schema,
    grpc::{
        self,
        proto::{
            certificate_service_client::CertificateServiceClient, ResolveCertificateV2Request,
        },
    },
    identity::repo as identity_repo,
    keys::{self, ActiveKeys},
    state::AppState,
};
use rcgen::{CertificateParams, DnType, KeyPair};
use ring::digest;
use serde_json::{json, Value};
use sqlx::PgPool;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::{
    task::JoinSet,
    time::{sleep, timeout, Duration},
};
use tonic::{metadata::MetadataValue, transport::Channel, Code, Request as GrpcRequest};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;

#[tokio::test]
#[ignore]
async fn runtime_resolver_v2_enforces_issuer_scoped_identity() {
    let pool = common::pool().await;
    let config = common::pki::managed_config(false, true);
    let root = common::pki::test_root("Resolver Test Root");
    let tenant_a = common::pki::create_tenant(&pool, "pki-resolver-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-resolver-b").await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-resolver-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-resolver-b").await;
    let issuer_a = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let issuer_b = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_b).await;
    let leaf_a = issue_managed(&pool, &config, tenant_a, entity_a, "resolver-a").await;
    let leaf_b = issue_managed(&pool, &config, tenant_b, entity_b, "resolver-b").await;

    // The same serial may exist under two managed issuers because the unique
    // index is `(issuer_id, identifier)`. A duplicate inside one issuer is
    // still a database-level conflict.
    sqlx::query("UPDATE credentials SET identifier = $1 WHERE id = $2")
        .bind(&leaf_a.serial_number)
        .bind(leaf_b.credential_id)
        .execute(&pool)
        .await
        .unwrap();
    let same_issuer_conflict = sqlx::query(
        "INSERT INTO credentials
             (id, entity_id, kind, identifier, issuer_id, metadata, expires_at)
         VALUES ($1, $2, 'certificate', $3, $4, $5, now() + interval '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(entity_a)
    .bind(&leaf_a.serial_number)
    .bind(issuer_a.id)
    .bind(json!({"fingerprint_sha256": random_fingerprint()}))
    .execute(&pool)
    .await
    .expect_err("one issuer cannot reuse a certificate serial");
    assert_eq!(
        database_code(&same_issuer_conflict).as_deref(),
        Some("23505")
    );

    let issuer_a_fingerprint = issuer_a.fingerprint_sha256.as_deref().unwrap();
    let issuer_b_fingerprint = issuer_b.fingerprint_sha256.as_deref().unwrap();
    let by_fingerprint = resolve(
        &pool,
        ResolveCertificateV2 {
            certificate_der: None,
            fingerprint_sha256: Some(leaf_a.fingerprint_sha256.clone()),
            issuer_fingerprint_sha256: None,
            serial_number: None,
            expected_tenant_id: Some(tenant_a),
        },
    )
    .await;
    assert_identity(&by_fingerprint, &leaf_a, issuer_a.id, Some(tenant_a));

    let by_issuer_a = resolve(
        &pool,
        issuer_serial_input(issuer_a_fingerprint, &leaf_a.serial_number, Some(tenant_a)),
    )
    .await;
    assert_identity(&by_issuer_a, &leaf_a, issuer_a.id, Some(tenant_a));
    let by_issuer_b = resolve(
        &pool,
        issuer_serial_input(issuer_b_fingerprint, &leaf_a.serial_number, Some(tenant_b)),
    )
    .await;
    assert_identity(&by_issuer_b, &leaf_b, issuer_b.id, Some(tenant_b));

    let leaf_a_der = certificate_der(&leaf_a.certificate_pem);
    let by_der = resolve(
        &pool,
        ResolveCertificateV2 {
            certificate_der: Some(leaf_a_der.clone()),
            fingerprint_sha256: Some(colon_fingerprint(&leaf_a.fingerprint_sha256)),
            issuer_fingerprint_sha256: Some(issuer_a_fingerprint.to_string()),
            serial_number: Some(leaf_a.serial_number.clone()),
            expected_tenant_id: Some(tenant_a),
        },
    )
    .await;
    assert_identity(&by_der, &leaf_a, issuer_a.id, Some(tenant_a));

    assert_unauthorized(
        service::resolve_certificate_identity_v2(
            &pool,
            ResolveCertificateV2 {
                certificate_der: Some(leaf_a_der.clone()),
                fingerprint_sha256: Some(leaf_b.fingerprint_sha256.clone()),
                issuer_fingerprint_sha256: None,
                serial_number: None,
                expected_tenant_id: None,
            },
        )
        .await,
    );
    assert_unauthorized(
        service::resolve_certificate_identity_v2(
            &pool,
            ResolveCertificateV2 {
                certificate_der: None,
                fingerprint_sha256: Some(leaf_a.fingerprint_sha256.clone()),
                issuer_fingerprint_sha256: Some(issuer_b_fingerprint.to_string()),
                serial_number: Some(leaf_a.serial_number.clone()),
                expected_tenant_id: None,
            },
        )
        .await,
    );
    assert!(matches!(
        service::resolve_certificate_identity_v2(
            &pool,
            fingerprint_input(&leaf_a.fingerprint_sha256, Some(tenant_b)),
        )
        .await,
        Err(AppError::Forbidden)
    ));
    assert!(matches!(
        service::resolve_certificate_identity_v2(
            &pool,
            fingerprint_input(&random_fingerprint(), None),
        )
        .await,
        Err(AppError::NotFound(_))
    ));
    assert!(matches!(
        service::resolve_certificate_identity_v2(
            &pool,
            ResolveCertificateV2 {
                certificate_der: None,
                fingerprint_sha256: None,
                issuer_fingerprint_sha256: None,
                serial_number: None,
                expected_tenant_id: None,
            },
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    assert!(matches!(
        service::resolve_certificate_identity_v2(
            &pool,
            ResolveCertificateV2 {
                certificate_der: Some(vec![0x30, 0x82, 0xff]),
                fingerprint_sha256: None,
                issuer_fingerprint_sha256: None,
                serial_number: None,
                expected_tenant_id: None,
            },
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    assert!(matches!(
        service::resolve_certificate_identity_v2(
            &pool,
            ResolveCertificateV2 {
                certificate_der: Some(vec![0; service::RUNTIME_CERTIFICATE_DER_MAX_BYTES + 1]),
                fingerprint_sha256: None,
                issuer_fingerprint_sha256: None,
                serial_number: None,
                expected_tenant_id: None,
            },
        )
        .await,
        Err(AppError::PayloadTooLarge(_))
    ));

    // Retiring and retained issuers remain valid for verification. Pending or
    // revoked credentials, expired leaves, disabled/expired issuers, inactive
    // entities, and frozen/deleted tenants all fail closed immediately.
    set_issuer_status(&pool, issuer_a.id, "retiring", false).await;
    resolve(
        &pool,
        fingerprint_input(&leaf_a.fingerprint_sha256, Some(tenant_a)),
    )
    .await;
    set_issuer_status(&pool, issuer_a.id, "retired", false).await;
    resolve(
        &pool,
        fingerprint_input(&leaf_a.fingerprint_sha256, Some(tenant_a)),
    )
    .await;
    set_issuer_status(&pool, issuer_a.id, "active", true).await;

    sqlx::query("UPDATE credentials SET status = 'revocation_pending' WHERE id = $1")
        .bind(leaf_a.credential_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    sqlx::query("UPDATE credentials SET status = 'active' WHERE id = $1")
        .bind(leaf_a.credential_id)
        .execute(&pool)
        .await
        .unwrap();

    let original_expiry = leaf_a.expires_at.as_ref().unwrap();
    sqlx::query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(leaf_a.credential_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    sqlx::query("UPDATE credentials SET expires_at = $2 WHERE id = $1")
        .bind(leaf_a.credential_id)
        .bind(original_expiry)
        .execute(&pool)
        .await
        .unwrap();

    set_issuer_status(&pool, issuer_a.id, "failed", false).await;
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    set_issuer_status(&pool, issuer_a.id, "expired", false).await;
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    set_issuer_status(&pool, issuer_a.id, "active", false).await;
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    set_issuer_status(&pool, issuer_a.id, "active", true).await;

    sqlx::query("UPDATE entities SET status = 'inactive' WHERE id = $1")
        .bind(entity_a)
        .execute(&pool)
        .await
        .unwrap();
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    sqlx::query("UPDATE entities SET status = 'active' WHERE id = $1")
        .bind(entity_a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE entities SET status = 'inactive', deleted_at = now() WHERE id = $1")
        .bind(entity_a)
        .execute(&pool)
        .await
        .unwrap();
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    sqlx::query("UPDATE entities SET status = 'active', deleted_at = NULL WHERE id = $1")
        .bind(entity_a)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("UPDATE tenants SET status = 'frozen' WHERE id = $1")
        .bind(tenant_a)
        .execute(&pool)
        .await
        .unwrap();
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    sqlx::query("UPDATE tenants SET status = 'active' WHERE id = $1")
        .bind(tenant_a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE tenants SET status = 'deleted', deleted_at = now() WHERE id = $1")
        .bind(tenant_a)
        .execute(&pool)
        .await
        .unwrap();
    assert_fingerprint_denied(&pool, &leaf_a.fingerprint_sha256).await;
    sqlx::query("UPDATE tenants SET status = 'active', deleted_at = NULL WHERE id = $1")
        .bind(tenant_a)
        .execute(&pool)
        .await
        .unwrap();

    // Existing certificate lifecycle events are the stable cache-invalidation
    // contract. Revoke through the public GraphQL transaction and prove the
    // event names the exact credential and issuer before resolver denial.
    let schema = build_schema(common::pki::graphql_state(pool.clone(), config.clone()));
    let revoked = schema
        .execute(
            GraphqlRequest::new(
                r#"mutation Revoke($input: RevokeCertificateV2Input!) {
                  revokeCertificateV2(input: $input) { certificate { credentialId status } }
                }"#,
            )
            .variables(Variables::from_json(json!({
                "input": {"credentialId": leaf_b.credential_id, "reason": "cessation_of_operation"}
            })))
            .data(admin_auth()),
        )
        .await;
    assert!(revoked.errors.is_empty(), "{:?}", revoked.errors);
    let lifecycle_event: Value = sqlx::query_scalar(
        "SELECT payload FROM event_outbox
         WHERE event = 'certificate.revoke' AND (payload->>'target_id')::uuid = $1",
    )
    .bind(leaf_b.credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        lifecycle_event["details"]["credential_id"],
        leaf_b.credential_id.to_string()
    );
    assert_eq!(
        lifecycle_event["details"]["issuer_id"],
        issuer_b.id.to_string()
    );
    assert_fingerprint_denied(&pool, &leaf_b.fingerprint_sha256).await;

    // A global entity keeps an empty tenant while still returning its exact
    // platform issuer.
    let global_entity = common::pki::create_global_entity(&pool, "pki-resolver-global").await;
    let global_issuer = common::pki::provision_platform_leaf_issuer(&pool, &config, &root).await;
    let global_leaf =
        issue_managed_optional_tenant(&pool, &config, None, global_entity, "resolver-global").await;
    let global = resolve(
        &pool,
        fingerprint_input(&global_leaf.fingerprint_sha256, None),
    )
    .await;
    assert_identity(&global, &global_leaf, global_issuer.id, None);

    // Ninety-six simultaneous exact lookups complete inside a bounded window
    // and never cross-resolve the duplicate serial.
    timeout(Duration::from_secs(10), async {
        let mut tasks = JoinSet::new();
        for index in 0..96 {
            let pool = pool.clone();
            let fingerprint_a = leaf_a.fingerprint_sha256.clone();
            let issuer_b_fingerprint = issuer_b_fingerprint.to_string();
            let shared_serial = leaf_a.serial_number.clone();
            let expected_a = leaf_a.credential_id;
            let expected_b = leaf_b.credential_id;
            tasks.spawn(async move {
                if index % 2 == 0 {
                    let resolved = service::resolve_certificate_identity_v2(
                        &pool,
                        fingerprint_input(&fingerprint_a, Some(tenant_a)),
                    )
                    .await
                    .unwrap();
                    (resolved.credential_id, expected_a)
                } else {
                    let resolved = service::resolve_certificate_identity_v2(
                        &pool,
                        issuer_serial_input(&issuer_b_fingerprint, &shared_serial, Some(tenant_b)),
                    )
                    .await
                    .expect_err("revoked duplicate must remain denied");
                    assert!(matches!(resolved, AppError::Unauthorized(_)));
                    (expected_b, expected_b)
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (actual, expected) = result.unwrap();
            assert_eq!(actual, expected);
        }
    })
    .await
    .expect("resolver concurrency check exceeded ten seconds");

    // Exercise the actual versioned gRPC contract and its deprecated sibling.
    let active_keys = active_keys(&pool, &config).await;
    let admin_token = token_for(&pool, &config, &active_keys, common::admin_id()).await;
    let state = AppState::new(pool.clone(), config.clone(), active_keys, None);
    let listener = grpc::bind_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = grpc::serve(listener, state, None).await;
    });
    let mut client = certificate_client(address).await;

    let missing_auth = client
        .resolve_certificate_v2(ResolveCertificateV2Request {
            fingerprint_sha256: leaf_a.fingerprint_sha256.clone(),
            ..Default::default()
        })
        .await
        .expect_err("resolver requires authenticated service metadata");
    assert_eq!(missing_auth.code(), Code::Unauthenticated);

    let response = client
        .resolve_certificate_v2(authed_request(
            &admin_token,
            ResolveCertificateV2Request {
                certificate_der: leaf_a_der,
                fingerprint_sha256: leaf_a.fingerprint_sha256.clone(),
                issuer_fingerprint_sha256: issuer_a_fingerprint.to_string(),
                serial_number: leaf_a.serial_number.clone(),
                expected_tenant_id: tenant_a.to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.entity_id, entity_a.to_string());
    assert_eq!(response.tenant_id, tenant_a.to_string());
    assert_eq!(response.credential_id, leaf_a.credential_id.to_string());
    assert_eq!(response.issuer_id, issuer_a.id.to_string());
    assert_eq!(response.status, "active");

    let tenant_mismatch = client
        .resolve_certificate_v2(authed_request(
            &admin_token,
            ResolveCertificateV2Request {
                fingerprint_sha256: leaf_a.fingerprint_sha256.clone(),
                expected_tenant_id: tenant_b.to_string(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("expected tenant mismatch must fail before authorization");
    assert_eq!(tenant_mismatch.code(), Code::PermissionDenied);

    let global_response = client
        .resolve_certificate_v2(authed_request(
            &admin_token,
            ResolveCertificateV2Request {
                fingerprint_sha256: global_leaf.fingerprint_sha256,
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(global_response.entity_id, global_entity.to_string());
    assert!(global_response.tenant_id.is_empty());
    assert_eq!(global_response.issuer_id, global_issuer.id.to_string());

    server.abort();
}

async fn resolve(pool: &PgPool, input: ResolveCertificateV2) -> service::CertificateIdentity {
    service::resolve_certificate_identity_v2(pool, input)
        .await
        .unwrap()
}

fn fingerprint_input(fingerprint: &str, tenant_id: Option<Uuid>) -> ResolveCertificateV2 {
    ResolveCertificateV2 {
        certificate_der: None,
        fingerprint_sha256: Some(fingerprint.to_string()),
        issuer_fingerprint_sha256: None,
        serial_number: None,
        expected_tenant_id: tenant_id,
    }
}

fn issuer_serial_input(
    issuer_fingerprint: &str,
    serial_number: &str,
    tenant_id: Option<Uuid>,
) -> ResolveCertificateV2 {
    ResolveCertificateV2 {
        certificate_der: None,
        fingerprint_sha256: None,
        issuer_fingerprint_sha256: Some(issuer_fingerprint.to_string()),
        serial_number: Some(serial_number.to_string()),
        expected_tenant_id: tenant_id,
    }
}

fn assert_identity(
    actual: &service::CertificateIdentity,
    certificate: &CertificateRecord,
    issuer_id: Uuid,
    tenant_id: Option<Uuid>,
) {
    assert_eq!(actual.entity_id, certificate.entity_id);
    assert_eq!(actual.tenant_id, tenant_id);
    assert_eq!(actual.credential_id, certificate.credential_id);
    assert_eq!(actual.issuer_id, Some(issuer_id));
    assert_eq!(&actual.expires_at, certificate.expires_at.as_ref().unwrap());
    assert_eq!(actual.status, "active");
}

fn assert_unauthorized(result: Result<service::CertificateIdentity, AppError>) {
    assert!(
        matches!(&result, Err(AppError::Unauthorized(_))),
        "expected unauthorized resolver result, got {result:?}"
    );
}

async fn assert_fingerprint_denied(pool: &PgPool, fingerprint: &str) {
    assert_unauthorized(
        service::resolve_certificate_identity_v2(pool, fingerprint_input(fingerprint, None)).await,
    );
}

async fn issue_managed(
    pool: &PgPool,
    config: &atom::config::Config,
    tenant_id: Uuid,
    entity_id: Uuid,
    label: &str,
) -> CertificateRecord {
    issue_managed_optional_tenant(pool, config, Some(tenant_id), entity_id, label).await
}

async fn issue_managed_optional_tenant(
    pool: &PgPool,
    config: &atom::config::Config,
    tenant_id: Option<Uuid>,
    entity_id: Uuid,
    label: &str,
) -> CertificateRecord {
    service::issue_certificate_from_csr_v2(
        pool,
        config,
        tenant_id,
        service::IssueCertificateFromCsrV2 {
            entity_id,
            ttl_secs: Some(3600),
            csr_pem: csr(label),
            idempotency_key: format!("pr011-{label}-{}", Uuid::new_v4()),
        },
    )
    .await
    .unwrap()
    .certificate
}

fn csr(label: &str) -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, label);
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::hours(2);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

async fn set_issuer_status(pool: &PgPool, issuer_id: Uuid, status: &str, enabled: bool) {
    sqlx::query(
        "UPDATE pki_authorities
         SET status = $2, issuance_enabled = $3,
             retiring_at = CASE WHEN $2 = 'retiring' THEN now() ELSE NULL END,
             retired_at = CASE WHEN $2 = 'retired' THEN now() ELSE NULL END,
             failure_reason = CASE
                 WHEN $2 = 'failed' THEN 'PR-011 lifecycle test'
                 ELSE NULL
             END
         WHERE id = $1",
    )
    .bind(issuer_id)
    .bind(status)
    .bind(enabled)
    .execute(pool)
    .await
    .unwrap();
}

fn certificate_der(certificate_pem: &str) -> Vec<u8> {
    let (remaining, pem) = parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    assert!(remaining.iter().all(u8::is_ascii_whitespace));
    pem.contents
}

fn sha256(value: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, value).as_ref())
}

fn random_fingerprint() -> String {
    sha256(Uuid::new_v4().as_bytes())
}

fn colon_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

fn database_code(error: &sqlx::Error) -> Option<String> {
    match error {
        sqlx::Error::Database(error) => error.code().map(|code| code.into_owned()),
        _ => None,
    }
}

fn admin_auth() -> AuthContext {
    AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
        ..Default::default()
    }
}

async fn active_keys(pool: &PgPool, config: &atom::config::Config) -> ActiveKeys {
    keys::rotate(pool, &config.signing_keys)
        .await
        .expect("rotate signing key")
}

async fn token_for(
    pool: &PgPool,
    config: &atom::config::Config,
    keys: &ActiveKeys,
    entity_id: Uuid,
) -> String {
    let session = identity_repo::create_session(pool, entity_id, 3600)
        .await
        .expect("create session");
    encode_jwt(
        entity_id,
        session.id,
        None,
        &keys.primary,
        3600,
        &config.jwt_issuer,
        &config.jwt_audience,
    )
    .expect("encode jwt")
}

fn authed_request<T>(token: &str, message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    let value = format!("Bearer {token}")
        .parse::<MetadataValue<_>>()
        .expect("metadata value");
    request.metadata_mut().insert("authorization", value);
    request
}

async fn certificate_client(address: std::net::SocketAddr) -> CertificateServiceClient<Channel> {
    let endpoint = format!("http://{address}");
    for _ in 0..20 {
        if let Ok(channel) = Channel::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
        {
            return CertificateServiceClient::new(channel);
        }
        sleep(Duration::from_millis(25)).await;
    }
    CertificateServiceClient::connect(endpoint).await.unwrap()
}
