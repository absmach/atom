mod common;

use async_graphql::Request as GraphqlRequest;
use atom::{
    auth::AuthContext,
    certs::authority::{
        provisioning, repo, AuthorityKeyBackend, AuthorityKind, AuthorityRecord, AuthorityStatus,
    },
    config::{Config, PkiCaKeyConfig},
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use chrono::{Duration as ChronoDuration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
};
use serde_json::Value;
use sqlx::PgPool;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::prelude::FromDer;

struct TestRoot {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}

#[tokio::test]
#[ignore]
async fn graphql_provisioning_writes_redacted_audit_and_outbox_events() {
    let pool = common::pool().await;
    let root = test_root("PR-003 Audit Root", -1, 365);
    import_root(&pool, &root.pem).await;
    let tenant_id = create_tenant(&pool, "pki-audit").await;
    let schema = build_schema(graphql_state(pool.clone()));

    let response = schema
        .execute(
            GraphqlRequest::new(format!(
                r#"
                mutation {{
                  beginTenantAuthorityProvisioning(tenantId: "{tenant_id}") {{
                    id
                    status
                  }}
                }}
                "#
            ))
            .data(AuthContext {
                entity_id: common::admin_id(),
                tenant_id: None,
                session_id: None,
                ..Default::default()
            }),
        )
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let body: Value = response.data.into_json().expect("GraphQL JSON");
    let authority_id: Uuid = body["beginTenantAuthorityProvisioning"]["id"]
        .as_str()
        .expect("authority ID")
        .parse()
        .expect("authority UUID");

    let audit_details: Value = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE event = 'pki.authority.provisioning_started' AND target_id = $1",
    )
    .bind(authority_id)
    .fetch_one(&pool)
    .await
    .expect("provisioning audit event");
    assert_eq!(audit_details["status"], "pending_signature");
    assert!(audit_details.get("csr_pem").is_none());
    assert!(audit_details.get("key_reference").is_none());

    let outbox_payload: Value = sqlx::query_scalar(
        "SELECT payload FROM event_outbox WHERE event = 'pki.authority.provisioning_started' AND (payload->>'target_id')::uuid = $1",
    )
    .bind(authority_id)
    .fetch_one(&pool)
    .await
    .expect("provisioning outbox event");
    assert_eq!(
        outbox_payload["event"],
        "pki.authority.provisioning_started"
    );
    assert_eq!(outbox_payload["target_kind"], "pki_authority");
    assert_eq!(outbox_payload["tenant_id"], tenant_id.to_string());
    assert_eq!(outbox_payload["details"]["status"], "pending_signature");

    let replay = schema
        .execute(
            GraphqlRequest::new(format!(
                r#"
                mutation {{
                  beginTenantAuthorityProvisioning(tenantId: "{tenant_id}") {{
                    id
                    status
                  }}
                }}
                "#
            ))
            .data(AuthContext {
                entity_id: common::admin_id(),
                tenant_id: None,
                session_id: None,
                ..Default::default()
            }),
        )
        .await;
    assert!(replay.errors.is_empty(), "{:?}", replay.errors);
    assert_eq!(
        replay.data.into_json().expect("replay JSON")["beginTenantAuthorityProvisioning"]["id"],
        authority_id.to_string()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM event_outbox WHERE event = 'pki.authority.provisioning_started' AND (payload->>'target_id')::uuid = $1",
        )
        .bind(authority_id)
        .fetch_one(&pool)
        .await
        .expect("one transition event"),
        1,
        "an idempotent replay must not publish another lifecycle transition"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_logs WHERE event = 'pki.authority.provisioning_replayed' AND target_id = $1",
        )
        .bind(authority_id)
        .fetch_one(&pool)
        .await
        .expect("replay audit"),
        1
    );

    let invalid_root = schema
        .execute(
            GraphqlRequest::new(
                r#"
                mutation {
                  importRootAuthority(certificatePem: "not a certificate") {
                    id
                  }
                }
                "#,
            )
            .data(AuthContext {
                entity_id: common::admin_id(),
                tenant_id: None,
                session_id: None,
                ..Default::default()
            }),
        )
        .await;
    assert!(!invalid_root.errors.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT count(*)
            FROM event_outbox
            WHERE event = 'pki.authority.root_imported'
              AND payload->'details'->>'transport' = 'graphql'
              AND payload->>'outcome' = 'error'
            "#,
        )
        .fetch_one(&pool)
        .await
        .expect("failure observation"),
        1,
        "failed authority mutations must publish one error observation"
    );
}

#[tokio::test]
#[ignore]
async fn ca_provisioning_is_validated_idempotent_and_restart_safe() {
    let pool = common::pool().await;
    let ca_keys = atom::config::Config::for_tests().pki_ca_keys;
    let root = test_root("PR-003 Offline Root", -1, 365);

    let imported_root = import_root(&pool, &root.pem).await;
    assert_eq!(imported_root.kind, AuthorityKind::Root);
    assert_eq!(imported_root.key_backend, AuthorityKeyBackend::PublicOnly);
    assert!(imported_root.encrypted_private_key.is_none());
    assert_eq!(import_root(&pool, &root.pem).await.id, imported_root.id);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM actions WHERE name = 'pki.provision_automated'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    let tenant_id = create_tenant(&pool, "pki-offline-valid").await;

    // Wrong parent signature is retained as a failed authority.
    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    assert_generated_ca_csr(&pending, BasicConstraints::Constrained(0));
    let wrong_root = test_root("PR-003 Offline Root", -1, 365);
    let wrong_parent_cert = sign_csr(&pending, &wrong_root, |_| {});
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &wrong_parent_cert).await);

    // A certificate with the intended subject but another key cannot activate.
    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let wrong_key_cert = sign_with_wrong_key(&pending, &root);
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &wrong_key_cert).await);

    // The subject is derived from the stored tenant; a signer cannot substitute it.
    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let wrong_tenant_cert = sign_csr(&pending, &root, |csr| {
        let mut subject = DistinguishedName::new();
        subject.push(
            DnType::CommonName,
            "Atom Tenant attacker Intermediate CA v1",
        );
        csr.params.distinguished_name = subject;
    });
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &wrong_tenant_cert).await);

    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let not_a_ca = sign_csr(&pending, &root, |csr| csr.params.is_ca = IsCa::NoCa);
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &not_a_ca).await);

    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let missing_usage = sign_csr(&pending, &root, |csr| csr.params.key_usages.clear());
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &missing_usage).await);

    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let excessive_path = sign_csr(&pending, &root, |csr| {
        csr.params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    });
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &excessive_path).await);

    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let excessive_validity = sign_csr(&pending, &root, |csr| {
        csr.params.not_after = root.params.not_after + TimeDuration::days(1);
    });
    assert_failed(import_signed(&pool, &ca_keys, pending.id, &excessive_validity).await);

    // The valid offline flow activates exactly the generated key and chain.
    let pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let signed = sign_csr(&pending, &root, |_| {});
    let valid = import_signed(&pool, &ca_keys, pending.id, &signed).await;
    assert!(valid.succeeded(), "{:?}", valid.validation_error);
    assert_eq!(valid.authority.status, AuthorityStatus::Active);
    assert!(valid.authority.issuance_enabled);
    assert!(valid
        .authority
        .chain_pem
        .as_deref()
        .is_some_and(|chain| chain.matches("BEGIN CERTIFICATE").count() == 2));

    // Importing the same certificate is idempotent and cannot create a second row.
    let duplicate = import_signed(&pool, &ca_keys, pending.id, &signed).await;
    assert!(duplicate.succeeded());
    assert_eq!(duplicate.authority.id, valid.authority.id);

    // A new version performs a one-active-issuer handover.
    let replacement_pending = begin_tenant(&pool, &ca_keys, tenant_id).await;
    let replacement_pem = sign_csr(&replacement_pending, &root, |_| {});
    let replacement =
        import_signed(&pool, &ca_keys, replacement_pending.id, &replacement_pem).await;
    assert!(replacement.succeeded());
    assert_eq!(replacement.replaced_authorities, vec![valid.authority.id]);
    let old = repo::authority_by_id(&pool, valid.authority.id)
        .await
        .unwrap();
    assert_eq!(old.status, AuthorityStatus::Retiring);
    assert!(!old.issuance_enabled);
    assert_eq!(
        repo::active_leaf_issuer_for_scope(&pool, Some(tenant_id))
            .await
            .unwrap()
            .id,
        replacement.authority.id
    );

    // Global entities have a distinct pathLen=0 leaf issuer.
    let platform_pending = begin_platform_leaf(&pool, &ca_keys).await;
    assert_generated_ca_csr(&platform_pending, BasicConstraints::Constrained(0));
    let platform_pem = sign_csr(&platform_pending, &root, |_| {});
    let platform = import_signed(&pool, &ca_keys, platform_pending.id, &platform_pem).await;
    assert!(platform.succeeded());
    assert_eq!(
        repo::active_leaf_issuer_for_scope(&pool, None)
            .await
            .unwrap()
            .id,
        platform.authority.id
    );
    assert_ne!(platform.authority.id, replacement.authority.id);

    // Automated tenant provisioning uses the separately authorized platform
    // intermediate, never the high-volume global leaf issuer.
    let platform_ca_pending = begin_platform_intermediate(&pool, &ca_keys).await;
    assert_generated_ca_csr(&platform_ca_pending, BasicConstraints::Constrained(1));
    let platform_ca_pem = sign_csr(&platform_ca_pending, &root, |_| {});
    let platform_ca =
        import_signed(&pool, &ca_keys, platform_ca_pending.id, &platform_ca_pem).await;
    assert!(platform_ca.succeeded());
    assert!(!platform_ca.authority.issuance_enabled);
    let automated_tenant = create_tenant(&pool, "pki-automated").await;
    let automated = provision_automatically(&pool, &ca_keys, automated_tenant).await;
    assert!(automated.succeeded());
    assert_eq!(
        automated.authority.parent_id,
        Some(platform_ca.authority.id)
    );
    assert!(automated.authority.issuance_enabled);

    // Trust bundle generation is database-backed and changes without a restart.
    let bundle_before = provisioning::trust_bundle(&pool).await.unwrap();
    let bundle_tenant = create_tenant(&pool, "pki-trust-bundle").await;
    let bundle_pending = begin_tenant(&pool, &ca_keys, bundle_tenant).await;
    let bundle_cert = sign_csr(&bundle_pending, &root, |_| {});
    let bundle_authority = import_signed(&pool, &ca_keys, bundle_pending.id, &bundle_cert).await;
    assert!(bundle_authority.succeeded());
    let bundle_after = provisioning::trust_bundle(&pool).await.unwrap();
    assert_ne!(bundle_before.version, bundle_after.version);
    assert!(bundle_after.pem.contains(&bundle_cert));

    // Concurrent requests serialize and return one persisted CSR/key row.
    let concurrent_tenant = create_tenant(&pool, "pki-concurrent").await;
    let first = begin_tenant_owned(pool.clone(), ca_keys.clone(), concurrent_tenant);
    let second = begin_tenant_owned(pool.clone(), ca_keys.clone(), concurrent_tenant);
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.id, second.id);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pki_authorities WHERE tenant_id = $1 AND status = 'pending_signature'",
        )
        .bind(concurrent_tenant)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // A committed pending row can be resumed through a fresh pool, proving that
    // restart recovery does not depend on process memory.
    let restart_tenant = create_tenant(&pool, "pki-restart").await;
    let restart_pending = begin_tenant(&pool, &ca_keys, restart_tenant).await;
    let restart_cert = sign_csr(&restart_pending, &root, |_| {});
    let restarted_pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let restarted =
        import_signed(&restarted_pool, &ca_keys, restart_pending.id, &restart_cert).await;
    assert!(restarted.succeeded());
    restarted_pool.close().await;

    // Parent state is checked at import time, independently of certificate parsing.
    let expired_tenant = create_tenant(&pool, "pki-expired-parent").await;
    let expired_pending = begin_tenant(&pool, &ca_keys, expired_tenant).await;
    let expired_cert = sign_csr(&expired_pending, &root, |_| {});
    set_parent_validity(
        &pool,
        imported_root.id,
        Utc::now() - ChronoDuration::days(2),
        Utc::now() - ChronoDuration::days(1),
    )
    .await;
    assert_failed(import_signed(&pool, &ca_keys, expired_pending.id, &expired_cert).await);

    set_parent_validity(
        &pool,
        imported_root.id,
        imported_root.not_before.unwrap(),
        imported_root.not_after.unwrap(),
    )
    .await;
    let future_tenant = create_tenant(&pool, "pki-future-parent").await;
    let future_pending = begin_tenant(&pool, &ca_keys, future_tenant).await;
    let future_cert = sign_csr(&future_pending, &root, |_| {});
    set_parent_validity(
        &pool,
        imported_root.id,
        Utc::now() + ChronoDuration::hours(1),
        imported_root.not_after.unwrap(),
    )
    .await;
    assert_failed(import_signed(&pool, &ca_keys, future_pending.id, &future_cert).await);
}

fn test_root(common_name: &str, starts_in_days: i64, lasts_days: i64) -> TestRoot {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(2));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.not_before = OffsetDateTime::now_utc() + TimeDuration::days(starts_in_days);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(lasts_days);
    let pem = params.self_signed(&key).unwrap().pem();
    TestRoot { params, key, pem }
}

fn sign_csr(
    pending: &AuthorityRecord,
    root: &TestRoot,
    mutate: impl FnOnce(&mut CertificateSigningRequestParams),
) -> String {
    let mut csr =
        CertificateSigningRequestParams::from_pem(pending.csr_pem.as_deref().unwrap()).unwrap();
    csr.params.not_before = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
    csr.params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(30);
    csr.params.use_authority_key_identifier_extension = true;
    mutate(&mut csr);
    csr.signed_by(&Issuer::from_params(&root.params, &root.key))
        .unwrap()
        .pem()
}

fn sign_with_wrong_key(pending: &AuthorityRecord, root: &TestRoot) -> String {
    let wrong_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, pending.subject.as_str());
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.use_authority_key_identifier_extension = true;
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(30);
    params
        .signed_by(&wrong_key, &Issuer::from_params(&root.params, &root.key))
        .unwrap()
        .pem()
}

fn assert_generated_ca_csr(authority: &AuthorityRecord, expected: BasicConstraints) {
    let parsed =
        CertificateSigningRequestParams::from_pem(authority.csr_pem.as_deref().unwrap()).unwrap();
    assert_eq!(parsed.params.is_ca, IsCa::Ca(expected));
    assert!(parsed
        .params
        .key_usages
        .contains(&KeyUsagePurpose::KeyCertSign));
    assert!(parsed.params.key_usages.contains(&KeyUsagePurpose::CrlSign));
}

fn assert_failed(outcome: provisioning::AuthorityImportOutcome) {
    assert!(!outcome.succeeded());
    assert_eq!(outcome.authority.status, AuthorityStatus::Failed);
    assert!(!outcome.authority.issuance_enabled);
    assert!(outcome.authority.failure_reason.is_some());
}

async fn import_root(pool: &PgPool, pem: &str) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    let authority = provisioning::import_root_in_tx(&mut tx, pem).await.unwrap();
    tx.commit().await.unwrap();
    authority
}

async fn begin_tenant(pool: &PgPool, ca_keys: &PkiCaKeyConfig, tenant_id: Uuid) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    let authority = provisioning::begin_tenant_authority_in_tx(&mut tx, ca_keys, tenant_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    authority
}

async fn begin_tenant_owned(
    pool: PgPool,
    ca_keys: PkiCaKeyConfig,
    tenant_id: Uuid,
) -> AuthorityRecord {
    begin_tenant(&pool, &ca_keys, tenant_id).await
}

async fn begin_platform_leaf(pool: &PgPool, ca_keys: &PkiCaKeyConfig) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    let authority = provisioning::begin_platform_leaf_issuer_in_tx(&mut tx, ca_keys)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    authority
}

async fn begin_platform_intermediate(pool: &PgPool, ca_keys: &PkiCaKeyConfig) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    let authority = provisioning::begin_platform_intermediate_in_tx(&mut tx, ca_keys)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    authority
}

async fn provision_automatically(
    pool: &PgPool,
    ca_keys: &PkiCaKeyConfig,
    tenant_id: Uuid,
) -> provisioning::AuthorityImportOutcome {
    let mut tx = pool.begin().await.unwrap();
    let outcome = provisioning::provision_tenant_automatically_in_tx(&mut tx, ca_keys, tenant_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    outcome
}

async fn import_signed(
    pool: &PgPool,
    ca_keys: &PkiCaKeyConfig,
    authority_id: Uuid,
    certificate_pem: &str,
) -> provisioning::AuthorityImportOutcome {
    let mut tx = pool.begin().await.unwrap();
    let outcome = provisioning::import_signed_authority_in_tx(
        &mut tx,
        ca_keys,
        authority_id,
        certificate_pem,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    outcome
}

async fn create_tenant(pool: &PgPool, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{prefix}-{id}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

fn graphql_state(pool: PgPool) -> AppState {
    let mut config = Config::for_tests();
    config.events.amqp_url = Some("amqp://unused-in-this-test".to_string());
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
        None,
    )
}

async fn set_parent_validity(
    pool: &PgPool,
    authority_id: Uuid,
    not_before: chrono::DateTime<Utc>,
    not_after: chrono::DateTime<Utc>,
) {
    sqlx::query(
        "UPDATE pki_authorities SET not_before = $2, not_after = $3, updated_at = now() WHERE id = $1",
    )
    .bind(authority_id)
    .bind(not_before)
    .bind(not_after)
    .execute(pool)
    .await
    .unwrap();
}

#[test]
fn signed_certificates_are_parseable_by_an_independent_parser() {
    let root = test_root("Independent Parser Root", -1, 30);
    let pem = x509_parser::pem::parse_x509_pem(root.pem.as_bytes())
        .unwrap()
        .1;
    let certificate = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .unwrap()
        .1;
    assert!(certificate.tbs_certificate.is_ca());
}
