//! PR-005 managed CSR issuance coverage.
//!
//! Requires PostgreSQL and OpenSSL. The CI fresh-database matrix executes this
//! ignored test binary single-threaded.

mod common;

use std::{fs, process::Command};

use async_graphql::{Request, Variables};
use atom::{
    auth::AuthContext,
    certs::authority::{provisioning, repo as authority_repo, AuthorityRecord},
    config::{Config, PkiCaKeyConfig},
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, SanType,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;

const OCSP_URL: &str = "https://pki.example.test/tenant/ocsp";
const CA_ISSUERS_URL: &str = "https://pki.example.test/tenant/ca.der";
const CRL_URL: &str = "https://pki.example.test/tenant/crl.der";

struct TestRoot {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}

#[tokio::test]
#[ignore]
async fn managed_csr_issuance_enforces_the_pr005_contract() {
    let pool = common::pool().await;
    let config = managed_config();
    let tenant_a = create_tenant(&pool, "pki-csr-a").await;
    let tenant_b = create_tenant(&pool, "pki-csr-b").await;
    let tenant_without_issuer = create_tenant(&pool, "pki-csr-none").await;
    let entity_a = create_entity(&pool, tenant_a, "pki-csr-actor-a").await;
    let entity_b = create_entity(&pool, tenant_b, "pki-csr-target-b").await;
    let entity_without_issuer =
        create_entity(&pool, tenant_without_issuer, "pki-csr-no-issuer").await;

    let root = test_root();
    let issuer = provision_tenant_issuer(&pool, &config.pki_ca_keys, &root, tenant_a).await;
    let schema = build_schema(graphql_state(pool.clone(), config.clone()));

    // The public v2 contract has no tenant, issuer, CA path, key reference, or
    // profile selector. Scope and signer selection remain internal.
    let introspection = schema
        .execute(Request::new(
            r#"{
              __type(name: "IssueCertificateFromCsrV2Input") {
                inputFields { name }
              }
            }"#,
        ))
        .await;
    assert!(
        introspection.errors.is_empty(),
        "{:?}",
        introspection.errors
    );
    let mut input_fields = introspection.data.into_json().unwrap()["__type"]["inputFields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    input_fields.sort();
    assert_eq!(
        input_fields,
        vec![
            "csrPem".to_string(),
            "entityId".to_string(),
            "idempotencyKey".to_string(),
            "ttlSecs".to_string(),
        ]
    );

    let plain_csr = csr(|_| {});
    let first = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &plain_csr,
            "request-one",
            Some(3600),
        ))
        .await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let first = first.data.into_json().unwrap()["issueCertificateFromCsrV2"].clone();
    assert_eq!(first["privateKeyPem"], Value::Null);
    assert_eq!(first["idempotentReplay"], false);
    assert_eq!(first["certificate"]["issuerId"], issuer.id.to_string());
    assert_eq!(first["certificate"]["entityId"], entity_a.to_string());
    assert_eq!(first["certificate"]["tenantId"], tenant_a.to_string());
    assert_eq!(first["certificate"]["profileName"], "client");
    assert_eq!(
        first["certificate"]["identityUri"],
        format!("urn:atom:tenant:{tenant_a}:entity:{entity_a}")
    );
    let credential_id: Uuid = first["certificate"]["credentialId"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let serial_number = first["certificate"]["serialNumber"]
        .as_str()
        .unwrap()
        .to_string();
    let leaf_pem = first["certificate"]["certificatePem"]
        .as_str()
        .unwrap()
        .to_string();
    let chain_pem = first["chainPem"].as_str().unwrap().to_string();
    assert_eq!(chain_pem.matches("BEGIN CERTIFICATE").count(), 3);
    assert_chain_with_openssl(&leaf_pem, &chain_pem, &root.pem);

    let persisted: (Option<Uuid>, Uuid, Value, Option<String>, Option<Vec<u8>>) = sqlx::query_as(
        r#"SELECT issuer_id, entity_id, metadata, secret_hash, secret_ciphertext
               FROM credentials WHERE id = $1"#,
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted.0, Some(issuer.id));
    assert_eq!(persisted.1, entity_a);
    assert!(persisted.3.is_none() && persisted.4.is_none());
    let persisted_text = persisted.2.to_string();
    assert!(!persisted_text.contains("PRIVATE KEY"));
    assert_eq!(persisted.2["profile_name"], "client");
    assert_eq!(
        persisted.2["identity_uri"],
        first["certificate"]["identityUri"]
    );

    // An exact retry resolves to the original credential and creates neither a
    // second certificate nor a second domain event.
    let replay = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &plain_csr,
            "request-one",
            Some(3600),
        ))
        .await;
    assert!(replay.errors.is_empty(), "{:?}", replay.errors);
    let replay = replay.data.into_json().unwrap()["issueCertificateFromCsrV2"].clone();
    assert_eq!(replay["idempotentReplay"], true);
    assert_eq!(
        replay["certificate"]["credentialId"],
        credential_id.to_string()
    );
    assert_eq!(replay["certificate"]["serialNumber"], serial_number);
    assert_eq!(certificate_count(&pool, entity_a).await, 1);

    let mismatched_retry = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &csr(|_| {}),
            "request-one",
            Some(3600),
        ))
        .await;
    assert!(errors_contain(&mismatched_retry.errors, "idempotency key"));
    assert_eq!(certificate_count(&pool, entity_a).await, 1);

    let ledger: (String, String, Option<Uuid>) = sqlx::query_as(
        r#"SELECT request_key_hash, request_fingerprint_sha256, credential_id
           FROM certificate_issuance_requests WHERE entity_id = $1"#,
    )
    .bind(entity_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(ledger.0, "request-one");
    assert_eq!(ledger.0.len(), 64);
    assert_eq!(ledger.1.len(), 64);
    assert_eq!(ledger.2, Some(credential_id));
    assert_eq!(
        event_count(&pool, "audit_logs", "certificate.issue", entity_a).await,
        1
    );
    assert_eq!(
        event_count(&pool, "event_outbox", "certificate.issue", entity_a).await,
        1
    );
    assert_eq!(
        event_count(&pool, "audit_logs", "certificate.issue_replayed", entity_a,).await,
        1
    );

    // A tenant-A principal can manage itself but cannot use that identity to
    // sign a certificate for a tenant-B entity.
    let cross_tenant = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_b,
            &plain_csr,
            "cross-tenant",
            Some(3600),
        ))
        .await;
    assert!(errors_contain(&cross_tenant.errors, "forbidden"));
    assert_eq!(certificate_count(&pool, entity_b).await, 0);

    // The same issuer mismatch is rejected if an internal/import path attempts
    // to bypass the service boundary.
    let db_scope_error = sqlx::query(
        r#"INSERT INTO credentials (
               id, entity_id, kind, identifier, issuer_id, metadata
           ) VALUES ($1, $2, 'certificate', $3, $4, '{}')"#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_b)
    .bind(format!("deadbeef{}", Uuid::new_v4().simple()))
    .bind(issuer.id)
    .execute(&pool)
    .await
    .expect_err("cross-tenant issuer insert must fail");
    assert!(matches!(
        db_scope_error,
        sqlx::Error::Database(ref database) if database.code().as_deref() == Some("23514")
    ));

    let no_issuer = schema
        .execute(issue_request(
            entity_without_issuer,
            Some(tenant_without_issuer),
            entity_without_issuer,
            &plain_csr,
            "no-issuer",
            Some(3600),
        ))
        .await;
    assert!(errors_contain(
        &no_issuer.errors,
        "no active issuing authority"
    ));
    assert_eq!(certificate_count(&pool, entity_without_issuer).await, 0);

    // The production route reaches the PR-004 CSR policy boundary rather than
    // copying privileged request extensions.
    let attacks = [
        ("malformed", "not a CSR".to_string()),
        ("invalid-signature", corrupt_csr_signature(&plain_csr)),
        (
            "ca-request",
            csr(|params| {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            }),
        ),
        (
            "identity-substitution",
            csr(|params| {
                params.subject_alt_names = vec![SanType::URI(
                    "urn:atom:tenant:attacker:entity:attacker"
                        .try_into()
                        .unwrap(),
                )];
            }),
        ),
        (
            "arbitrary-eku",
            csr(|params| params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth]),
        ),
    ];
    for (key, attack) in attacks {
        let response = schema
            .execute(issue_request(
                entity_a,
                Some(tenant_a),
                entity_a,
                &attack,
                key,
                Some(3600),
            ))
            .await;
        assert!(
            !response.errors.is_empty(),
            "attack {key} unexpectedly passed"
        );
    }
    assert_eq!(certificate_count(&pool, entity_a).await, 1);

    // A synthetic first-attempt unique violation proves the service rolls back
    // the poisoned savepoint and retries on the same outer connection.
    install_serial_collision_trigger(&pool, entity_a).await;
    let collision = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &plain_csr,
            "serial-collision",
            Some(3600),
        ))
        .await;
    assert!(collision.errors.is_empty(), "{:?}", collision.errors);
    let collision_attempts: i64 =
        sqlx::query_scalar("SELECT last_value FROM pki_test_serial_collision_seq")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(collision_attempts, 2);
    remove_serial_collision_trigger(&pool).await;
    assert_eq!(certificate_count(&pool, entity_a).await, 2);

    // Signing occurs before credential persistence. A forced database failure
    // returns no artifact and rolls back the credential, retry ledger, audit,
    // and outbox state together.
    install_persistence_failure_trigger(&pool, entity_a).await;
    let before_credentials = certificate_count(&pool, entity_a).await;
    let before_requests = issuance_request_count(&pool, entity_a).await;
    let before_events = event_count(&pool, "event_outbox", "certificate.issue", entity_a).await;
    let rollback = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &plain_csr,
            "forced-rollback",
            Some(3600),
        ))
        .await;
    assert!(!rollback.errors.is_empty());
    remove_persistence_failure_trigger(&pool).await;
    assert_eq!(certificate_count(&pool, entity_a).await, before_credentials);
    assert_eq!(
        issuance_request_count(&pool, entity_a).await,
        before_requests
    );
    assert_eq!(
        event_count(&pool, "event_outbox", "certificate.issue", entity_a).await,
        before_events
    );

    // Both expired and retiring issuers are excluded by the internal selector.
    let original_not_before = issuer.not_before.unwrap();
    let original_not_after = issuer.not_after.unwrap();
    sqlx::query(
        r#"UPDATE pki_authorities
           SET not_before = $2, not_after = now() - interval '1 second'
           WHERE id = $1"#,
    )
    .bind(issuer.id)
    .bind(original_not_before)
    .execute(&pool)
    .await
    .unwrap();
    let expired = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &plain_csr,
            "expired-issuer",
            Some(3600),
        ))
        .await;
    assert!(errors_contain(
        &expired.errors,
        "no active issuing authority"
    ));
    sqlx::query("UPDATE pki_authorities SET not_before = $2, not_after = $3 WHERE id = $1")
        .bind(issuer.id)
        .bind(original_not_before)
        .bind(original_not_after)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        r#"UPDATE pki_authorities
           SET status = 'retiring', issuance_enabled = false, retiring_at = now()
           WHERE id = $1"#,
    )
    .bind(issuer.id)
    .execute(&pool)
    .await
    .unwrap();
    let retiring = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            &plain_csr,
            "retiring-issuer",
            Some(3600),
        ))
        .await;
    assert!(errors_contain(
        &retiring.errors,
        "no active issuing authority"
    ));
}

fn managed_config() -> Config {
    let mut config = Config::for_tests();
    config.events.amqp_url = Some("amqp://unused-in-pr005-test".to_string());
    config.graphql_limits.introspection_enabled = true;
    config
}

fn graphql_state(pool: PgPool, config: Config) -> AppState {
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

fn issue_request(
    actor_id: Uuid,
    actor_tenant_id: Option<Uuid>,
    entity_id: Uuid,
    csr_pem: &str,
    idempotency_key: &str,
    ttl_secs: Option<u64>,
) -> Request {
    Request::new(
        r#"mutation Issue($input: IssueCertificateFromCsrV2Input!) {
          issueCertificateFromCsrV2(input: $input) {
            idempotentReplay
            chainPem
            privateKeyPem
            certificate {
              credentialId
              issuerId
              entityId
              tenantId
              serialNumber
              certificatePem
              fingerprintSha256
              profileId
              profileName
              identityUri
            }
          }
        }"#,
    )
    .variables(Variables::from_json(json!({
        "input": {
            "entityId": entity_id,
            "ttlSecs": ttl_secs,
            "csrPem": csr_pem,
            "idempotencyKey": idempotency_key,
        }
    })))
    .data(AuthContext {
        entity_id: actor_id,
        tenant_id: actor_tenant_id,
        session_id: None,
        ..Default::default()
    })
}

fn errors_contain(errors: &[async_graphql::ServerError], expected: &str) -> bool {
    errors.iter().any(|error| error.message.contains(expected))
}

fn csr(mutate: impl FnOnce(&mut CertificateParams)) -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    mutate(&mut params);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

fn corrupt_csr_signature(csr_pem: &str) -> String {
    let (_, pem) = parse_x509_pem(csr_pem.as_bytes()).unwrap();
    let mut der = pem.contents;
    *der.last_mut().unwrap() ^= 0x01;
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

fn test_root() -> TestRoot {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "PR-005 Offline Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(2));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    let pem = params.self_signed(&key).unwrap().pem();
    TestRoot { params, key, pem }
}

async fn provision_tenant_issuer(
    pool: &PgPool,
    ca_keys: &PkiCaKeyConfig,
    root: &TestRoot,
    tenant_id: Uuid,
) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    provisioning::import_root_in_tx(&mut tx, &root.pem)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let mut pending = provisioning::begin_platform_intermediate_in_tx(&mut tx, ca_keys)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    pending.commit_generated_key();
    let signed = sign_authority_csr(&pending, root);
    let mut tx = pool.begin().await.unwrap();
    let imported =
        provisioning::import_signed_authority_in_tx(&mut tx, ca_keys, pending.id, &signed)
            .await
            .unwrap();
    assert!(imported.succeeded(), "{:?}", imported.validation_error);
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let mut provisioned =
        provisioning::provision_tenant_automatically_in_tx(&mut tx, ca_keys, tenant_id)
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
    .bind(OCSP_URL)
    .bind(CA_ISSUERS_URL)
    .bind(CRL_URL)
    .execute(pool)
    .await
    .unwrap();
    authority_repo::authority_by_id(pool, provisioned.authority.id)
        .await
        .unwrap()
}

fn sign_authority_csr(pending: &AuthorityRecord, root: &TestRoot) -> String {
    let mut csr =
        CertificateSigningRequestParams::from_pem(pending.csr_pem.as_deref().unwrap()).unwrap();
    csr.params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    csr.params.not_after = OffsetDateTime::now_utc() + Duration::days(180);
    csr.params.use_authority_key_identifier_extension = true;
    csr.signed_by(&Issuer::from_params(&root.params, &root.key))
        .unwrap()
        .pem()
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

async fn create_entity(pool: &PgPool, tenant_id: Uuid, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'device', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("{prefix}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn certificate_count(pool: &PgPool, entity_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'certificate'",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn issuance_request_count(pool: &PgPool, entity_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM certificate_issuance_requests WHERE entity_id = $1")
        .bind(entity_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn event_count(pool: &PgPool, table: &str, event: &str, target_id: Uuid) -> i64 {
    let query = match table {
        "audit_logs" => "SELECT COUNT(*) FROM audit_logs WHERE event = $1 AND target_id = $2",
        "event_outbox" => {
            "SELECT COUNT(*) FROM event_outbox WHERE event = $1 AND (payload->>'target_id')::uuid = $2"
        }
        _ => panic!("unsupported event table"),
    };
    sqlx::query_scalar(query)
        .bind(event)
        .bind(target_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn install_serial_collision_trigger(pool: &PgPool, entity_id: Uuid) {
    sqlx::query("CREATE SEQUENCE pki_test_serial_collision_seq")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(&format!(
        r#"CREATE FUNCTION pki_test_serial_collision() RETURNS trigger AS $$
        BEGIN
            IF NEW.entity_id = '{entity_id}'::uuid
               AND NEW.kind = 'certificate'
               AND NEW.issuer_id IS NOT NULL
               AND nextval('pki_test_serial_collision_seq') = 1 THEN
                RAISE EXCEPTION 'synthetic serial collision' USING ERRCODE = '23505';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql"#,
    ))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER trg_pki_test_serial_collision BEFORE INSERT ON credentials FOR EACH ROW EXECUTE FUNCTION pki_test_serial_collision()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn remove_serial_collision_trigger(pool: &PgPool) {
    sqlx::query("DROP TRIGGER trg_pki_test_serial_collision ON credentials")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION pki_test_serial_collision()")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP SEQUENCE pki_test_serial_collision_seq")
        .execute(pool)
        .await
        .unwrap();
}

async fn install_persistence_failure_trigger(pool: &PgPool, entity_id: Uuid) {
    sqlx::query(&format!(
        r#"CREATE FUNCTION pki_test_persistence_failure() RETURNS trigger AS $$
        BEGIN
            IF NEW.entity_id = '{entity_id}'::uuid
               AND NEW.kind = 'certificate'
               AND NEW.issuer_id IS NOT NULL THEN
                RAISE EXCEPTION 'synthetic managed credential failure' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql"#,
    ))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER trg_pki_test_persistence_failure BEFORE INSERT ON credentials FOR EACH ROW EXECUTE FUNCTION pki_test_persistence_failure()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn remove_persistence_failure_trigger(pool: &PgPool) {
    sqlx::query("DROP TRIGGER trg_pki_test_persistence_failure ON credentials")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION pki_test_persistence_failure()")
        .execute(pool)
        .await
        .unwrap();
}

fn assert_chain_with_openssl(leaf_pem: &str, chain_pem: &str, root_pem: &str) {
    let directory = std::env::temp_dir().join(format!("atom-pr005-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let leaf_path = directory.join("leaf.pem");
    let chain_path = directory.join("chain.pem");
    let root_path = directory.join("root.pem");
    fs::write(&leaf_path, leaf_pem).unwrap();
    let root_start = chain_pem
        .rfind("-----BEGIN CERTIFICATE-----")
        .expect("managed chain contains its root");
    fs::write(&chain_path, &chain_pem[..root_start]).unwrap();
    fs::write(&root_path, root_pem).unwrap();
    let output = Command::new("openssl")
        .args(["verify", "-purpose", "sslclient", "-CAfile"])
        .arg(&root_path)
        .arg("-untrusted")
        .arg(&chain_path)
        .arg(&leaf_path)
        .output()
        .expect("OpenSSL must be installed for PR-005 chain verification");
    assert!(
        output.status.success(),
        "OpenSSL chain verification failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(directory).unwrap();

    let (_, leaf) = parse_x509_pem(leaf_pem.as_bytes()).unwrap();
    let (_, issuer) = parse_x509_pem(chain_pem.as_bytes()).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf.contents).unwrap();
    let (_, issuer) = x509_parser::parse_x509_certificate(&issuer.contents).unwrap();
    leaf.verify_signature(Some(issuer.public_key())).unwrap();
}
