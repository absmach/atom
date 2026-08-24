//! PR-006 managed generated-key leaf issuance coverage.
//!
//! Requires PostgreSQL and OpenSSL. CI runs this ignored binary against its own
//! freshly migrated database, single-threaded.

mod common;

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use async_graphql::{Request, Variables};
use atom::{auth::AuthContext, config::Config, graphql::build_schema};
use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroize;

#[tokio::test]
#[ignore]
async fn managed_generated_key_issuance_enforces_the_pr006_contract() {
    let pool = common::pool().await;
    let enabled = common::pki::managed_config(true, true);
    let tenant_a = common::pki::create_tenant(&pool, "pki-generated-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-generated-b").await;
    let tenant_without_issuer = common::pki::create_tenant(&pool, "pki-generated-none").await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-generated-actor-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-generated-target-b").await;
    let entity_without_issuer =
        common::pki::create_entity(&pool, tenant_without_issuer, "pki-generated-no-issuer").await;
    let root = common::pki::test_root("PR-006 Offline Root");
    let issuer = common::pki::provision_tenant_issuer(&pool, &enabled, &root, tenant_a).await;

    // Make the stored profile choose P-384. This proves generated-key
    // selection follows profile data rather than a hardcoded P-256 default.
    sqlx::query(
        r#"UPDATE certificate_profiles
           SET permitted_key_algorithms = '[{"algorithm":"ecdsa","sizes":[384]}]'::jsonb
           WHERE tenant_id IS NULL AND name = 'client'"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let logs = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(logs.clone())
        .finish();
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);

    // The feature remains fail-closed unless an operator explicitly opts in.
    let disabled_schema = build_schema(common::pki::graphql_state(
        pool.clone(),
        common::pki::managed_config(false, true),
    ));
    let disabled = disabled_schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            Some(3600),
        ))
        .await;
    assert!(errors_contain(&disabled.errors, "forbidden"));
    assert_eq!(certificate_count(&pool, entity_a).await, 0);

    let schema = build_schema(common::pki::graphql_state(pool.clone(), enabled.clone()));

    // The new contract is deliberately narrow and the v1 migration path is
    // still present rather than being silently redirected.
    let introspection = schema
        .execute(Request::new(
            r#"{
              generated: __type(name: "IssueGeneratedCertificateV2Input") {
                inputFields { name }
              }
              certificate: __type(name: "Certificate") { fields { name } }
              mutation: __schema { mutationType { fields { name } } }
            }"#,
        ))
        .await;
    assert!(
        introspection.errors.is_empty(),
        "{:?}",
        introspection.errors
    );
    let introspection = introspection.data.into_json().unwrap();
    let mut generated_fields = field_names(&introspection["generated"]["inputFields"]);
    generated_fields.sort();
    assert_eq!(generated_fields, vec!["entityId", "ttlSecs"]);
    let certificate_fields = field_names(&introspection["certificate"]["fields"]);
    assert!(!certificate_fields
        .iter()
        .any(|field| field.contains("private")));
    let mutation_fields = field_names(&introspection["mutation"]["mutationType"]["fields"]);
    assert!(mutation_fields.contains(&"issueGeneratedCertificateV2".to_string()));

    let unauthenticated = schema
        .execute(Request::new(issue_document()).variables(issue_variables(entity_a, Some(3600))))
        .await;
    assert!(!unauthenticated.errors.is_empty());
    assert_eq!(certificate_count(&pool, entity_a).await, 0);

    let cross_tenant = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_b,
            Some(3600),
        ))
        .await;
    assert!(errors_contain(&cross_tenant.errors, "forbidden"));
    assert_eq!(certificate_count(&pool, entity_b).await, 0);

    let no_issuer = schema
        .execute(issue_request(
            entity_without_issuer,
            Some(tenant_without_issuer),
            entity_without_issuer,
            Some(3600),
        ))
        .await;
    assert!(errors_contain(
        &no_issuer.errors,
        "no active issuing authority"
    ));
    assert_eq!(certificate_count(&pool, entity_without_issuer).await, 0);
    assert_eq!(
        error_event_count(&pool, "certificate.issue", entity_without_issuer).await,
        1,
        "failed generated issuance must publish one error observation"
    );

    let issued = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            Some(3600),
        ))
        .await;
    assert!(issued.errors.is_empty(), "{:?}", issued.errors);
    let serialized = issued.data.into_json().unwrap();
    let issued = serialized["issueGeneratedCertificateV2"].clone();
    let mut private_key_pem = issued["privateKeyPem"]
        .as_str()
        .expect("one-time private key in successful response")
        .to_string();
    assert!(private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert_eq!(issued["idempotentReplay"], false);
    assert_eq!(issued["certificate"]["issuerId"], issuer.id.to_string());
    assert_eq!(issued["certificate"]["entityId"], entity_a.to_string());
    assert_eq!(issued["certificate"]["tenantId"], tenant_a.to_string());
    assert_eq!(issued["certificate"]["profileName"], "client");

    let credential_id: Uuid = issued["certificate"]["credentialId"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let leaf_pem = issued["certificate"]["certificatePem"]
        .as_str()
        .unwrap()
        .to_string();
    let chain_pem = issued["chainPem"].as_str().unwrap().to_string();
    assert_generated_key_matches_certificate(&private_key_pem, &leaf_pem);
    common::pki::assert_chain_with_openssl(&leaf_pem, &chain_pem, &root.pem);

    // The only durable artifact is the issuer-bound certificate and its
    // non-secret profile/chain metadata.
    let persisted: (Option<Uuid>, Value, Option<String>, Option<Vec<u8>>) = sqlx::query_as(
        r#"SELECT issuer_id, metadata, secret_hash, secret_ciphertext
           FROM credentials WHERE id = $1"#,
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted.0, Some(issuer.id));
    assert!(persisted.2.is_none() && persisted.3.is_none());
    let persisted_text = persisted.1.to_string();
    assert!(!persisted_text.contains(&private_key_pem));
    assert!(!persisted_text.contains("PRIVATE KEY"));
    assert_eq!(persisted.1["profile_name"], "client");
    assert_eq!(persisted.1["chain_pem"], chain_pem);

    let audit_details: Value = sqlx::query_scalar(
        r#"SELECT details FROM audit_logs
           WHERE event = 'certificate.issue' AND target_id = $1
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(entity_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    let outbox_payload: Value = sqlx::query_scalar(
        r#"SELECT payload FROM event_outbox
           WHERE event = 'certificate.issue'
             AND (payload->>'target_id')::uuid = $1
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(entity_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    for observable in [&audit_details, &outbox_payload] {
        let text = observable.to_string();
        assert!(!text.contains(&private_key_pem));
        assert!(!text.contains("PRIVATE KEY"));
    }
    assert_eq!(audit_details["generated_key"], true);
    assert_eq!(audit_details["credential_id"], credential_id.to_string());
    let captured_logs = logs.contents();
    assert!(!captured_logs.contains(&private_key_pem));
    assert!(!captured_logs.contains("PRIVATE KEY"));

    // A later credential read has no field or storage channel from which to
    // reveal the key returned by the issuance response.
    let retrieved = schema
        .execute(
            Request::new(format!(
                r#"{{ certificate(credentialId: "{credential_id}") {{
                  credentialId certificatePem issuerId profileId identityUri
                }} }}"#
            ))
            // Credential reads require an explicit read/manage capability;
            // use the seeded platform administrator so this assertion tests
            // the persisted response shape rather than self-management auth.
            .data(auth(common::admin_id(), None)),
        )
        .await;
    assert!(retrieved.errors.is_empty(), "{:?}", retrieved.errors);
    assert_eq!(
        retrieved.data.into_json().unwrap()["certificate"]["credentialId"],
        credential_id.to_string()
    );

    // A failure after signing but before persistence commits no credential or
    // success audit, but it does emit one error observation. The generated
    // secret is dropped/zeroized and never appears in the returned error/logs.
    install_persistence_failure_trigger(&pool, entity_a).await;
    let before_credentials = certificate_count(&pool, entity_a).await;
    let before_audits = event_count(&pool, "audit_logs", entity_a).await;
    let before_events = event_count(&pool, "event_outbox", entity_a).await;
    let rollback = schema
        .execute(issue_request(
            entity_a,
            Some(tenant_a),
            entity_a,
            Some(3600),
        ))
        .await;
    assert!(!rollback.errors.is_empty());
    assert!(!format!("{:?}", rollback.errors).contains("PRIVATE KEY"));
    remove_persistence_failure_trigger(&pool).await;
    assert_eq!(certificate_count(&pool, entity_a).await, before_credentials);
    assert_eq!(
        event_count(&pool, "audit_logs", entity_a).await,
        before_audits
    );
    assert_eq!(
        event_count(&pool, "event_outbox", entity_a).await,
        before_events + 1
    );
    let failure: (String, String) = sqlx::query_as(
        r#"SELECT payload->>'outcome', payload->'details'->>'transport'
           FROM event_outbox
           WHERE event = 'certificate.issue'
             AND actor_entity_id = $1
             AND payload->>'outcome' = 'error'
           ORDER BY created_at DESC
           LIMIT 1"#,
    )
    .bind(entity_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(failure, ("error".into(), "graphql".into()));

    private_key_pem.zeroize();
}

fn issue_document() -> &'static str {
    r#"mutation Issue($input: IssueGeneratedCertificateV2Input!) {
      issueGeneratedCertificateV2(input: $input) {
        idempotentReplay
        chainPem
        privateKeyPem
        certificate {
          credentialId
          issuerId
          entityId
          tenantId
          certificatePem
          profileId
          profileName
          identityUri
        }
      }
    }"#
}

fn issue_variables(entity_id: Uuid, ttl_secs: Option<u64>) -> Variables {
    Variables::from_json(json!({
        "input": {"entityId": entity_id, "ttlSecs": ttl_secs}
    }))
}

fn issue_request(
    actor_id: Uuid,
    actor_tenant_id: Option<Uuid>,
    entity_id: Uuid,
    ttl_secs: Option<u64>,
) -> Request {
    Request::new(issue_document())
        .variables(issue_variables(entity_id, ttl_secs))
        .data(auth(actor_id, actor_tenant_id))
}

fn auth(entity_id: Uuid, tenant_id: Option<Uuid>) -> AuthContext {
    AuthContext {
        entity_id,
        tenant_id,
        session_id: None,
        ..Default::default()
    }
}

fn field_names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap().to_string())
        .collect()
}

fn errors_contain(errors: &[async_graphql::ServerError], expected: &str) -> bool {
    errors.iter().any(|error| error.message.contains(expected))
}

fn assert_generated_key_matches_certificate(private_key_pem: &str, certificate_pem: &str) {
    let key = KeyPair::from_pem(private_key_pem).unwrap();
    assert!(std::ptr::eq(key.algorithm(), &PKCS_ECDSA_P384_SHA384));
    let (_, public_pem) = parse_x509_pem(key.public_key_pem().as_bytes()).unwrap();
    let (_, certificate_pem) = parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(&certificate_pem.contents).unwrap();
    assert_eq!(public_pem.contents, certificate.public_key().raw);
    assert_eq!(certificate.public_key().parsed().unwrap().key_size(), 384);
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

async fn error_event_count(pool: &PgPool, event: &str, target_id: Uuid) -> i64 {
    sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM event_outbox
           WHERE event = $1
             AND (payload->>'target_id')::uuid = $2
             AND payload->>'outcome' = 'error'
             AND payload->'details'->>'transport' = 'graphql'"#,
    )
    .bind(event)
    .bind(target_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn event_count(pool: &PgPool, table: &str, target_id: Uuid) -> i64 {
    let query = match table {
        "audit_logs" => {
            "SELECT COUNT(*) FROM audit_logs WHERE event = 'certificate.issue' AND target_id = $1"
        }
        "event_outbox" => {
            "SELECT COUNT(*) FROM event_outbox WHERE event = 'certificate.issue' AND (payload->>'target_id')::uuid = $1"
        }
        _ => panic!("unsupported event table"),
    };
    sqlx::query_scalar(query)
        .bind(target_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn install_persistence_failure_trigger(pool: &PgPool, entity_id: Uuid) {
    sqlx::query(&format!(
        r#"CREATE FUNCTION pki_test_generated_persistence_failure() RETURNS trigger AS $$
        BEGIN
            IF NEW.entity_id = '{entity_id}'::uuid
               AND NEW.kind = 'certificate'
               AND NEW.issuer_id IS NOT NULL THEN
                RAISE EXCEPTION 'synthetic generated credential failure' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql"#,
    ))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER trg_pki_test_generated_persistence_failure BEFORE INSERT ON credentials FOR EACH ROW EXECUTE FUNCTION pki_test_generated_persistence_failure()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn remove_persistence_failure_trigger(pool: &PgPool) {
    sqlx::query("DROP TRIGGER trg_pki_test_generated_persistence_failure ON credentials")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION pki_test_generated_persistence_failure()")
        .execute(pool)
        .await
        .unwrap();
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self.0.clone())
    }
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn generated_key_gate_is_off_in_test_config() {
    let config = Config::for_tests();
    assert!(!config.pki_generated_key_issuance_enabled);
}
