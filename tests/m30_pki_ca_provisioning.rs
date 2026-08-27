mod common;

use async_graphql::Request as GraphqlRequest;
use atom::{
    auth::AuthContext,
    certs::authority::provisioning,
    config::Config,
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
};
use serde_json::Value;
use sqlx::PgPool;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::prelude::FromDer;

struct TestRoot {
    #[allow(dead_code)]
    params: CertificateParams,
    #[allow(dead_code)]
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

async fn import_root(pool: &PgPool, pem: &str) {
    let mut tx = pool.begin().await.unwrap();
    provisioning::import_root_in_tx(&mut tx, pem).await.unwrap();
    tx.commit().await.unwrap();
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
