//! PR-008 issuer-aware revocation state-machine coverage.
//!
//! Requires PostgreSQL and OpenSSL. CI runs this ignored binary against its own
//! freshly migrated database, single-threaded.

mod common;

use async_graphql::{Request, Variables};
use atom::{
    auth::AuthContext, certs::service, graphql::build_schema, models::enums::TenantStatus, tenants,
};
use rcgen::{CertificateParams, DnType, KeyPair};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn issuer_aware_revocation_enforces_the_pr008_contract() {
    let pool = common::pool().await;
    let config = common::pki::managed_config(false, true);
    let root = common::pki::test_root("PR-008 Offline Root");
    let tenant_a = common::pki::create_tenant(&pool, "pki-revoke-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-revoke-b").await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-revoke-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-revoke-b").await;
    let issuer_a = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let issuer_b = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_b).await;
    let schema = build_schema(common::pki::graphql_state(pool.clone(), config.clone()));

    assert_v2_schema_contract(&schema).await;

    let exact = issue_managed(&pool, &config, tenant_a, entity_a, "exact").await;
    let unaffected = issue_managed(&pool, &config, tenant_b, entity_b, "unaffected").await;
    set_artifact_clean(&pool, issuer_a.id, issuer_a.fingerprint_sha256.as_deref()).await;
    set_artifact_clean(&pool, issuer_b.id, issuer_b.fingerprint_sha256.as_deref()).await;

    // Authorization is evaluated against the exact resolved credential and
    // rechecked under lock, so another tenant cannot revoke it.
    let denied = schema
        .execute(revoke_request(
            entity_b,
            Some(tenant_b),
            json!({"credentialId": exact.credential_id, "reason": "key_compromise"}),
        ))
        .await;
    assert!(errors_contain(&denied.errors, "forbidden"));
    assert_eq!(
        certificate_status(&pool, exact.credential_id).await,
        "active"
    );

    // Exact ID revocation is immediately authoritative and records immutable
    // actor/reason/issuer evidence without dirtying any other issuer.
    let first = schema
        .execute(revoke_request(
            common::admin_id(),
            None,
            json!({"credentialId": exact.credential_id, "reason": "key_compromise"}),
        ))
        .await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let first = first.data.into_json().unwrap()["revokeCertificateV2"].clone();
    assert_eq!(first["idempotentReplay"], false);
    assert_eq!(first["reason"], "key_compromise");
    assert_eq!(first["actorEntityId"], common::admin_id().to_string());
    assert_eq!(
        first["certificate"]["credentialId"],
        exact.credential_id.to_string()
    );
    assert_eq!(first["certificate"]["status"], "revoked");
    let first_revoked_at = first["revokedAt"].as_str().unwrap().to_string();
    assert_revocation_row(
        &pool,
        exact.credential_id,
        issuer_a.id,
        "key_compromise",
        Some(common::admin_id()),
    )
    .await;
    assert!(artifact_dirty(&pool, issuer_a.id).await);
    assert!(!artifact_dirty(&pool, issuer_b.id).await);
    assert!(service::resolve_certificate_identity(
        &pool,
        &exact.serial_number,
        Some(&exact.fingerprint_sha256),
    )
    .await
    .is_err());

    // Repeated revocation is a no-op: it returns the original evidence and
    // does not enqueue a second lifecycle event or rewrite reason/time.
    let first_event_count = event_count(&pool, "certificate.revoke", exact.credential_id).await;
    let replay = schema
        .execute(revoke_request(
            common::admin_id(),
            None,
            json!({"credentialId": exact.credential_id, "reason": "superseded"}),
        ))
        .await;
    assert!(replay.errors.is_empty(), "{:?}", replay.errors);
    let replay = replay.data.into_json().unwrap()["revokeCertificateV2"].clone();
    assert_eq!(replay["idempotentReplay"], true);
    assert_eq!(replay["reason"], "key_compromise");
    assert_eq!(replay["revokedAt"], first_revoked_at);
    assert_eq!(
        event_count(&pool, "certificate.revoke", exact.credential_id).await,
        first_event_count
    );
    assert_audit_and_outbox(&pool, exact.credential_id, issuer_a.id).await;

    // A revoked certificate cannot enter the PR-007 renewal state machine.
    let renew_revoked = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::Operator {
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_a,
            expected_tenant_id: Some(tenant_a),
        },
        service::RenewCertificateV2 {
            credential_id: exact.credential_id,
            ttl_secs: Some(3600),
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "revoked-renewal".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(renew_revoked.to_string().contains("revoked"));

    // Fingerprint and issuer+serial are independent exact selectors. The old
    // serial-only mutation rejects managed certificates.
    let by_fingerprint = issue_managed(&pool, &config, tenant_a, entity_a, "fingerprint").await;
    let fingerprint_response = schema
        .execute(revoke_request(
            common::admin_id(),
            None,
            json!({
                "fingerprintSha256": by_fingerprint.fingerprint_sha256,
                "reason": "affiliation_changed"
            }),
        ))
        .await;
    assert!(
        fingerprint_response.errors.is_empty(),
        "{:?}",
        fingerprint_response.errors
    );
    assert_eq!(
        certificate_status(&pool, by_fingerprint.credential_id).await,
        "revoked"
    );

    let by_issuer_serial = issue_managed(&pool, &config, tenant_b, entity_b, "issuer-serial").await;
    let issuer_serial_response = schema
        .execute(revoke_request(
            common::admin_id(),
            None,
            json!({
                "issuerId": issuer_b.id,
                "serialNumber": by_issuer_serial.serial_number,
                "reason": "cessation_of_operation"
            }),
        ))
        .await;
    assert!(
        issuer_serial_response.errors.is_empty(),
        "{:?}",
        issuer_serial_response.errors
    );
    assert_eq!(
        certificate_status(&pool, by_issuer_serial.credential_id).await,
        "revoked"
    );
    let legacy_managed = schema
        .execute(
            Request::new(format!(
                r#"mutation {{ revokeCertificate(input: {{ serialNumber: "{}" }}) {{ credentialId }} }}"#,
                unaffected.serial_number
            ))
            .data(auth(common::admin_id(), None)),
        )
        .await;
    assert!(errors_contain(
        &legacy_managed.errors,
        "requires revokeCertificateV2"
    ));

    // The selector remains unambiguous once PR-011 removes global serial
    // uniqueness. Exercise that future database shape inside a rolled-back DDL
    // transaction so this PR does not perform the resolver-v2 cutover early.
    let duplicate_a = issue_managed(&pool, &config, tenant_a, entity_a, "duplicate-a").await;
    let duplicate_b = issue_managed(&pool, &config, tenant_b, entity_b, "duplicate-b").await;
    let mut duplicate_tx = pool.begin().await.unwrap();
    sqlx::query("DROP INDEX idx_credentials_certificate_serial")
        .execute(&mut *duplicate_tx)
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET identifier = $1 WHERE id = $2")
        .bind(&duplicate_a.serial_number)
        .bind(duplicate_b.credential_id)
        .execute(&mut *duplicate_tx)
        .await
        .unwrap();
    let duplicate_result = service::revoke_certificate_v2_in_tx(
        &mut duplicate_tx,
        service::RevokeCertificateV2 {
            selector: service::CertificateRevocationSelector::IssuerSerial {
                issuer_id: issuer_b.id,
                serial_number: duplicate_a.serial_number.clone(),
            },
            reason: Some("duplicate_serial_test".into()),
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_b,
            expected_tenant_id: Some(tenant_b),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        duplicate_result.certificate.credential_id,
        duplicate_b.credential_id
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM credentials WHERE id = $1")
            .bind(duplicate_a.credential_id)
            .fetch_one(&mut *duplicate_tx)
            .await
            .unwrap(),
        "active"
    );
    duplicate_tx.rollback().await.unwrap();

    // Entity-wide revocation changes every active certificate exactly once and
    // carries the affected credential/issuer set in its audit/outbox payload.
    let bulk_entity = common::pki::create_entity(&pool, tenant_a, "pki-revoke-bulk").await;
    let bulk_one = issue_managed(&pool, &config, tenant_a, bulk_entity, "bulk-one").await;
    let bulk_two = issue_managed(&pool, &config, tenant_a, bulk_entity, "bulk-two").await;
    let bulk = schema
        .execute(
            Request::new(format!(
                r#"mutation {{ revokeEntityCertificates(entityId: "{bulk_entity}", reason: "entity_revoked") }}"#
            ))
            .data(auth(common::admin_id(), None)),
        )
        .await;
    assert!(bulk.errors.is_empty(), "{:?}", bulk.errors);
    assert_eq!(
        bulk.data.into_json().unwrap()["revokeEntityCertificates"],
        2
    );
    assert_eq!(
        certificate_status(&pool, bulk_one.credential_id).await,
        "revoked"
    );
    assert_eq!(
        certificate_status(&pool, bulk_two.credential_id).await,
        "revoked"
    );
    let repeated_bulk =
        service::revoke_entity_certificates(&pool, bulk_entity, Some("entity_revoked".into()))
            .await
            .unwrap();
    assert_eq!(repeated_bulk, 0);

    // A transaction failure rolls credential state, immutable evidence, and
    // issuer dirtiness back together.
    let rollback_cert = issue_managed(&pool, &config, tenant_b, entity_b, "rollback").await;
    set_artifact_clean(&pool, issuer_b.id, issuer_b.fingerprint_sha256.as_deref()).await;
    let mut rollback_tx = pool.begin().await.unwrap();
    service::revoke_certificate_v2_in_tx(
        &mut rollback_tx,
        service::RevokeCertificateV2 {
            selector: service::CertificateRevocationSelector::CredentialId(
                rollback_cert.credential_id,
            ),
            reason: Some("transaction_rollback".into()),
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_b,
            expected_tenant_id: Some(tenant_b),
        },
    )
    .await
    .unwrap();
    rollback_tx.rollback().await.unwrap();
    assert_eq!(
        certificate_status(&pool, rollback_cert.credential_id).await,
        "active"
    );
    assert!(!revocation_exists(&pool, rollback_cert.credential_id).await);
    assert!(!artifact_dirty(&pool, issuer_b.id).await);

    // The GraphQL/outbox boundary is atomic too: a forced lifecycle-event
    // insert failure must undo the revocation trigger's status, evidence, and
    // exact issuer dirty mark.
    let outbox_failure = issue_managed(&pool, &config, tenant_b, entity_b, "outbox-failure").await;
    set_artifact_clean(&pool, issuer_b.id, issuer_b.fingerprint_sha256.as_deref()).await;
    install_rejecting_outbox_trigger(&pool).await;
    let failed = schema
        .execute(revoke_request(
            common::admin_id(),
            None,
            json!({
                "credentialId": outbox_failure.credential_id,
                "reason": "transaction_failure"
            }),
        ))
        .await;
    drop_rejecting_outbox_trigger(&pool).await;
    assert!(!failed.errors.is_empty());
    assert_eq!(
        certificate_status(&pool, outbox_failure.credential_id).await,
        "active"
    );
    assert!(!revocation_exists(&pool, outbox_failure.credential_id).await);
    assert!(!artifact_dirty(&pool, issuer_b.id).await);
    assert_eq!(
        event_count(&pool, "certificate.revoke", outbox_failure.credential_id).await,
        0
    );

    // Entity and tenant suspension/freeze fail closed without inventing a
    // revocation. Tenant deletion then performs durable lifecycle revocation.
    let lifecycle_tenant = common::pki::create_tenant(&pool, "pki-revoke-lifecycle").await;
    let lifecycle_entity =
        common::pki::create_entity(&pool, lifecycle_tenant, "pki-revoke-lifecycle").await;
    let lifecycle_issuer =
        common::pki::provision_tenant_issuer(&pool, &config, &root, lifecycle_tenant).await;
    let lifecycle = issue_managed(
        &pool,
        &config,
        lifecycle_tenant,
        lifecycle_entity,
        "lifecycle",
    )
    .await;
    tenants::repo::change_tenant_status_with_audit(
        &pool,
        true,
        Some(common::admin_id()),
        lifecycle_tenant,
        TenantStatus::Frozen,
        "tenant.freeze",
    )
    .await
    .unwrap();
    assert!(service::resolve_certificate_identity(
        &pool,
        &lifecycle.serial_number,
        Some(&lifecycle.fingerprint_sha256),
    )
    .await
    .is_err());
    assert_eq!(
        certificate_status(&pool, lifecycle.credential_id).await,
        "active"
    );
    tenants::repo::change_tenant_status(
        &pool,
        lifecycle_tenant,
        TenantStatus::Active,
        Some(common::admin_id()),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE entities SET status = 'inactive' WHERE id = $1")
        .bind(lifecycle_entity)
        .execute(&pool)
        .await
        .unwrap();
    assert!(service::resolve_certificate_identity(
        &pool,
        &lifecycle.serial_number,
        Some(&lifecycle.fingerprint_sha256),
    )
    .await
    .is_err());
    sqlx::query("UPDATE entities SET status = 'active' WHERE id = $1")
        .bind(lifecycle_entity)
        .execute(&pool)
        .await
        .unwrap();
    set_artifact_clean(
        &pool,
        lifecycle_issuer.id,
        lifecycle_issuer.fingerprint_sha256.as_deref(),
    )
    .await;
    tenants::repo::soft_delete_tenant_with_audit(
        &pool,
        true,
        Some(common::admin_id()),
        lifecycle_tenant,
        Some(common::admin_id()),
    )
    .await
    .unwrap();
    assert_eq!(
        certificate_status(&pool, lifecycle.credential_id).await,
        "revoked"
    );
    assert_revocation_row(
        &pool,
        lifecycle.credential_id,
        lifecycle_issuer.id,
        "tenant_deleted",
        Some(common::admin_id()),
    )
    .await;
    assert!(artifact_dirty(&pool, lifecycle_issuer.id).await);
    assert!(service::resolve_certificate_identity(
        &pool,
        &lifecycle.serial_number,
        Some(&lifecycle.fingerprint_sha256),
    )
    .await
    .is_err());
    assert_tenant_delete_event(&pool, lifecycle_tenant, lifecycle.credential_id).await;
}

async fn assert_v2_schema_contract(schema: &atom::graphql::AtomSchema) {
    let response = schema
        .execute(Request::new(
            r#"{
              input: __type(name: "RevokeCertificateV2Input") { inputFields { name } }
              result: __type(name: "CertificateRevocation") { fields { name } }
              mutation: __schema { mutationType { fields { name } } }
            }"#,
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(
        sorted_field_names(&data["input"]["inputFields"]),
        vec![
            "credentialId",
            "fingerprintSha256",
            "issuerId",
            "reason",
            "serialNumber"
        ]
    );
    assert_eq!(
        sorted_field_names(&data["result"]["fields"]),
        vec![
            "actorEntityId",
            "certificate",
            "idempotentReplay",
            "reason",
            "revokedAt"
        ]
    );
    let mutations = sorted_field_names(&data["mutation"]["mutationType"]["fields"]);
    assert!(mutations.contains(&"revokeCertificate"));
    assert!(mutations.contains(&"revokeCertificateV2"));
    assert!(mutations.contains(&"revokeEntityCertificates"));
}

async fn issue_managed(
    pool: &PgPool,
    config: &atom::config::Config,
    tenant_id: Uuid,
    entity_id: Uuid,
    key: &str,
) -> service::CertificateRecord {
    let issued = service::issue_certificate_from_csr_v2(
        pool,
        config,
        Some(tenant_id),
        service::IssueCertificateFromCsrV2 {
            entity_id,
            ttl_secs: Some(3600),
            csr_pem: csr(),
            idempotency_key: format!("pr008-{key}"),
        },
    )
    .await
    .unwrap();
    issued.certificate
}

fn csr() -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "pr008-device");
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(2);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

fn revoke_request(actor: Uuid, tenant_id: Option<Uuid>, input: Value) -> Request {
    Request::new(
        r#"mutation Revoke($input: RevokeCertificateV2Input!) {
          revokeCertificateV2(input: $input) {
            certificate { credentialId issuerId serialNumber fingerprintSha256 status }
            reason
            actorEntityId
            revokedAt
            idempotentReplay
          }
        }"#,
    )
    .variables(Variables::from_json(json!({"input": input})))
    .data(auth(actor, tenant_id))
}

fn auth(entity_id: Uuid, tenant_id: Option<Uuid>) -> AuthContext {
    AuthContext {
        entity_id,
        tenant_id,
        session_id: None,
        ..Default::default()
    }
}

fn sorted_field_names(value: &Value) -> Vec<&str> {
    let mut names = value
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|field| field["name"].as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn errors_contain(errors: &[async_graphql::ServerError], expected: &str) -> bool {
    errors.iter().any(|error| error.message.contains(expected))
}

async fn certificate_status(pool: &PgPool, credential_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(credential_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_revocation_row(
    pool: &PgPool,
    credential_id: Uuid,
    issuer_id: Uuid,
    reason: &str,
    actor_entity_id: Option<Uuid>,
) {
    let row = sqlx::query(
        r#"SELECT issuer_id, issuer_fingerprint_sha256, serial_number,
                  reason, actor_entity_id, revoked_at
             FROM certificate_revocations WHERE credential_id = $1"#,
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.get::<Option<Uuid>, _>("issuer_id"), Some(issuer_id));
    assert_eq!(
        row.get::<Option<String>, _>("issuer_fingerprint_sha256")
            .unwrap()
            .len(),
        64
    );
    assert!(!row.get::<String, _>("serial_number").is_empty());
    assert_eq!(row.get::<String, _>("reason"), reason);
    assert_eq!(
        row.get::<Option<Uuid>, _>("actor_entity_id"),
        actor_entity_id
    );
    let _: chrono::DateTime<chrono::Utc> = row.get("revoked_at");
}

async fn set_artifact_clean(pool: &PgPool, issuer_id: Uuid, fingerprint: Option<&str>) {
    let fingerprint = fingerprint.expect("managed issuer fingerprint");
    sqlx::query(
        r#"INSERT INTO certificate_crl_state
              (issuer_fingerprint_sha256, issuer_id, crl_number, dirty)
           VALUES ($1, $2, 0, FALSE)
           ON CONFLICT (issuer_fingerprint_sha256) DO UPDATE
             SET issuer_id = EXCLUDED.issuer_id, dirty = FALSE, updated_at = now()"#,
    )
    .bind(fingerprint)
    .bind(issuer_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn artifact_dirty(pool: &PgPool, issuer_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT dirty FROM certificate_crl_state WHERE issuer_id = $1")
        .bind(issuer_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn revocation_exists(pool: &PgPool, credential_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM certificate_revocations WHERE credential_id = $1)",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn event_count(pool: &PgPool, event: &str, credential_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_outbox WHERE event = $1 AND (payload->>'target_id')::uuid = $2",
    )
    .bind(event)
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_audit_and_outbox(pool: &PgPool, credential_id: Uuid, issuer_id: Uuid) {
    let audit: Value = sqlx::query_scalar(
        r#"SELECT details FROM audit_logs
           WHERE event = 'certificate.revoke' AND target_id = $1
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audit["credential_id"], credential_id.to_string());
    assert_eq!(audit["issuer_id"], issuer_id.to_string());
    assert_eq!(audit["reason"], "key_compromise");
    let outbox: Value = sqlx::query_scalar(
        r#"SELECT payload FROM event_outbox
           WHERE event = 'certificate.revoke' AND (payload->>'target_id')::uuid = $1
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        outbox["details"]["credential_id"],
        credential_id.to_string()
    );
    assert_eq!(outbox["details"]["issuer_id"], issuer_id.to_string());
    assert_eq!(outbox["details"]["reason"], "key_compromise");
    let serialized = outbox.to_string();
    assert!(!serialized.contains("PRIVATE KEY"));
    assert!(!serialized.contains("BEGIN CERTIFICATE"));
}

async fn assert_tenant_delete_event(pool: &PgPool, tenant_id: Uuid, credential_id: Uuid) {
    let payload: Value = sqlx::query_scalar(
        r#"SELECT payload FROM event_outbox
           WHERE event = 'tenant.delete' AND tenant_id = $1
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let revocations = &payload["details"]["certificate_revocations"];
    assert_eq!(revocations["reason"], "tenant_deleted");
    assert!(revocations["credential_ids"]
        .as_array()
        .unwrap()
        .contains(&json!(credential_id)));
    assert!(!payload.to_string().contains("PRIVATE KEY"));
}

async fn install_rejecting_outbox_trigger(pool: &PgPool) {
    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION m35_reject_certificate_revoke_event()
           RETURNS trigger AS $$
           BEGIN
             IF NEW.event = 'certificate.revoke' THEN
               RAISE EXCEPTION 'forced PR-008 outbox failure';
             END IF;
             RETURN NEW;
           END;
           $$ LANGUAGE plpgsql"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"CREATE TRIGGER m35_reject_certificate_revoke_event
           BEFORE INSERT ON event_outbox
           FOR EACH ROW EXECUTE FUNCTION m35_reject_certificate_revoke_event()"#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn drop_rejecting_outbox_trigger(pool: &PgPool) {
    sqlx::query("DROP TRIGGER m35_reject_certificate_revoke_event ON event_outbox")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION m35_reject_certificate_revoke_event()")
        .execute(pool)
        .await
        .unwrap();
}
