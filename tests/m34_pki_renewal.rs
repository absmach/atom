//! PR-007 exact-credential, issuer-aware renewal coverage.
//!
//! Requires PostgreSQL and OpenSSL. CI runs this ignored binary against its own
//! freshly migrated database, single-threaded.

mod common;

use async_graphql::{Request, Variables};
use atom::{
    auth::AuthContext,
    certs::{authority::AuthorityStatus, service},
    config::Config,
    graphql::build_schema,
};
use chrono::{Duration as ChronoDuration, Utc};
use rcgen::{CertificateParams, DnType, KeyPair};
use ring::digest;
use serde_json::{json, Value};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroize;

#[tokio::test]
#[ignore]
async fn issuer_aware_renewal_enforces_the_pr007_contract() {
    let pool = common::pool().await;
    let config = common::pki::managed_config(true, true);
    let tenant_a = common::pki::create_tenant(&pool, "pki-renew-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-renew-b").await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-renew-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-renew-b").await;
    let root = common::pki::test_root("PR-007 Offline Root");
    let issuer_v1 = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let schema = build_schema(common::pki::graphql_state(pool.clone(), config.clone()));

    assert_v2_schema_contract(&schema).await;

    // Same-issuer renewal preserves overlap and records one exact history link.
    let old_overlap = issue_managed(&pool, &config, tenant_a, entity_a, "old-overlap").await;
    assert_eq!(old_overlap.issuer_id, Some(issuer_v1.id));
    let overlap_csr = csr();
    let overlap = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            old_overlap.credential_id,
            &overlap_csr,
            "renew-overlap",
            false,
        ))
        .await;
    assert!(overlap.errors.is_empty(), "{:?}", overlap.errors);
    let overlap = overlap.data.into_json().unwrap()["renewCertificateFromCsrV2"].clone();
    assert_eq!(overlap["idempotentReplay"], false);
    assert!(overlap["privateKeyPem"].is_null());
    let overlap_id = uuid_field(&overlap, "credentialId");
    assert_eq!(
        overlap["certificate"]["renewedFromCredentialId"],
        old_overlap.credential_id.to_string()
    );
    assert_eq!(overlap["certificate"]["issuerId"], issuer_v1.id.to_string());
    assert!(overlap["certificate"]["renewalDueAt"].is_string());
    let old_after = service::certificate_by_id(&pool, old_overlap.credential_id)
        .await
        .unwrap();
    let new_after = service::certificate_by_id(&pool, overlap_id).await.unwrap();
    assert_eq!(old_after.status, "active");
    assert_eq!(new_after.status, "active");
    assert_eq!(
        new_after.renewed_from_credential_id,
        Some(old_overlap.credential_id)
    );
    assert_ne!(new_after.serial_number, old_after.serial_number);
    assert_ne!(new_after.fingerprint_sha256, old_after.fingerprint_sha256);
    assert_eq!(
        renewal_replacement(&pool, old_overlap.credential_id).await,
        overlap_id
    );
    assert_profile_window(&pool, overlap_id).await;

    // Exact retries return the original replacement without a second event or
    // certificate. Any changed request for the already-renewed source conflicts.
    let replay = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            old_overlap.credential_id,
            &overlap_csr,
            "renew-overlap",
            false,
        ))
        .await;
    assert!(replay.errors.is_empty(), "{:?}", replay.errors);
    let replay = replay.data.into_json().unwrap()["renewCertificateFromCsrV2"].clone();
    assert_eq!(replay["idempotentReplay"], true);
    assert_eq!(uuid_field(&replay, "credentialId"), overlap_id);
    assert!(replay["privateKeyPem"].is_null());
    let changed_retry = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            old_overlap.credential_id,
            &csr(),
            "renew-overlap-changed",
            false,
        ))
        .await;
    assert!(errors_contain(&changed_retry.errors, "already renewed"));
    assert_eq!(renewal_count(&pool, old_overlap.credential_id).await, 1);
    assert_audit_and_outbox_linkage(&pool, old_overlap.credential_id, overlap_id).await;

    // A caller from another tenant cannot rotate the exact credential.
    let cross_tenant = schema
        .execute(renew_csr_request(
            entity_b,
            Some(tenant_b),
            old_overlap.credential_id,
            &csr(),
            "renew-cross-tenant",
            false,
        ))
        .await;
    assert!(errors_contain(&cross_tenant.errors, "forbidden"));
    assert_eq!(renewal_count(&pool, old_overlap.credential_id).await, 1);

    // A leaf issued by v1 renews under v2 after the one-active-issuer handover.
    let old_rotation = issue_managed(&pool, &config, tenant_a, entity_a, "old-rotation").await;
    let old_retiring_self =
        issue_managed(&pool, &config, tenant_a, entity_a, "old-retiring-self").await;
    let issuer_v2 = common::pki::rotate_tenant_issuer(&pool, &config, &root, tenant_a).await;
    assert_ne!(issuer_v1.id, issuer_v2.id);
    let retired_v1 = atom::certs::authority::repo::authority_by_id(&pool, issuer_v1.id)
        .await
        .unwrap();
    assert_eq!(retired_v1.status, AuthorityStatus::Retiring);
    assert!(!retired_v1.issuance_enabled);
    let rotated = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            old_rotation.credential_id,
            &csr(),
            "renew-rotation",
            false,
        ))
        .await;
    assert!(rotated.errors.is_empty(), "{:?}", rotated.errors);
    let rotated = rotated.data.into_json().unwrap()["renewCertificateFromCsrV2"].clone();
    assert_eq!(rotated["certificate"]["issuerId"], issuer_v2.id.to_string());
    assert_eq!(old_rotation.issuer_id, Some(issuer_v1.id));
    let retiring_self = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::PresentedCertificate {
            credential_id: old_retiring_self.credential_id,
        },
        service::RenewCertificateV2 {
            credential_id: old_retiring_self.credential_id,
            ttl_secs: Some(3600),
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "retiring-self".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(retiring_self.certificate.issuer_id, Some(issuer_v2.id));
    assert_eq!(
        retiring_self.certificate.renewed_from_credential_id,
        Some(old_retiring_self.credential_id)
    );

    // Generated renewal is a separate explicit API. Its key is returned only
    // on the first response and immediate revocation is atomic with linkage.
    let old_generated = issue_managed(&pool, &config, tenant_a, entity_a, "old-generated").await;
    let generated = schema
        .execute(renew_generated_request(
            common::admin_id(),
            None,
            old_generated.credential_id,
            "renew-generated",
            true,
        ))
        .await;
    assert!(generated.errors.is_empty(), "{:?}", generated.errors);
    let generated = generated.data.into_json().unwrap()["renewGeneratedCertificateV2"].clone();
    let generated_id = uuid_field(&generated, "credentialId");
    let mut generated_key = generated["privateKeyPem"].as_str().unwrap().to_string();
    let generated_pem = generated["certificate"]["certificatePem"].as_str().unwrap();
    assert_key_matches_certificate(&generated_key, generated_pem);
    assert_eq!(
        service::certificate_by_id(&pool, old_generated.credential_id)
            .await
            .unwrap()
            .status,
        "revoked"
    );
    assert_eq!(
        renewal_replacement(&pool, old_generated.credential_id).await,
        generated_id
    );
    let generated_audit =
        audit_details(&pool, "certificate.renew", old_generated.credential_id).await;
    assert_eq!(generated_audit["key_mode"], "generated");
    assert_eq!(generated_audit["revoke_old"], true);
    let generated_replay = schema
        .execute(renew_generated_request(
            common::admin_id(),
            None,
            old_generated.credential_id,
            "renew-generated",
            true,
        ))
        .await;
    assert!(
        generated_replay.errors.is_empty(),
        "{:?}",
        generated_replay.errors
    );
    let generated_replay =
        generated_replay.data.into_json().unwrap()["renewGeneratedCertificateV2"].clone();
    assert_eq!(generated_replay["idempotentReplay"], true);
    assert!(generated_replay["privateKeyPem"].is_null());
    assert_eq!(uuid_field(&generated_replay, "credentialId"), generated_id);

    // A revoked certificate is never renewal authentication and cannot be
    // recovered through operator renewal; it must follow fresh enrollment.
    let old_revoked = issue_managed(&pool, &config, tenant_a, entity_a, "old-revoked").await;
    revoke_certificate(&pool, old_revoked.credential_id).await;
    let revoked_self = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::PresentedCertificate {
            credential_id: old_revoked.credential_id,
        },
        service::RenewCertificateV2 {
            credential_id: old_revoked.credential_id,
            ttl_secs: Some(3600),
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "revoked-self".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(revoked_self.to_string().contains("revoked"));
    let revoked_operator = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            old_revoked.credential_id,
            &csr(),
            "revoked-operator",
            false,
        ))
        .await;
    assert!(errors_contain(&revoked_operator.errors, "revoked"));

    // The certificate-authenticated service seam accepts an exact, valid
    // certificate in its profile window and rejects credential substitution.
    let old_self = issue_managed(&pool, &config, tenant_a, entity_a, "old-self").await;
    let wrong_presented = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::PresentedCertificate {
            credential_id: old_generated.credential_id,
        },
        service::RenewCertificateV2 {
            credential_id: old_self.credential_id,
            ttl_secs: Some(3600),
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "wrong-presented".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(wrong_presented.to_string().contains("forbidden"));
    let self_renewed = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::PresentedCertificate {
            credential_id: old_self.credential_id,
        },
        service::RenewCertificateV2 {
            credential_id: old_self.credential_id,
            ttl_secs: Some(3600),
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "valid-self".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        self_renewed.certificate.renewed_from_credential_id,
        Some(old_self.credential_id)
    );

    // Expired certificate authentication fails, while a normally authorized
    // operator can explicitly recover the expired (not revoked) subject.
    let old_expired = issue_managed(&pool, &config, tenant_a, entity_a, "old-expired").await;
    expire_certificate(&pool, old_expired.credential_id).await;
    let expired_self = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::PresentedCertificate {
            credential_id: old_expired.credential_id,
        },
        service::RenewCertificateV2 {
            credential_id: old_expired.credential_id,
            ttl_secs: Some(3600),
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "expired-self".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(expired_self.to_string().contains("expired"));
    let recovered = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            old_expired.credential_id,
            &csr(),
            "expired-operator-recovery",
            false,
        ))
        .await;
    assert!(recovered.errors.is_empty(), "{:?}", recovered.errors);

    // Legacy issuer_id=NULL credentials migrate by renewal, never rewriting:
    // tenant subjects use their tenant issuer and global subjects use the
    // separately provisioned platform leaf issuer.
    let legacy_tenant = insert_legacy_certificate(&pool, entity_a).await;
    let tenant_migration = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            legacy_tenant,
            &csr(),
            "legacy-tenant",
            false,
        ))
        .await;
    assert!(
        tenant_migration.errors.is_empty(),
        "{:?}",
        tenant_migration.errors
    );
    assert_eq!(
        tenant_migration.data.into_json().unwrap()["renewCertificateFromCsrV2"]["certificate"]
            ["issuerId"],
        issuer_v2.id.to_string()
    );
    assert!(service::certificate_by_id(&pool, legacy_tenant)
        .await
        .unwrap()
        .issuer_id
        .is_none());

    let global_entity = common::pki::create_global_entity(&pool, "pki-renew-global").await;
    let platform_issuer = common::pki::provision_platform_leaf_issuer(&pool, &config, &root).await;
    let legacy_global = insert_legacy_certificate(&pool, global_entity).await;
    let global_migration = schema
        .execute(renew_csr_request(
            common::admin_id(),
            None,
            legacy_global,
            &csr(),
            "legacy-global",
            false,
        ))
        .await;
    assert!(
        global_migration.errors.is_empty(),
        "{:?}",
        global_migration.errors
    );
    assert_eq!(
        global_migration.data.into_json().unwrap()["renewCertificateFromCsrV2"]["certificate"]
            ["issuerId"],
        platform_issuer.id.to_string()
    );

    generated_key.zeroize();
}

async fn assert_v2_schema_contract(schema: &atom::graphql::AtomSchema) {
    let response = schema
        .execute(Request::new(
            r#"{
              csr: __type(name: "RenewCertificateFromCsrV2Input") { inputFields { name } }
              generated: __type(name: "RenewGeneratedCertificateV2Input") { inputFields { name } }
              certificate: __type(name: "Certificate") { fields { name } }
              mutation: __schema { mutationType { fields { name } } }
            }"#,
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(
        sorted_field_names(&data["csr"]["inputFields"]),
        vec![
            "credentialId",
            "csrPem",
            "idempotencyKey",
            "revokeOld",
            "ttlSecs"
        ]
    );
    assert_eq!(
        sorted_field_names(&data["generated"]["inputFields"]),
        vec!["credentialId", "idempotencyKey", "revokeOld", "ttlSecs"]
    );
    let certificate_fields = sorted_field_names(&data["certificate"]["fields"]);
    assert!(certificate_fields.contains(&"renewalDueAt"));
    assert!(certificate_fields.contains(&"renewedFromCredentialId"));
    let mutations = sorted_field_names(&data["mutation"]["mutationType"]["fields"]);
    assert!(mutations.contains(&"renewCertificate"));
    assert!(mutations.contains(&"renewCertificateFromCsrV2"));
    assert!(mutations.contains(&"renewGeneratedCertificateV2"));
}

async fn issue_managed(
    pool: &PgPool,
    config: &Config,
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
            csr_pem: csr(),
            idempotency_key: format!("{label}-{}", Uuid::new_v4()),
        },
    )
    .await
    .unwrap()
    .certificate
}

fn csr() -> String {
    let key = KeyPair::generate().unwrap();
    CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap()
}

fn renew_csr_request(
    actor_id: Uuid,
    actor_tenant_id: Option<Uuid>,
    credential_id: Uuid,
    csr_pem: &str,
    idempotency_key: &str,
    revoke_old: bool,
) -> Request {
    Request::new(
        r#"mutation Renew($input: RenewCertificateFromCsrV2Input!) {
          renewCertificateFromCsrV2(input: $input) {
            idempotentReplay privateKeyPem chainPem
            certificate {
              credentialId renewedFromCredentialId entityId tenantId issuerId
              serialNumber fingerprintSha256 certificatePem profileId
              renewalDueAt status
            }
          }
        }"#,
    )
    .variables(Variables::from_json(json!({
        "input": {
            "credentialId": credential_id,
            "ttlSecs": 3600,
            "csrPem": csr_pem,
            "revokeOld": revoke_old,
            "idempotencyKey": idempotency_key,
        }
    })))
    .data(auth(actor_id, actor_tenant_id))
}

fn renew_generated_request(
    actor_id: Uuid,
    actor_tenant_id: Option<Uuid>,
    credential_id: Uuid,
    idempotency_key: &str,
    revoke_old: bool,
) -> Request {
    Request::new(
        r#"mutation Renew($input: RenewGeneratedCertificateV2Input!) {
          renewGeneratedCertificateV2(input: $input) {
            idempotentReplay privateKeyPem chainPem
            certificate {
              credentialId renewedFromCredentialId entityId tenantId issuerId
              serialNumber fingerprintSha256 certificatePem profileId
              renewalDueAt status
            }
          }
        }"#,
    )
    .variables(Variables::from_json(json!({
        "input": {
            "credentialId": credential_id,
            "ttlSecs": 3600,
            "revokeOld": revoke_old,
            "idempotencyKey": idempotency_key,
        }
    })))
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

fn uuid_field(value: &Value, field: &str) -> Uuid {
    value["certificate"][field]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn sorted_field_names(value: &Value) -> Vec<&str> {
    let mut names = value
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn errors_contain(errors: &[async_graphql::ServerError], expected: &str) -> bool {
    errors.iter().any(|error| error.message.contains(expected))
}

async fn renewal_replacement(pool: &PgPool, old_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT replacement_credential_id FROM certificate_renewals WHERE previous_credential_id = $1",
    )
    .bind(old_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn renewal_count(pool: &PgPool, old_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM certificate_renewals WHERE previous_credential_id = $1",
    )
    .bind(old_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_profile_window(pool: &PgPool, credential_id: Uuid) {
    let (metadata, expires_at): (Value, chrono::DateTime<Utc>) =
        sqlx::query_as("SELECT metadata, expires_at FROM credentials WHERE id = $1")
            .bind(credential_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(metadata["renewal_threshold_seconds"], 86_400);
    let due_at = chrono::DateTime::parse_from_rfc3339(metadata["renewal_due_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let not_before = chrono::DateTime::parse_from_rfc3339(metadata["not_before"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(due_at, not_before);
    assert!(due_at < expires_at);
}

async fn assert_audit_and_outbox_linkage(pool: &PgPool, old_id: Uuid, new_id: Uuid) {
    let details = audit_details(pool, "certificate.renew", old_id).await;
    assert_eq!(details["old_credential_id"], old_id.to_string());
    assert_eq!(details["new_credential_id"], new_id.to_string());
    assert_eq!(details["key_mode"], "csr");
    assert_eq!(details["revoke_old"], false);
    let payload: Value = sqlx::query_scalar(
        r#"SELECT payload FROM event_outbox
           WHERE event = 'certificate.renew' AND (payload->>'target_id')::uuid = $1"#,
    )
    .bind(old_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(payload["details"]["new_credential_id"], new_id.to_string());
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_outbox WHERE event = 'certificate.renew' AND (payload->>'target_id')::uuid = $1",
    )
    .bind(old_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(event_count, 1);
    let replay_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event = 'certificate.renew_replayed' AND target_id = $1",
    )
    .bind(old_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(replay_count, 1);
}

async fn audit_details(pool: &PgPool, event: &str, old_id: Uuid) -> Value {
    sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE event = $1 AND target_id = $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(event)
    .bind(old_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn expire_certificate(pool: &PgPool, credential_id: Uuid) {
    sqlx::query(
        r#"UPDATE credentials
           SET expires_at = now() - interval '1 minute',
               metadata = jsonb_set(
                   metadata,
                   '{not_after}',
                   to_jsonb(now() - interval '1 minute')
               )
           WHERE id = $1"#,
    )
    .bind(credential_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn revoke_certificate(pool: &PgPool, credential_id: Uuid) {
    sqlx::query(
        r#"UPDATE credentials
           SET status = 'revoked',
               metadata = jsonb_set(
                   jsonb_set(metadata, '{revoked_at}', to_jsonb(now())),
                   '{revocation_reason}',
                   '"test_revocation"'::jsonb
               )
           WHERE id = $1"#,
    )
    .bind(credential_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_legacy_certificate(pool: &PgPool, entity_id: Uuid) -> Uuid {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, entity_id.to_string());
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(1);
    let certificate = params.self_signed(&key).unwrap();
    let fingerprint = hex::encode(digest::digest(&digest::SHA256, certificate.der().as_ref()));
    let id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = now + ChronoDuration::days(1);
    let metadata = json!({
        "certificate_pem": certificate.pem(),
        "chain_pem": null,
        "subject": {"common_name": entity_id},
        "dns_names": [],
        "ip_addresses": [],
        "issuer_kind": "legacy_file_issuer",
        "issuer_subject": "PR-007 legacy issuer",
        "issuer_serial_number": "01",
        "issuer_fingerprint_sha256": format!("legacy-{}", Uuid::new_v4()),
        "fingerprint_sha256": fingerprint,
        "profile_id": null,
        "profile_name": null,
        "identity_uri": null,
        "not_before": now - ChronoDuration::minutes(1),
        "not_after": expires_at,
        "issued_from_csr": false,
        "revoked_at": null,
        "revocation_reason": null,
    });
    sqlx::query(
        r#"INSERT INTO credentials (
               id, entity_id, kind, identifier, metadata, expires_at, issuer_id
           ) VALUES ($1, $2, 'certificate', $3, $4, $5, NULL)"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(metadata)
    .bind(expires_at)
    .execute(pool)
    .await
    .unwrap();
    id
}

fn assert_key_matches_certificate(private_key_pem: &str, certificate_pem: &str) {
    let key = KeyPair::from_pem(private_key_pem).unwrap();
    let (_, public_pem) = parse_x509_pem(key.public_key_pem().as_bytes()).unwrap();
    let (_, certificate_pem) = parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(&certificate_pem.contents).unwrap();
    assert_eq!(public_pem.contents, certificate.public_key().raw);
}
