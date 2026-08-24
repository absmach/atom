//! PR-009 per-issuer CRL generation, retention, caching, and interoperability.
//!
//! Requires PostgreSQL and OpenSSL. CI runs this ignored binary against its own
//! freshly migrated database, single-threaded.

mod common;

use std::{fs, process::Command};

use atom::{
    certs::{
        authority::{provisioning, repo as authority_repo, AuthorityStatus},
        pki_core::PkiIssuer,
        service,
    },
    routes::create_router,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use rcgen::{CertificateParams, DnType, KeyPair};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn per_issuer_crls_enforce_the_pr009_contract() {
    let pool = common::pool().await;
    let config = common::pki::managed_config(false, false);
    let root = common::pki::test_root("PR-009 Offline Root");
    let tenant_a = common::pki::create_tenant(&pool, "pki-crl-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-crl-b").await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-crl-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-crl-b").await;
    let issuer_a = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let issuer_b = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_b).await;
    let platform_leaf = common::pki::provision_platform_leaf_issuer(&pool, &config, &root).await;

    // An empty CRL is signed by the exact leaf issuer, has bounded update
    // times, and is reused without another signing/number increment.
    let empty_a = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(empty_a.crl_number, 1);
    assert!(!empty_a.cache_hit);
    assert!(empty_a.next_update > empty_a.this_update);
    assert!(crl_serials(&empty_a.der).is_empty());
    assert_openssl_crl(
        &empty_a.der,
        issuer_a.certificate_pem.as_deref().unwrap(),
        None,
    );
    let cached_a = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert!(cached_a.cache_hit);
    assert_eq!(cached_a.crl_number, 1);
    assert_eq!(cached_a.der, empty_a.der);

    // A stale CRL-state fingerprint is a data-integrity failure, not a cache
    // miss. Regenerating would re-sign on every public request forever while
    // leaving the corrupted state untouched.
    sqlx::query(
        "UPDATE certificate_crl_state SET issuer_fingerprint_sha256 = repeat('0', 64) WHERE issuer_id = $1",
    )
    .bind(issuer_a.id)
    .execute(&pool)
    .await
    .unwrap();
    let mismatch = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap_err();
    assert!(mismatch
        .to_string()
        .contains("CRL state fingerprint does not match"));
    sqlx::query(
        "UPDATE certificate_crl_state SET issuer_fingerprint_sha256 = $1 WHERE issuer_id = $2",
    )
    .bind(issuer_a.fingerprint_sha256.as_deref().unwrap())
    .bind(issuer_a.id)
    .execute(&pool)
    .await
    .unwrap();

    // Tenant B publishes a fresh CRL keyed on issuer_id, starting at 1.
    let empty_b = service::issuer_crl(&pool, &config, issuer_b.id)
        .await
        .unwrap();
    assert_eq!(empty_b.crl_number, 1);
    assert!(crl_serials(&empty_b.der).is_empty());
    let b_issuer_id: Uuid =
        sqlx::query_scalar("SELECT issuer_id FROM certificate_crl_state WHERE issuer_id = $1")
            .bind(issuer_b.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(b_issuer_id, issuer_b.id);

    // The platform leaf issuer publishes too; roots and platform
    // intermediates never expose leaf-credential CRLs.
    let platform_crl = service::issuer_crl(&pool, &config, platform_leaf.id)
        .await
        .unwrap();
    assert!(crl_serials(&platform_crl.der).is_empty());
    assert_openssl_crl(
        &platform_crl.der,
        platform_leaf.certificate_pem.as_deref().unwrap(),
        None,
    );
    for authority_id in non_leaf_authority_ids(&pool).await {
        let error = service::issuer_crl(&pool, &config, authority_id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not publish"));
    }

    // Public HTTP delivery carries a stable validator and a bounded freshness
    // lifetime. Conditional polling returns 304 with no body.
    let app = create_router(common::pki::graphql_state(pool.clone(), config.clone()));
    // /certs/crl is not a registered route; only per-issuer CRLs are served.
    let unrouted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/certs/crl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unrouted.status(), StatusCode::NOT_FOUND);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/certs/issuers/{}/crl", issuer_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/pkix-crl"
    );
    assert!(response.headers()[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .starts_with("public, max-age="));
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        empty_a.der
    );
    let not_modified = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/certs/issuers/{}/crl", issuer_a.id))
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert!(to_bytes(not_modified.into_body(), usize::MAX)
        .await
        .unwrap()
        .is_empty());
    let weak_not_modified = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/certs/issuers/{}/crl", issuer_a.id))
                .header(header::IF_NONE_MATCH, format!("W/{etag}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(weak_not_modified.status(), StatusCode::NOT_MODIFIED);

    let key_compromise = issue_managed(&pool, &config, tenant_a, entity_a, "key-compromise").await;
    revoke(
        &pool,
        key_compromise.credential_id,
        entity_a,
        tenant_a,
        "key_compromise",
    )
    .await;
    let revoked_a = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(revoked_a.crl_number, 2);
    assert_eq!(
        crl_serials(&revoked_a.der),
        vec![hex::decode(&key_compromise.serial_number).unwrap()]
    );
    let openssl_text = assert_openssl_crl(
        &revoked_a.der,
        issuer_a.certificate_pem.as_deref().unwrap(),
        Some("key compromise"),
    );
    assert!(openssl_text.to_ascii_lowercase().contains("crl number"));

    // Tenant A dirtiness does not touch Tenant B's cached bytes or number.
    let still_b = service::issuer_crl(&pool, &config, issuer_b.id)
        .await
        .unwrap();
    assert!(still_b.cache_hit);
    assert_eq!(still_b.crl_number, empty_b.crl_number);
    assert_eq!(still_b.der, empty_b.der);
    assert_openssl_rejects_crl(&revoked_a.der, issuer_b.certificate_pem.as_deref().unwrap());

    let superseded = issue_managed(&pool, &config, tenant_a, entity_a, "superseded").await;
    revoke(
        &pool,
        superseded.credential_id,
        entity_a,
        tenant_a,
        "superseded",
    )
    .await;
    let numbered = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(numbered.crl_number, 3);
    assert_eq!(crl_serials(&numbered.der).len(), 2);

    // Concurrent replicas share an issuer-scoped lock. Exactly one request
    // advances the number; all callers observe the same committed artifact.
    let concurrent = issue_managed(&pool, &config, tenant_a, entity_a, "concurrent").await;
    revoke(
        &pool,
        concurrent.credential_id,
        entity_a,
        tenant_a,
        "cessation_of_operation",
    )
    .await;
    let mut tasks = Vec::new();
    let concurrent_issuer_id = issuer_a.id;
    for _ in 0..8 {
        let pool = pool.clone();
        let config = config.clone();
        tasks.push(tokio::spawn(async move {
            service::issuer_crl(&pool, &config, concurrent_issuer_id)
                .await
                .unwrap()
        }));
    }
    let mut concurrent_results = Vec::new();
    for task in tasks {
        concurrent_results.push(task.await.unwrap());
    }
    assert!(concurrent_results
        .iter()
        .all(|artifact| artifact.crl_number == 4));
    assert!(concurrent_results
        .iter()
        .all(|artifact| artifact.der == concurrent_results[0].der));

    // Corrupt bytes with a matching cache hash still fail ASN.1 validation and
    // are regenerated from durable revocation state. A subsequent call models
    // a process restart and reuses the repaired database artifact.
    sqlx::query(
        r#"UPDATE certificate_crl_state
           SET crl_der = decode('010203', 'hex'),
               crl_sha256 = encode(digest(decode('010203', 'hex'), 'sha256'), 'hex'),
               dirty = FALSE,
               next_update = now() + interval '1 hour'
           WHERE issuer_id = $1"#,
    )
    .bind(issuer_a.id)
    .execute(&pool)
    .await
    .unwrap();
    let repaired = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(repaired.crl_number, 5);
    assert!(!repaired.cache_hit);
    assert_eq!(crl_serials(&repaired.der).len(), 3);
    let after_restart = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert!(after_restart.cache_hit);
    assert_eq!(after_restart.der, repaired.der);

    let purge_entity = common::pki::create_entity(&pool, tenant_a, "pki-crl-purge").await;
    let purge_leaf = issue_managed(&pool, &config, tenant_a, purge_entity, "purge").await;

    // Rotation retains old-authority publication. One old leaf is revoked
    // while the issuer is retiring and another after it is retired; neither
    // lifecycle state can issue a new leaf, but both can sign their own CRL.
    let retiring_leaf = issue_managed(&pool, &config, tenant_a, entity_a, "retiring").await;
    let retired_leaf = issue_managed(&pool, &config, tenant_a, entity_a, "retired").await;
    let issuer_a_v2 = common::pki::rotate_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let old = authority_repo::authority_by_id(&pool, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(old.status, AuthorityStatus::Retiring);
    assert!(PkiIssuer::from_managed_authority(&old, &config.pki_ca_keys).is_err());
    // Retained artifact signing must not depend on discovery-route metadata
    // added after the original authority could have been provisioned.
    sqlx::query(
        r#"UPDATE pki_authorities
           SET ocsp_url = NULL, ca_issuers_url = NULL,
               crl_distribution_point_url = NULL
           WHERE id = $1"#,
    )
    .bind(issuer_a.id)
    .execute(&pool)
    .await
    .unwrap();
    revoke(
        &pool,
        retiring_leaf.credential_id,
        entity_a,
        tenant_a,
        "certificate_hold",
    )
    .await;
    let retiring_crl = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(retiring_crl.crl_number, 6);
    assert!(crl_contains(
        &retiring_crl.der,
        &retiring_leaf.serial_number
    ));

    let mut tx = pool.begin().await.unwrap();
    provisioning::complete_retirement_in_tx(&mut tx, issuer_a.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let old = authority_repo::authority_by_id(&pool, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(old.status, AuthorityStatus::Retired);
    revoke(
        &pool,
        retired_leaf.credential_id,
        entity_a,
        tenant_a,
        "privilege_withdrawn",
    )
    .await;
    let retired_crl = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(retired_crl.crl_number, 7);
    assert!(crl_contains(&retired_crl.der, &retired_leaf.serial_number));
    assert_openssl_crl(
        &retired_crl.der,
        issuer_a.certificate_pem.as_deref().unwrap(),
        Some("privilege withdrawn"),
    );

    let new_leaf = issue_managed(&pool, &config, tenant_a, entity_a, "new-issuer").await;
    assert_eq!(new_leaf.issuer_id, Some(issuer_a_v2.id));
    revoke(
        &pool,
        new_leaf.credential_id,
        entity_a,
        tenant_a,
        "affiliation_changed",
    )
    .await;
    let new_crl = service::issuer_crl(&pool, &config, issuer_a_v2.id)
        .await
        .unwrap();
    assert_eq!(new_crl.crl_number, 1);
    assert_eq!(
        crl_serials(&new_crl.der),
        vec![hex::decode(&new_leaf.serial_number).unwrap()]
    );
    assert!(!crl_contains(&new_crl.der, &retired_leaf.serial_number));
    assert_openssl_crl(
        &new_crl.der,
        issuer_a_v2.certificate_pem.as_deref().unwrap(),
        Some("affiliation changed"),
    );
    assert_openssl_rejects_crl(&new_crl.der, issuer_a.certificate_pem.as_deref().unwrap());

    // Expired issuers may serve an already-valid retained artifact, but they
    // cannot regenerate or sign after that artifact is invalidated.
    sqlx::query(
        "UPDATE pki_authorities SET status = 'expired', issuance_enabled = FALSE WHERE id = $1",
    )
    .bind(issuer_a_v2.id)
    .execute(&pool)
    .await
    .unwrap();
    let retained_expired = service::issuer_crl(&pool, &config, issuer_a_v2.id)
        .await
        .unwrap();
    assert!(retained_expired.cache_hit);
    assert_eq!(retained_expired.der, new_crl.der);
    sqlx::query("UPDATE certificate_crl_state SET dirty = TRUE WHERE issuer_id = $1")
        .bind(issuer_a_v2.id)
        .execute(&pool)
        .await
        .unwrap();
    let expired_error = service::issuer_crl(&pool, &config, issuer_a_v2.id)
        .await
        .unwrap_err();
    assert!(expired_error.to_string().contains("no publishable CRL"));

    // Tenant B can independently revoke and publish without changing any old
    // or new Tenant A artifact.
    let b_leaf = issue_managed(&pool, &config, tenant_b, entity_b, "tenant-b").await;
    revoke(
        &pool,
        b_leaf.credential_id,
        entity_b,
        tenant_b,
        "affiliation_changed",
    )
    .await;
    let changed_b = service::issuer_crl(&pool, &config, issuer_b.id)
        .await
        .unwrap();
    assert_eq!(changed_b.crl_number, still_b.crl_number + 1);
    assert_eq!(
        crl_serials(&changed_b.der),
        vec![hex::decode(&b_leaf.serial_number).unwrap()]
    );
    assert_eq!(
        service::issuer_crl(&pool, &config, issuer_a.id)
            .await
            .unwrap()
            .der,
        retired_crl.der
    );

    // Revocation publication evidence is independent of credential/entity
    // retention. Purging the owning entity before regeneration cannot remove
    // a still-valid serial from the issuer's next CRL.
    revoke(
        &pool,
        purge_leaf.credential_id,
        purge_entity,
        tenant_a,
        "key_compromise",
    )
    .await;
    sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(purge_entity)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM certificate_revocations WHERE credential_id = $1",
        )
        .bind(purge_leaf.credential_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let after_purge = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert_eq!(after_purge.crl_number, 8);
    assert!(crl_contains(&after_purge.der, &purge_leaf.serial_number));
}

async fn issue_managed(
    pool: &PgPool,
    config: &atom::config::Config,
    tenant_id: Uuid,
    entity_id: Uuid,
    key: &str,
) -> service::CertificateRecord {
    service::issue_certificate_from_csr_v2(
        pool,
        config,
        Some(tenant_id),
        service::IssueCertificateFromCsrV2 {
            entity_id,
            ttl_secs: Some(3600),
            csr_pem: csr(),
            idempotency_key: format!("pr009-{key}"),
        },
    )
    .await
    .unwrap()
    .certificate
}

async fn revoke(
    pool: &PgPool,
    credential_id: Uuid,
    entity_id: Uuid,
    tenant_id: Uuid,
    reason: &str,
) {
    service::revoke_certificate_v2(
        pool,
        service::RevokeCertificateV2 {
            selector: service::CertificateRevocationSelector::CredentialId(credential_id),
            reason: Some(reason.to_string()),
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_id,
            expected_tenant_id: Some(tenant_id),
        },
    )
    .await
    .unwrap();
}

fn csr() -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "pr009-device");
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(2);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

fn crl_serials(der: &[u8]) -> Vec<Vec<u8>> {
    let (remaining, crl) = x509_parser::parse_x509_crl(der).unwrap();
    assert!(remaining.is_empty());
    crl.iter_revoked_certificates()
        .map(|certificate| certificate.raw_serial().to_vec())
        .collect()
}

fn crl_contains(der: &[u8], serial_number: &str) -> bool {
    let serial = hex::decode(serial_number).unwrap();
    crl_serials(der)
        .iter()
        .any(|candidate| candidate == &serial)
}

async fn non_leaf_authority_ids(pool: &PgPool) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM pki_authorities
         WHERE kind IN ('root', 'platform_intermediate') ORDER BY kind",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn assert_openssl_crl(der: &[u8], issuer_pem: &str, expected_reason: Option<&str>) -> String {
    let directory = std::env::temp_dir().join(format!("atom-pr009-crl-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let crl_path = directory.join("issuer.crl");
    let issuer_path = directory.join("issuer.pem");
    fs::write(&crl_path, der).unwrap();
    fs::write(&issuer_path, issuer_pem).unwrap();
    let output = Command::new("openssl")
        .args(["crl", "-inform", "DER", "-in"])
        .arg(&crl_path)
        .arg("-CAfile")
        .arg(&issuer_path)
        .args(["-noout", "-verify", "-text"])
        .output()
        .expect("OpenSSL must be installed for PR-009 verification");
    fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "OpenSSL CRL verification failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.to_ascii_lowercase().contains("verify ok"));
    if let Some(reason) = expected_reason {
        assert!(
            text.to_ascii_lowercase()
                .contains(&reason.to_ascii_lowercase()),
            "missing CRL reason {reason}: {text}"
        );
    }
    text
}

fn assert_openssl_rejects_crl(der: &[u8], wrong_issuer_pem: &str) {
    let directory = std::env::temp_dir().join(format!("atom-pr009-wrong-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let crl_path = directory.join("issuer.crl");
    let issuer_path = directory.join("wrong-issuer.pem");
    fs::write(&crl_path, der).unwrap();
    fs::write(&issuer_path, wrong_issuer_pem).unwrap();
    let output = Command::new("openssl")
        .args(["crl", "-inform", "DER", "-in"])
        .arg(&crl_path)
        .arg("-CAfile")
        .arg(&issuer_path)
        .args(["-noout", "-verify"])
        .output()
        .expect("OpenSSL must be installed for PR-009 verification");
    fs::remove_dir_all(directory).unwrap();
    assert!(
        !output.status.success(),
        "wrong issuer unexpectedly verified CRL"
    );
}
