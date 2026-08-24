//! Migration 017 regression coverage: tenant purge must succeed even when the
//! tenant's issuer has published revocations, and the immutable ledger row
//! must survive the purge with issuer_id cascaded to NULL and the
//! issuer_fingerprint_sha256 preserved for continued publication.
//!
//! Requires PostgreSQL. CI runs this ignored binary against its own freshly
//! migrated database, single-threaded.

mod common;

use atom::{certs::service, tenants};
use rcgen::{CertificateParams, DnType, KeyPair};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn tenant_purge_succeeds_after_revocation_and_ledger_survives() {
    let pool = common::pool().await;
    let config = common::pki::managed_config(false, false);
    let root = common::pki::test_root("PR-017 Purge Root");
    let tenant = common::pki::create_tenant(&pool, "purge-after-revoke").await;
    let entity = common::pki::create_entity(&pool, tenant, "purge-device").await;
    let issuer = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant).await;

    let issued = service::issue_certificate_from_csr_v2(
        &pool,
        &config,
        Some(tenant),
        service::IssueCertificateFromCsrV2 {
            entity_id: entity,
            ttl_secs: Some(3600),
            csr_pem: csr(),
            idempotency_key: "pr017-cert".into(),
        },
    )
    .await
    .unwrap();
    let cert = issued.certificate;

    let mut tx = pool.begin().await.unwrap();
    service::revoke_certificate_v2_in_tx(
        &mut tx,
        service::RevokeCertificateV2 {
            selector: service::CertificateRevocationSelector::CredentialId(cert.credential_id),
            reason: Some("key_compromise".into()),
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity,
            expected_tenant_id: Some(tenant),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let (ledger_issuer_id, ledger_fingerprint): (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT issuer_id, issuer_fingerprint_sha256 FROM certificate_revocations \
         WHERE credential_id = $1",
    )
    .bind(cert.credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        ledger_issuer_id,
        Some(issuer.id),
        "revocation trigger must record the issuing authority"
    );
    let ledger_fingerprint =
        ledger_fingerprint.expect("revocation trigger must record the issuer fingerprint");

    tenants::repo::soft_delete_tenant(&pool, tenant, None)
        .await
        .unwrap();
    // Before migration 017 this fails: certificate_revocations.issuer_id had
    // ON DELETE RESTRICT, so DELETE FROM pki_authorities inside purge_tenant
    // aborted with foreign_key_violation and the whole tenant purge rolled back.
    tenants::repo::purge_tenant(&pool, tenant).await.unwrap();

    let authority_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pki_authorities WHERE id = $1")
            .bind(issuer.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(authority_count, 0, "purge must remove the authority row");

    let (post_issuer_id, post_fingerprint): (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT issuer_id, issuer_fingerprint_sha256 FROM certificate_revocations \
         WHERE credential_id = $1",
    )
    .bind(cert.credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        post_issuer_id.is_none(),
        "FK cascade must clear issuer_id when the authority row is removed"
    );
    assert_eq!(
        post_fingerprint.as_deref(),
        Some(ledger_fingerprint.as_str()),
        "issuer_fingerprint_sha256 must survive so CRL/OCSP publication can continue"
    );
}

fn csr() -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "pr017-device");
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(2);
    params.serialize_request(&key).unwrap().pem().unwrap()
}
