//! PR-015 lifecycle automation and bounded fleet-operation coverage.
//!
//! CI runs this ignored binary against a fresh PostgreSQL database,
//! single-threaded.

mod common;

use async_graphql::{Request, Variables};
use atom::{
    auth::AuthContext,
    certs::{enrollment::service as enrollment, lifecycle, service},
    config::PkiLifecycleConfig,
    graphql::build_schema,
    identity, metrics,
    models::{
        enums::{Effect, SubjectKind},
        group::CreateGroup,
        policy::{CreatePermissionBlock, CreateRoleAssignment},
        role::CreateRole,
    },
};
use chrono::{DateTime, Duration, Utc};
use rcgen::{CertificateParams, KeyPair};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn lifecycle_automation_enforces_the_pr015_contract() {
    let pool = common::pool().await;
    metrics::init(true);
    let mut config = common::pki::managed_config(false, true);
    config.graphql_limits.introspection_enabled = true;
    config.pki_lifecycle = PkiLifecycleConfig {
        enabled: true,
        interval_secs: 60,
        batch_size: 100,
        expiry_warning_secs: 3_600,
        authority_warning_secs: 30 * 86_400,
    };
    let state = common::pki::graphql_state(pool.clone(), config.clone());
    let schema = build_schema(state.clone());
    let root = common::pki::test_root("PR-015 Offline Root");

    let tenant_a = common::pki::create_tenant(&pool, "pki-life-a").await;
    let tenant_b = common::pki::create_tenant(&pool, "pki-life-b").await;
    let issuer_a = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_a).await;
    let _issuer_b = common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_b).await;
    let expiring_authority_tenant =
        common::pki::create_tenant(&pool, "pki-life-expiring-authority").await;
    let expiring_authority =
        common::pki::provision_tenant_issuer(&pool, &config, &root, expiring_authority_tenant)
            .await;
    let entity_a = common::pki::create_entity(&pool, tenant_a, "pki-life-a").await;
    let entity_b = common::pki::create_entity(&pool, tenant_b, "pki-life-b").await;

    let due = issue(&pool, &config, tenant_a, entity_a, "due").await;
    let future = issue(&pool, &config, tenant_a, entity_a, "future").await;
    let critical = issue(&pool, &config, tenant_a, entity_a, "critical").await;
    let unaffected_b = issue(&pool, &config, tenant_b, entity_b, "tenant-b").await;
    let now = Utc::now();

    // Pre-PR-007 rows without a stored threshold use the referenced profile.
    // Exactly-at-boundary is due; one second beyond is not.
    set_profile_fallback_expiry(&pool, due.credential_id, now + Duration::days(1)).await;
    set_profile_fallback_expiry(
        &pool,
        future.credential_id,
        now + Duration::days(1) + Duration::seconds(1),
    )
    .await;
    // The critical expiry boundary is independently visible without making
    // the renewal window due in this synthetic boundary fixture.
    set_expiry_and_renewal(
        &pool,
        critical.credential_id,
        now + Duration::hours(1),
        now + Duration::minutes(30),
    )
    .await;

    // A tenant issuer at the exact 30-day lead boundary is surfaced early
    // enough to run the PR-003 rotation procedure.
    sqlx::query("UPDATE pki_authorities SET not_after = $2 WHERE id = $1")
        .bind(expiring_authority.id)
        .bind(now + Duration::days(30))
        .execute(&pool)
        .await
        .unwrap();

    // Disabling automation is a no-op and does not affect normal issuance.
    let disabled = lifecycle::sweep_once(
        &pool,
        PkiLifecycleConfig {
            enabled: false,
            ..config.pki_lifecycle
        },
        true,
        now,
    )
    .await
    .unwrap();
    assert_eq!(disabled, lifecycle::SweepSummary::default());
    assert_eq!(outbox_count(&pool, "certificate.expiring").await, 0);
    let mut disabled_config = config.clone();
    disabled_config.pki_lifecycle.enabled = false;
    let disabled_mode = issue(&pool, &disabled_config, tenant_b, entity_b, "disabled-mode").await;
    assert_eq!(
        certificate_status(&pool, disabled_mode.credential_id).await,
        "active"
    );

    // Concurrent replica ticks and a subsequent restart converge on one event
    // for each due window through the advisory lock plus durable unique marker.
    let (left, right) = tokio::join!(
        lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now),
        lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.certificate_events + right.certificate_events, 2);
    assert_eq!(left.authority_events + right.authority_events, 1);
    assert_eq!(outbox_count(&pool, "certificate.expiring").await, 2);
    assert_eq!(
        outbox_count(&pool, "certificate.authority_expiring").await,
        1
    );
    let restart = lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now)
        .await
        .unwrap();
    assert_eq!(restart.certificate_events, 0);
    assert_eq!(restart.authority_events, 0);

    // A later profile snapshot/correction may move the timestamp but does not
    // create a second logical renewal-window notification for this certificate.
    sqlx::query(
        "UPDATE credentials SET metadata = jsonb_set(metadata, '{renewal_due_at}', to_jsonb($2::timestamptz)) WHERE id = $1",
    )
    .bind(due.credential_id)
    .bind(now - Duration::hours(1))
    .execute(&pool)
    .await
    .unwrap();
    let shifted_window = lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now)
        .await
        .unwrap();
    assert_eq!(shifted_window.certificate_events, 0);
    assert_eq!(outbox_count(&pool, "certificate.expiring").await, 2);

    assert_certificate_event(&pool, due.credential_id, "renewal").await;
    assert_certificate_event(&pool, critical.credential_id, "expiry").await;
    assert_authority_event(&pool, expiring_authority.id, expiring_authority_tenant).await;
    assert_eq!(
        marker_count(&pool, future.credential_id, "renewal").await,
        0
    );

    // A delayed or failed sweep still claims windows after the subject has
    // crossed its expiry timestamp; those events must not disappear merely
    // because the next successful retry is late.
    let overdue = issue(&pool, &config, tenant_b, entity_b, "overdue").await;
    set_expiry_and_renewal(
        &pool,
        overdue.credential_id,
        now - Duration::minutes(1),
        now - Duration::hours(2),
    )
    .await;
    let overdue_authority_tenant =
        common::pki::create_tenant(&pool, "pki-life-overdue-authority").await;
    let overdue_authority =
        common::pki::provision_tenant_issuer(&pool, &config, &root, overdue_authority_tenant).await;
    sqlx::query("UPDATE pki_authorities SET not_after = $2 WHERE id = $1")
        .bind(overdue_authority.id)
        // Keep the synthetic expiry after the authority's not-before value.
        // The test root is only backdated by one minute, so using the same
        // minute boundary here can invert the interval by a fraction of a
        // second when provisioning happens after `now` was captured.
        .bind(now - Duration::seconds(1))
        .execute(&pool)
        .await
        .unwrap();
    let overdue_sweep = lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now)
        .await
        .unwrap();
    assert_eq!(overdue_sweep.certificate_events, 2);
    assert_eq!(overdue_sweep.authority_events, 1);
    assert_eq!(
        marker_count(&pool, overdue.credential_id, "expiry").await,
        1
    );
    assert_eq!(
        marker_count(&pool, overdue_authority.id, "authority_expiry").await,
        1
    );

    // The marker and outbox insert are one transaction: a forced outbox error
    // leaves neither, and the next healthy sweep can retry it.
    let transactional = issue(&pool, &config, tenant_a, entity_a, "transactional").await;
    set_profile_fallback_expiry(&pool, transactional.credential_id, now + Duration::days(1)).await;
    install_outbox_failure(&pool).await;
    let failed = lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now).await;
    assert!(failed.is_err());
    assert_eq!(
        marker_count(&pool, transactional.credential_id, "renewal").await,
        0
    );
    remove_outbox_failure(&pool).await;
    lifecycle::sweep_once(&pool, config.pki_lifecycle, true, now)
        .await
        .unwrap();
    assert_eq!(
        marker_count(&pool, transactional.credential_id, "renewal").await,
        1
    );

    // A tenant-scoped operator sees only its tenant because the filter is part
    // of the SQL query; expiry pagination is stable and reports the true total.
    let tenant_operator = common::pki::create_entity(&pool, tenant_a, "life-operator").await;
    grant_tenant_manage(&pool, tenant_a, tenant_operator).await;
    let from = (now - Duration::days(1)).to_rfc3339();
    let before = (now + Duration::days(2)).to_rfc3339();
    let page_one = schema
        .execute(
            Request::new(format!(
                r#"query {{ certificates(issuerId: "{}", status: "active", expiresFrom: "{from}", expiresBefore: "{before}", limit: 1, offset: 0) {{ total items {{ credentialId tenantId issuerId expiresAt }} }} }}"#,
                issuer_a.id,
            ))
            .data(auth(tenant_operator, Some(tenant_a))),
        )
        .await;
    assert!(page_one.errors.is_empty(), "{:?}", page_one.errors);
    let page_one = page_one.data.into_json().unwrap()["certificates"].clone();
    assert!(page_one["total"].as_i64().unwrap() >= 4);
    assert_eq!(page_one["items"].as_array().unwrap().len(), 1);
    assert_eq!(page_one["items"][0]["tenantId"], tenant_a.to_string());
    assert_eq!(page_one["items"][0]["issuerId"], issuer_a.id.to_string());
    let first_page_id = page_one["items"][0]["credentialId"]
        .as_str()
        .unwrap()
        .to_string();
    let page_two = schema
        .execute(
            Request::new(format!(
                r#"query {{ certificates(issuerId: "{}", status: "active", expiresFrom: "{from}", expiresBefore: "{before}", limit: 1, offset: 1) {{ items {{ credentialId tenantId }} }} }}"#,
                issuer_a.id,
            ))
            .data(auth(tenant_operator, Some(tenant_a))),
        )
        .await;
    assert!(page_two.errors.is_empty(), "{:?}", page_two.errors);
    let page_two = page_two.data.into_json().unwrap();
    assert_ne!(
        page_two["certificates"]["items"][0]["credentialId"],
        first_page_id
    );
    assert_eq!(
        page_two["certificates"]["items"][0]["tenantId"],
        tenant_a.to_string()
    );
    let cross_tenant = schema
        .execute(
            Request::new(format!(
                r#"query {{ certificates(tenantId: "{tenant_b}", expiresBefore: "{before}") {{ total }} }}"#
            ))
            .data(auth(tenant_operator, Some(tenant_a))),
        )
        .await;
    assert!(errors_contain(&cross_tenant.errors, "forbidden"));

    // Create group-scoped fleet members and prove the group selector is both
    // generic and bounded. The other tenant remains untouched.
    let group_entity_a = common::pki::create_entity(&pool, tenant_a, "life-group-a").await;
    let group_entity_b = common::pki::create_entity(&pool, tenant_a, "life-group-b").await;
    let group_cert_a = issue(&pool, &config, tenant_a, group_entity_a, "group-a").await;
    let group_cert_b = issue(&pool, &config, tenant_a, group_entity_b, "group-b").await;
    let group_id = create_principal_group(&pool, tenant_a, &[group_entity_a, group_entity_b]).await;
    // Even a corrupt cross-tenant membership row is constrained by the SQL
    // selector scope and cannot turn a tenant-wide permission into platform
    // revocation authority.
    sqlx::query("INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2)")
        .bind(group_id)
        .bind(entity_b)
        .execute(&pool)
        .await
        .unwrap();
    let group_bulk = execute_bulk(
        &schema,
        tenant_operator,
        Some(tenant_a),
        json!({"principalGroupId": group_id, "reason": "cessation_of_operation", "limit": 10}),
    )
    .await;
    assert!(group_bulk["complete"].as_bool().unwrap());
    assert_eq!(group_bulk["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        certificate_status(&pool, group_cert_a.credential_id).await,
        "revoked"
    );
    assert_eq!(
        certificate_status(&pool, group_cert_b.credential_id).await,
        "revoked"
    );
    assert_eq!(
        certificate_status(&pool, unaffected_b.credential_id).await,
        "active"
    );

    // Successful and failed renewal paths feed bounded lifecycle counters.
    let renewed_b = service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::Operator {
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_b,
            expected_tenant_id: Some(tenant_b),
        },
        service::RenewCertificateV2 {
            credential_id: unaffected_b.credential_id,
            ttl_secs: None,
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "m40-renew-success".into(),
        },
    )
    .await
    .unwrap();
    assert!(service::renew_certificate_v2(
        &pool,
        &config,
        service::CertificateRenewalAuthorization::Operator {
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: group_entity_a,
            expected_tenant_id: Some(tenant_a),
        },
        service::RenewCertificateV2 {
            credential_id: group_cert_a.credential_id,
            ttl_secs: None,
            key_source: service::RenewalKeySource::Csr(csr()),
            revoke_old: false,
            idempotency_key: "m40-renew-failure".into(),
        },
    )
    .await
    .is_err());

    // Issuer selector finishes the remaining tenant-A fleet without touching B.
    let issuer_bulk = execute_bulk(
        &schema,
        tenant_operator,
        Some(tenant_a),
        json!({"issuerId": issuer_a.id, "reason": "superseded", "limit": 100}),
    )
    .await;
    assert!(issuer_bulk["complete"].as_bool().unwrap());
    assert_eq!(
        certificate_status(&pool, unaffected_b.credential_id).await,
        "active"
    );
    assert_eq!(
        certificate_status(&pool, renewed_b.certificate.credential_id).await,
        "active"
    );

    // Partial failure stops at the first failed item and returns the last
    // contiguous cursor. Repairing the row and resuming does not revisit or
    // duplicate the already committed revocation.
    let tenant_c = common::pki::create_tenant(&pool, "pki-life-c").await;
    common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_c).await;
    let entity_c = common::pki::create_entity(&pool, tenant_c, "pki-life-c").await;
    let c_one = issue(&pool, &config, tenant_c, entity_c, "resume-one").await;
    let c_two = issue(&pool, &config, tenant_c, entity_c, "resume-two").await;
    let mut ordered = [c_one.credential_id, c_two.credential_id];
    ordered.sort();
    let original_metadata: Value =
        sqlx::query_scalar("SELECT metadata FROM credentials WHERE id = $1")
            .bind(ordered[1])
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE credentials SET metadata = metadata - 'certificate_pem' WHERE id = $1")
        .bind(ordered[1])
        .execute(&pool)
        .await
        .unwrap();
    let partial = execute_bulk(
        &schema,
        common::admin_id(),
        None,
        json!({"tenantId": tenant_c, "reason": "key_compromise", "limit": 10}),
    )
    .await;
    assert!(!partial["complete"].as_bool().unwrap());
    assert_eq!(partial["items"].as_array().unwrap().len(), 2);
    assert_eq!(partial["items"][0]["outcome"], "revoked");
    assert_eq!(partial["items"][1]["outcome"], "failed");
    assert_eq!(partial["items"][1]["errorCode"], "internal");
    assert_eq!(partial["nextCursor"], ordered[0].to_string());
    let partial_snapshot = partial["snapshotAt"].as_str().unwrap().to_string();
    let failed_observation: (String, String) = sqlx::query_as(
        r#"
        SELECT payload->>'outcome', payload->'details'->>'error_code'
        FROM event_outbox
        WHERE event = 'certificate.bulk_revoke' AND payload->>'target_id' = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(ordered[1].to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(failed_observation.0, "error");
    assert_eq!(failed_observation.1, "internal");
    sqlx::query("UPDATE credentials SET metadata = $2 WHERE id = $1")
        .bind(ordered[1])
        .bind(original_metadata)
        .execute(&pool)
        .await
        .unwrap();
    let resumed = execute_bulk(
        &schema,
        common::admin_id(),
        None,
        json!({
            "tenantId": tenant_c,
            "reason": "key_compromise",
            "afterCredentialId": ordered[0],
            "snapshotAt": partial_snapshot,
            "limit": 10
        }),
    )
    .await;
    assert!(resumed["complete"].as_bool().unwrap());
    assert_eq!(resumed["items"].as_array().unwrap().len(), 1);
    assert_eq!(resumed["items"][0]["credentialId"], ordered[1].to_string());
    assert_eq!(resumed["items"][0]["outcome"], "revoked");

    // A bulk operation freezes its membership at page one. Certificates
    // issued between pages are deliberately excluded even when their random
    // UUID sorts after the cursor; a later operation then picks them up.
    let tenant_d = common::pki::create_tenant(&pool, "pki-life-d").await;
    common::pki::provision_tenant_issuer(&pool, &config, &root, tenant_d).await;
    let entity_d = common::pki::create_entity(&pool, tenant_d, "pki-life-d").await;
    issue(&pool, &config, tenant_d, entity_d, "snapshot-one").await;
    issue(&pool, &config, tenant_d, entity_d, "snapshot-two").await;
    let snapshot_first = execute_bulk(
        &schema,
        common::admin_id(),
        None,
        json!({"tenantId": tenant_d, "reason": "superseded", "limit": 1}),
    )
    .await;
    assert!(!snapshot_first["complete"].as_bool().unwrap());
    let snapshot_cursor = Uuid::parse_str(snapshot_first["nextCursor"].as_str().unwrap()).unwrap();
    let snapshot_at = snapshot_first["snapshotAt"].as_str().unwrap().to_string();
    let mut issued_during_scan = None;
    for index in 0..32 {
        let issued = issue(
            &pool,
            &config,
            tenant_d,
            entity_d,
            &format!("snapshot-late-{index}"),
        )
        .await;
        if issued.credential_id > snapshot_cursor {
            issued_during_scan = Some(issued);
            break;
        }
    }
    let issued_during_scan = issued_during_scan.expect("random UUID after first-page cursor");
    let snapshot_resumed = execute_bulk(
        &schema,
        common::admin_id(),
        None,
        json!({
            "tenantId": tenant_d,
            "reason": "superseded",
            "afterCredentialId": snapshot_cursor,
            "snapshotAt": snapshot_at,
            "limit": 100
        }),
    )
    .await;
    assert!(snapshot_resumed["complete"].as_bool().unwrap());
    assert_eq!(
        certificate_status(&pool, issued_during_scan.credential_id).await,
        "active",
        "the frozen operation must not absorb certificates issued between pages"
    );
    let catch_up = execute_bulk(
        &schema,
        common::admin_id(),
        None,
        json!({"tenantId": tenant_d, "reason": "superseded", "limit": 100}),
    )
    .await;
    assert!(catch_up["complete"].as_bool().unwrap());
    assert_eq!(
        certificate_status(&pool, issued_during_scan.credential_id).await,
        "revoked"
    );

    // First enrollment is included in the unified lifecycle operation metric;
    // a deliberately invalid issuance and unknown revocation prove failures.
    let enrollment_entity =
        common::pki::create_entity(&pool, tenant_b, "life-enrollment-metric").await;
    enrollment::enroll(
        &state,
        auth(enrollment_entity, Some(tenant_b)),
        enrollment::EnrollmentInput {
            csr_pem: csr(),
            ttl_secs: None,
            idempotency_key: "m40-enrollment-metric".into(),
        },
    )
    .await
    .unwrap();
    assert!(service::issue_certificate_from_csr_v2(
        &pool,
        &config,
        Some(tenant_b),
        service::IssueCertificateFromCsrV2 {
            entity_id: entity_b,
            ttl_secs: None,
            csr_pem: "not a CSR".into(),
            idempotency_key: "m40-issuance-failure".into(),
        },
    )
    .await
    .is_err());
    assert!(service::revoke_certificate_v2(
        &pool,
        service::RevokeCertificateV2 {
            selector: service::CertificateRevocationSelector::CredentialId(Uuid::new_v4()),
            reason: None,
            actor_entity_id: Some(common::admin_id()),
            expected_entity_id: entity_b,
            expected_tenant_id: Some(tenant_b),
        },
    )
    .await
    .is_err());

    let crl = service::issuer_crl(&pool, &config, issuer_a.id)
        .await
        .unwrap();
    assert!(!crl.der.is_empty());

    // `_in_tx` success is provisional. Rolling the caller-owned transaction
    // back must not publish a successful issuance sample.
    let before_rollback = lifecycle_metric_value(&metrics::render(&pool), "issuance", "success");
    let mut rollback_tx = pool.begin().await.unwrap();
    service::issue_certificate_from_csr_v2_in_tx(
        &mut rollback_tx,
        &config,
        Some(tenant_b),
        service::IssueCertificateFromCsrV2 {
            entity_id: entity_b,
            ttl_secs: None,
            csr_pem: csr(),
            idempotency_key: "m40-rolled-back-issuance".into(),
        },
    )
    .await
    .unwrap();
    rollback_tx.rollback().await.unwrap();
    let after_rollback = lifecycle_metric_value(&metrics::render(&pool), "issuance", "success");
    assert_eq!(before_rollback, after_rollback);

    let rendered = metrics::render(&pool);
    for metric in [
        metrics::PKI_LIFECYCLE_OPERATIONS,
        metrics::PKI_CERTIFICATE_EXPIRY_COUNT,
        metrics::PKI_CRL_SIZE_BYTES,
        metrics::PKI_CRL_GENERATION_DURATION,
        metrics::PKI_AUTHORITY_TIME_TO_EXPIRY,
    ] {
        assert!(
            rendered.contains(metric),
            "missing metric {metric}: {rendered}"
        );
    }
    for operation in ["issuance", "renewal", "revocation", "enrollment"] {
        assert!(rendered.contains(&format!("operation=\"{operation}\"")));
    }
    assert!(rendered.contains("outcome=\"failure\""));
    for secret_or_identifier in [
        tenant_a.to_string(),
        entity_a.to_string(),
        issuer_a.id.to_string(),
        "BEGIN PRIVATE KEY".to_string(),
        "BEGIN CERTIFICATE".to_string(),
    ] {
        assert!(!rendered.contains(&secret_or_identifier));
    }
    metrics::record_pki_fleet_snapshot(&[], &[]);
    let absent_snapshot = metrics::render(&pool);
    assert!(
        absent_snapshot.lines().any(|line| {
            line.starts_with(metrics::PKI_AUTHORITY_TIME_TO_EXPIRY)
                && line.contains("kind=\"root\"")
                && line.ends_with(" NaN")
        }),
        "an absent authority kind must be explicit rather than a false zero: {absent_snapshot}"
    );
}

fn lifecycle_metric_value(rendered: &str, operation: &str, outcome: &str) -> f64 {
    rendered
        .lines()
        .find(|line| {
            line.starts_with(metrics::PKI_LIFECYCLE_OPERATIONS)
                && line.contains(&format!("operation=\"{operation}\""))
                && line.contains(&format!("outcome=\"{outcome}\""))
        })
        .and_then(|line| line.rsplit_once(' '))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0.0)
}

async fn issue(
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
            // Keep ordinary fixtures outside the one-day default renewal
            // threshold; boundary fixtures explicitly rewrite their windows.
            ttl_secs: Some(7 * 86_400),
            csr_pem: csr(),
            idempotency_key: format!("m40-{key}"),
        },
    )
    .await
    .unwrap()
    .certificate
}

fn csr() -> String {
    CertificateParams::default()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap()
}

async fn set_profile_fallback_expiry(
    pool: &PgPool,
    credential_id: Uuid,
    expires_at: DateTime<Utc>,
) {
    sqlx::query(
        r#"
        UPDATE credentials
        SET expires_at = $2,
            metadata = jsonb_set(
                metadata - 'renewal_due_at' - 'renewal_threshold_seconds',
                '{not_after}',
                to_jsonb($2::timestamptz)
            )
        WHERE id = $1
        "#,
    )
    .bind(credential_id)
    .bind(expires_at)
    .execute(pool)
    .await
    .unwrap();
}

async fn set_expiry_and_renewal(
    pool: &PgPool,
    credential_id: Uuid,
    expires_at: DateTime<Utc>,
    renewal_due_at: DateTime<Utc>,
) {
    sqlx::query(
        r#"
        UPDATE credentials
        SET expires_at = $2,
            metadata = jsonb_set(
                jsonb_set(metadata, '{not_after}', to_jsonb($2::timestamptz)),
                '{renewal_due_at}',
                to_jsonb($3::timestamptz)
            )
        WHERE id = $1
        "#,
    )
    .bind(credential_id)
    .bind(expires_at)
    .bind(renewal_due_at)
    .execute(pool)
    .await
    .unwrap();
}

async fn install_outbox_failure(pool: &PgPool) {
    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION m40_reject_expiry_event() RETURNS trigger AS $$
        BEGIN
            IF NEW.event = 'certificate.expiring' THEN
                RAISE EXCEPTION 'forced PR-015 outbox failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER m40_reject_expiry_event BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION m40_reject_expiry_event()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn remove_outbox_failure(pool: &PgPool) {
    sqlx::query("DROP TRIGGER m40_reject_expiry_event ON event_outbox")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION m40_reject_expiry_event()")
        .execute(pool)
        .await
        .unwrap();
}

async fn marker_count(pool: &PgPool, subject_id: Uuid, window: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM pki_lifecycle_notifications WHERE subject_id = $1 AND window_kind = $2",
    )
    .bind(subject_id)
    .bind(window)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn outbox_count(pool: &PgPool, event: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM event_outbox WHERE event = $1")
        .bind(event)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_certificate_event(pool: &PgPool, credential_id: Uuid, window: &str) {
    let expected: (Option<Uuid>, Uuid, Option<Uuid>) = sqlx::query_as(
        r#"
        SELECT c.issuer_id, c.entity_id, e.tenant_id
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        WHERE c.id = $1
        "#,
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let details: Value = sqlx::query_scalar(
        "SELECT payload->'details' FROM event_outbox WHERE event = 'certificate.expiring' AND payload->>'target_id' = $1",
    )
    .bind(credential_id.to_string())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(details["credential_id"], credential_id.to_string());
    assert_eq!(details["issuer_id"], json!(expected.0));
    assert_eq!(details["entity_id"], expected.1.to_string());
    assert_eq!(details["tenant_id"], json!(expected.2));
    assert_eq!(details["window"], window);
    for key in ["issuer_id", "credential_id", "entity_id", "tenant_id"] {
        assert!(details.get(key).is_some(), "missing {key}: {details}");
    }
    let encoded = details.to_string();
    assert!(!encoded.contains("certificate_pem"));
    assert!(!encoded.contains("private_key"));
}

async fn assert_authority_event(pool: &PgPool, issuer_id: Uuid, tenant_id: Uuid) {
    let details: Value = sqlx::query_scalar(
        "SELECT payload->'details' FROM event_outbox WHERE event = 'certificate.authority_expiring' AND payload->>'target_id' = $1",
    )
    .bind(issuer_id.to_string())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(details["issuer_id"], issuer_id.to_string());
    assert_eq!(details["tenant_id"], tenant_id.to_string());
    assert_eq!(details["rotation_procedure"], "PR-003");
    assert!(details["credential_id"].is_null());
    assert!(details["entity_id"].is_null());
}

async fn grant_tenant_manage(pool: &PgPool, tenant_id: Uuid, actor_id: Uuid) {
    let manage: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage' LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap();
    let role = atom::authz::repo::create_role(
        pool,
        CreateRole {
            name: format!("m40-manager-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .unwrap();
    let block = atom::authz::repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "tenant".into(),
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({}),
            action_ids: vec![manage],
        },
    )
    .await
    .unwrap();
    atom::authz::repo::replace_role_permission_block_links(pool, role.id, &[block.id])
        .await
        .unwrap();
    atom::authz::repo::create_role_assignment(
        pool,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: actor_id,
            role_id: role.id,
        },
    )
    .await
    .unwrap();
}

async fn create_principal_group(pool: &PgPool, tenant_id: Uuid, members: &[Uuid]) -> Uuid {
    let group = identity::repo::create_group(
        pool,
        CreateGroup {
            id: None,
            name: format!("m40-fleet-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            group_type: Some("principal".into()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .unwrap();
    for member in members {
        sqlx::query("INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2)")
            .bind(group.id)
            .bind(member)
            .execute(pool)
            .await
            .unwrap();
    }
    group.id
}

async fn execute_bulk(
    schema: &atom::graphql::AtomSchema,
    actor_id: Uuid,
    tenant_id: Option<Uuid>,
    input: Value,
) -> Value {
    let response = schema
        .execute(
            Request::new(
                r#"mutation Bulk($input: BulkRevokeCertificatesInput!) {
                    bulkRevokeCertificates(input: $input) {
                        complete
                        snapshotAt
                        nextCursor
                        items { credentialId issuerId entityId tenantId outcome errorCode }
                    }
                }"#,
            )
            .variables(Variables::from_json(json!({"input": input})))
            .data(auth(actor_id, tenant_id)),
        )
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    response.data.into_json().unwrap()["bulkRevokeCertificates"].clone()
}

fn auth(entity_id: Uuid, tenant_id: Option<Uuid>) -> AuthContext {
    AuthContext {
        entity_id,
        tenant_id,
        ..Default::default()
    }
}

fn errors_contain(errors: &[async_graphql::ServerError], needle: &str) -> bool {
    errors.iter().any(|error| error.message.contains(needle))
}

async fn certificate_status(pool: &PgPool, credential_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(credential_id)
        .fetch_one(pool)
        .await
        .unwrap()
}
