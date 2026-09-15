//! Issue #110, workstream B: approval-gated remediation tooling.
//!
//! Every mutation under test targets exactly one operator-identified row and
//! requires a non-empty evidence/reason string. Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m54_legacy_identity_remediation -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

fn state(pool: PgPool) -> AppState {
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        Config::for_tests(),
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

async fn human(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status, attributes) \
         VALUES ($1, 'human', $2, NULL, 'active', '{}')",
    )
    .bind(id)
    .bind(format!("legacy-remediation-{id}"))
    .execute(pool)
    .await
    .expect("insert human");
    id
}

async fn entity_email(pool: &PgPool, entity_id: Uuid, email: &str, verified: bool) {
    sqlx::query(
        "INSERT INTO entity_emails (id, entity_id, email, verified_at) \
         VALUES ($1, $2, $3, CASE WHEN $4 THEN now() ELSE NULL END)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(email)
    .bind(verified)
    .execute(pool)
    .await
    .expect("insert entity_emails");
}

async fn oauth_link(pool: &PgPool, entity_id: Uuid, provider: &str, subject: &str, email: &str) {
    sqlx::query(
        "INSERT INTO oauth_identities (id, entity_id, provider, subject, email, email_verified) \
         VALUES ($1, $2, $3, $4, $5, true)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(provider)
    .bind(subject)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert oauth identity");
}

async fn latest_audit_details(pool: &PgPool, entity_id: Uuid) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT details FROM audit_logs \
         WHERE target_kind = 'entity' AND target_id = $1 AND event = 'entity.update' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("latest audit event")
}

#[tokio::test]
#[ignore]
async fn record_administrator_assisted_email_verification_requires_evidence() {
    let pool = common::pool().await;
    let entity_id = human(&pool).await;
    entity_email(
        &pool,
        entity_id,
        &format!("unverified-{entity_id}@example.test"),
        false,
    )
    .await;
    let schema = build_schema(state(pool.clone()));

    let response = schema
        .execute(authed(format!(
            r#"mutation {{ recordAdministratorAssistedEmailVerification(
                entityId: "{entity_id}", evidence: "   ") }}"#
        )))
        .await;
    assert!(!response.errors.is_empty());
    assert!(response.errors[0].message.contains("evidence"));

    let verified_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT verified_at FROM entity_emails WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("verified_at unchanged");
    assert!(verified_at.is_none());
}

#[tokio::test]
#[ignore]
async fn record_administrator_assisted_email_verification_is_idempotent_and_audited() {
    let pool = common::pool().await;
    let entity_id = human(&pool).await;
    entity_email(
        &pool,
        entity_id,
        &format!("unverified-{entity_id}@example.test"),
        false,
    )
    .await;
    let schema = build_schema(state(pool.clone()));
    let evidence = "confirmed identity via support ticket #4821, caller matched on file";

    let first = schema
        .execute(authed(format!(
            r#"mutation {{ recordAdministratorAssistedEmailVerification(
                entityId: "{entity_id}", evidence: "{evidence}") }}"#
        )))
        .await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let verified_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT verified_at FROM entity_emails WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("verified_at set");
    assert!(verified_at.is_some());

    let details = latest_audit_details(&pool, entity_id).await;
    assert_eq!(details["field"], "email_verified_administrative");
    assert_eq!(details["evidence"], evidence);

    let audit_count_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE target_id = $1 AND event = 'entity.update'",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("audit count before repeat");

    let second = schema
        .execute(authed(format!(
            r#"mutation {{ recordAdministratorAssistedEmailVerification(
                entityId: "{entity_id}", evidence: "{evidence}") }}"#
        )))
        .await;
    assert!(
        second.errors.is_empty(),
        "repeat call must be a no-op, not an error"
    );

    let audit_count_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE target_id = $1 AND event = 'entity.update'",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("audit count after repeat");
    assert_eq!(
        audit_count_before, audit_count_after,
        "an already-verified email must not be re-audited"
    );
}

#[tokio::test]
#[ignore]
async fn quarantine_and_revoke_oauth_link_require_a_reason() {
    let pool = common::pool().await;
    let entity_id = human(&pool).await;
    let email = format!("oauth-{entity_id}@example.test");
    entity_email(&pool, entity_id, &email, true).await;
    oauth_link(
        &pool,
        entity_id,
        "test-provider",
        &format!("subject-{entity_id}"),
        &email,
    )
    .await;
    let schema = build_schema(state(pool.clone()));

    for mutation in [
        format!(
            r#"mutation {{ quarantineOauthLink(entityId: "{entity_id}", provider: "test-provider", subject: "subject-{entity_id}", reason: "") }}"#
        ),
        format!(
            r#"mutation {{ revokeOauthLink(entityId: "{entity_id}", provider: "test-provider", subject: "subject-{entity_id}", reason: "") }}"#
        ),
    ] {
        let response = schema.execute(authed(mutation)).await;
        assert!(!response.errors.is_empty());
        assert!(response.errors[0].message.to_lowercase().contains("reason"));
    }

    let still_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oauth_identities WHERE entity_id = $1 AND quarantined_at IS NULL)",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("link untouched");
    assert!(still_present);
}

#[tokio::test]
#[ignore]
async fn quarantine_oauth_link_is_idempotent_and_audited() {
    let pool = common::pool().await;
    let entity_id = human(&pool).await;
    let email = format!("quarantine-{entity_id}@example.test");
    entity_email(&pool, entity_id, &email, true).await;
    let provider = "test-provider";
    let subject = format!("subject-{entity_id}");
    oauth_link(&pool, entity_id, provider, &subject, &email).await;
    let schema = build_schema(state(pool.clone()));
    let reason = "no supporting ticket for this preclaim-era association";

    let first = schema
        .execute(authed(format!(
            r#"mutation {{ quarantineOauthLink(
                entityId: "{entity_id}", provider: "{provider}", subject: "{subject}",
                reason: "{reason}") }}"#
        )))
        .await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let quarantined_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT quarantined_at FROM oauth_identities WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("quarantined_at set");
    assert!(quarantined_at.is_some());

    let details = latest_audit_details(&pool, entity_id).await;
    assert_eq!(details["field"], "oauth_link_quarantined");
    assert_eq!(details["reason"], reason);

    let second = schema
        .execute(authed(format!(
            r#"mutation {{ quarantineOauthLink(
                entityId: "{entity_id}", provider: "{provider}", subject: "{subject}",
                reason: "{reason}") }}"#
        )))
        .await;
    assert!(
        second.errors.is_empty(),
        "repeat quarantine must be a no-op"
    );
    let still_present: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oauth_identities WHERE entity_id = $1)")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("row preserved, not deleted");
    assert!(still_present, "quarantine must preserve the row for audit");
}

#[tokio::test]
#[ignore]
async fn revoke_oauth_link_deletes_and_is_idempotent() {
    let pool = common::pool().await;
    let entity_id = human(&pool).await;
    let email = format!("revoke-{entity_id}@example.test");
    entity_email(&pool, entity_id, &email, true).await;
    let provider = "test-provider";
    let subject = format!("subject-{entity_id}");
    oauth_link(&pool, entity_id, provider, &subject, &email).await;
    let schema = build_schema(state(pool.clone()));
    let reason = "confirmed via ticket #99: never authorized by the account owner";

    let first = schema
        .execute(authed(format!(
            r#"mutation {{ revokeOauthLink(
                entityId: "{entity_id}", provider: "{provider}", subject: "{subject}",
                reason: "{reason}") }}"#
        )))
        .await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_identities WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("row deleted");
    assert_eq!(remaining, 0);

    let details = latest_audit_details(&pool, entity_id).await;
    assert_eq!(details["field"], "oauth_link_revoked");
    assert_eq!(details["reason"], reason);

    let second = schema
        .execute(authed(format!(
            r#"mutation {{ revokeOauthLink(
                entityId: "{entity_id}", provider: "{provider}", subject: "{subject}",
                reason: "{reason}") }}"#
        )))
        .await;
    assert!(
        second.errors.is_empty(),
        "repeat revoke must be a no-op, not an error"
    );
}

#[tokio::test]
#[ignore]
async fn remediation_mutations_require_platform_manage() {
    let pool = common::pool().await;
    let caller = human(&pool).await;
    let target = human(&pool).await;
    entity_email(
        &pool,
        target,
        &format!("target-{target}@example.test"),
        false,
    )
    .await;
    let schema = build_schema(state(pool.clone()));

    for mutation in [
        format!(
            r#"mutation {{ recordAdministratorAssistedEmailVerification(entityId: "{target}", evidence: "x") }}"#
        ),
        format!(
            r#"mutation {{ quarantineOauthLink(entityId: "{target}", provider: "p", subject: "s", reason: "x") }}"#
        ),
        format!(
            r#"mutation {{ revokeOauthLink(entityId: "{target}", provider: "p", subject: "s", reason: "x") }}"#
        ),
    ] {
        let response = schema.execute(authed_as(caller, mutation.clone())).await;
        assert_eq!(
            response.errors.len(),
            1,
            "{mutation}: {:?}",
            response.errors
        );
        assert_eq!(response.errors[0].message, "forbidden", "{mutation}");
    }

    let verified_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT verified_at FROM entity_emails WHERE entity_id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("target unchanged");
    assert!(verified_at.is_none());
}

#[tokio::test]
#[ignore]
async fn record_administrator_assisted_email_verification_is_absent_from_the_legacy_report_afterward(
) {
    let pool = common::pool().await;
    let entity_id = human(&pool).await;
    entity_email(
        &pool,
        entity_id,
        &format!("resolved-{entity_id}@example.test"),
        false,
    )
    .await;
    let schema = build_schema(state(pool.clone()));

    let before = schema
        .execute(authed(format!(
            r#"{{ legacyUnverifiedEmails(entityId: "{entity_id}") {{ entityId }} }}"#
        )))
        .await;
    assert!(before.errors.is_empty(), "{:?}", before.errors);
    let before_data = before.data.into_json().expect("json");
    assert_eq!(
        before_data["legacyUnverifiedEmails"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let fix = schema
        .execute(authed(format!(
            r#"mutation {{ recordAdministratorAssistedEmailVerification(
                entityId: "{entity_id}", evidence: "verified in person") }}"#
        )))
        .await;
    assert!(fix.errors.is_empty(), "{:?}", fix.errors);

    let after = schema
        .execute(authed(format!(
            r#"{{ legacyUnverifiedEmails(entityId: "{entity_id}") {{ entityId }} }}"#
        )))
        .await;
    assert!(after.errors.is_empty(), "{:?}", after.errors);
    let after_data = after.data.into_json().expect("json");
    assert_eq!(
        after_data["legacyUnverifiedEmails"].as_array().unwrap().len(),
        0,
        "a remediated row must disappear from the report — the post-run verification the runbook relies on"
    );
}
