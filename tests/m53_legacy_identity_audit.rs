//! Issue #110, workstream B: the dry-run legacy identity audit report.
//!
//! Every query here is read-only — these tests assert findings appear (or
//! are correctly excluded) and that nothing in the database changes as a
//! side effect of running the report.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m53_legacy_identity_audit -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::build_schema,
    identity::service,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use serde_json::json;
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

async fn human(pool: &PgPool, attributes: serde_json::Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status, attributes) \
         VALUES ($1, 'human', $2, NULL, 'active', $3)",
    )
    .bind(id)
    .bind(format!("legacy-audit-{id}"))
    .bind(attributes)
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

async fn password_credential(pool: &PgPool, entity_id: Uuid, identifier: &str) {
    let hash = service::hash_secret(b"irrelevant-test-secret").expect("hash");
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash) \
         VALUES ($1, $2, 'password', $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(identifier)
    .bind(hash)
    .execute(pool)
    .await
    .expect("insert password credential");
}

async fn oauth_identity(pool: &PgPool, entity_id: Uuid, email: &str, verified: bool) {
    sqlx::query(
        "INSERT INTO oauth_identities (id, entity_id, provider, subject, email, email_verified) \
         VALUES ($1, $2, 'test-provider', $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(format!("subject-{entity_id}"))
    .bind(email)
    .bind(verified)
    .execute(pool)
    .await
    .expect("insert oauth identity");
}

fn find<'a>(items: &'a serde_json::Value, entity_id: Uuid) -> Option<&'a serde_json::Value> {
    items
        .as_array()
        .expect("array")
        .iter()
        .find(|item| item["entityId"] == entity_id.to_string())
}

#[tokio::test]
#[ignore]
async fn legacy_unverified_emails_lists_only_unverified_live_rows() {
    let pool = common::pool().await;
    let unverified = human(&pool, json!({})).await;
    entity_email(
        &pool,
        unverified,
        &format!("unverified-{unverified}@example.test"),
        false,
    )
    .await;
    let verified = human(&pool, json!({})).await;
    entity_email(
        &pool,
        verified,
        &format!("verified-{verified}@example.test"),
        true,
    )
    .await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(
            "{ legacyUnverifiedEmails(limit: 200) { entityId email entityKind entityStatus \
             pendingTokens { verification passwordReset emailChange invitation } } }",
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json");
    let items = &data["legacyUnverifiedEmails"];

    let row = find(items, unverified).expect("unverified email must be reported");
    assert_eq!(row["entityKind"], "human");
    assert_eq!(row["entityStatus"], "active");
    assert_eq!(row["pendingTokens"]["verification"], 0);
    assert_eq!(row["pendingTokens"]["passwordReset"], 0);
    assert_eq!(row["pendingTokens"]["emailChange"], 0);
    assert_eq!(row["pendingTokens"]["invitation"], 0);

    assert!(
        find(items, verified).is_none(),
        "a verified email must not be reported"
    );
}

#[tokio::test]
#[ignore]
async fn legacy_unverified_emails_counts_pending_tokens() {
    let pool = common::pool().await;
    let entity_id = human(&pool, json!({})).await;
    let email = format!("pending-{entity_id}@example.test");
    entity_email(&pool, entity_id, &email, false).await;
    let email_id: Uuid = sqlx::query_scalar("SELECT id FROM entity_emails WHERE entity_id = $1")
        .bind(entity_id)
        .fetch_one(&pool)
        .await
        .expect("email id");
    sqlx::query(
        r#"INSERT INTO email_verification_tokens (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, now() + interval '1 day')"#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(email_id)
    .bind(service::hash_secret(b"irrelevant").expect("hash"))
    .execute(&pool)
    .await
    .expect("insert verification token");

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            "{{ legacyUnverifiedEmails(entityId: \"{entity_id}\") {{ entityId \
             pendingTokens {{ verification }} }} }}"
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json");
    let row = find(&data["legacyUnverifiedEmails"], entity_id).expect("row present");
    assert_eq!(row["pendingTokens"]["verification"], 1);
}

#[tokio::test]
#[ignore]
async fn legacy_credential_identifier_mismatches_excludes_matching_and_includes_missing_canonical()
{
    let pool = common::pool().await;
    let matching = human(&pool, json!({})).await;
    let matching_email = format!("matches-{matching}@example.test");
    entity_email(&pool, matching, &matching_email, true).await;
    password_credential(&pool, matching, &matching_email).await;

    let drifted = human(&pool, json!({})).await;
    entity_email(
        &pool,
        drifted,
        &format!("canonical-{drifted}@example.test"),
        true,
    )
    .await;
    password_credential(&pool, drifted, &format!("stale-{drifted}@example.test")).await;

    let no_canonical = human(&pool, json!({})).await;
    password_credential(
        &pool,
        no_canonical,
        &format!("orphan-{no_canonical}@example.test"),
    )
    .await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(
            "{ legacyCredentialIdentifierMismatches(limit: 200) { entityId identifier \
             canonicalEmail } }",
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json");
    let items = &data["legacyCredentialIdentifierMismatches"];

    assert!(
        find(items, matching).is_none(),
        "a credential matching the canonical email must not be reported"
    );
    let drifted_row = find(items, drifted).expect("drifted identifier must be reported");
    assert!(drifted_row["canonicalEmail"].is_string());
    let orphan_row =
        find(items, no_canonical).expect("credential with no canonical email must be reported");
    assert!(orphan_row["canonicalEmail"].is_null());
}

#[tokio::test]
#[ignore]
async fn legacy_oauth_email_mismatches_flags_stale_and_unverified_links() {
    let pool = common::pool().await;
    let matching = human(&pool, json!({})).await;
    let matching_email = format!("oauth-match-{matching}@example.test");
    entity_email(&pool, matching, &matching_email, true).await;
    oauth_identity(&pool, matching, &matching_email, true).await;

    let stale = human(&pool, json!({})).await;
    entity_email(
        &pool,
        stale,
        &format!("canonical-{stale}@example.test"),
        true,
    )
    .await;
    oauth_identity(
        &pool,
        stale,
        &format!("stale-oauth-{stale}@example.test"),
        true,
    )
    .await;

    let unverified_canonical = human(&pool, json!({})).await;
    let shared_email = format!("shared-{unverified_canonical}@example.test");
    entity_email(&pool, unverified_canonical, &shared_email, false).await;
    oauth_identity(&pool, unverified_canonical, &shared_email, true).await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(
            "{ legacyOauthEmailMismatches(limit: 200) { entityId oauthEmail canonicalEmail \
             canonicalVerifiedAt } }",
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json");
    let items = &data["legacyOauthEmailMismatches"];

    assert!(
        find(items, matching).is_none(),
        "an oauth link matching a verified canonical email must not be reported"
    );
    assert!(
        find(items, stale).is_some(),
        "a stale oauth link must be reported"
    );
    let unverified_row =
        find(items, unverified_canonical).expect("an unverified canonical email must be reported");
    assert!(unverified_row["canonicalVerifiedAt"].is_null());
}

#[tokio::test]
#[ignore]
async fn legacy_attributes_email_mismatches_ignores_entities_without_the_legacy_key() {
    let pool = common::pool().await;
    let drifted = human(
        &pool,
        json!({ "email": format!("legacy-{}@example.test", Uuid::new_v4()) }),
    )
    .await;
    let canonical_email = format!("canonical-{drifted}@example.test");
    entity_email(&pool, drifted, &canonical_email, true).await;

    let never_had_one = human(&pool, json!({})).await;
    entity_email(
        &pool,
        never_had_one,
        &format!("only-canonical-{never_had_one}@example.test"),
        true,
    )
    .await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(
            "{ legacyAttributesEmailMismatches(limit: 200) { entityId attributesEmail \
             canonicalEmail } }",
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json");
    let items = &data["legacyAttributesEmailMismatches"];

    let row = find(items, drifted).expect("drifted attributes.email must be reported");
    assert_eq!(row["canonicalEmail"], canonical_email);
    assert!(
        find(items, never_had_one).is_none(),
        "an entity that never had attributes.email must not be reported"
    );
}

#[tokio::test]
#[ignore]
async fn legacy_reports_require_platform_manage() {
    let pool = common::pool().await;
    let caller = human(&pool, json!({})).await;
    let schema = build_schema(state(pool));

    for query in [
        "{ legacyUnverifiedEmails(limit: 1) { entityId } }",
        "{ legacyCredentialIdentifierMismatches(limit: 1) { entityId } }",
        "{ legacyOauthEmailMismatches(limit: 1) { entityId } }",
        "{ legacyAttributesEmailMismatches(limit: 1) { entityId } }",
    ] {
        let response = schema.execute(authed_as(caller, query)).await;
        assert_eq!(response.errors.len(), 1, "{query}: {:?}", response.errors);
        assert_eq!(response.errors[0].message, "forbidden", "{query}");
    }
}

#[tokio::test]
#[ignore]
async fn legacy_reports_mutate_nothing() {
    let pool = common::pool().await;
    let entity_id = human(&pool, json!({ "email": "unused" })).await;
    let email = format!("read-only-{entity_id}@example.test");
    entity_email(&pool, entity_id, &email, false).await;
    password_credential(
        &pool,
        entity_id,
        &format!("mismatched-{entity_id}@example.test"),
    )
    .await;
    let before: (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT ee.email, ee.verified_at, e.attributes \
         FROM entity_emails ee JOIN entities e ON e.id = ee.entity_id \
         WHERE ee.entity_id = $1",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("before state");

    let schema = build_schema(state(pool.clone()));
    let response = schema
        .execute(authed(format!(
            "{{ legacyUnverifiedEmails(entityId: \"{entity_id}\") {{ entityId }} \
             legacyCredentialIdentifierMismatches(entityId: \"{entity_id}\") {{ entityId }} }}"
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    let after: (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT ee.email, ee.verified_at, e.attributes \
         FROM entity_emails ee JOIN entities e ON e.id = ee.entity_id \
         WHERE ee.entity_id = $1",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("after state");
    assert_eq!(before, after, "running the report must not mutate any row");
}
