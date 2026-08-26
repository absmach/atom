//! M15 integration tests — public human signup.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m15_signup -- --ignored
//! ```

mod common;

use atom::error::AppError;
use atom::{
    config::Config,
    identity::{repo, service},
    keys,
    models::{entity::CreateEntity, session::SignupRequest},
};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

fn config(dev_allow_unverified_email_login: bool) -> Config {
    Config {
        self_registration_enabled: true,
        dev_allow_unverified_email_login,
        ..Config::for_tests()
    }
}

#[tokio::test]
#[ignore]
async fn signup_creates_global_unverified_human_password_email_and_dev_login() {
    let pool = common::pool().await;
    let cfg = config(true);
    keys::bootstrap_if_needed(&pool, &cfg.signing_keys)
        .await
        .expect("bootstrap keys");
    let keys = keys::load_active_keys(&pool, &cfg.signing_keys)
        .await
        .expect("load keys");

    let name = format!("m16-human-{}", Uuid::new_v4());
    let email = format!("{name}@example.test");
    let response = service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name: name.clone(),
            email: email.clone(),
            password: "test-password-123".into(),
            attributes: json!({"source": "m16"}),
        },
    )
    .await
    .expect("signup");
    assert_eq!(response.email, email);
    assert!(response.verification_required);

    let entity = sqlx::query("SELECT kind, tenant_id FROM entities WHERE id = $1")
        .bind(response.entity_id)
        .fetch_one(&pool)
        .await
        .expect("entity");
    assert_eq!(entity.try_get::<String, _>("kind").expect("kind"), "human");
    assert_eq!(
        entity
            .try_get::<Option<Uuid>, _>("tenant_id")
            .expect("tenant id"),
        None
    );

    let credential_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND identifier = $2 AND status = 'active'",
    )
    .bind(response.entity_id)
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("credential count");
    assert_eq!(credential_count, 1);

    let email_row =
        sqlx::query("SELECT verified_at FROM entity_emails WHERE entity_id = $1 AND email = $2")
            .bind(response.entity_id)
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("email row");
    assert!(email_row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("verified_at")
        .expect("verified_at")
        .is_none());

    let token_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_verification_tokens WHERE entity_id = $1 AND consumed_at IS NULL",
    )
    .bind(response.entity_id)
    .fetch_one(&pool)
    .await
    .expect("token count");
    assert_eq!(token_count, 1);

    let membership_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE entity_id = $1")
            .bind(response.entity_id)
            .fetch_one(&pool)
            .await
            .expect("membership count");
    assert_eq!(membership_count, 0);

    let strict_login = service::login_password(
        &pool,
        &config(false),
        &keys.primary,
        &email,
        "test-password-123",
    )
    .await;
    assert!(strict_login.is_err());

    let strict_name_login = service::login_password(
        &pool,
        &config(false),
        &keys.primary,
        &name,
        "test-password-123",
    )
    .await;
    assert!(strict_name_login.is_err());

    let login = service::login_password(
        &pool,
        &config(true),
        &keys.primary,
        &email,
        "test-password-123",
    )
    .await
    .expect("dev login");
    assert_eq!(login.entity_id, response.entity_id);
    assert_eq!(login.email_verified, Some(false));
    assert!(login.verification_required);

    let name_login = service::login_password(
        &pool,
        &config(true),
        &keys.primary,
        &name,
        "test-password-123",
    )
    .await
    .expect("dev login by account name");
    assert_eq!(name_login.entity_id, response.entity_id);
    assert_eq!(name_login.email_verified, Some(false));
    assert!(name_login.verification_required);

    sqlx::query("UPDATE entity_emails SET verified_at = now() WHERE entity_id = $1")
        .bind(response.entity_id)
        .execute(&pool)
        .await
        .expect("verify email");
    let verified_name_login = service::login_password(
        &pool,
        &config(false),
        &keys.primary,
        &name,
        "test-password-123",
    )
    .await
    .expect("strict login by verified account name");
    assert_eq!(verified_name_login.entity_id, response.entity_id);
    assert_eq!(verified_name_login.email_verified, Some(true));
    assert!(!verified_name_login.verification_required);

    sqlx::query("UPDATE entities SET status = 'suspended' WHERE id = $1")
        .bind(response.entity_id)
        .execute(&pool)
        .await
        .expect("suspend entity");
    let suspended_login = service::login_password(
        &pool,
        &config(true),
        &keys.primary,
        &email,
        "test-password-123",
    )
    .await;
    assert!(suspended_login.is_err());
}

#[tokio::test]
#[ignore]
async fn signup_rejects_duplicate_email_even_with_distinct_name() {
    let pool = common::pool().await;
    let cfg = config(true);

    let suffix = Uuid::new_v4();
    let email = format!("m15-dup-email-{suffix}@example.test");
    let first_name = format!("m15-dup-email-a-{suffix}");
    let second_name = format!("m15-dup-email-b-{suffix}");

    service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name: first_name,
            email: email.clone(),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await
    .expect("first signup");

    let err = service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name: second_name.clone(),
            email: email.to_uppercase(),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await
    .expect_err("duplicate email must be rejected");

    match err {
        AppError::Conflict(message) => assert_eq!(message, "Email address already taken"),
        other => panic!("expected email conflict, got {other:?}"),
    }

    let email_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_emails WHERE lower(email) = lower($1) AND deleted_at IS NULL",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("email count");
    assert_eq!(email_count, 1);

    let second_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM entities WHERE name = $1)")
            .bind(second_name)
            .fetch_one(&pool)
            .await
            .expect("second entity existence");
    assert!(!second_exists);
}

#[tokio::test]
#[ignore]
async fn signup_rejects_duplicate_name_with_username_conflict() {
    let pool = common::pool().await;
    let cfg = config(true);

    let suffix = Uuid::new_v4();
    let name = format!("m15-dup-name-{suffix}");

    service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name: name.clone(),
            email: format!("{name}-first@example.test"),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await
    .expect("first signup");

    let err = service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name,
            email: format!("m15-dup-name-{suffix}-second@example.test"),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await
    .expect_err("duplicate username must be rejected");

    match err {
        AppError::Conflict(message) => assert_eq!(message, "Username already taken"),
        other => panic!("expected username conflict, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn admin_created_human_uses_same_unique_email_identity() {
    let pool = common::pool().await;
    let cfg = config(true);

    let suffix = Uuid::new_v4();
    let email = format!("m15-admin-email-{suffix}@example.test");

    service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name: format!("m15-admin-email-signup-{suffix}"),
            email: email.clone(),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await
    .expect("signup");

    let err = repo::create_entity(
        &pool,
        CreateEntity {
            id: None,
            kind: None,
            profile_id: None,
            profile_version_id: None,
            name: format!("m15-admin-email-create-{suffix}"),
            alias: None,
            external_id: None,
            tenant_id: None,
            attributes: json!({ "email": email.to_uppercase() }),
        },
    )
    .await
    .expect_err("admin-created duplicate email must be rejected");

    match err {
        AppError::Conflict(message) => assert_eq!(message, "Email address already taken"),
        other => panic!("expected email conflict, got {other:?}"),
    }
}

/// Sending the verification email must happen *after* the signup transaction
/// commits, not inside it.
///
/// Two things break if the send moves back inside: the account is rolled back
/// when SMTP is unreachable (so a broker outage blocks registration entirely),
/// and — worse — a pooled Postgres connection is held for the whole SMTP
/// round-trip plus a blocking template read, on a public unauthenticated
/// endpoint. The rest of the suite runs with SMTP unconfigured, where
/// `send_templated_email` returns early, so nothing else covers this ordering.
#[tokio::test]
#[ignore]
async fn account_survives_an_unreachable_smtp_server() {
    let pool = common::pool().await;
    let cfg = Config {
        // Port 1 is reserved and refuses immediately: a fast, deterministic
        // send failure rather than a timeout.
        smtp: Some(atom::config::SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
            from: "atom@example.test".into(),
            tls: atom::config::SmtpTls::None,
        }),
        // Without the dev bypass an unconfigured SMTP would short-circuit
        // before ever dialing; this forces the real send path.
        ..config(false)
    };

    let name = format!("m15-smtp-down-{}", Uuid::new_v4());
    let email = format!("{name}@example.test");
    let result = service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name: name.clone(),
            email: email.clone(),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await;
    assert!(
        result.is_err(),
        "an unreachable SMTP server must surface as an error"
    );

    let entity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM entities e JOIN entity_emails ee ON ee.entity_id = e.id WHERE ee.email = $1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .expect("query signed-up entity");
    let entity_id = entity_id.expect(
        "the account and its email must be committed before the verification email is sent",
    );

    let credential_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password'",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("credential count");
    assert_eq!(
        credential_count, 1,
        "the password credential must be committed too, so resendVerification can be used"
    );
}
