//! M15 integration tests — public human signup.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m15_signup -- --ignored
//! ```

mod common;

use atom::{config::Config, identity::service, keys, models::session::SignupRequest};
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
