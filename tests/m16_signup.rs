//! M16 integration tests — public human signup.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m16_signup -- --ignored
//! ```

mod common;

use atom::{
    config::{Config, ADMIN_ENTITY_ID},
    identity::service,
    keys,
    models::session::SignupRequest,
};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

fn config(dev_allow_unverified_email_login: bool) -> Config {
    Config {
        database_url: String::new(),
        listen_addr: String::new(),
        grpc_addr: String::new(),
        jwt_expiry_secs: 3600,
        jwt_issuer: "http://localhost:8080".to_string(),
        jwt_audience: "magistrala".to_string(),
        admin_entity_id: ADMIN_ENTITY_ID,
        admin_secret: None,
        service_secret: None,
        service_entity_id: atom::config::SERVICE_ENTITY_ID,
        signup_enabled: true,
        dev_allow_unverified_email_login,
        public_base_url: "http://localhost:8080".into(),
        cors_allowed_origins: vec!["http://localhost:8080".into()],
        email_verification_redirect: "http://localhost:8080/graphql/console/auth/verify-email"
            .into(),
        password_reset_redirect: "http://localhost:8080/graphql/console/auth/reset-password".into(),
        invitation_redirect: "http://localhost:8080/graphql/console/invitations/accept".into(),
        oauth_success_redirect: "http://localhost:8080".into(),
        oauth_error_redirect: "http://localhost:8080".into(),
        oidc_providers: vec![],
        smtp: None,
        email_verification_expiry_secs: 86_400,
        invitation_expiry_secs: 604_800,
        oauth_state_expiry_secs: 600,
        auth_exchange_code_expiry_secs: 300,
        graphql_console_enabled: false,
        graphql_console_dist_dir: "console/dist".into(),
    }
}

#[tokio::test]
#[ignore]
async fn signup_creates_global_unverified_human_password_email_and_dev_login() {
    let pool = common::pool().await;
    keys::bootstrap_if_needed(&pool)
        .await
        .expect("bootstrap keys");
    let keys = keys::load_active_keys(&pool).await.expect("load keys");

    let name = format!("m16-human-{}", Uuid::new_v4());
    let email = format!("{name}@example.test");
    let response = service::signup_human(
        &pool,
        &config(true),
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
