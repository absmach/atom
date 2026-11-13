//! M29 integration tests — a new password-reset request supersedes the older link.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m29_password_reset_supersede -- --ignored
//! ATOM_TEST_BACKEND=sqlite cargo test --test m29_password_reset_supersede -- --ignored
//! ```

mod common;

use atom::{
    config::Config,
    identity::service,
    models::session::{PasswordResetRequest, SignupRequest},
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn a_new_reset_request_consumes_the_older_outstanding_link() {
    let pool = common::pool().await;
    let cfg = Config {
        self_registration_enabled: true,
        dev_allow_unverified_email_login: true,
        ..Config::for_tests()
    };
    let name = format!("m29-human-{}", Uuid::new_v4());
    let email = format!("{name}@example.test");
    let response = service::signup_human(
        &pool,
        &cfg,
        SignupRequest {
            name,
            email: email.clone(),
            password: "test-password-123".into(),
            attributes: json!({}),
        },
    )
    .await
    .expect("signup");

    for _ in 0..2 {
        service::request_password_reset(
            &pool,
            &cfg,
            PasswordResetRequest {
                email: email.clone(),
            },
        )
        .await
        .expect("request reset");
    }

    let all = "SELECT COUNT(*) FROM password_reset_tokens WHERE entity_id = $1";
    let open =
        "SELECT COUNT(*) FROM password_reset_tokens WHERE entity_id = $1 AND consumed_at IS NULL";
    let total: i64 = common::db::query_scalar(all, all)
        .bind(response.entity_id)
        .fetch_one(&pool)
        .await
        .expect("count all");
    let outstanding: i64 = common::db::query_scalar(open, open)
        .bind(response.entity_id)
        .fetch_one(&pool)
        .await
        .expect("count outstanding");

    assert_eq!(total, 2, "each request issues a link");
    assert_eq!(
        outstanding, 1,
        "only the newest link may still be usable; the older one must not be replayable"
    );
}
