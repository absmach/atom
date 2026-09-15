//! Issue #110, workstream A: the dedicated verified email-change flow.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m52_email_change -- --ignored
//! ```

mod common;

use atom::{
    auth::AuthContext,
    config::Config,
    error::AppError,
    identity::{repo, service},
    keys,
    models::session::{EmailChangeConfirmRequest, EmailChangeRequest, PasswordResetConfirmRequest},
};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

const PASSWORD: &str = "correct-horse-battery-staple";

/// A global (`tenant_id IS NULL`) human with a verified email, an active
/// password credential, and a fresh real session row (required — unlike
/// GraphQL-layer tests, `request_email_change` reads `sessions.created_at`
/// from the database, so a fabricated `AuthContext.session_id` with no
/// backing row would fail the lookup, not just the recency check).
async fn human_with_session(pool: &PgPool) -> (Uuid, Uuid, String) {
    let entity_id = Uuid::new_v4();
    let email = format!("old-{entity_id}@example.test");
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status, attributes) \
         VALUES ($1, 'human', $2, NULL, 'active', $3)",
    )
    .bind(entity_id)
    .bind(format!("email-change-{entity_id}"))
    .bind(serde_json::json!({ "email": email }))
    .execute(pool)
    .await
    .expect("insert human");
    sqlx::query(
        "INSERT INTO entity_emails (id, entity_id, email, verified_at) \
         VALUES ($1, $2, $3, now())",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert entity_emails");
    let password_hash = service::hash_secret(PASSWORD.as_bytes()).expect("hash password");
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash) \
         VALUES ($1, $2, 'password', $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(&email)
    .bind(password_hash)
    .execute(pool)
    .await
    .expect("insert password credential");
    let session = repo::create_session(pool, entity_id, 3600)
        .await
        .expect("create session");
    (entity_id, session.id, email)
}

fn session_auth(entity_id: Uuid, session_id: Uuid) -> AuthContext {
    AuthContext {
        entity_id,
        tenant_id: None,
        session_id: Some(session_id),
        ..Default::default()
    }
}

fn token_auth(entity_id: Uuid, scoped: bool) -> AuthContext {
    AuthContext {
        entity_id,
        tenant_id: None,
        credential_id: Some(Uuid::new_v4()),
        scoped,
        ..Default::default()
    }
}

async fn pending_token_count(pool: &PgPool, entity_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_change_tokens WHERE entity_id = $1 AND consumed_at IS NULL",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("count pending email-change tokens")
}

/// Inserts a ready-to-confirm token directly (bypassing SMTP delivery, which
/// isn't configured in tests) with a known plaintext, following the same
/// pattern `m21_soft_delete.rs` uses for password-reset tokens.
async fn mint_confirm_token(
    pool: &PgPool,
    entity_id: Uuid,
    session_id: Uuid,
    current_email: &str,
    new_email: &str,
    expires_at: chrono::DateTime<Utc>,
) -> String {
    let token_id = Uuid::new_v4();
    let secret = "ab".repeat(32);
    let token = format!("atomc_{}_{}", hex::encode(token_id.as_bytes()), secret);
    let secret_hash = service::hash_secret(secret.as_bytes()).expect("hash token secret");
    sqlx::query(
        r#"INSERT INTO email_change_tokens
             (id, entity_id, session_id, current_email, new_email, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(session_id)
    .bind(current_email)
    .bind(new_email)
    .bind(secret_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("insert email-change token");
    token
}

#[tokio::test]
#[ignore]
async fn request_does_not_change_the_current_login_before_confirmation() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let new_email = format!("new-{entity_id}@example.test");

    service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: new_email.clone(),
        },
    )
    .await
    .expect("request email change");

    let (live_email, identifier): (String, Option<String>) = sqlx::query_as(
        "SELECT ee.email, c.identifier FROM entity_emails ee \
         JOIN credentials c ON c.entity_id = ee.entity_id AND c.kind = 'password' \
         WHERE ee.entity_id = $1",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("live identity row");
    assert_eq!(live_email, old_email);
    assert_eq!(identifier.as_deref(), Some(old_email.as_str()));
    assert_eq!(pending_token_count(&pool, entity_id).await, 1);
}

#[tokio::test]
#[ignore]
async fn request_rejects_access_tokens_scoped_and_unscoped() {
    let pool = common::pool().await;
    let (entity_id, _session_id, _email) = human_with_session(&pool).await;

    for scoped in [false, true] {
        let err = service::request_email_change(
            &pool,
            &Config::for_tests(),
            &token_auth(entity_id, scoped),
            EmailChangeRequest {
                new_email: format!("attacker-{entity_id}@example.test"),
            },
        )
        .await
        .expect_err("access token must not request an email change");
        assert!(
            matches!(err, AppError::Forbidden),
            "scoped={scoped}: {err:?}"
        );
    }
    assert_eq!(pending_token_count(&pool, entity_id).await, 0);
}

#[tokio::test]
#[ignore]
async fn request_rejects_a_stale_session() {
    let pool = common::pool().await;
    let (entity_id, session_id, _email) = human_with_session(&pool).await;
    sqlx::query("UPDATE sessions SET created_at = now() - interval '1 day' WHERE id = $1")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("age the session");

    let err = service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: format!("new-{entity_id}@example.test"),
        },
    )
    .await
    .expect_err("a stale session must not request an email change");
    assert!(matches!(err, AppError::Unauthorized(_)), "{err:?}");
    assert_eq!(pending_token_count(&pool, entity_id).await, 0);
}

#[tokio::test]
#[ignore]
async fn request_is_enumeration_resistant_for_an_email_already_taken() {
    let pool = common::pool().await;
    let (entity_id, session_id, _email) = human_with_session(&pool).await;
    let (_other_id, _other_session, taken_email) = human_with_session(&pool).await;

    service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: taken_email.clone(),
        },
    )
    .await
    .expect("request must not reveal that the email is taken");
    assert_eq!(
        pending_token_count(&pool, entity_id).await,
        0,
        "no token should be minted for an already-taken email"
    );

    // A case-variant spelling of the same taken email must normalize to the
    // identical comparison and stay just as enumeration-resistant — every
    // writer in this codebase lowercases before storage, so the taken check
    // must too, or a differently-cased probe would leak the collision.
    service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: taken_email.to_ascii_uppercase(),
        },
    )
    .await
    .expect("a case-variant probe of a taken email must not reveal the collision either");
    assert_eq!(pending_token_count(&pool, entity_id).await, 0);
}

#[tokio::test]
#[ignore]
async fn request_rejects_the_same_email_and_supersedes_prior_pending_requests() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;

    let same_email_err = service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: old_email,
        },
    )
    .await
    .expect_err("requesting the current email must fail");
    assert!(matches!(same_email_err, AppError::BadRequest(_)));

    let first_target = format!("first-{entity_id}@example.test");
    service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: first_target,
        },
    )
    .await
    .expect("first request");
    assert_eq!(pending_token_count(&pool, entity_id).await, 1);

    let second_target = format!("second-{entity_id}@example.test");
    service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity_id, session_id),
        EmailChangeRequest {
            new_email: second_target.clone(),
        },
    )
    .await
    .expect("second request supersedes the first");
    assert_eq!(
        pending_token_count(&pool, entity_id).await,
        1,
        "only the newest request stays pending"
    );
    let live_pending: String = sqlx::query_scalar(
        "SELECT new_email FROM email_change_tokens \
         WHERE entity_id = $1 AND consumed_at IS NULL",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("live pending token");
    assert_eq!(live_pending, second_target);
}

#[tokio::test]
#[ignore]
async fn confirm_rejects_wrong_expired_replayed_and_superseded_tokens() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let new_email = format!("new-{entity_id}@example.test");
    let future = Utc::now() + Duration::minutes(30);

    // Wrong secret.
    let real_token =
        mint_confirm_token(&pool, entity_id, session_id, &old_email, &new_email, future).await;
    let wrong_token = format!("{}f", &real_token[..real_token.len() - 1]);
    let err = service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token: wrong_token },
    )
    .await
    .expect_err("wrong secret must be rejected");
    assert!(matches!(err, AppError::BadRequest(_)));

    // Expired.
    let expired_token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() - Duration::minutes(1),
    )
    .await;
    let err = service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest {
            token: expired_token,
        },
    )
    .await
    .expect_err("expired token must be rejected");
    assert!(matches!(err, AppError::BadRequest(_)));

    // Replayed: the real token succeeds once, then fails.
    service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest {
            token: real_token.clone(),
        },
    )
    .await
    .expect("first confirmation succeeds");
    let err = service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token: real_token },
    )
    .await
    .expect_err("replayed token must be rejected");
    assert!(matches!(err, AppError::BadRequest(_)));

    // Superseded: mint against a *fresh* account state, request again to
    // supersede, then try to confirm the stale (superseded) token.
    let (entity2, session2, old_email2) = human_with_session(&pool).await;
    let stale = mint_confirm_token(
        &pool,
        entity2,
        session2,
        &old_email2,
        &format!("stale-{entity2}@example.test"),
        future,
    )
    .await;
    service::request_email_change(
        &pool,
        &Config::for_tests(),
        &session_auth(entity2, session2),
        EmailChangeRequest {
            new_email: format!("fresh-{entity2}@example.test"),
        },
    )
    .await
    .expect("superseding request");
    let err = service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token: stale },
    )
    .await
    .expect_err("superseded token must be rejected");
    assert!(matches!(err, AppError::BadRequest(_)));

    let live_email2: String =
        sqlx::query_scalar("SELECT email FROM entity_emails WHERE entity_id = $1")
            .bind(entity2)
            .fetch_one(&pool)
            .await
            .expect("entity2 email unchanged");
    assert_eq!(live_email2, old_email2);
}

#[tokio::test]
#[ignore]
async fn confirm_updates_email_credential_and_attributes_mirror_atomically() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let new_email = format!("new-{entity_id}@example.test");
    let token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;

    service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token },
    )
    .await
    .expect("confirm email change");

    let (live_email, verified): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT email, verified_at FROM entity_emails WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("entity_emails after confirm");
    assert_eq!(live_email, new_email);
    assert!(verified.is_some(), "new email must come out verified");

    let identifier: String = sqlx::query_scalar(
        "SELECT identifier FROM credentials WHERE entity_id = $1 AND kind = 'password'",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("credential identifier after confirm");
    assert_eq!(identifier, new_email);

    let attributes: serde_json::Value =
        sqlx::query_scalar("SELECT attributes FROM entities WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("attributes after confirm");
    assert_eq!(
        attributes["email"], new_email,
        "attributes.email compatibility mirror must stay in sync"
    );

    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE entity_id = $1 AND revoked_at IS NULL",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("active session count");
    assert_eq!(active_sessions, 0, "every session must be revoked");
}

#[tokio::test]
#[ignore]
async fn confirm_leaves_the_attributes_mirror_untouched_when_never_present() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    // This account never carried attributes.email.
    sqlx::query("UPDATE entities SET attributes = '{}' WHERE id = $1")
        .bind(entity_id)
        .execute(&pool)
        .await
        .expect("clear attributes");
    let new_email = format!("new-{entity_id}@example.test");
    let token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;

    service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token },
    )
    .await
    .expect("confirm email change");

    let attributes: serde_json::Value =
        sqlx::query_scalar("SELECT attributes FROM entities WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("attributes after confirm");
    assert!(
        attributes.get("email").is_none(),
        "a never-present mirror key must not be created by this flow"
    );
}

#[tokio::test]
#[ignore]
async fn confirm_rechecks_collision_at_confirmation_time_including_case_variants() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let contested_email = format!("contested-{entity_id}@example.test");
    let token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &contested_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;

    // Someone else takes a case-variant of the exact same address after the
    // token was minted but before it is confirmed.
    let (other_id, _other_session, _other_email) = human_with_session(&pool).await;
    sqlx::query("UPDATE entity_emails SET email = $2 WHERE entity_id = $1")
        .bind(other_id)
        .bind(contested_email.to_ascii_uppercase())
        .execute(&pool)
        .await
        .expect("collide on a case variant");
    sqlx::query(
        "UPDATE credentials SET identifier = $2 \
         WHERE entity_id = $1 AND kind = 'password'",
    )
    .bind(other_id)
    .bind(contested_email.to_ascii_uppercase())
    .execute(&pool)
    .await
    .expect("keep credential identifier in sync for the collision setup");

    let err = service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token },
    )
    .await
    .expect_err("case-variant collision must be rejected at confirmation time");
    assert!(matches!(err, AppError::Conflict(_)), "{err:?}");

    let (live_email, identifier): (String, Option<String>) = sqlx::query_as(
        "SELECT ee.email, c.identifier FROM entity_emails ee \
         JOIN credentials c ON c.entity_id = ee.entity_id AND c.kind = 'password' \
         WHERE ee.entity_id = $1",
    )
    .bind(entity_id)
    .fetch_one(&pool)
    .await
    .expect("live identity row unchanged");
    assert_eq!(live_email, old_email);
    assert_eq!(identifier.as_deref(), Some(old_email.as_str()));
}

#[tokio::test]
#[ignore]
async fn old_email_login_fails_and_new_email_login_succeeds_after_confirmation() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let new_email = format!("new-{entity_id}@example.test");
    let token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;

    let mut cfg = Config::for_tests();
    cfg.signing_keys.allow_plaintext_signing_keys = true;
    keys::bootstrap_if_needed(&pool, &cfg.signing_keys)
        .await
        .expect("bootstrap signing keys");
    let active_keys = keys::load_active_keys(&pool, &cfg.signing_keys)
        .await
        .expect("load signing keys");

    service::confirm_email_change(
        &pool,
        &cfg,
        None,
        false,
        EmailChangeConfirmRequest { token },
    )
    .await
    .expect("confirm email change");

    let old_login = service::login_credential_with_tenant(
        &pool,
        &cfg,
        &active_keys.primary,
        service::CredentialLoginRequest {
            identifier: &old_email,
            secret: PASSWORD,
            tenant_id: None,
            tenant_alias: None,
            kind: atom::models::enums::CredentialKind::Password,
        },
    )
    .await;
    assert!(old_login.is_err(), "the old email must no longer log in");

    let new_login = service::login_credential_with_tenant(
        &pool,
        &cfg,
        &active_keys.primary,
        service::CredentialLoginRequest {
            identifier: &new_email,
            secret: PASSWORD,
            tenant_id: None,
            tenant_alias: None,
            kind: atom::models::enums::CredentialKind::Password,
        },
    )
    .await
    .expect("the new email must log in with the unchanged password");
    assert_eq!(new_login.entity_id, entity_id);
}

#[tokio::test]
#[ignore]
async fn confirm_invalidates_stale_verification_and_reset_tokens_for_the_old_email() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let email_id: Uuid = sqlx::query_scalar("SELECT id FROM entity_emails WHERE entity_id = $1")
        .bind(entity_id)
        .fetch_one(&pool)
        .await
        .expect("email id");

    let verify_token_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO email_verification_tokens (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, now() + interval '1 day')"#,
    )
    .bind(verify_token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(service::hash_secret(b"irrelevant").expect("hash"))
    .execute(&pool)
    .await
    .expect("insert stale verification token");

    let reset_token_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO password_reset_tokens (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, now() + interval '1 hour')"#,
    )
    .bind(reset_token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(service::hash_secret(b"irrelevant").expect("hash"))
    .execute(&pool)
    .await
    .expect("insert stale reset token");

    let new_email = format!("new-{entity_id}@example.test");
    let confirm_token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;
    service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest {
            token: confirm_token,
        },
    )
    .await
    .expect("confirm email change");

    let verify_consumed: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT consumed_at FROM email_verification_tokens WHERE id = $1")
            .bind(verify_token_id)
            .fetch_one(&pool)
            .await
            .expect("verification token state");
    assert!(verify_consumed.is_some());

    let reset_consumed: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT consumed_at FROM password_reset_tokens WHERE id = $1")
            .bind(reset_token_id)
            .fetch_one(&pool)
            .await
            .expect("reset token state");
    assert!(reset_consumed.is_some());

    // And a stale reset token cannot be redeemed even before confirm ran —
    // the important part here is it is *consumed*, which the reset flow's
    // own "consumed_at IS NULL" guard already turns into a hard rejection.
    let err = service::reset_password(
        &pool,
        None,
        PasswordResetConfirmRequest {
            token: format!(
                "atomr_{}_{}",
                hex::encode(reset_token_id.as_bytes()),
                "0".repeat(64)
            ),
            password: "irrelevant-new-password".into(),
            confirm_password: None,
        },
    )
    .await
    .expect_err("a consumed reset token can never succeed regardless of secret match");
    assert!(matches!(err, AppError::BadRequest(_)));
}

#[tokio::test]
#[ignore]
async fn confirm_fails_safely_when_the_current_email_drifted_since_the_request() {
    let pool = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&pool).await;
    let new_email = format!("new-{entity_id}@example.test");
    let token = mint_confirm_token(
        &pool,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;

    // Simulate an admin (or OAuth linking) changing the email out from under
    // the pending request.
    let drifted_email = format!("drifted-{entity_id}@example.test");
    sqlx::query("UPDATE entity_emails SET email = $2 WHERE entity_id = $1")
        .bind(entity_id)
        .bind(&drifted_email)
        .execute(&pool)
        .await
        .expect("simulate concurrent drift");

    let err = service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest {
            token: token.clone(),
        },
    )
    .await
    .expect_err("drifted current email must fail safely");
    assert!(matches!(err, AppError::BadRequest(_)));

    let live_email: String =
        sqlx::query_scalar("SELECT email FROM entity_emails WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&pool)
            .await
            .expect("email unchanged by the failed confirm");
    assert_eq!(live_email, drifted_email);

    // The token is not consumed by this failure mode — reverting the drift
    // lets the same token still succeed.
    sqlx::query("UPDATE entity_emails SET email = $2 WHERE entity_id = $1")
        .bind(entity_id)
        .bind(&old_email)
        .execute(&pool)
        .await
        .expect("revert drift");
    service::confirm_email_change(
        &pool,
        &Config::for_tests(),
        None,
        false,
        EmailChangeConfirmRequest { token },
    )
    .await
    .expect("confirm succeeds once the precondition holds again");
}

/// Proves the fixed `upsert_oauth_identity` lookup lock (`FOR UPDATE OF e,
/// ee`, see `identity::service`) actually serializes against a concurrent
/// `entity_emails` row lock — the mechanism `confirm_email_change` and the
/// OAuth auto-link path both rely on to avoid a split identity. Mirrors
/// `m51_self_profile_update.rs`'s
/// `self_profile_update_preserves_concurrent_admin_attributes` timeout-based
/// lock-contention proof.
#[tokio::test]
#[ignore]
async fn oauth_style_auto_link_lookup_blocks_on_a_concurrent_email_change_lock_holder() {
    let pool = common::pool().await;
    let (entity_id, _session_id, email) = human_with_session(&pool).await;

    let mut holder_tx = pool.begin().await.expect("begin holder tx");
    sqlx::query(
        "SELECT id, email FROM entity_emails WHERE entity_id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(entity_id)
    .fetch_one(&mut *holder_tx)
    .await
    .expect("hold the entity_emails lock, as confirm_email_change would");

    let pool2 = pool.clone();
    let email2 = email.clone();
    let mut racer = tokio::spawn(async move {
        let mut tx = pool2.begin().await.expect("begin racer tx");
        sqlx::query(
            "SELECT ee.entity_id, ee.verified_at
             FROM entity_emails ee
             JOIN entities e ON e.id = ee.entity_id
             WHERE ee.email = $1 AND ee.deleted_at IS NULL
             FOR UPDATE OF e, ee",
        )
        .bind(&email2)
        .fetch_optional(&mut *tx)
        .await
        .expect("oauth-style auto-link lookup")
    });

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut racer)
            .await
            .is_err(),
        "the oauth-style lookup must block while confirm_email_change's lock is held"
    );
    holder_tx.rollback().await.expect("release holder lock");

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), racer)
        .await
        .expect("racer should finish once the lock is released")
        .expect("racer task");
    assert!(
        result.is_some(),
        "email was never changed, so it still resolves"
    );
}

/// `single_connection_pool` mirrors `m25_config_bootstrap.rs`'s helper of the
/// same name: a pool capped at exactly one connection proves
/// `confirm_email_change` never borrows a second connection while its
/// transaction is open (it would otherwise deadlock outright).
async fn single_connection_pool() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("single-connection pool");
    sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .expect("load migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    pool
}

#[tokio::test]
#[ignore]
async fn confirm_email_change_works_with_a_single_connection_pool() {
    let shared = common::pool().await;
    let (entity_id, session_id, old_email) = human_with_session(&shared).await;
    let new_email = format!("new-{entity_id}@example.test");
    let token = mint_confirm_token(
        &shared,
        entity_id,
        session_id,
        &old_email,
        &new_email,
        Utc::now() + Duration::minutes(30),
    )
    .await;

    let pool = single_connection_pool().await;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        service::confirm_email_change(
            &pool,
            &Config::for_tests(),
            None,
            false,
            EmailChangeConfirmRequest { token },
        ),
    )
    .await
    .expect("single-connection confirm must not deadlock")
    .expect("confirm email change");

    let live_email: String =
        sqlx::query_scalar("SELECT email FROM entity_emails WHERE entity_id = $1")
            .bind(entity_id)
            .fetch_one(&shared)
            .await
            .expect("email changed");
    assert_eq!(live_email, new_email);
}
