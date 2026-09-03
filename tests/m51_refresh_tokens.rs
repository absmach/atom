//! DB-gated tests for rotating refresh tokens (issue #100): issuance at
//! login, rotation, replay detection, lifecycle interaction, concurrency,
//! and cleanup.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m51_refresh_tokens -- --ignored
//! ```

mod common;

use atom::{
    auth::{authenticate_token, parse_refresh_token, JwtSigner},
    config::Config,
    identity::{refresh_tokens, repo as identity_repo, service as identity_service},
    keys::{self, ActiveKeys},
    models::{entity::CreateEntity, enums::EntityKind, tenant::CreateTenant},
    state::AppState,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const SECRET: &str = "dev1_key";

fn slug(prefix: &str) -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..12])
}

/// `Config::for_tests()` with refresh tokens enabled and (by default) a
/// short access-token TTL, so tests can cheaply exercise "refresh past JWT
/// expiry" with a short sleep rather than a real 3600s wait.
fn refresh_enabled_config(access_token_expiry_secs: u64, refresh_token_expiry_secs: u64) -> Config {
    let mut cfg = Config::for_tests();
    cfg.refresh_tokens.enabled = true;
    cfg.refresh_tokens.access_token_expiry_secs = access_token_expiry_secs;
    cfg.refresh_tokens.refresh_token_expiry_secs = refresh_token_expiry_secs;
    cfg
}

async fn active_keys(pool: &PgPool) -> ActiveKeys {
    keys::rotate(pool, &Config::for_tests().signing_keys)
        .await
        .expect("rotate signing key")
}

async fn make_tenant(pool: &PgPool) -> Uuid {
    atom::tenants::repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: slug("tenant"),
            alias: Some(slug("dom")),
            tags: vec![],
            attributes: json!({}),
        },
        None,
    )
    .await
    .expect("create tenant")
    .id
}

/// A device entity with a password credential — mirrors `tests/m23_authenticate_credential.rs`'s
/// `make_device`, avoiding any email-verification path so login always
/// succeeds regardless of `dev_allow_unverified_email_login`.
async fn make_device(pool: &PgPool, tenant_id: Uuid) -> (Uuid, String) {
    let name = slug("dev");
    let device = identity_repo::create_entity(
        pool,
        CreateEntity {
            id: None,
            kind: Some(EntityKind::Device),
            profile_id: None,
            profile_version_id: None,
            name: name.clone(),
            alias: Some(slug("meter")),
            external_id: None,
            tenant_id: Some(tenant_id),
            attributes: json!({}),
        },
    )
    .await
    .expect("create device");
    identity_service::create_password(pool, device.id, SECRET)
        .await
        .expect("create password");
    (device.id, name)
}

async fn login(
    pool: &PgPool,
    keys: &ActiveKeys,
    cfg: &Config,
    identifier: &str,
) -> atom::models::session::LoginResponse {
    identity_service::login_password(pool, cfg, &keys.primary, identifier, SECRET)
        .await
        .expect("login")
}

async fn active_refresh_token_count(pool: &PgPool, session_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens WHERE session_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await
    .expect("count active refresh tokens")
}

async fn session_revoked(pool: &PgPool, session_id: Uuid) -> bool {
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(pool)
            .await
            .expect("session row");
    revoked_at.is_some()
}

#[tokio::test]
#[ignore]
async fn login_with_refresh_disabled_omits_refresh_fields_and_keeps_token_alias() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let cfg = Config::for_tests();
    assert!(!cfg.refresh_tokens.enabled);

    let (_, name) = make_device(&pool, make_tenant(&pool).await).await;
    let response = login(&pool, &keys, &cfg, &name).await;

    assert!(response.refresh_token.is_none());
    assert!(response.refresh_token_expires_at.is_none());
    assert_eq!(response.token, response.access_token);
    assert_eq!(response.expires_at, response.access_token_expires_at);

    assert_eq!(
        active_refresh_token_count(&pool, response.session_id).await,
        0,
        "disabled feature must create no refresh-token rows for this session"
    );
}

#[tokio::test]
#[ignore]
async fn login_with_refresh_enabled_returns_one_active_refresh_token() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let cfg = refresh_enabled_config(3600, 2_592_000);

    let (_, name) = make_device(&pool, make_tenant(&pool).await).await;
    let response = login(&pool, &keys, &cfg, &name).await;

    assert_eq!(response.token, response.access_token);
    let refresh_token = response.refresh_token.expect("refresh token issued");
    assert!(refresh_token.starts_with("atom_rt_"));
    // Two independent `Utc::now()` calls (one for the access-token expiry,
    // one — inside `create_session_in_tx` — for the family deadline), so
    // compare with a generous tolerance rather than exact equality.
    let expected_family_deadline =
        response.expires_at + chrono::Duration::seconds(2_592_000 - 3600);
    let actual_family_deadline = response.refresh_token_expires_at.expect("deadline");
    assert!(
        (actual_family_deadline - expected_family_deadline)
            .num_seconds()
            .abs()
            <= 5
    );
    assert_eq!(
        active_refresh_token_count(&pool, response.session_id).await,
        1
    );

    let (_, secret_bytes) = parse_refresh_token(&refresh_token).expect("parse issued token");
    let secret_hash: Vec<u8> =
        sqlx::query_scalar("SELECT secret_hash FROM refresh_tokens WHERE session_id = $1")
            .bind(response.session_id)
            .fetch_one(&pool)
            .await
            .expect("secret_hash column");
    assert_eq!(secret_hash.len(), 32, "HMAC-SHA256 digest length");
    assert_ne!(
        secret_hash,
        secret_bytes.to_vec(),
        "the raw secret must never be stored — only its keyed digest"
    );
}

#[tokio::test]
#[ignore]
async fn exchange_rotates_the_token_and_works_after_access_jwt_expiry() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let cfg = refresh_enabled_config(1, 3600);
    let signer = JwtSigner::from_key(&keys.primary).expect("signer");

    let (_, name) = make_device(&pool, make_tenant(&pool).await).await;
    let login_response = login(&pool, &keys, &cfg, &name).await;
    let original_refresh = login_response.refresh_token.clone().expect("refresh token");

    // Let the 1-second access JWT actually expire — the whole point of the
    // feature is that the refresh exchange does not need it to still be valid.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let pair = identity_service::exchange_refresh_token(&pool, &cfg, &signer, &original_refresh)
        .await
        .expect("exchange succeeds after access JWT expiry");

    assert_eq!(pair.token, pair.access_token);
    assert_eq!(pair.entity_id, login_response.entity_id);
    assert_eq!(pair.session_id, login_response.session_id);
    assert_ne!(pair.refresh_token, original_refresh);
    assert_eq!(
        pair.refresh_token_expires_at,
        login_response.refresh_token_expires_at.expect("deadline")
    );

    // Exactly one linked replacement, and the original is gone from the
    // active set (consumed, not deleted — retained for replay detection).
    assert_eq!(
        active_refresh_token_count(&pool, login_response.session_id).await,
        1
    );
    let (original_id, _) = parse_refresh_token(&original_refresh).expect("parse original");
    let (consumed_at, replaced_by): (Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>) =
        sqlx::query_as("SELECT consumed_at, replaced_by FROM refresh_tokens WHERE id = $1")
            .bind(original_id)
            .fetch_one(&pool)
            .await
            .expect("original row still present");
    assert!(consumed_at.is_some());
    let (new_id, _) = parse_refresh_token(&pair.refresh_token).expect("parse new token");
    assert_eq!(replaced_by, Some(new_id));

    // The previous refresh token is now unusable.
    let reuse = identity_service::exchange_refresh_token(&pool, &cfg, &signer, &original_refresh)
        .await
        .expect_err("consumed token must be rejected");
    assert!(reuse.to_string().contains("invalid refresh token"));
}

#[tokio::test]
#[ignore]
async fn reuse_of_a_consumed_token_revokes_the_session_and_its_live_descendant() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let cfg = refresh_enabled_config(3600, 7200);
    let signer = JwtSigner::from_key(&keys.primary).expect("signer");

    let (_, name) = make_device(&pool, make_tenant(&pool).await).await;
    let login_response = login(&pool, &keys, &cfg, &name).await;
    let original_refresh = login_response.refresh_token.expect("refresh token");

    let pair = identity_service::exchange_refresh_token(&pool, &cfg, &signer, &original_refresh)
        .await
        .expect("first exchange succeeds");
    assert!(!session_revoked(&pool, login_response.session_id).await);

    // Replay the already-consumed original: this must revoke the whole
    // family, including the token the exchange above just minted.
    let replay = identity_service::exchange_refresh_token(&pool, &cfg, &signer, &original_refresh)
        .await
        .expect_err("replay must be rejected");
    assert!(replay.to_string().contains("invalid refresh token"));
    assert!(session_revoked(&pool, login_response.session_id).await);
    assert_eq!(
        active_refresh_token_count(&pool, login_response.session_id).await,
        0
    );

    let descendant_dead =
        identity_service::exchange_refresh_token(&pool, &cfg, &signer, &pair.refresh_token)
            .await
            .expect_err("the winner's replacement must also be dead now");
    assert!(descendant_dead
        .to_string()
        .contains("invalid refresh token"));
}

#[tokio::test]
#[ignore]
async fn concurrent_exchange_of_the_same_token_yields_exactly_one_success() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let cfg = refresh_enabled_config(3600, 7200);
    let signer_a = JwtSigner::from_key(&keys.primary).expect("signer a");
    let signer_b = JwtSigner::from_key(&keys.primary).expect("signer b");

    let (_, name) = make_device(&pool, make_tenant(&pool).await).await;
    let login_response = login(&pool, &keys, &cfg, &name).await;
    let refresh_token = login_response.refresh_token.expect("refresh token");

    let (first, second) = tokio::join!(
        identity_service::exchange_refresh_token(&pool, &cfg, &signer_a, &refresh_token),
        identity_service::exchange_refresh_token(&pool, &cfg, &signer_b, &refresh_token),
    );
    let successes = [&first, &second].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "exactly one of two concurrent exchanges of the same token must succeed"
    );

    // The loser observed replay (it blocked on the row lock, then saw
    // `consumed_at` already set) — this is required, not incidental: it
    // revokes the session and the winner's freshly-minted replacement too,
    // so no two active descendants can ever coexist.
    assert!(session_revoked(&pool, login_response.session_id).await);
    assert_eq!(
        active_refresh_token_count(&pool, login_response.session_id).await,
        0
    );
}

#[tokio::test]
#[ignore]
async fn logout_revokes_the_family_and_expired_family_is_rejected() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let signer = JwtSigner::from_key(&keys.primary).expect("signer");

    // Logout (session revocation) blocks exchange even though the token
    // itself was never consumed.
    let logout_cfg = refresh_enabled_config(3600, 7200);
    let (_, logout_name) = make_device(&pool, make_tenant(&pool).await).await;
    let logout_login = login(&pool, &keys, &logout_cfg, &logout_name).await;
    let mut tx = pool.begin().await.expect("begin");
    identity_repo::revoke_session_in_tx(&mut tx, logout_login.session_id)
        .await
        .expect("revoke session");
    tx.commit().await.expect("commit revoke");
    let after_logout = identity_service::exchange_refresh_token(
        &pool,
        &logout_cfg,
        &signer,
        &logout_login.refresh_token.expect("refresh token"),
    )
    .await
    .expect_err("revoked session must reject exchange");
    assert!(after_logout.to_string().contains("invalid refresh token"));

    // A family whose absolute deadline has passed is rejected even though
    // the token itself was never consumed or revoked.
    let expired_cfg = refresh_enabled_config(1, 1);
    let (_, expired_name) = make_device(&pool, make_tenant(&pool).await).await;
    let expired_login = login(&pool, &keys, &expired_cfg, &expired_name).await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let expired = identity_service::exchange_refresh_token(
        &pool,
        &expired_cfg,
        &signer,
        &expired_login.refresh_token.expect("refresh token"),
    )
    .await
    .expect_err("expired family must reject exchange");
    assert!(expired.to_string().contains("invalid refresh token"));

    // An inactive entity blocks exchange too.
    let inactive_cfg = refresh_enabled_config(3600, 7200);
    let (inactive_id, inactive_name) = make_device(&pool, make_tenant(&pool).await).await;
    let inactive_login = login(&pool, &keys, &inactive_cfg, &inactive_name).await;
    sqlx::query("UPDATE entities SET status = 'inactive' WHERE id = $1")
        .bind(inactive_id)
        .execute(&pool)
        .await
        .expect("deactivate entity");
    let inactive = identity_service::exchange_refresh_token(
        &pool,
        &inactive_cfg,
        &signer,
        &inactive_login.refresh_token.expect("refresh token"),
    )
    .await
    .expect_err("inactive entity must reject exchange");
    assert!(inactive.to_string().contains("invalid refresh token"));
}

#[tokio::test]
#[ignore]
async fn refresh_token_is_rejected_as_a_bearer_credential() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let cfg = refresh_enabled_config(3600, 7200);

    let (_, name) = make_device(&pool, make_tenant(&pool).await).await;
    let login_response = login(&pool, &keys, &cfg, &name).await;
    let refresh_token = login_response.refresh_token.expect("refresh token");

    let state = AppState::new(pool.clone(), cfg, keys, None);
    let err = authenticate_token(&state, &refresh_token)
        .await
        .expect_err("refresh token must not authenticate as a Bearer token");
    assert!(err.to_string().contains("invalid credential"));
}

#[tokio::test]
#[ignore]
async fn purge_expired_only_removes_rows_past_the_family_deadline() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;

    let expired_cfg = refresh_enabled_config(1, 1);
    let (_, expired_name) = make_device(&pool, make_tenant(&pool).await).await;
    let expired_login = login(&pool, &keys, &expired_cfg, &expired_name).await;

    let live_cfg = refresh_enabled_config(3600, 7200);
    let (_, live_name) = make_device(&pool, make_tenant(&pool).await).await;
    let live_login = login(&pool, &keys, &live_cfg, &live_name).await;

    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let deleted = refresh_tokens::purge_expired(&pool, 1000)
        .await
        .expect("purge expired refresh tokens");
    assert!(deleted >= 1);

    assert_eq!(
        active_refresh_token_count(&pool, expired_login.session_id).await,
        0,
        "expired family's row must be gone"
    );
    assert_eq!(
        active_refresh_token_count(&pool, live_login.session_id).await,
        1,
        "live family's row must survive"
    );
}
