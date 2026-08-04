//! Bootstrap-managed entities, credentials and access tokens.
//!
//! Covers migration 005: entities and credentials created from the bootstrap
//! YAML are stamped `managed_by='config'`, blocking API mutation and hiding
//! credentials from list/read responses.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m27_config_managed_identity -- --ignored
//! ```

mod common;

use atom::auth::make_api_key;
use atom::bootstrap::{apply, BootstrapConfig, BootstrapCredential, BootstrapEntity};
use atom::config::Config;
use atom::identity::{access_tokens, repo, service};
use atom::models::entity::UpdateEntity;
use atom::models::enums::{EntityKind, EntityStatus};
use common::pool;
use uuid::Uuid;

fn service_entity(id: Uuid, credentials: Vec<BootstrapCredential>) -> BootstrapConfig {
    BootstrapConfig {
        entities: vec![BootstrapEntity {
            id,
            kind: EntityKind::Service,
            name: format!("cfg-service-{id}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: None,
            credentials,
        }],
        ..Default::default()
    }
}

async fn managed_by_entity(pool: &sqlx::PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT managed_by FROM entities WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("entity managed_by lookup")
}

async fn managed_by_credential(pool: &sqlx::PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT managed_by FROM credentials WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("credential managed_by lookup")
}

fn bootstrap_token() -> (Uuid, String) {
    let cred_id = Uuid::new_v4();
    let mut secret = [0u8; 32];
    for (i, b) in secret.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(1);
    }
    (cred_id, make_api_key(cred_id, &secret))
}

#[tokio::test]
#[ignore]
async fn bootstrap_entity_is_stamped_and_rejects_api_mutations() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let entity_id = Uuid::new_v4();
    let cfg = service_entity(entity_id, vec![]);

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    assert_eq!(
        managed_by_entity(&p, entity_id).await.as_deref(),
        Some("config")
    );

    let err = repo::update_entity(
        &p,
        entity_id,
        UpdateEntity {
            name: Some("hijacked".to_string()),
            kind: None,
            alias: None,
            tenant_id: None,
            profile_id: None,
            profile_version_id: None,
            status: None,
            attributes: None,
        },
    )
    .await
    .expect_err("update must be rejected");
    assert!(
        format!("{err:?}").contains("bootstrap config"),
        "unexpected: {err:?}"
    );

    let err = repo::delete_entity(&p, entity_id, None)
        .await
        .expect_err("delete must be rejected");
    assert!(
        format!("{err:?}").contains("bootstrap config"),
        "unexpected: {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_access_token_is_hidden_and_rejects_revoke() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let entity_id = Uuid::new_v4();
    let (cred_id, token) = bootstrap_token();
    let cfg = service_entity(
        entity_id,
        vec![BootstrapCredential::AccessToken {
            token: token.clone(),
            name: "journal".to_string(),
            description: Some("bootstrap".to_string()),
        }],
    );

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    // The credential row exists and is stamped.
    assert_eq!(
        managed_by_credential(&p, cred_id).await.as_deref(),
        Some("config")
    );

    // list_credentials must NOT surface it.
    let creds = service::list_credentials(&p, entity_id)
        .await
        .expect("list");
    assert!(
        creds.iter().all(|c| c.id != cred_id),
        "bootstrap-managed credential leaked to list_credentials"
    );

    // list_access_tokens must NOT surface it either.
    let (tokens, total) = access_tokens::list_access_tokens(
        &p,
        entity_id,
        access_tokens::ListAccessTokens {
            status: None,
            limit: 100,
            offset: 0,
        },
    )
    .await
    .expect("list access tokens");
    assert_eq!(total, 0, "bootstrap tokens should not appear in count");
    assert!(
        tokens.is_empty(),
        "bootstrap tokens should not appear in list"
    );

    // Revoke must return not_found — the API pretends the row does not exist.
    let err = access_tokens::revoke_access_token(&p, entity_id, cred_id)
        .await
        .expect_err("revoke must be rejected");
    assert!(
        format!("{err:?}").contains("not found") || format!("{err:?}").contains("NotFound"),
        "unexpected: {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_access_token_is_idempotent() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let entity_id = Uuid::new_v4();
    let (cred_id, token) = bootstrap_token();
    let cfg = service_entity(
        entity_id,
        vec![BootstrapCredential::AccessToken {
            token,
            name: "journal".to_string(),
            description: None,
        }],
    );

    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    apply(&p, &signing_keys, &cfg).await.expect("second apply");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&p)
        .await
        .expect("count credential");
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore]
async fn bootstrap_access_token_authenticates_at_runtime() {
    // The whole point of bootstrap tokens is that services authenticate with
    // them at runtime — so the managed_by hide must NOT reach the auth path.
    // Verify the auth lookup ignores managed_by by asking the same query the
    // auth path runs and confirming the row is visible for authentication.
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let entity_id = Uuid::new_v4();
    let (cred_id, _token) = bootstrap_token();
    let cfg = service_entity(
        entity_id,
        vec![BootstrapCredential::AccessToken {
            token: _token,
            name: "journal".to_string(),
            description: None,
        }],
    );

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    let entity_ok: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT c.entity_id
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.id = $1 AND c.kind = 'access_token' AND c.status = 'active'
             AND e.deleted_at IS NULL"#,
    )
    .bind(cred_id)
    .fetch_optional(&p)
    .await
    .expect("auth-path lookup");
    assert_eq!(entity_ok, Some(entity_id));
}

#[tokio::test]
#[ignore]
async fn api_created_entity_and_credential_are_not_stamped() {
    // Sanity check: only bootstrap-planted rows carry the flag; normal API
    // creations remain fully mutable and visible.
    let p = pool().await;

    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')",
    )
    .bind(entity_id)
    .bind(format!("runtime-{entity_id}"))
    .execute(&p)
    .await
    .expect("insert entity");
    assert!(managed_by_entity(&p, entity_id).await.is_none());

    let cred_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', 'x')",
    )
    .bind(cred_id)
    .bind(entity_id)
    .execute(&p)
    .await
    .expect("insert credential");
    assert!(managed_by_credential(&p, cred_id).await.is_none());

    // The API mutation guard lets these through.
    let creds = service::list_credentials(&p, entity_id)
        .await
        .expect("list");
    assert!(creds.iter().any(|c| c.id == cred_id));
}
