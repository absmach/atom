//! Config-file bootstrap integration tests (issue #27).
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m25_config_bootstrap -- --ignored
//! ```

mod common;

use atom::bootstrap::{apply, BootstrapConfig, BootstrapCredential, BootstrapEntity};
use atom::config::Config;
use atom::models::enums::{EntityKind, EntityStatus};
use common::pool;
use uuid::Uuid;

async fn count_active_credentials(pool: &sqlx::PgPool, entity_id: Uuid, kind: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active'",
    )
    .bind(entity_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .expect("count credentials")
}

fn sample_config(human: Uuid, service: Uuid) -> BootstrapConfig {
    BootstrapConfig {
        entities: vec![
            BootstrapEntity {
                id: human,
                kind: EntityKind::Human,
                name: format!("bootstrap-human-{human}"),
                alias: None,
                status: EntityStatus::Active,
                attributes: Some(serde_json::json!({ "system": true })),
                credentials: vec![BootstrapCredential::Password {
                    secret: "bootstrap-pw-123456".to_string(),
                }],
            },
            BootstrapEntity {
                id: service,
                kind: EntityKind::Service,
                name: format!("bootstrap-service-{service}"),
                alias: None,
                status: EntityStatus::Active,
                attributes: None,
                credentials: vec![BootstrapCredential::SharedKey {
                    key: "bootstrap-machine-secret".to_string(),
                    description: Some("integration test".to_string()),
                }],
            },
        ],
    }
}

#[tokio::test]
#[ignore]
async fn bootstrap_creates_entities_and_credentials() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();
    let cfg = sample_config(human, service);

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    let human_kind: String = sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
        .bind(human)
        .fetch_one(&p)
        .await
        .expect("human entity exists");
    assert_eq!(human_kind, "human");

    let service_kind: String = sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
        .bind(service)
        .fetch_one(&p)
        .await
        .expect("service entity exists");
    assert_eq!(service_kind, "service");

    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
    assert_eq!(count_active_credentials(&p, service, "shared_key").await, 1);
}

#[tokio::test]
#[ignore]
async fn bootstrap_is_idempotent() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();
    let cfg = sample_config(human, service);

    // Apply twice; the second run must not create duplicate rows.
    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    apply(&p, &signing_keys, &cfg).await.expect("second apply");

    let entity_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entities WHERE id = $1")
        .bind(human)
        .fetch_one(&p)
        .await
        .expect("count human");
    assert_eq!(entity_count, 1);

    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
    assert_eq!(count_active_credentials(&p, service, "shared_key").await, 1);
}

#[tokio::test]
#[ignore]
async fn bootstrap_does_not_clobber_existing_credentials() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();

    apply(&p, &signing_keys, &sample_config(human, service))
        .await
        .expect("first apply");

    let original_hash: String =
        sqlx::query_scalar("SELECT secret_hash FROM credentials WHERE entity_id = $1")
            .bind(human)
            .fetch_one(&p)
            .await
            .expect("password hash");

    // A second run declaring a different secret for the same entity must not
    // rotate the existing credential — bootstrap only fills in what is missing.
    let mut changed = sample_config(human, service);
    changed.entities[0].credentials = vec![BootstrapCredential::Password {
        secret: "a-totally-different-secret".to_string(),
    }];
    apply(&p, &signing_keys, &changed)
        .await
        .expect("second apply");

    let after_hash: String =
        sqlx::query_scalar("SELECT secret_hash FROM credentials WHERE entity_id = $1")
            .bind(human)
            .fetch_one(&p)
            .await
            .expect("password hash after");
    assert_eq!(
        original_hash, after_hash,
        "existing password must be preserved"
    );
    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
}
