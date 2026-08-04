//! Bootstrap-managed capabilities, applicability and assignment rules.
//!
//! Covers the `managed_by='config'` marker written by the bootstrap loader and
//! the API guard that refuses to mutate rows carrying it.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m26_config_managed_capabilities -- --ignored
//! ```

mod common;

use atom::authz::repo;
use atom::bootstrap::{
    apply, BootstrapActionAssignmentRule, BootstrapCapability, BootstrapCapabilityApplicability,
    BootstrapConfig,
};
use atom::config::Config;
use atom::models::capability::{CapabilityApplicabilityInput, CreateCapability, UpdateCapability};
use atom::models::enums::{ActionAssignmentDecision, EntityKind, ObjectKind};
use common::pool;
use uuid::Uuid;

fn capability_config(name: &str, object_type: &str) -> BootstrapConfig {
    BootstrapConfig {
        capabilities: vec![BootstrapCapability {
            name: name.to_string(),
            description: Some(format!("bootstrap {name}")),
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Resource,
                object_type: Some(object_type.to_string()),
            }],
        }],
        ..Default::default()
    }
}

async fn action_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("capability id lookup")
}

async fn managed_by(pool: &sqlx::PgPool, name: &str) -> Option<String> {
    sqlx::query_scalar("SELECT managed_by FROM actions WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("capability managed_by lookup")
}

#[tokio::test]
#[ignore]
async fn capability_bootstrap_stamps_managed_by_config() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap-cap-{}", Uuid::new_v4());
    let object_type = format!("resource:bootstrap-{}", Uuid::new_v4());
    let cfg = capability_config(&name, &object_type);

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    assert_eq!(managed_by(&p, &name).await.as_deref(), Some("config"));

    let app_managed: Option<String> = sqlx::query_scalar(
        r#"SELECT ca.managed_by
             FROM action_applicability ca
             JOIN actions a ON a.id = ca.action_id
            WHERE a.name = $1 AND ca.object_type = $2"#,
    )
    .bind(&name)
    .bind(&object_type)
    .fetch_one(&p)
    .await
    .expect("applicability lookup");
    assert_eq!(app_managed.as_deref(), Some("config"));
}

#[tokio::test]
#[ignore]
async fn capability_bootstrap_is_idempotent() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap-cap-{}", Uuid::new_v4());
    let object_type = format!("resource:bootstrap-{}", Uuid::new_v4());
    let cfg = capability_config(&name, &object_type);

    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    apply(&p, &signing_keys, &cfg).await.expect("second apply");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE name = $1")
        .bind(&name)
        .fetch_one(&p)
        .await
        .expect("count capabilities");
    assert_eq!(count, 1);

    let app_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
             FROM action_applicability ca
             JOIN actions a ON a.id = ca.action_id
            WHERE a.name = $1"#,
    )
    .bind(&name)
    .fetch_one(&p)
    .await
    .expect("count applicability");
    assert_eq!(app_count, 1);
}

#[tokio::test]
#[ignore]
async fn api_cannot_update_config_managed_capability() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap-cap-{}", Uuid::new_v4());
    let object_type = format!("resource:bootstrap-{}", Uuid::new_v4());
    apply(&p, &signing_keys, &capability_config(&name, &object_type))
        .await
        .expect("apply bootstrap");

    let id = action_id(&p, &name).await;
    let err = repo::update_capability(
        &p,
        id,
        UpdateCapability {
            name: None,
            description: Some("hijacked".to_string()),
            applicability: None,
        },
    )
    .await
    .expect_err("update must be rejected");
    assert!(
        format!("{err:?}").contains("bootstrap config"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn api_cannot_delete_config_managed_capability() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap-cap-{}", Uuid::new_v4());
    let object_type = format!("resource:bootstrap-{}", Uuid::new_v4());
    apply(&p, &signing_keys, &capability_config(&name, &object_type))
        .await
        .expect("apply bootstrap");

    let id = action_id(&p, &name).await;
    let err = repo::delete_capability(&p, id)
        .await
        .expect_err("delete must be rejected");
    assert!(
        format!("{err:?}").contains("bootstrap config"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn api_can_add_but_not_remove_config_managed_applicability() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap-cap-{}", Uuid::new_v4());
    let seeded_type = format!("resource:bootstrap-{}", Uuid::new_v4());
    apply(&p, &signing_keys, &capability_config(&name, &seeded_type))
        .await
        .expect("apply bootstrap");

    let id = action_id(&p, &name).await;

    // Adding a new applicability entry alongside a config-managed one is
    // allowed — API extensions are additive.
    let extra_type = format!("resource:api-{}", Uuid::new_v4());
    repo::add_capability_applicability(&p, id, "resource".to_string(), Some(extra_type.clone()))
        .await
        .expect("add applicability");

    // Removing the config-managed row must be rejected.
    let err = repo::remove_capability_applicability(
        &p,
        id,
        "resource".to_string(),
        Some(seeded_type.clone()),
    )
    .await
    .expect_err("removing config-managed applicability must be rejected");
    assert!(
        format!("{err:?}").contains("bootstrap config"),
        "unexpected error: {err:?}"
    );

    // Removing the API-added row is still allowed.
    repo::remove_capability_applicability(&p, id, "resource".to_string(), Some(extra_type))
        .await
        .expect("removing api-managed applicability is allowed");
}

#[tokio::test]
#[ignore]
async fn assignment_rule_bootstrap_stamps_managed_by_and_guards_delete() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap-cap-{}", Uuid::new_v4());
    let object_type = format!("resource:bootstrap-{}", Uuid::new_v4());

    // Bootstrap must declare the capability before the rule that references it.
    let cfg = BootstrapConfig {
        capabilities: vec![BootstrapCapability {
            name: name.clone(),
            description: None,
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Resource,
                object_type: Some(object_type.clone()),
            }],
        }],
        action_assignment_rules: vec![BootstrapActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: Some(object_type.clone()),
            decision: ActionAssignmentDecision::Allow,
            is_absolute: false,
        }],
        ..Default::default()
    };

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    let (rule_id, rule_managed_by): (Uuid, Option<String>) = sqlx::query_as(
        r#"SELECT id, managed_by
             FROM action_assignment_rules
            WHERE entity_kind = 'device'
              AND action_name = $1"#,
    )
    .bind(&name)
    .fetch_one(&p)
    .await
    .expect("rule lookup");
    assert_eq!(rule_managed_by.as_deref(), Some("config"));

    let err = repo::delete_action_assignment_rule(&p, rule_id)
        .await
        .expect_err("delete must be rejected");
    assert!(
        format!("{err:?}").contains("bootstrap config"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn api_created_capability_stays_api_managed() {
    // Sanity check: rows created via the API must not accidentally be stamped
    // as config-managed, so their normal edit/delete paths still work.
    let p = pool().await;
    let name = format!("api-cap-{}", Uuid::new_v4());
    let cap = repo::create_capability(
        &p,
        CreateCapability {
            name: name.clone(),
            description: Some("api-created".to_string()),
            applicability: Some(vec![CapabilityApplicabilityInput {
                object_kind: "resource".to_string(),
                object_type: Some(format!("resource:api-{}", Uuid::new_v4())),
            }]),
        },
    )
    .await
    .expect("create capability");

    assert!(managed_by(&p, &name).await.is_none());
    repo::delete_capability(&p, cap.id)
        .await
        .expect("delete api-managed capability");
}
