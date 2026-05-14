//! Profile-backed entity tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m9_profiles -- --ignored
//! ```

mod common;

use atom::{
    error::AppError,
    identity::{profile_repo, repo},
    models::{
        entity::CreateEntity,
        enums::EntityKind,
        profile::{CreateProfile, CreateProfileVersion},
    },
};
use serde_json::{json, Value};
use uuid::Uuid;

async fn seeded_client_profile(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM profiles WHERE object_kind = 'entity' AND kind = 'device' AND key = 'client' AND tenant_id IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("seeded client profile")
}

async fn profile_with_schema(pool: &sqlx::PgPool, json_schema: Value) -> Uuid {
    let suffix = Uuid::new_v4();
    let profile = profile_repo::create_profile(
        pool,
        CreateProfile {
            tenant_id: None,
            object_kind: "entity".into(),
            kind: "device".into(),
            key: format!("serial-device-{suffix}"),
            display_name: "Serial Device".into(),
            description: None,
            status: None,
        },
    )
    .await
    .expect("create profile");

    profile_repo::create_profile_version(
        pool,
        profile.id,
        CreateProfileVersion {
            version: 1,
            json_schema,
            ui_schema: json!({}),
            status: None,
        },
    )
    .await
    .expect("create profile version");

    profile.id
}

fn entity_request(name: String) -> CreateEntity {
    CreateEntity {
        id: None,
        kind: None,
        profile_id: None,
        profile_version_id: None,
        name,
        tenant_id: None,
        attributes: json!({}),
    }
}

#[tokio::test]
#[ignore]
async fn create_entity_using_profile_id_derives_kind_and_version() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;

    let mut req = entity_request(format!("m9-profile-only-{}", Uuid::new_v4()));
    req.profile_id = Some(profile_id);

    let entity = repo::create_entity(&pool, req)
        .await
        .expect("create entity");

    assert_eq!(entity.kind, EntityKind::Device);
    assert_eq!(entity.profile_id, Some(profile_id));
    assert!(entity.profile_version_id.is_some());
}

#[tokio::test]
#[ignore]
async fn create_entity_rejects_profile_kind_conflict() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;

    let mut req = entity_request(format!("m9-profile-conflict-{}", Uuid::new_v4()));
    req.profile_id = Some(profile_id);
    req.kind = Some(EntityKind::Human);

    match repo::create_entity(&pool, req).await {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("conflicts")),
        other => panic!("expected bad request, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn profile_json_schema_validation_is_enforced() {
    let pool = common::pool().await;
    let profile_id = profile_with_schema(
        &pool,
        json!({
            "type": "object",
            "required": ["serial_no"],
            "properties": {
                "serial_no": { "type": "string" }
            }
        }),
    )
    .await;

    let mut missing = entity_request(format!("m9-missing-serial-{}", Uuid::new_v4()));
    missing.profile_id = Some(profile_id);
    match repo::create_entity(&pool, missing).await {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("schema validation")),
        other => panic!("expected schema validation failure, got {other:?}"),
    }

    let mut present = entity_request(format!("m9-present-serial-{}", Uuid::new_v4()));
    present.profile_id = Some(profile_id);
    present.attributes = json!({"serial_no": "SN-001"});
    let entity = repo::create_entity(&pool, present)
        .await
        .expect("create schema-valid entity");

    assert_eq!(entity.kind, EntityKind::Device);
    assert_eq!(entity.profile_id, Some(profile_id));
}

#[tokio::test]
#[ignore]
async fn create_entity_with_kind_only_remains_supported() {
    let pool = common::pool().await;

    let mut req = entity_request(format!("m9-kind-only-{}", Uuid::new_v4()));
    req.kind = Some(EntityKind::Service);

    let entity = repo::create_entity(&pool, req)
        .await
        .expect("create entity");

    assert_eq!(entity.kind, EntityKind::Service);
    assert_eq!(entity.profile_id, None);
    assert_eq!(entity.profile_version_id, None);
}
