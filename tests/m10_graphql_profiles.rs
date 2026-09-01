//! GraphQL profile and profile-backed entity tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m10_graphql_profiles -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::build_schema,
    identity::profile_repo,
    keys::{ActiveKeys, LoadedKey},
    models::profile::{CreateProfile, CreateProfileVersion},
    state::AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn seeded_client_profile(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM profiles WHERE object_kind = 'entity' AND kind = 'device' AND key = 'client' AND tenant_id IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("seeded client profile")
}

async fn profile_with_schema(pool: &PgPool, json_schema: Value) -> Uuid {
    let suffix = Uuid::new_v4();
    let profile = profile_repo::create_profile(
        pool,
        CreateProfile {
            tenant_id: None,
            object_kind: "entity".into(),
            kind: "device".into(),
            key: format!("graphql-schema-device-{suffix}"),
            display_name: "GraphQL Schema Device".into(),
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

fn state(pool: PgPool) -> AppState {
    let config = Config::for_tests();
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        config,
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

#[tokio::test]
#[ignore]
async fn profiles_query_returns_seeded_entity_profiles() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(
            r#"
            {
              profiles(objectKind: "entity", kind: "device") {
                items { id key displayName }
                total
              }
            }
            "#,
        ))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let items = data["profiles"]["items"].as_array().expect("items array");
    assert!(items.iter().any(|item| item["key"] == "client"));
}

#[tokio::test]
#[ignore]
async fn profile_versions_query_returns_seeded_version() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(format!(
            r#"
            {{
              profileVersions(profileId: "{profile_id}") {{
                id
                version
                jsonSchema
                uiSchema
                status
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let versions = data["profileVersions"].as_array().expect("versions array");
    assert_eq!(versions[0]["version"], 1);
    assert_eq!(versions[0]["status"], "active");
}

#[tokio::test]
#[ignore]
async fn unauthorized_profile_lookup_does_not_reveal_id_existence() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;
    let caller_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')",
    )
    .bind(caller_id)
    .bind(format!("profile-unprivileged-{caller_id}"))
    .execute(&pool)
    .await
    .expect("insert unprivileged caller");
    let schema = build_schema(state(pool));

    let existing = schema
        .execute(authed_as(
            caller_id,
            format!(r#"{{ profile(id: "{profile_id}") {{ id }} }}"#),
        ))
        .await;
    let missing = schema
        .execute(authed_as(
            caller_id,
            format!(r#"{{ profile(id: "{}") {{ id }} }}"#, Uuid::new_v4()),
        ))
        .await;

    assert_eq!(existing.errors.len(), 1);
    assert_eq!(missing.errors.len(), 1);
    assert_eq!(existing.errors[0].message, missing.errors[0].message);
}

#[tokio::test]
#[ignore]
async fn update_profile_mutation_updates_metadata_and_status() {
    let pool = common::pool().await;
    let profile_id = profile_with_schema(&pool, json!({})).await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              updateProfile(
                id: "{profile_id}",
                input: {{
                  displayName: "Updated GraphQL Profile",
                  description: "updated through GraphQL",
                  status: "deprecated"
                }}
              ) {{
                id
                displayName
                description
                status
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let profile = &response.data.into_json().expect("json data")["updateProfile"];
    assert_eq!(profile["id"], profile_id.to_string());
    assert_eq!(profile["displayName"], "Updated GraphQL Profile");
    assert_eq!(profile["description"], "updated through GraphQL");
    assert_eq!(profile["status"], "deprecated");
}

#[tokio::test]
#[ignore]
async fn update_profile_version_mutation_updates_status_only() {
    let pool = common::pool().await;
    let schema_body = json!({"type": "object"});
    let profile_id = profile_with_schema(&pool, schema_body.clone()).await;
    let versions = profile_repo::list_profile_versions(&pool, profile_id)
        .await
        .expect("list versions");
    let version_id = versions[0].id;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              updateProfileVersion(
                id: "{version_id}",
                input: {{ status: "deprecated" }}
              ) {{
                id
                status
                jsonSchema
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let version = &response.data.into_json().expect("json data")["updateProfileVersion"];
    assert_eq!(version["id"], version_id.to_string());
    assert_eq!(version["status"], "deprecated");
    // jsonSchema stays exactly what it was created with — updateProfileVersion
    // has no way to touch it, since entities already bound to this version
    // validate writes against it.
    assert_eq!(version["jsonSchema"], schema_body);
}

#[tokio::test]
#[ignore]
async fn update_profile_version_mutation_rejects_unknown_status() {
    let pool = common::pool().await;
    let profile_id = profile_with_schema(&pool, json!({})).await;
    let versions = profile_repo::list_profile_versions(&pool, profile_id)
        .await
        .expect("list versions");
    let version_id = versions[0].id;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              updateProfileVersion(
                id: "{version_id}",
                input: {{ status: "not-a-status" }}
              ) {{
                id
              }}
            }}
            "#
        )))
        .await;

    assert!(!response.errors.is_empty());
    assert!(response.errors[0]
        .message
        .contains("status must be draft, active, deprecated, or disabled"));
}

#[tokio::test]
#[ignore]
async fn create_entity_with_profile_id_derives_kind() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-meter-{}", Uuid::new_v4());

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createEntity(input: {{
                profileId: "{profile_id}",
                name: "{name}",
                attributes: {{ serial_no: "WM-001" }}
              }}) {{
                id
                kind
                profileId
                profileVersionId
                attributes
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let entity = &response.data.into_json().expect("json data")["createEntity"];
    assert_eq!(entity["kind"], "device");
    assert_eq!(entity["profileId"], profile_id.to_string());
    assert!(entity["profileVersionId"].as_str().is_some());
    assert_eq!(entity["attributes"]["serial_no"], "WM-001");
}

#[tokio::test]
#[ignore]
async fn create_entity_with_conflicting_kind_and_profile_returns_error() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-conflict-{}", Uuid::new_v4());

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createEntity(input: {{
                profileId: "{profile_id}",
                kind: human,
                name: "{name}",
                attributes: {{}}
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;

    assert!(!response.errors.is_empty());
    assert!(response.errors[0].message.contains("conflicts"));
}

#[tokio::test]
#[ignore]
async fn create_entity_with_schema_validation_failure_returns_error() {
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
    let schema = build_schema(state(pool));
    let name = format!("graphql-schema-fail-{}", Uuid::new_v4());

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createEntity(input: {{
                profileId: "{profile_id}",
                name: "{name}",
                attributes: {{}}
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;

    assert!(!response.errors.is_empty());
    assert!(response.errors[0].message.contains("schema validation"));
}
