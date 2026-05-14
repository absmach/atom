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
    config::{Config, ADMIN_ENTITY_ID},
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
    let config = Config {
        database_url: "postgres://atom:atom@localhost/atom_test".into(),
        listen_addr: "127.0.0.1:0".into(),
        grpc_addr: "127.0.0.1:0".into(),
        jwt_expiry_secs: 3600,
        jwt_issuer: "http://localhost:8080".to_string(),
        jwt_audience: "magistrala".to_string(),
        admin_entity_id: ADMIN_ENTITY_ID,
        admin_secret: None,
        service_secret: None,
        service_entity_id: atom::config::SERVICE_ENTITY_ID,
        signup_enabled: false,
        dev_allow_unverified_email_login: false,
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
    };
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
    )
}

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
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
