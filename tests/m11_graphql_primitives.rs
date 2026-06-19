//! GraphQL generic Atom primitive tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m11_graphql_primitives -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::build_schema,
    identity::{profile_repo, service},
    keys,
    models::{
        profile::{CreateProfile, CreateProfileVersion},
        tenant::Tenant,
    },
    state::AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn state(pool: PgPool) -> AppState {
    let config = Config::for_tests();
    keys::bootstrap_if_needed(&pool, &config.signing_keys)
        .await
        .expect("bootstrap signing keys");
    let active_keys = keys::load_active_keys(&pool, &config.signing_keys)
        .await
        .expect("load signing keys");
    AppState::new(pool, config, active_keys, None)
}

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
    })
}

async fn create_human(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let name = format!("graphql-human-{id}");
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'human', $2, 'active')")
        .bind(id)
        .bind(&name)
        .execute(pool)
        .await
        .expect("insert human");
    (id, name)
}

async fn create_device(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("graphql-device-{id}");
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'device', $2, 'active')",
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await
    .expect("insert device");
    id
}

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
            key: format!("graphql-primitive-device-{suffix}"),
            display_name: "GraphQL Primitive Device".into(),
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

async fn delete_tenant_row(pool: &PgPool, tenant_id: Uuid) {
    let _ = sqlx::query_as::<_, Tenant>("DELETE FROM tenants WHERE id = $1 RETURNING id, name, alias, status, tags, attributes, created_by, updated_by, created_at, updated_at")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await;
}

#[tokio::test]
#[ignore]
async fn login_mutation_returns_token() {
    let pool = common::pool().await;
    let (entity_id, name) = create_human(&pool).await;
    service::create_password(&pool, entity_id, "test-password-123")
        .await
        .expect("create password");
    let schema = build_schema(state(pool).await);

    let response = schema
        .execute(Request::new(format!(
            r#"
            mutation {{
              login(input: {{
                identifier: "{name}",
                secret: "test-password-123"
              }}) {{
                token
                entityId
                sessionId
                expiresAt
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let login = &response.data.into_json().expect("json data")["login"];
    assert_eq!(login["entityId"], entity_id.to_string());
    assert!(login["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert!(login["sessionId"].as_str().is_some());
    assert!(login["expiresAt"].as_str().is_some());
}

#[tokio::test]
#[ignore]
async fn login_mutation_accepts_entity_uuid_identifier() {
    let pool = common::pool().await;
    let (entity_id, _) = create_human(&pool).await;
    service::create_password(&pool, entity_id, "test-password-123")
        .await
        .expect("create password");
    let schema = build_schema(state(pool).await);

    let response = schema
        .execute(Request::new(format!(
            r#"
            mutation {{
              login(input: {{
                identifier: "{entity_id}",
                secret: "test-password-123"
              }}) {{
                token
                entityId
                sessionId
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let login = &response.data.into_json().expect("json data")["login"];
    assert_eq!(login["entityId"], entity_id.to_string());
    assert!(login["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert!(login["sessionId"].as_str().is_some());
}

#[tokio::test]
#[ignore]
async fn create_password_allows_legacy_device_secret_and_login_by_uuid() {
    let pool = common::pool().await;
    let entity_id = create_device(&pool).await;
    service::create_password(&pool, entity_id, "device1")
        .await
        .expect("create device password");
    let schema = build_schema(state(pool).await);

    let response = schema
        .execute(Request::new(format!(
            r#"
            mutation {{
              login(input: {{
                identifier: "{entity_id}",
                secret: "device1"
              }}) {{
                token
                entityId
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let login = &response.data.into_json().expect("json data")["login"];
    assert_eq!(login["entityId"], entity_id.to_string());
    assert!(login["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
}

#[tokio::test]
#[ignore]
async fn create_list_and_get_tenant() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool.clone()).await);
    let name = format!("graphql-tenant-{}", Uuid::new_v4());
    let alias = format!("graphql-alias-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createTenant(input: {{
                name: "{name}",
                alias: "{alias}",
                tags: ["graphql"],
                attributes: {{ source: "graphql" }}
              }}) {{
                id
                name
                alias
                status
                tags
                attributes
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let tenant = &created.data.into_json().expect("json data")["createTenant"];
    let tenant_id = tenant["id"].as_str().expect("tenant id").to_owned();
    assert_eq!(tenant["name"], name);
    assert_eq!(tenant["status"], "active");

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              tenants(name: "{name}") {{
                items {{ id name alias }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert!(data["tenants"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .any(|item| item["id"] == tenant_id));

    let fetched = schema
        .execute(authed(format!(
            r#"
            {{
              tenant(id: "{tenant_id}") {{
                id
                name
                alias
              }}
            }}
            "#
        )))
        .await;
    assert!(fetched.errors.is_empty(), "{:?}", fetched.errors);
    assert_eq!(
        fetched.data.into_json().expect("json data")["tenant"]["id"],
        tenant_id
    );

    let cleared = schema
        .execute(authed(format!(
            r#"
            mutation {{
              updateTenant(id: "{tenant_id}", input: {{ alias: null }}) {{
                id
                alias
              }}
            }}
            "#
        )))
        .await;
    assert!(cleared.errors.is_empty(), "{:?}", cleared.errors);
    assert!(
        cleared.data.into_json().expect("json data")["updateTenant"]["alias"].is_null(),
        "explicit GraphQL null must clear an existing alias"
    );

    delete_tenant_row(&pool, tenant_id.parse().expect("tenant uuid")).await;
}

#[tokio::test]
#[ignore]
async fn create_list_and_get_resource_channel() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool).await);
    let name = format!("graphql-channel-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createResource(input: {{
                kind: "channel",
                name: "{name}",
                attributes: {{ source: "graphql" }}
              }}) {{
                id
                kind
                name
                attributes
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let resource = &created.data.into_json().expect("json data")["createResource"];
    let resource_id = resource["id"].as_str().expect("resource id").to_owned();
    assert_eq!(resource["kind"], "channel");
    assert_eq!(resource["name"], name);

    let listed = schema
        .execute(authed(
            r#"
            {
              resources(kind: "channel") {
                items { id kind name }
                total
              }
            }
            "#,
        ))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert!(data["resources"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .any(|item| item["id"] == resource_id));

    let fetched = schema
        .execute(authed(format!(
            r#"
            {{
              resource(id: "{resource_id}") {{
                id
                kind
                name
              }}
            }}
            "#
        )))
        .await;
    assert!(fetched.errors.is_empty(), "{:?}", fetched.errors);
    assert_eq!(
        fetched.data.into_json().expect("json data")["resource"]["id"],
        resource_id
    );
}

#[tokio::test]
#[ignore]
async fn create_entity_with_profile_still_derives_kind() {
    let pool = common::pool().await;
    let profile_id = seeded_client_profile(&pool).await;
    let schema = build_schema(state(pool).await);
    let name = format!("graphql-client-{}", Uuid::new_v4());

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
async fn create_entity_with_kind_enum_still_works() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool).await);
    let name = format!("graphql-service-{}", Uuid::new_v4());

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createEntity(input: {{
                kind: service,
                name: "{name}",
                attributes: {{ role: "worker" }}
              }}) {{
                id
                kind
                name
                attributes
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let entity = &response.data.into_json().expect("json data")["createEntity"];
    assert_eq!(entity["kind"], "service");
    assert_eq!(entity["name"], name);
    assert_eq!(entity["attributes"]["role"], "worker");
}

#[tokio::test]
#[ignore]
async fn create_entity_schema_validation_failure_still_errors() {
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
    let schema = build_schema(state(pool).await);
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
