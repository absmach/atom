//! GraphQL generic identity operation tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m12_graphql_identity -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::build_schema,
    identity::service as identity_service,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use sqlx::PgPool;
use uuid::Uuid;

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
    })
}

async fn entity(pool: &PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("graphql-identity-{kind}-{id}"))
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

#[tokio::test]
#[ignore]
async fn create_group_returns_group() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-group-{}", Uuid::new_v4());

    let missing_type = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createGroup(input: {{
                name: "{name}-missing"
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(
        missing_type
            .errors
            .iter()
            .any(|err| err.message.contains("groupType is required")),
        "{:?}",
        missing_type.errors
    );

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createGroup(input: {{
                name: "{name}",
                groupType: "object",
                description: "GraphQL group"
              }}) {{
                id
                name
                groupType
                tenantId
                description
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let group = &response.data.into_json().expect("json data")["createGroup"];
    assert_eq!(group["name"], name);
    assert_eq!(group["groupType"], "object");
    assert_eq!(group["description"], "GraphQL group");
    assert!(group["id"].as_str().is_some());
}

#[tokio::test]
#[ignore]
async fn add_and_remove_group_member() {
    let pool = common::pool().await;
    let member_id = entity(&pool, "device").await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-members-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPrincipalGroup(input: {{ name: "{name}" }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let group_id = created.data.into_json().expect("json data")["createPrincipalGroup"]["id"]
        .as_str()
        .expect("group id")
        .to_owned();

    let added = schema
        .execute(authed(format!(
            r#"
            mutation {{
              addGroupMember(groupId: "{group_id}", entityId: "{member_id}")
            }}
            "#
        )))
        .await;
    assert!(added.errors.is_empty(), "{:?}", added.errors);
    assert_eq!(
        added.data.into_json().expect("json data")["addGroupMember"],
        true
    );

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              groupMembers(groupId: "{group_id}") {{
                id
              }}
              entityGroups(entityId: "{member_id}")
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert!(data["groupMembers"]
        .as_array()
        .expect("members")
        .iter()
        .any(|item| item["id"] == member_id.to_string()));
    assert!(data["entityGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .any(|id| id == group_id.as_str()));

    let removed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              removeGroupMember(groupId: "{group_id}", entityId: "{member_id}")
            }}
            "#
        )))
        .await;
    assert!(removed.errors.is_empty(), "{:?}", removed.errors);
    assert_eq!(
        removed.data.into_json().expect("json data")["removeGroupMember"],
        true
    );
}

#[tokio::test]
#[ignore]
async fn create_api_key_returns_secret_once_and_credentials_list_contains_it() {
    let pool = common::pool().await;
    let entity_id = entity(&pool, "service").await;
    let schema = build_schema(state(pool));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createApiKey(entityId: "{entity_id}", input: {{
                description: "GraphQL API key"
              }}) {{
                credentialId
                key
                expiresAt
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let api_key = &created.data.into_json().expect("json data")["createApiKey"];
    let credential_id = api_key["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    assert!(api_key["key"]
        .as_str()
        .is_some_and(|key| key.starts_with("atom_")));

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              credentials(entityId: "{entity_id}") {{
                items {{
                  id
                  kind
                  status
                  identifier
                }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let credentials = listed.data.into_json().expect("json data")["credentials"]["items"]
        .as_array()
        .expect("credentials")
        .clone();
    assert!(credentials.iter().any(|credential| {
        credential["id"] == credential_id
            && credential["kind"] == "api_key"
            && credential["status"] == "active"
    }));
}

#[tokio::test]
#[ignore]
async fn shared_key_can_be_created_revealed_and_used_for_authentication() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let human_id = entity(&pool, "human").await;
    let schema = build_schema(state(pool.clone()));

    let rejected = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createSharedKey(entityId: "{human_id}", input: {{}}) {{
                credentialId
              }}
            }}
            "#
        )))
        .await;
    assert!(!rejected.errors.is_empty());
    assert!(rejected.errors[0]
        .message
        .contains("can only be created for device entities"));

    let direct_human_insert = sqlx::query(
        "INSERT INTO credentials (entity_id, kind, secret_hash) VALUES ($1, 'shared_key', 'hash')",
    )
    .bind(human_id)
    .execute(&pool)
    .await;
    let db_err = direct_human_insert
        .expect_err("DB constraint should reject shared_key credentials for non-device entities")
        .into_database_error()
        .expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("23514"));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createSharedKey(entityId: "{device_id}", input: {{
                description: "Provisioning key"
              }}) {{
                credentialId
                key
                expiresAt
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let created_json = created.data.into_json().expect("json data");
    let shared_key = &created_json["createSharedKey"];
    let credential_id = shared_key["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    let key = shared_key["key"].as_str().expect("shared key").to_owned();
    assert!(key.starts_with("atom_shared_"));

    let (hash, metadata): (String, serde_json::Value) =
        sqlx::query_as("SELECT secret_hash, metadata FROM credentials WHERE id = $1")
            .bind(credential_id.parse::<Uuid>().expect("credential uuid"))
            .fetch_one(&pool)
            .await
            .expect("credential row");
    assert_ne!(hash, key);
    assert_eq!(metadata["shared_key"].as_str(), Some(key.as_str()));

    let device_kind_change = sqlx::query("UPDATE entities SET kind = 'human' WHERE id = $1")
        .bind(device_id)
        .execute(&pool)
        .await;
    let db_err = device_kind_change
        .expect_err("DB constraint should reject changing a shared-key device to non-device")
        .into_database_error()
        .expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("23514"));

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              credentials(entityId: "{device_id}") {{
                items {{
                  id
                  kind
                  status
                  identifier
                }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let credentials = listed.data.into_json().expect("json data")["credentials"]["items"]
        .as_array()
        .expect("credentials")
        .clone();
    assert!(credentials.iter().any(|credential| {
        credential["id"] == credential_id
            && credential["kind"] == "shared_key"
            && credential["status"] == "active"
            && credential["identifier"].is_null()
    }));

    let revealed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              revealSharedKey(entityId: "{device_id}", credentialId: "{credential_id}") {{
                credentialId
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(revealed.errors.is_empty(), "{:?}", revealed.errors);
    assert_eq!(
        revealed.data.into_json().expect("json data")["revealSharedKey"]["key"],
        key
    );

    let authenticated = identity_service::authenticate_password_credential_in_tenant(
        &pool,
        &Config::for_tests(),
        &device_id.to_string(),
        &key,
        None,
    )
    .await
    .expect("authenticate shared key");
    assert_eq!(authenticated.entity_id, device_id);
    assert_eq!(authenticated.credential_id.to_string(), credential_id);

    sqlx::query(
        r#"UPDATE credentials
           SET metadata = jsonb_set(metadata, '{shared_key}', to_jsonb('mismatched-key'::text))
           WHERE id = $1"#,
    )
    .bind(credential_id.parse::<Uuid>().expect("credential uuid"))
    .execute(&pool)
    .await
    .expect("corrupt shared key metadata");

    let lost_key = schema
        .execute(authed(format!(
            r#"
            mutation {{
              revealSharedKey(entityId: "{device_id}", credentialId: "{credential_id}") {{
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(!lost_key.errors.is_empty());
    assert!(lost_key.errors[0]
        .message
        .contains("could not retrieve the device key"));
}

#[tokio::test]
#[ignore]
async fn add_and_remove_ownership() {
    let pool = common::pool().await;
    let owner_id = entity(&pool, "human").await;
    let owned_id = entity(&pool, "device").await;
    let schema = build_schema(state(pool));

    let added = schema
        .execute(authed(format!(
            r#"
            mutation {{
              addOwnership(ownerId: "{owner_id}", ownedId: "{owned_id}", relation: "manages") {{
                ownerId
                ownedId
                relation
              }}
            }}
            "#
        )))
        .await;
    assert!(added.errors.is_empty(), "{:?}", added.errors);
    let ownership = &added.data.into_json().expect("json data")["addOwnership"];
    assert_eq!(ownership["ownerId"], owner_id.to_string());
    assert_eq!(ownership["ownedId"], owned_id.to_string());
    assert_eq!(ownership["relation"], "manages");

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              ownedEntities(ownerId: "{owner_id}") {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    assert!(listed.data.into_json().expect("json data")["ownedEntities"]
        .as_array()
        .expect("owned entities")
        .iter()
        .any(|entity| entity["id"] == owned_id.to_string()));

    let removed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              removeOwnership(ownerId: "{owner_id}", ownedId: "{owned_id}")
            }}
            "#
        )))
        .await;
    assert!(removed.errors.is_empty(), "{:?}", removed.errors);
    assert_eq!(
        removed.data.into_json().expect("json data")["removeOwnership"],
        true
    );
}
