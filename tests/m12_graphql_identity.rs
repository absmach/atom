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
    config::{Config, ADMIN_ENTITY_ID},
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use sqlx::PgPool;
use uuid::Uuid;

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
        email_verification_redirect: "http://localhost:3005/verify-email".into(),
        password_reset_redirect: "http://localhost:3005/reset-password".into(),
        invitation_redirect: "http://localhost:3005/invitations/accept".into(),
        oauth_success_redirect: "http://localhost:8080".into(),
        oauth_error_redirect: "http://localhost:8080".into(),
        oidc_providers: vec![],
        smtp: None,
        email_verification_expiry_secs: 86_400,
        invitation_expiry_secs: 604_800,
        oauth_state_expiry_secs: 600,
        auth_exchange_code_expiry_secs: 300,
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

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createGroup(input: {{
                name: "{name}",
                description: "GraphQL group"
              }}) {{
                id
                name
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
              createGroup(input: {{ name: "{name}" }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let group_id = created.data.into_json().expect("json data")["createGroup"]["id"]
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
