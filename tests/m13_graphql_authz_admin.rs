//! GraphQL authorization and admin operation tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m13_graphql_authz_admin -- --ignored
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
        admin_entity_id: ADMIN_ENTITY_ID,
        admin_secret: None,
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

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
    })
}

async fn entity(pool: &PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("graphql-authz-{kind}-{id}"))
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn channel(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO resources (id, kind, name, attributes) VALUES ($1, 'channel', $2, '{}')",
    )
    .bind(id)
    .bind(format!("graphql-channel-{id}"))
    .execute(pool)
    .await
    .expect("insert channel");
    id
}

async fn seeded_capability(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM capabilities WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seeded capability")
}

#[tokio::test]
#[ignore]
async fn create_capability_and_list_it() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-cap-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createCapability(input: {{
                name: "{name}",
                resourceKind: "channel",
                description: "GraphQL capability"
              }}) {{
                id
                name
                resourceKind
                description
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let capability = &created.data.into_json().expect("json data")["createCapability"];
    let capability_id = capability["id"].as_str().expect("capability id").to_owned();
    assert_eq!(capability["name"], name);
    assert_eq!(capability["resourceKind"], "channel");

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              capabilities(resourceKind: "channel") {{
                items {{ id name resourceKind }}
                total
              }}
              capability(id: "{capability_id}") {{
                id
                name
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert_eq!(data["capability"]["id"], capability_id);
    assert!(data["capabilities"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .any(|item| item["id"] == capability_id));
}

#[tokio::test]
#[ignore]
async fn unauthenticated_protected_query_fails() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(Request::new(
            r#"
            {
              tenants {
                total
              }
            }
            "#,
        ))
        .await;

    assert!(!response.errors.is_empty());
    assert!(response.errors[0]
        .message
        .contains("missing authentication"));
}

#[tokio::test]
#[ignore]
async fn unauthorized_read_query_fails_and_admin_read_succeeds() {
    let pool = common::pool().await;
    let reader_id = entity(&pool, "human").await;
    let schema = build_schema(state(pool));

    let unauthorized = schema
        .execute(authed_as(
            reader_id,
            r#"
            {
              resources {
                total
              }
            }
            "#,
        ))
        .await;
    assert!(!unauthorized.errors.is_empty());
    assert!(unauthorized.errors[0].message.contains("forbidden"));

    let authorized = schema
        .execute(authed(
            r#"
            {
              resources(limit: 1) {
                total
              }
            }
            "#,
        ))
        .await;
    assert!(authorized.errors.is_empty(), "{:?}", authorized.errors);
}

#[tokio::test]
#[ignore]
async fn create_role_and_attach_capability() {
    let pool = common::pool().await;
    let publish_id = seeded_capability(&pool, "publish").await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-role-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createRole(input: {{
                name: "{name}",
                description: "GraphQL role"
              }}) {{
                id
                name
                description
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let role = &created.data.into_json().expect("json data")["createRole"];
    let role_id = role["id"].as_str().expect("role id").to_owned();
    assert_eq!(role["name"], name);

    let added = schema
        .execute(authed(format!(
            r#"
            mutation {{
              addRoleCapability(roleId: "{role_id}", capabilityId: "{publish_id}")
            }}
            "#
        )))
        .await;
    assert!(added.errors.is_empty(), "{:?}", added.errors);
    assert_eq!(
        added.data.into_json().expect("json data")["addRoleCapability"],
        true
    );

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              roles {{
                items {{ id name }}
              }}
              role(id: "{role_id}") {{ id name }}
              roleCapabilities(roleId: "{role_id}") {{ id name }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert_eq!(data["role"]["id"], role_id);
    assert!(data["roles"]["items"]
        .as_array()
        .expect("roles")
        .iter()
        .any(|item| item["id"] == role_id));
    assert!(data["roleCapabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .any(|item| item["id"] == publish_id.to_string()));
}

#[tokio::test]
#[ignore]
async fn create_policy_and_authz_check_allow_and_deny() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let publish_id = seeded_capability(&pool, "publish").await;
    let schema = build_schema(state(pool));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPolicy(input: {{
                subjectKind: entity,
                subjectId: "{device_id}",
                grantKind: capability,
                grantId: "{publish_id}",
                scopeKind: object,
                scopeRef: "{channel_id}",
                effect: allow
              }}) {{
                id
                subjectKind
                grantKind
                scopeKind
                scopeRef
                effect
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let policy = &created.data.into_json().expect("json data")["createPolicy"];
    let policy_id = policy["id"].as_str().expect("policy id").to_owned();
    assert_eq!(policy["effect"], "allow");

    let checked = schema
        .execute(authed(format!(
            r#"
            mutation {{
              allow: authzCheck(input: {{
                subjectId: "{device_id}",
                action: "publish",
                resourceId: "{channel_id}"
              }}) {{
                allowed
                reason
              }}
              deny: authzCheck(input: {{
                subjectId: "{device_id}",
                action: "subscribe",
                resourceId: "{channel_id}"
              }}) {{
                allowed
                reason
              }}
            }}
            "#
        )))
        .await;
    assert!(checked.errors.is_empty(), "{:?}", checked.errors);
    let data = checked.data.into_json().expect("json data");
    assert_eq!(data["allow"]["allowed"], true);
    assert_eq!(data["deny"]["allowed"], false);

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              policies(subjectId: "{device_id}", subjectKind: entity) {{
                items {{ id subjectId }}
                total
              }}
              policy(id: "{policy_id}") {{ id subjectId }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert_eq!(data["policy"]["id"], policy_id);
    assert!(data["policies"]["items"]
        .as_array()
        .expect("policies")
        .iter()
        .any(|item| item["id"] == policy_id));
}

#[tokio::test]
#[ignore]
async fn authz_explain_returns_decision_details() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let publish_id = seeded_capability(&pool, "publish").await;
    let schema = build_schema(state(pool));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPolicy(input: {{
                subjectKind: entity,
                subjectId: "{device_id}",
                grantKind: capability,
                grantId: "{publish_id}",
                scopeKind: object,
                scopeRef: "{channel_id}"
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);

    let explained = schema
        .execute(authed(format!(
            r#"
            mutation {{
              authzExplain(input: {{
                subjectId: "{device_id}",
                action: "publish",
                resourceId: "{channel_id}"
              }}) {{
                allowed
                reason
                subject
                resource
                capability
                matchedBinding
                evaluatedBindings
              }}
            }}
            "#
        )))
        .await;
    assert!(explained.errors.is_empty(), "{:?}", explained.errors);
    let explain = &explained.data.into_json().expect("json data")["authzExplain"];
    assert_eq!(explain["allowed"], true);
    assert_eq!(explain["reason"], "allowed");
    assert!(explain["matchedBinding"].is_object());
    assert!(explain["evaluatedBindings"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[tokio::test]
#[ignore]
async fn authz_explain_requires_stronger_permission_than_check() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let schema = build_schema(state(pool));

    let check = schema
        .execute(authed_as(
            device_id,
            format!(
                r#"
                mutation {{
                  authzCheck(input: {{
                    subjectId: "{device_id}",
                    action: "publish",
                    resourceId: "{channel_id}"
                  }}) {{
                    allowed
                  }}
                }}
                "#
            ),
        ))
        .await;
    assert!(check.errors.is_empty(), "{:?}", check.errors);

    let explain = schema
        .execute(authed_as(
            device_id,
            format!(
                r#"
                mutation {{
                  authzExplain(input: {{
                    subjectId: "{device_id}",
                    action: "publish",
                    resourceId: "{channel_id}"
                  }}) {{
                    allowed
                  }}
                }}
                "#
            ),
        ))
        .await;
    assert!(!explain.errors.is_empty());
    assert!(explain.errors[0].message.contains("forbidden"));
}

#[tokio::test]
#[ignore]
async fn ownership_mutation_requires_manage_permission() {
    let pool = common::pool().await;
    let owner_id = entity(&pool, "human").await;
    let owned_id = entity(&pool, "device").await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed_as(
            owner_id,
            format!(
                r#"
                mutation {{
                  addOwnership(ownerId: "{owner_id}", ownedId: "{owned_id}") {{
                    ownerId
                    ownedId
                  }}
                }}
                "#
            ),
        ))
        .await;

    assert!(!response.errors.is_empty());
    assert!(response.errors[0].message.contains("forbidden"));
}

#[tokio::test]
#[ignore]
async fn audit_and_admin_queries_smoke() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let schema = build_schema(state(pool));

    let checked = schema
        .execute(authed(format!(
            r#"
            mutation {{
              authzCheck(input: {{
                subjectId: "{device_id}",
                action: "subscribe",
                resourceId: "{channel_id}"
              }}) {{
                allowed
              }}
            }}
            "#
        )))
        .await;
    assert!(checked.errors.is_empty(), "{:?}", checked.errors);

    let queried = schema
        .execute(authed(format!(
            r#"
            {{
              auditLogs(limit: 5) {{
                items {{ id event outcome }}
                total
              }}
              entityAuditLogs(entityId: "{device_id}") {{
                items {{ id event outcome }}
                total
              }}
              orphanPolicies(limit: 1) {{ id }}
              unprotectedResources(limit: 1) {{ id kind }}
              expiringCredentials(limit: 1) {{ id entityId kind status }}
            }}
            "#
        )))
        .await;
    assert!(queried.errors.is_empty(), "{:?}", queried.errors);
    let data = queried.data.into_json().expect("json data");
    assert!(data["auditLogs"]["items"].is_array());
    assert!(data["entityAuditLogs"]["items"].is_array());
    assert!(data["orphanPolicies"].is_array());
    assert!(data["unprotectedResources"].is_array());
    assert!(data["expiringCredentials"].is_array());
}
