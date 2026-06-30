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
    config::Config,
    graphql::build_schema,
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

async fn latest_entity_audit_details(
    pool: &PgPool,
    entity_id: Uuid,
    event: &str,
) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE target_kind = 'entity' AND target_id = $1 AND event = $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity_id)
    .bind(event)
    .fetch_one(pool)
    .await
    .expect("entity audit event")
}

async fn latest_resource_audit_details(
    pool: &PgPool,
    resource_id: Uuid,
    event: &str,
) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE target_kind = 'resource' AND target_id = $1 AND event = $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(resource_id)
    .bind(event)
    .fetch_one(pool)
    .await
    .expect("resource audit event")
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

async fn seeded_action(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seeded action")
}

async fn tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("graphql-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn add_tenant_membership(pool: &PgPool, tenant_id: Uuid, entity_id: Uuid) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status)
         VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(pool)
    .await
    .expect("insert tenant membership");
}

async fn tenant_entity(pool: &PgPool, tenant_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("graphql-tenant-{kind}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert tenant entity");
    id
}

async fn tenant_group(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO principal_groups (id, name, tenant_id, attributes) VALUES ($1, $2, $3, '{}')",
    )
    .bind(id)
    .bind(format!("graphql-group-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert group");
    id
}

async fn scoped_role(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    _scope_kind: &str,
    _scope_ref: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("{name}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert role");
    id
}

async fn attach_role_action(
    pool: &PgPool,
    role_id: Uuid,
    tenant_id: Uuid,
    object_id: Uuid,
    object_kind: &str,
    action_id: Uuid,
) {
    let block_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks
           (tenant_id, scope_mode, object_kind, object_id, effect)
         VALUES ($1, 'object', $2, $3, 'allow')
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(object_kind)
    .bind(object_id)
    .fetch_one(pool)
    .await
    .expect("insert permission block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id)
         VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(action_id)
    .execute(pool)
    .await
    .expect("insert permission block action");
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id)
         VALUES ($1, $2)",
    )
    .bind(role_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("insert role permission block");
}

#[tokio::test]
#[ignore]
async fn create_action_and_list_it() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-cap-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createAction(input: {{
                name: "{name}",
                description: "GraphQL action",
                applicability: [{{ objectKind: "resource", objectType: "resource:channel" }}]
              }}) {{
                id
                name
                description
                applicability {{ objectKind objectType }}
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let action = &created.data.into_json().expect("json data")["createAction"];
    let action_id = action["id"].as_str().expect("action id").to_owned();
    assert_eq!(action["name"], name);
    assert_eq!(action["applicability"][0]["objectKind"], "resource");
    assert_eq!(action["applicability"][0]["objectType"], "resource:channel");

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              actions(objectKind: "resource", objectType: "resource:channel") {{
                items {{ id name applicability {{ objectKind objectType }} }}
                total
              }}
              action(id: "{action_id}") {{
                id
                name
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert_eq!(data["action"]["id"], action_id);
    assert!(data["actions"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .any(|item| item["id"] == action_id));
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
    assert!(unauthorized.errors.is_empty(), "{:?}", unauthorized.errors);
    assert_eq!(
        unauthorized.data.into_json().expect("json data")["resources"]["total"],
        0
    );

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
async fn entity_query_allows_self_read_without_policy() {
    let pool = common::pool().await;
    let entity_id = entity(&pool, "human").await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed_as(
            entity_id,
            format!(
                r#"
                {{
                  entity(id: "{entity_id}") {{
                    id
                    name
                  }}
                }}
                "#
            ),
        ))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let entity = &response.data.into_json().expect("json data")["entity"];
    assert_eq!(entity["id"], entity_id.to_string());
}

#[tokio::test]
#[ignore]
async fn create_role_and_attach_capability() {
    let pool = common::pool().await;
    let publish_id = seeded_action(&pool, "publish").await;
    let channel_id = channel(&pool).await;
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

    let block = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPermissionBlock(input: {{
                scopeMode: "object",
                objectId: "{channel_id}",
                actionIds: ["{publish_id}"]
              }}) {{
                id
                actions {{ id name }}
              }}
            }}
            "#
        )))
        .await;
    assert!(block.errors.is_empty(), "{:?}", block.errors);
    let block_id = block.data.into_json().expect("json data")["createPermissionBlock"]["id"]
        .as_str()
        .expect("block id")
        .to_owned();

    let linked = schema
        .execute(authed(format!(
            r#"
            mutation {{
              replaceRolePermissionBlocks(roleId: "{role_id}", permissionBlockIds: ["{block_id}"])
            }}
            "#
        )))
        .await;
    assert!(linked.errors.is_empty(), "{:?}", linked.errors);
    assert_eq!(
        linked.data.into_json().expect("json data")["replaceRolePermissionBlocks"],
        true
    );

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              roles(q: "{name}") {{
                items {{ id name derivedKind }}
              }}
              role(id: "{role_id}") {{ id name }}
              attached: role(id: "{role_id}") {{
                permissionBlocks {{ id actions {{ id name }} }}
              }}
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
    assert!(data["attached"]["permissionBlocks"][0]["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .any(|item| item["id"] == publish_id.to_string()));
}

#[tokio::test]
#[ignore]
async fn create_policy_and_authz_check_allow_and_deny() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let publish_id = seeded_action(&pool, "publish").await;
    let schema = build_schema(state(pool));

    let block = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPermissionBlock(input: {{
                scopeMode: "object",
                objectId: "{channel_id}",
                effect: allow,
                actionIds: ["{publish_id}"]
              }}) {{
                id
                effect
              }}
            }}
            "#
        )))
        .await;
    assert!(block.errors.is_empty(), "{:?}", block.errors);
    let block_id = block.data.into_json().expect("json data")["createPermissionBlock"]["id"]
        .as_str()
        .expect("block id")
        .to_owned();

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createDirectPolicy(input: {{
                subjectKind: entity,
                subjectId: "{device_id}",
                permissionBlockId: "{block_id}"
              }}) {{
                id
                subjectKind
                subjectId
                permissionBlockId
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let policy = &created.data.into_json().expect("json data")["createDirectPolicy"];
    let policy_id = policy["id"].as_str().expect("policy id").to_owned();
    assert_eq!(policy["permissionBlockId"], block_id);

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
              directPolicies(subjectId: "{device_id}", subjectKind: entity) {{
                items {{ id subjectId permissionBlockId }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert!(data["directPolicies"]["items"]
        .as_array()
        .expect("direct policies")
        .iter()
        .any(|item| item["id"] == policy_id));
}

#[tokio::test]
#[ignore]
async fn subject_role_assignments_list_group_composites_and_authorize_members() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let user_id = tenant_entity(&pool, tenant_id, "human").await;
    let group_id = tenant_group(&pool, tenant_id).await;
    sqlx::query("INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2)")
        .bind(group_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert group member");
    let read_id = seeded_action(&pool, "read").await;
    let role_id = scoped_role(
        &pool,
        tenant_id,
        "group-reader",
        "object",
        &group_id.to_string(),
    )
    .await;
    attach_role_action(&pool, role_id, tenant_id, group_id, "group", read_id).await;
    let schema = build_schema(state(pool));

    let assigned = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createRoleAssignment(input: {{
                tenantId: "{tenant_id}",
                subjectKind: group,
                subjectId: "{group_id}",
                roleId: "{role_id}"
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(assigned.errors.is_empty(), "{:?}", assigned.errors);

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
                roleAssignments(
                tenantId: "{tenant_id}",
                subjectKind: group,
                subjectId: "{group_id}"
              ) {{
                total
                items {{
                  role {{ id name derivedKind }}
                }}
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    let assignments = &data["roleAssignments"];
    assert_eq!(assignments["total"], 1);
    assert_eq!(assignments["items"][0]["role"]["id"], role_id.to_string());
    assert_eq!(assignments["items"][0]["role"]["derivedKind"], "simple");

    let checked = schema
        .execute(authed_as(
            user_id,
            format!(
                r#"
                mutation {{
                  authzCheck(input: {{
                    subjectId: "{user_id}",
                    action: "read",
                    objectKind: "group",
                    objectId: "{group_id}"
                  }}) {{
                    allowed
                    reason
                  }}
                }}
                "#
            ),
        ))
        .await;
    assert!(checked.errors.is_empty(), "{:?}", checked.errors);
    let data = checked.data.into_json().expect("json data");
    assert_eq!(data["authzCheck"]["allowed"], true);
}

#[tokio::test]
#[ignore]
async fn create_policy_rejects_cross_tenant_role_assignment() {
    let pool = common::pool().await;
    let tenant_a = tenant(&pool).await;
    let tenant_b = tenant(&pool).await;
    let group_id = tenant_group(&pool, tenant_a).await;
    let foreign_role_id = scoped_role(
        &pool,
        tenant_b,
        "foreign-role",
        "tenant",
        &tenant_b.to_string(),
    )
    .await;
    let schema = build_schema(state(pool));

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createRoleAssignment(input: {{
                tenantId: "{tenant_a}",
                subjectKind: group,
                subjectId: "{group_id}",
                roleId: "{foreign_role_id}"
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;

    assert!(!response.errors.is_empty());
    assert!(response.errors[0]
        .message
        .contains("tenantId must match role tenantId"));
}

#[tokio::test]
#[ignore]
async fn authz_explain_returns_decision_details() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let publish_id = seeded_action(&pool, "publish").await;
    let schema = build_schema(state(pool));

    let block = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPermissionBlock(input: {{
                scopeMode: "object",
                objectId: "{channel_id}",
                actionIds: ["{publish_id}"]
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(block.errors.is_empty(), "{:?}", block.errors);
    let block_id = block.data.into_json().expect("json data")["createPermissionBlock"]["id"]
        .as_str()
        .expect("block id")
        .to_owned();

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createDirectPolicy(input: {{
                subjectKind: entity,
                subjectId: "{device_id}",
                permissionBlockId: "{block_id}"
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
    assert!(data["expiringCredentials"].is_array());
}

#[tokio::test]
#[ignore]
async fn entity_create_is_the_entity_targeted_audit_event_when_password_is_created() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool.clone()));
    let entity_id = Uuid::new_v4();
    let name = format!("audit-created-entity-{entity_id}");

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createEntity(input: {{
                id: "{entity_id}",
                kind: human,
                name: "{name}"
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);

    let password = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPassword(entityId: "{entity_id}", password: "test-password-123")
            }}
            "#
        )))
        .await;
    assert!(password.errors.is_empty(), "{:?}", password.errors);

    let queried = schema
        .execute(authed(format!(
            r#"
            {{
              auditLogs(targetKind: "entity", targetId: "{entity_id}", limit: 10) {{
                items {{ event targetKind targetId }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(queried.errors.is_empty(), "{:?}", queried.errors);
    let data = queried.data.into_json().expect("json data");
    let items = data["auditLogs"]["items"].as_array().expect("items");
    assert!(
        items.iter().any(|item| item["event"] == "entity.create"),
        "entity.create must be stored for the entity target: {items:?}"
    );
    assert!(
        !items
            .iter()
            .any(|item| item["event"] == "credential.create"),
        "credential.create should target the credential object, not the entity: {items:?}"
    );
}

#[tokio::test]
#[ignore]
async fn entity_and_resource_lifecycle_mutations_write_audit_events() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let channel_id = channel(&pool).await;
    let schema = build_schema(state(pool.clone()));

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              updateEntity(id: "{device_id}", input: {{ name: "audited-device-{device_id}" }}) {{
                id
                name
              }}
              enableEntity(id: "{device_id}") {{
                id
                status
              }}
              disableEntity(id: "{device_id}") {{
                id
                status
              }}
              deleteEntity(id: "{device_id}")
              restoreEntity(id: "{device_id}")
              updateResource(id: "{channel_id}", input: {{ name: "audited-channel-{channel_id}" }}) {{
                id
                name
              }}
              deleteResource(id: "{channel_id}")
              restoreResource(id: "{channel_id}")
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);

    let entity_details = latest_entity_audit_details(&pool, device_id, "entity.update").await;
    assert_eq!(
        entity_details["updated_fields"],
        serde_json::json!(["name"])
    );

    for event in [
        "entity.enable",
        "entity.disable",
        "entity.delete",
        "entity.restore",
    ] {
        let details = latest_entity_audit_details(&pool, device_id, event).await;
        assert_eq!(details, serde_json::json!({}), "{event}");
    }

    let resource_details =
        latest_resource_audit_details(&pool, channel_id, "resource.update").await;
    assert_eq!(
        resource_details["updated_fields"],
        serde_json::json!(["name"])
    );

    for event in ["resource.delete", "resource.restore"] {
        let details = latest_resource_audit_details(&pool, channel_id, event).await;
        assert_eq!(details, serde_json::json!({}), "{event}");
    }
}

/// Through an actual GraphQL resolver, an exact-object read deny must override a
/// tenant-wide read allow. The `entity(id)` resolver falls back to the
/// control-plane gate when the PDP denies, so the gate must apply cross-scope
/// deny-override (the GraphQL gate previously used a sequential-OR copy that let
/// the tenant allow win).
#[tokio::test]
#[ignore]
async fn graphql_entity_read_object_deny_overrides_tenant_allow() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let subject = tenant_entity(&pool, tenant_id, "human").await;
    let target = tenant_entity(&pool, tenant_id, "human").await;
    let read = seeded_action(&pool, "read").await;

    // Tenant-wide read allow + exact-object read deny on the target, both to the subject.
    let allow_block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, effect, conditions) VALUES ('tenant', $1, 'allow', '{}') RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("allow block");
    let deny_block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, object_id, effect, conditions) VALUES ('object', $1, 'deny', '{}') RETURNING id",
    )
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("deny block");
    for block in [allow_block, deny_block] {
        sqlx::query(
            "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
        )
        .bind(block)
        .bind(read)
        .execute(&pool)
        .await
        .expect("block action");
        sqlx::query("INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
            .bind(tenant_id)
            .bind(subject)
            .bind(block)
            .execute(&pool)
            .await
            .expect("direct policy");
    }

    let schema = build_schema(state(pool.clone()));
    let resp = schema
        .execute(authed_as(
            subject,
            format!("{{ entity(id: \"{target}\") {{ id }} }}"),
        ))
        .await;
    assert!(
        !resp.errors.is_empty(),
        "object read deny must override tenant read allow through the GraphQL gate, got: {:?}",
        resp.data
    );
}

/// manage implies read, evaluated through the PDP (not the old coarse gate
/// fallback). A caller with an object_type-scoped `manage` allow — a scope the
/// gate fallback did not match — can now read the entity.
#[tokio::test]
#[ignore]
async fn graphql_entity_read_allowed_via_object_type_manage() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let subject = tenant_entity(&pool, tenant_id, "human").await;
    let target = tenant_entity(&pool, tenant_id, "human").await;
    let manage = seeded_action(&pool, "manage").await;

    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, object_kind, object_type, tenant_id, effect, conditions) VALUES ('object_type', 'entity', 'entity:human', $1, 'allow', '{}') RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("manage block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(manage)
    .execute(&pool)
    .await
    .expect("block action");
    sqlx::query("INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(tenant_id)
        .bind(subject)
        .bind(block)
        .execute(&pool)
        .await
        .expect("direct policy");

    let schema = build_schema(state(pool.clone()));
    let resp = schema
        .execute(authed_as(
            subject,
            format!("{{ entity(id: \"{target}\") {{ id }} }}"),
        ))
        .await;
    assert!(
        resp.errors.is_empty(),
        "object_type manage must grant read through the PDP: {:?}",
        resp.errors
    );
    let data = resp.data.into_json().expect("json");
    assert_eq!(data["entity"]["id"], serde_json::json!(target.to_string()));
}

/// A tenant visible through an object-kind scoped tenant grant must also be
/// readable through `tenant(id)`. Listing already accepted this grant shape;
/// the point lookup used the coarser control-plane gate and rejected it.
#[tokio::test]
#[ignore]
async fn graphql_tenant_read_matches_listing_object_kind_grant() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let subject = tenant_entity(&pool, tenant_id, "human").await;
    let read = seeded_action(&pool, "read").await;

    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks
           (scope_mode, tenant_id, object_kind, effect, conditions)
         VALUES ('object_kind', $1, 'tenant', 'allow', '{}')
         RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("tenant object-kind read block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(read)
    .execute(&pool)
    .await
    .expect("block action");
    sqlx::query(
        "INSERT INTO direct_policies
           (tenant_id, subject_kind, subject_id, permission_block_id)
         VALUES ($1, 'entity', $2, $3)",
    )
    .bind(tenant_id)
    .bind(subject)
    .bind(block)
    .execute(&pool)
    .await
    .expect("direct policy");

    let schema = build_schema(state(pool.clone()));
    let listed = schema
        .execute(authed_as(subject, "{ tenants { items { id } total } }"))
        .await;
    assert!(
        listed.errors.is_empty(),
        "tenant list should accept object-kind tenant grants: {:?}",
        listed.errors
    );
    let listed_data = listed.data.into_json().expect("json");
    assert!(listed_data["tenants"]["items"]
        .as_array()
        .expect("tenant items")
        .iter()
        .any(|item| item["id"] == serde_json::json!(tenant_id.to_string())));

    let fetched = schema
        .execute(authed_as(
            subject,
            format!("{{ tenant(id: \"{tenant_id}\") {{ id }} }}"),
        ))
        .await;
    assert!(
        fetched.errors.is_empty(),
        "tenant(id) should use the same object-level PDP semantics as listing: {:?}",
        fetched.errors
    );
    let fetched_data = fetched.data.into_json().expect("json");
    assert_eq!(
        fetched_data["tenant"]["id"],
        serde_json::json!(tenant_id.to_string())
    );
}

/// A plain active tenant member can see and read the tenant, but membership does
/// not expose tenant administration surfaces such as member or invitation lists.
#[tokio::test]
#[ignore]
async fn graphql_membership_reads_tenant_without_admin_lists() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let member = entity(&pool, "human").await;
    add_tenant_membership(&pool, tenant_id, member).await;
    let schema = build_schema(state(pool));

    let listed = schema
        .execute(authed_as(
            member,
            r#"
            {
              tenants {
                items { id }
                total
              }
            }
            "#,
        ))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let listed_data = listed.data.into_json().expect("json");
    assert!(listed_data["tenants"]["items"]
        .as_array()
        .expect("tenant items")
        .iter()
        .any(|item| item["id"] == serde_json::json!(tenant_id.to_string())));

    let fetched = schema
        .execute(authed_as(
            member,
            format!("{{ tenant(id: \"{tenant_id}\") {{ id }} }}"),
        ))
        .await;
    assert!(fetched.errors.is_empty(), "{:?}", fetched.errors);
    assert_eq!(
        fetched.data.into_json().expect("json")["tenant"]["id"],
        serde_json::json!(tenant_id.to_string())
    );

    let checked = schema
        .execute(authed_as(
            member,
            format!(
                r#"
                mutation {{
                  authzCheck(input: {{
                    subjectId: "{member}",
                    action: "read",
                    objectKind: "tenant",
                    objectId: "{tenant_id}"
                  }}) {{
                    allowed
                    reason
                  }}
                }}
                "#
            ),
        ))
        .await;
    assert!(checked.errors.is_empty(), "{:?}", checked.errors);
    assert_eq!(
        checked.data.into_json().expect("json")["authzCheck"]["allowed"],
        true
    );

    let members = schema
        .execute(authed_as(
            member,
            format!("{{ tenantMembers(tenantId: \"{tenant_id}\") {{ total }} }}"),
        ))
        .await;
    assert!(
        !members.errors.is_empty(),
        "plain membership must not allow tenantMembers"
    );
    assert!(members.errors[0].message.contains("forbidden"));

    let invitations = schema
        .execute(authed_as(
            member,
            format!("{{ tenantInvitations(tenantId: \"{tenant_id}\") {{ total }} }}"),
        ))
        .await;
    assert!(
        !invitations.errors.is_empty(),
        "plain membership must not allow tenantInvitations"
    );
    assert!(invitations.errors[0].message.contains("forbidden"));
}
