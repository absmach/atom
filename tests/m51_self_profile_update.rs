//! Regression coverage for session-bound self-profile updates on global humans.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m51_self_profile_update -- --ignored
//! ```

mod common;

use async_graphql::{Request, Response};
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
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        Config::for_tests(),
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

fn session_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    session_in_tenant_as(entity_id, None, query)
}

fn session_in_tenant_as(
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
    query: impl Into<String>,
) -> Request {
    request_as(
        AuthContext {
            entity_id,
            tenant_id,
            session_id: Some(Uuid::new_v4()),
            ..Default::default()
        },
        query,
    )
}

fn request_as(auth: AuthContext, query: impl Into<String>) -> Request {
    Request::new(query).data(auth)
}

fn access_token_as(entity_id: Uuid, scoped: bool, query: impl Into<String>) -> Request {
    request_as(
        AuthContext {
            entity_id,
            tenant_id: None,
            credential_id: Some(Uuid::new_v4()),
            scoped,
            ..Default::default()
        },
        query,
    )
}

fn assert_forbidden(response: &Response, context: &str) {
    assert_eq!(
        response.errors.len(),
        1,
        "{context}: expected one authorization error, got {:?}",
        response.errors
    );
    assert_eq!(response.errors[0].message, "forbidden", "{context}");
}

async fn global_human(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, tenant_id, status, attributes)
           VALUES ($1, 'human', $2, NULL, 'active', $3)"#,
    )
    .bind(id)
    .bind(format!("self-profile-{id}"))
    .bind(serde_json::json!({
        "first_name": "Old",
        "last_name": "Name",
        "email": format!("old-{id}@example.test"),
        "department": "operations"
    }))
    .execute(pool)
    .await
    .expect("insert global human");
    id
}

#[tokio::test]
#[ignore]
async fn session_user_can_edit_own_global_profile_while_switched_to_a_tenant() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("self-profile-switched-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("insert switched tenant");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status)
         VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(caller)
    .execute(&pool)
    .await
    .expect("insert tenant membership");
    let schema = build_schema(state(pool.clone()));
    let updated_name = format!("alice-{caller}");

    let update = schema
        .execute(session_in_tenant_as(
            caller,
            Some(tenant_id),
            format!(
                r#"mutation {{
                    updateEntity(
                        id: "{caller}",
                        input: {{
                            name: "{updated_name}",
                            attributes: {{
                                first_name: "Alice",
                                last_name: "Updated",
                                picture: "https://example.test/alice.png"
                            }}
                        }}
                    ) {{
                        id
                        name
                        tenantId
                        attributes
                    }}
                }}"#
            ),
        ))
        .await;

    assert!(update.errors.is_empty(), "{:?}", update.errors);
    let data = update.data.into_json().expect("update json");
    assert_eq!(data["updateEntity"]["id"], caller.to_string());
    assert_eq!(data["updateEntity"]["name"], updated_name);
    assert!(data["updateEntity"]["tenantId"].is_null());
    assert_eq!(data["updateEntity"]["attributes"]["first_name"], "Alice");
    assert_eq!(
        data["updateEntity"]["attributes"]["email"],
        format!("old-{caller}@example.test")
    );
    assert_eq!(
        data["updateEntity"]["attributes"]["department"],
        "operations"
    );

    let persisted: (String, serde_json::Value, Option<Uuid>) =
        sqlx::query_as("SELECT name, attributes, tenant_id FROM entities WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .expect("updated entity");
    assert_eq!(persisted.0, updated_name);
    assert_eq!(persisted.1["last_name"], "Updated");
    assert_eq!(persisted.1["department"], "operations");
    assert_eq!(persisted.2, None);
}

#[tokio::test]
#[ignore]
async fn self_profile_path_does_not_authorize_entity_administration() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let destination = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(destination)
        .bind(format!("self-profile-destination-{destination}"))
        .execute(&pool)
        .await
        .expect("insert destination tenant");
    let schema = build_schema(state(pool.clone()));

    for (query, context) in [
        (
            format!(
                r#"mutation {{ updateEntity(id: "{caller}", input: {{ status: suspended }}) {{ id }} }}"#
            ),
            "status change",
        ),
        (
            format!(
                r#"mutation {{ updateEntity(id: "{caller}", input: {{ tenantId: "{destination}" }}) {{ id }} }}"#
            ),
            "tenant move",
        ),
        (
            format!(
                r#"mutation {{ updateEntity(id: "{caller}", input: {{ attributes: {{ department: "admin" }} }}) {{ id }} }}"#
            ),
            "arbitrary attribute",
        ),
        (
            format!(
                r#"mutation {{ updateEntity(id: "{caller}", input: {{ attributes: {{ email: "attacker@example.test" }} }}) {{ id }} }}"#
            ),
            "email change",
        ),
    ] {
        let response = schema.execute(session_as(caller, query)).await;
        assert_forbidden(&response, context);
    }

    let persisted: (String, Option<Uuid>, serde_json::Value) =
        sqlx::query_as("SELECT status::text, tenant_id, attributes FROM entities WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .expect("entity after denied updates");
    assert_eq!(persisted.0, "active");
    assert_eq!(persisted.1, None);
    assert_eq!(persisted.2["department"], "operations");
}

#[tokio::test]
#[ignore]
async fn access_tokens_cannot_use_the_session_only_self_profile_path() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let schema = build_schema(state(pool.clone()));

    for (scoped, context) in [
        (false, "unscoped access token"),
        (true, "scoped access token"),
    ] {
        let response = schema
            .execute(access_token_as(
                caller,
                scoped,
                format!(
                    r#"mutation {{
                        updateEntity(
                            id: "{caller}",
                            input: {{ attributes: {{ picture: "token.png" }} }}
                        ) {{ id }}
                    }}"#
                ),
            ))
            .await;
        assert_forbidden(&response, context);
    }

    let attributes: serde_json::Value =
        sqlx::query_scalar("SELECT attributes FROM entities WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .expect("entity after denied token updates");
    assert!(attributes.get("picture").is_none());
}

#[tokio::test]
#[ignore]
async fn self_profile_path_rejects_other_targets_and_non_global_humans() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let other = global_human(&pool).await;
    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("self-profile-scope-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("insert tenant");

    let tenant_human = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status, attributes)
         VALUES ($1, 'human', $2, $3, 'active', '{}')",
    )
    .bind(tenant_human)
    .bind(format!("tenant-human-{tenant_human}"))
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert tenant human");

    let global_device = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status, attributes)
         VALUES ($1, 'device', $2, NULL, 'active', '{}')",
    )
    .bind(global_device)
    .bind(format!("global-device-{global_device}"))
    .execute(&pool)
    .await
    .expect("insert global device");

    let schema = build_schema(state(pool));
    for (actor, target, context) in [
        (caller, other, "another global human"),
        (tenant_human, tenant_human, "tenant-scoped human"),
        (global_device, global_device, "non-human entity"),
    ] {
        let response = schema
            .execute(session_as(
                actor,
                format!(
                    r#"mutation {{
                        updateEntity(
                            id: "{target}",
                            input: {{ attributes: {{ picture: "not-allowed.png" }} }}
                        ) {{ id }}
                    }}"#
                ),
            ))
            .await;
        assert_forbidden(&response, context);
    }
}

#[tokio::test]
#[ignore]
async fn self_profile_null_removes_fields_and_preserves_legacy_metadata() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    sqlx::query(
        "UPDATE entities
         SET attributes = attributes || $2
         WHERE id = $1",
    )
    .bind(caller)
    .bind(serde_json::json!({
        "picture": "old-picture.png",
        "parent_group_id": Uuid::new_v4().to_string()
    }))
    .execute(&pool)
    .await
    .expect("add legacy metadata");
    let schema = build_schema(state(pool.clone()));

    let response = schema
        .execute(session_as(
            caller,
            format!(
                r#"mutation {{
                    updateEntity(
                        id: "{caller}",
                        input: {{
                            attributes: {{
                                first_name: null,
                                last_name: null,
                                picture: null
                            }}
                        }}
                    ) {{ attributes }}
                }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    let attributes: serde_json::Value =
        sqlx::query_scalar("SELECT attributes FROM entities WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .expect("cleared profile attributes");
    assert!(attributes.get("first_name").is_none());
    assert!(attributes.get("last_name").is_none());
    assert!(attributes.get("picture").is_none());
    assert_eq!(attributes["department"], "operations");
    assert!(attributes.get("parent_group_id").is_some());
}

#[tokio::test]
#[ignore]
async fn self_profile_name_is_normalized_and_cannot_create_login_ambiguity() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let existing = global_human(&pool).await;
    let existing_name: String = sqlx::query_scalar("SELECT name FROM entities WHERE id = $1")
        .bind(existing)
        .fetch_one(&pool)
        .await
        .expect("existing name");
    let schema = build_schema(state(pool.clone()));

    let collision = schema
        .execute(session_as(
            caller,
            format!(
                r#"mutation {{
                    updateEntity(id: "{caller}", input: {{ name: "{existing_name}" }}) {{ id }}
                }}"#
            ),
        ))
        .await;
    assert_eq!(collision.errors.len(), 1);
    assert!(collision.errors[0]
        .message
        .contains("name is already in use by another entity"));

    let blank = schema
        .execute(session_as(
            caller,
            format!(
                r#"mutation {{ updateEntity(id: "{caller}", input: {{ name: "   " }}) {{ id }} }}"#
            ),
        ))
        .await;
    assert_eq!(blank.errors.len(), 1);
    assert_eq!(blank.errors[0].message, "name is required");

    let normalized = format!("renamed-{caller}");
    let success = schema
        .execute(session_as(
            caller,
            format!(
                r#"mutation {{
                    updateEntity(id: "{caller}", input: {{ name: "  {normalized}  " }}) {{ name }}
                }}"#
            ),
        ))
        .await;
    assert!(success.errors.is_empty(), "{:?}", success.errors);
    let persisted: String = sqlx::query_scalar("SELECT name FROM entities WHERE id = $1")
        .bind(caller)
        .fetch_one(&pool)
        .await
        .expect("normalized name");
    assert_eq!(persisted, normalized);
}

#[tokio::test]
#[ignore]
async fn self_profile_update_preserves_concurrent_admin_attributes() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let schema = build_schema(state(pool.clone()));

    let mut admin_tx = pool.begin().await.expect("begin admin update");
    sqlx::query("UPDATE entities SET attributes = attributes || $2 WHERE id = $1")
        .bind(caller)
        .bind(serde_json::json!({ "department": "security" }))
        .execute(&mut *admin_tx)
        .await
        .expect("stage concurrent admin attributes");

    let mut update = tokio::spawn(async move {
        schema
            .execute(session_as(
                caller,
                format!(
                    r#"mutation {{
                        updateEntity(
                            id: "{caller}",
                            input: {{ attributes: {{ picture: "new-picture.png" }} }}
                        ) {{
                            attributes
                        }}
                    }}"#
                ),
            ))
            .await
    });

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut update)
            .await
            .is_err(),
        "self-profile update must wait for the entity row lock"
    );
    admin_tx.commit().await.expect("commit admin update");

    let response = tokio::time::timeout(std::time::Duration::from_secs(5), update)
        .await
        .expect("self-profile update should finish after lock release")
        .expect("self-profile update task");
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    let attributes: serde_json::Value =
        sqlx::query_scalar("SELECT attributes FROM entities WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .expect("updated attributes");
    assert_eq!(attributes["picture"], "new-picture.png");
    assert_eq!(
        attributes["department"], "security",
        "self-profile patch must preserve the admin's newer metadata"
    );
}
