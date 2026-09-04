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
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: Some(Uuid::new_v4()),
        ..Default::default()
    })
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
async fn session_user_can_edit_own_global_profile_without_platform_manage() {
    let pool = common::pool().await;
    let caller = global_human(&pool).await;
    let schema = build_schema(state(pool.clone()));
    let email = format!("new-{caller}@example.test");

    let update = schema
        .execute(session_as(
            caller,
            format!(
                r#"mutation {{
                    updateEntity(
                        id: "{caller}",
                        input: {{
                            name: "alice-updated",
                            attributes: {{
                                first_name: "Alice",
                                last_name: "Updated",
                                email: "{email}",
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
    assert_eq!(data["updateEntity"]["name"], "alice-updated");
    assert!(data["updateEntity"]["tenantId"].is_null());
    assert_eq!(data["updateEntity"]["attributes"]["first_name"], "Alice");
    assert_eq!(data["updateEntity"]["attributes"]["email"], email);
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
    assert_eq!(persisted.0, "alice-updated");
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
