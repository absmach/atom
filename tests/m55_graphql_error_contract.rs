//! Issue #101: the stable GraphQL error contract, proven end-to-end through
//! real resolvers (not just the unit-level `AppError::public_contract`
//! mapping in `src/error.rs`, or the DB-less transport-failure coverage in
//! `tests/api_contract.rs`).
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m55_graphql_error_contract -- --ignored
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

async fn human(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'human', $2, 'active')")
        .bind(id)
        .bind(format!("error-contract-{id}"))
        .execute(pool)
        .await
        .expect("insert human");
    id
}

/// Every error in `errors` carries `code`/`retryable` — the part of the
/// contract `graphql::auth::gql_error` sets inside the resolver, reachable
/// by driving the schema directly as these tests do. `requestId` is stamped
/// afterward by `graphql::attach_error_metadata`, which wraps the whole HTTP
/// handler rather than the schema — that half of the contract is exercised
/// end-to-end in `tests/api_contract.rs` instead. Returns the first error's
/// code.
fn extension_str(extensions: &async_graphql::ErrorExtensionValues, key: &str) -> String {
    match extensions.get(key) {
        Some(async_graphql::Value::String(s)) => s.clone(),
        other => panic!("expected extensions.{key} to be a string, got {other:?}"),
    }
}

fn assert_contract_extensions(errors: &[async_graphql::ServerError]) -> String {
    assert!(!errors.is_empty(), "expected at least one GraphQL error");
    let mut codes = Vec::new();
    for error in errors {
        let extensions = error
            .extensions
            .as_ref()
            .unwrap_or_else(|| panic!("error must carry extensions: {error:?}"));
        assert!(
            matches!(
                extensions.get("retryable"),
                Some(async_graphql::Value::Boolean(_))
            ),
            "error must carry a boolean extensions.retryable: {error:?}"
        );
        codes.push(extension_str(extensions, "code"));
    }
    codes.into_iter().next().unwrap()
}

#[tokio::test]
#[ignore]
async fn not_found_resolver_error_carries_contract_extensions() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let missing = Uuid::new_v4();

    let response = schema
        .execute(authed(format!(r#"{{ entity(id: "{missing}") {{ id }} }}"#)))
        .await;
    assert_eq!(assert_contract_extensions(&response.errors), "NOT_FOUND");
}

#[tokio::test]
#[ignore]
async fn conflict_resolver_error_carries_contract_extensions() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let name = format!("error-contract-tenant-{}", Uuid::new_v4());

    let first = schema
        .execute(authed(format!(
            r#"mutation {{ createTenant(input: {{ name: "{name}", alias: "{name}" }}) {{ id }} }}"#
        )))
        .await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);

    let second = schema
        .execute(authed(format!(
            r#"mutation {{ createTenant(input: {{ name: "{name}", alias: "{name}-2" }}) {{ id }} }}"#
        )))
        .await;
    assert_eq!(assert_contract_extensions(&second.errors), "CONFLICT");
}

#[tokio::test]
#[ignore]
async fn forbidden_resolver_error_carries_contract_extensions() {
    let pool = common::pool().await;
    let caller = human(&pool).await;
    let schema = build_schema(state(pool));
    let name = format!("error-contract-forbidden-{}", Uuid::new_v4());

    let response = schema
        .execute(authed_as(
            caller,
            format!(
                r#"mutation {{ createTenant(input: {{ name: "{name}", alias: "{name}" }}) {{ id }} }}"#
            ),
        ))
        .await;
    assert_eq!(assert_contract_extensions(&response.errors), "FORBIDDEN");
}

#[tokio::test]
#[ignore]
async fn partial_response_carries_both_data_and_contract_extensions() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let missing = Uuid::new_v4();

    let response = schema
        .execute(authed(format!(
            r#"{{ health entity(id: "{missing}") {{ id }} }}"#
        )))
        .await;
    assert_eq!(assert_contract_extensions(&response.errors), "NOT_FOUND");
    let data = response.data.into_json().expect("partial data");
    assert_eq!(
        data["health"], "ok",
        "a sibling field's success must survive alongside another field's error: {data}"
    );
}
