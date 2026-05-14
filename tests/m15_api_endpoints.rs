//! API endpoint metadata and execution tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m15_api_endpoints -- --ignored
//! ```

mod common;

use async_graphql::Request as GraphqlRequest;
use atom::{
    api_endpoints::repo as api_endpoint_repo,
    auth::{encode_jwt, AuthContext},
    config::{Config, ADMIN_ENTITY_ID},
    graphql::build_schema,
    identity::repo as identity_repo,
    keys::{self, ActiveKeys},
    models::api_endpoint::{CreateApiEndpoint, ListApiEndpoints, UpdateApiEndpoint},
    routes::create_router,
    state::AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn state(pool: PgPool, keys: ActiveKeys) -> AppState {
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
    AppState::new(pool, config, keys)
}

async fn active_keys(pool: &PgPool) -> ActiveKeys {
    keys::rotate(pool).await.expect("rotate test signing key")
}

async fn admin_token(pool: &PgPool, keys: &ActiveKeys) -> String {
    let session = identity_repo::create_session(pool, common::admin_id(), 3600)
        .await
        .expect("create admin session");
    encode_jwt(
        common::admin_id(),
        session.id,
        None,
        &keys.primary,
        3600,
        "http://localhost:8080",
        "magistrala",
    )
    .expect("encode jwt")
}

fn authed(query: impl Into<String>) -> GraphqlRequest {
    GraphqlRequest::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
    })
}

fn endpoint_req(key: &str, path: &str, graphql: &str) -> CreateApiEndpoint {
    CreateApiEndpoint {
        tenant_id: None,
        key: key.into(),
        name: key.into(),
        description: Some("test endpoint".into()),
        method: "POST".into(),
        path: path.into(),
        operation_kind: "query".into(),
        graphql: graphql.into(),
        auth_mode: Some("caller_context".into()),
        service_entity_id: None,
        variables_mapping: json!({}),
        request_schema: json!({}),
        response_mapping: json!({}),
        status: Some("draft".into()),
    }
}

#[tokio::test]
#[ignore]
async fn repo_create_list_update_enable_and_disable_api_endpoint() {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();
    let path = format!("/api/custom/repo-{suffix}");

    let created = api_endpoint_repo::create_api_endpoint(
        &pool,
        endpoint_req(&format!("endpoint_repo_{suffix}"), &path, "{ health }"),
        Some(common::admin_id()),
    )
    .await
    .expect("create endpoint");
    assert_eq!(created.status, "draft");
    assert_eq!(created.operation_kind, "query");
    assert_eq!(created.graphql, "{ health }");

    let list = api_endpoint_repo::list_api_endpoints(
        &pool,
        ListApiEndpoints {
            tenant_id: None,
            status: Some("draft".into()),
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list endpoints");
    assert!(list.items.iter().any(|endpoint| endpoint.id == created.id));

    let updated = api_endpoint_repo::update_api_endpoint(
        &pool,
        created.id,
        UpdateApiEndpoint {
            key: None,
            name: Some("Updated endpoint".into()),
            description: None,
            method: None,
            path: None,
            operation_kind: Some("query".into()),
            graphql: Some("query Health { health }".into()),
            auth_mode: None,
            service_entity_id: None,
            variables_mapping: Some(json!({"input.name": "$body.name"})),
            request_schema: None,
            response_mapping: Some(json!({"data": "$.health"})),
            status: None,
        },
        Some(common::admin_id()),
    )
    .await
    .expect("update endpoint");
    assert_eq!(updated.name, "Updated endpoint");
    assert_eq!(updated.graphql, "query Health { health }");

    let enabled =
        api_endpoint_repo::enable_api_endpoint(&pool, created.id, Some(common::admin_id()))
            .await
            .expect("enable endpoint");
    assert_eq!(enabled.status, "active");

    let disabled =
        api_endpoint_repo::disable_api_endpoint(&pool, created.id, Some(common::admin_id()))
            .await
            .expect("disable endpoint");
    assert_eq!(disabled.status, "disabled");
}

#[tokio::test]
#[ignore]
async fn repo_rejects_invalid_path_duplicate_active_path_and_introspection_graphql() {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();

    let invalid = api_endpoint_repo::create_api_endpoint(
        &pool,
        endpoint_req(&format!("bad_path_{suffix}"), "/devices", "{ health }"),
        Some(common::admin_id()),
    )
    .await;
    assert!(invalid.is_err());

    let path = format!("/api/custom/duplicate-{suffix}");
    let mut first = endpoint_req(
        &format!("endpoint_duplicate_a_{suffix}"),
        &path,
        "{ health }",
    );
    first.status = Some("active".into());
    api_endpoint_repo::create_api_endpoint(&pool, first, Some(common::admin_id()))
        .await
        .expect("first active endpoint");
    let mut second = endpoint_req(
        &format!("endpoint_duplicate_b_{suffix}"),
        &path,
        "{ health }",
    );
    second.status = Some("active".into());
    let duplicate =
        api_endpoint_repo::create_api_endpoint(&pool, second, Some(common::admin_id())).await;
    assert!(duplicate.is_err());

    let introspection = api_endpoint_repo::create_api_endpoint(
        &pool,
        endpoint_req(
            &format!("endpoint_introspection_{suffix}"),
            &format!("/api/custom/introspection-{suffix}"),
            "query IntrospectionQuery { __schema { queryType { name } } }",
        ),
        Some(common::admin_id()),
    )
    .await;
    assert!(introspection.is_err());
}

#[tokio::test]
#[ignore]
async fn graphql_management_api_creates_lists_updates_enables_and_disables_endpoint() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool.clone(), active_keys(&pool).await));
    let suffix = Uuid::new_v4();
    let key = format!("endpoint_graphql_{suffix}");
    let path = format!("/api/custom/graphql-{suffix}");

    let create = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createApiEndpoint(input: {{
                key: "{key}",
                name: "GraphQL endpoint",
                method: "POST",
                path: "{path}",
                operationKind: "query",
                graphql: "{{ health }}",
                status: "draft"
              }}) {{
                id
                key
                operationKind
                graphql
                status
              }}
            }}
            "#
        )))
        .await;
    assert!(create.errors.is_empty(), "{:?}", create.errors);
    let create_json = create.data.into_json().expect("json");
    let id = create_json["createApiEndpoint"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    assert_eq!(create_json["createApiEndpoint"]["operationKind"], "query");
    assert_eq!(create_json["createApiEndpoint"]["graphql"], "{ health }");

    let list = schema
        .execute(authed(
            r#"
            {
              apiEndpoints(status: "draft", limit: 20) {
                items { key operationKind graphql status }
                total
              }
            }
            "#,
        ))
        .await;
    assert!(list.errors.is_empty(), "{:?}", list.errors);

    let update = schema
        .execute(authed(format!(
            r#"
            mutation {{
              updateApiEndpoint(id: "{id}", input: {{
                name: "Updated GraphQL endpoint",
                graphql: "query Health {{ health }}"
              }}) {{
                name
                graphql
              }}
            }}
            "#
        )))
        .await;
    assert!(update.errors.is_empty(), "{:?}", update.errors);
    assert_eq!(
        update.data.into_json().expect("json")["updateApiEndpoint"]["graphql"],
        "query Health { health }"
    );

    let enable = schema
        .execute(authed(format!(
            r#"mutation {{ enableApiEndpoint(id: "{id}") {{ status }} }}"#
        )))
        .await;
    assert!(enable.errors.is_empty(), "{:?}", enable.errors);
    assert_eq!(
        enable.data.into_json().expect("json")["enableApiEndpoint"]["status"],
        "active"
    );

    let disable = schema
        .execute(authed(format!(
            r#"mutation {{ disableApiEndpoint(id: "{id}") {{ status }} }}"#
        )))
        .await;
    assert!(disable.errors.is_empty(), "{:?}", disable.errors);
    assert_eq!(
        disable.data.into_json().expect("json")["disableApiEndpoint"]["status"],
        "disabled"
    );
}

#[tokio::test]
#[ignore]
async fn service_context_creation_requires_super_admin() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool.clone(), active_keys(&pool).await));
    let suffix = Uuid::new_v4();
    let ordinary_entity_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO entities (kind, name, status, attributes)
           VALUES ('human', $1, 'active', '{}')
           RETURNING id"#,
    )
    .bind(format!("endpoint-non-admin-{suffix}"))
    .fetch_one(&pool)
    .await
    .expect("ordinary entity");

    let response = schema
        .execute(
            GraphqlRequest::new(format!(
                r#"
                mutation {{
                  createApiEndpoint(input: {{
                    key: "endpoint_service_{suffix}",
                    name: "Service endpoint",
                    method: "POST",
                    path: "/api/custom/service-{suffix}",
                    operationKind: "query",
                    graphql: "{{ health }}",
                    authMode: "service_context",
                    serviceEntityId: "{ordinary_entity_id}"
                  }}) {{ id }}
                }}
                "#
            ))
            .data(AuthContext {
                entity_id: ordinary_entity_id,
                tenant_id: None,
                session_id: None,
            }),
        )
        .await;

    assert!(!response.errors.is_empty());
}

#[tokio::test]
#[ignore]
async fn custom_endpoint_route_runs_as_caller_and_writes_audit_row() {
    let pool = common::pool().await;
    let active_keys = active_keys(&pool).await;
    let token = admin_token(&pool, &active_keys).await;
    let state = state(pool.clone(), active_keys);
    let app = create_router(state);
    let suffix = Uuid::new_v4();
    let path = format!("/api/custom/caller-{suffix}");
    let mut req = endpoint_req(
        &format!("endpoint_caller_{suffix}"),
        &path,
        "query Caller($id: ID!) { session(id: $id) { entityId } }",
    );
    req.status = Some("active".into());
    req.variables_mapping = json!({"id": "$auth.sessionId"});
    req.response_mapping = json!({"data": "$.session"});
    let endpoint = api_endpoint_repo::create_api_endpoint(&pool, req, Some(common::admin_id()))
        .await
        .expect("create active endpoint");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["data"]["entityId"], common::admin_id().to_string());

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_endpoint_executions WHERE endpoint_id = $1 AND status = 'success'",
    )
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("audit count");
    assert!(count >= 1);
}

#[tokio::test]
#[ignore]
async fn custom_endpoint_unauthorized_caller_is_denied_and_audited() {
    let pool = common::pool().await;
    let active_keys = active_keys(&pool).await;
    let state = state(pool.clone(), active_keys);
    let app = create_router(state);
    let suffix = Uuid::new_v4();
    let path = format!("/api/custom/denied-{suffix}");
    let mut req = endpoint_req(&format!("endpoint_denied_{suffix}"), &path, "{ health }");
    req.status = Some("active".into());
    let endpoint = api_endpoint_repo::create_api_endpoint(&pool, req, Some(common::admin_id()))
        .await
        .expect("create active endpoint");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&path)
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_endpoint_executions WHERE endpoint_id = $1 AND status = 'denied'",
    )
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("audit count");
    assert!(count >= 1);
}
