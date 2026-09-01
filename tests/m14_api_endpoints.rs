//! API endpoint metadata and execution tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m14_api_endpoints -- --ignored
//! ```

mod common;

use async_graphql::Request as GraphqlRequest;
use atom::{
    api_endpoints::repo as api_endpoint_repo,
    auth::{encode_jwt, has_capability_in_scope, has_global_manage, AuthContext, Scope},
    authz::repo as authz_repo,
    config::Config,
    graphql::build_schema,
    identity::repo as identity_repo,
    keys::{self, ActiveKeys},
    models::{
        api_endpoint::{CreateApiEndpoint, ListApiEndpoints, UpdateApiEndpoint},
        enums::{Effect, SubjectKind},
        policy::{CreatePermissionBlock, CreateRoleAssignment},
        role::CreateRole,
    },
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
    let config = Config::for_tests();
    AppState::new(pool, config, keys, None)
}

async fn active_keys(pool: &PgPool) -> ActiveKeys {
    keys::rotate(pool, &Config::for_tests().signing_keys)
        .await
        .expect("rotate test signing key")
}

async fn admin_token(pool: &PgPool, keys: &ActiveKeys) -> String {
    token_for_entity(pool, keys, common::admin_id()).await
}

async fn token_for_entity(pool: &PgPool, keys: &ActiveKeys, entity_id: Uuid) -> String {
    let session = identity_repo::create_session(pool, entity_id, 3600)
        .await
        .expect("create session");
    encode_jwt(
        entity_id,
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
        ..Default::default()
    })
}

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> GraphqlRequest {
    GraphqlRequest::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
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

async fn tenant_manager(pool: &PgPool) -> (Uuid, Uuid) {
    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("endpoint-tenant-{tenant_id}"))
        .execute(pool)
        .await
        .expect("insert tenant");

    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, 'human', $2, $3, 'active')",
    )
    .bind(entity_id)
    .bind(format!("endpoint-manager-{entity_id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert tenant manager");

    let manage_action_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage'")
        .fetch_one(pool)
        .await
        .expect("seeded manage action");
    let role = authz_repo::create_role(
        pool,
        CreateRole {
            name: format!("endpoint-manager-{entity_id}"),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create tenant-manager role");
    let block = authz_repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "tenant".into(),
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({}),
            action_ids: vec![manage_action_id],
        },
    )
    .await
    .expect("create tenant-manage block");
    authz_repo::replace_role_permission_block_links(pool, role.id, &[block.id])
        .await
        .expect("link tenant-manage block");
    authz_repo::create_role_assignment(
        pool,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            role_id: role.id,
        },
    )
    .await
    .expect("assign tenant-manager role");

    (tenant_id, entity_id)
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
async fn graphql_endpoint_authorization_masks_oracles_and_preserves_missing_results() {
    let pool = common::pool().await;
    let active_keys = active_keys(&pool).await;
    let suffix = Uuid::new_v4();
    let endpoint = api_endpoint_repo::create_api_endpoint(
        &pool,
        endpoint_req(
            &format!("endpoint_graphql_oracle_{suffix}"),
            &format!("/api/custom/graphql-oracle-{suffix}"),
            "{ health }",
        ),
        Some(common::admin_id()),
    )
    .await
    .expect("create endpoint");
    let outsider: Uuid = sqlx::query_scalar(
        r#"INSERT INTO entities (kind, name, status, attributes)
           VALUES ('human', $1, 'active', '{}')
           RETURNING id"#,
    )
    .bind(format!("endpoint-graphql-outsider-{suffix}"))
    .fetch_one(&pool)
    .await
    .expect("ordinary entity");
    let missing_id = Uuid::new_v4();
    let schema = build_schema(state(pool, active_keys));

    for id in [endpoint.id, missing_id] {
        let response = schema
            .execute(authed_as(
                outsider,
                format!("{{ apiEndpoint(id: \"{id}\") {{ id }} }}"),
            ))
            .await;
        assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
        assert_eq!(response.errors[0].message, "forbidden");
    }

    let outsider_list = schema
        .execute(authed_as(
            outsider,
            "{ apiEndpoints { items { id } total } }",
        ))
        .await;
    assert!(
        outsider_list.errors.is_empty(),
        "{:?}",
        outsider_list.errors
    );
    let outsider_data = outsider_list.data.into_json().expect("json data");
    assert_eq!(outsider_data["apiEndpoints"]["total"], 0);
    assert_eq!(
        outsider_data["apiEndpoints"]["items"],
        serde_json::json!([])
    );

    let admin_missing = schema
        .execute(authed(format!(
            "{{ apiEndpoint(id: \"{missing_id}\") {{ id }} }}"
        )))
        .await;
    assert_eq!(admin_missing.errors.len(), 1, "{:?}", admin_missing.errors);
    assert_eq!(
        admin_missing.errors[0].message,
        format!("api endpoint {missing_id} not found")
    );

    let missing_executions = schema
        .execute(authed(format!(
            "{{ apiEndpointExecutions(endpointId: \"{missing_id}\") {{ items {{ id }} total }} }}"
        )))
        .await;
    assert!(
        missing_executions.errors.is_empty(),
        "{:?}",
        missing_executions.errors
    );
    let execution_data = missing_executions.data.into_json().expect("json data");
    assert_eq!(execution_data["apiEndpointExecutions"]["total"], 0);
    assert_eq!(
        execution_data["apiEndpointExecutions"]["items"],
        serde_json::json!([])
    );
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

    let direct_list = authz_repo::list_api_endpoints_authorized(
        &pool,
        &AuthContext {
            entity_id: common::admin_id(),
            tenant_id: None,
            session_id: None,
            ..Default::default()
        },
        ListApiEndpoints {
            tenant_id: None,
            status: Some("draft".into()),
            limit: 20,
            offset: 0,
        },
    )
    .await;
    assert!(direct_list.is_ok(), "{direct_list:?}");

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
async fn service_context_management_requires_platform_admin() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool.clone(), active_keys(&pool).await));
    let suffix = Uuid::new_v4();
    let (tenant_id, tenant_manager_id) = tenant_manager(&pool).await;
    let tenant_manager_auth = AuthContext {
        entity_id: tenant_manager_id,
        tenant_id: Some(tenant_id),
        session_id: None,
        ..Default::default()
    };
    assert!(has_capability_in_scope(
        &pool,
        &tenant_manager_auth,
        "manage",
        Scope::Tenant(tenant_id),
    )
    .await
    .expect("check tenant manage"));
    assert!(!has_global_manage(&pool, &tenant_manager_auth)
        .await
        .expect("check platform manage"));
    let rejected_key = format!("endpoint_service_rejected_{suffix}");

    let response = schema
        .execute(
            GraphqlRequest::new(format!(
                r#"
                mutation {{
                  createApiEndpoint(input: {{
                    tenantId: "{tenant_id}",
                    key: "{rejected_key}",
                    name: "Service endpoint",
                    method: "POST",
                    path: "/api/custom/service-{suffix}",
                    operationKind: "query",
                    graphql: "{{ health }}",
                    authMode: "service_context",
                    serviceEntityId: "{}"
                  }}) {{ id }}
                }}
                "#,
                common::admin_id()
            ))
            .data(tenant_manager_auth),
        )
        .await;

    assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
    assert_eq!(response.errors[0].message, "forbidden");
    let rejected_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_endpoints WHERE key = $1")
            .bind(&rejected_key)
            .fetch_one(&pool)
            .await
            .expect("count rejected endpoint");
    assert_eq!(rejected_count, 0);

    let caller_path = format!("/api/custom/caller-transition-{suffix}");
    let mut caller_req = endpoint_req(
        &format!("endpoint_caller_transition_{suffix}"),
        &caller_path,
        "{ health }",
    );
    caller_req.tenant_id = Some(tenant_id);
    let caller_endpoint =
        api_endpoint_repo::create_api_endpoint(&pool, caller_req, Some(common::admin_id()))
            .await
            .expect("create caller-context endpoint");
    let transition = schema
        .execute(authed_as(
            tenant_manager_id,
            format!(
                r#"mutation {{ updateApiEndpoint(id: "{}", input: {{ authMode: "service_context", serviceEntityId: "{}" }}) {{ id }} }}"#,
                caller_endpoint.id,
                common::admin_id()
            ),
        ))
        .await;
    assert_eq!(transition.errors.len(), 1, "{:?}", transition.errors);
    assert_eq!(transition.errors[0].message, "forbidden");
    let unchanged_caller = api_endpoint_repo::get_api_endpoint(&pool, caller_endpoint.id)
        .await
        .expect("load unchanged caller-context endpoint");
    assert_eq!(unchanged_caller.auth_mode, "caller_context");
    assert_eq!(unchanged_caller.service_entity_id, None);

    let create = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createApiEndpoint(input: {{
                tenantId: "{tenant_id}",
                key: "endpoint_service_trusted_{suffix}",
                name: "Trusted service endpoint",
                method: "POST",
                path: "/api/custom/service-trusted-{suffix}",
                operationKind: "query",
                graphql: "{{ health }}",
                authMode: "service_context",
                serviceEntityId: "{}"
              }}) {{ id authMode serviceEntityId status }}
            }}
            "#,
            common::admin_id()
        )))
        .await;
    assert!(create.errors.is_empty(), "{:?}", create.errors);
    let created = create.data.into_json().expect("create json");
    let endpoint_id = created["createApiEndpoint"]["id"]
        .as_str()
        .expect("endpoint id")
        .parse::<Uuid>()
        .expect("endpoint UUID");
    assert_eq!(created["createApiEndpoint"]["authMode"], "service_context");
    assert_eq!(
        created["createApiEndpoint"]["serviceEntityId"],
        common::admin_id().to_string()
    );

    for mutation in [
        format!(
            r#"mutation {{ updateApiEndpoint(id: "{endpoint_id}", input: {{ graphql: "query Changed {{ health }}" }}) {{ id }} }}"#
        ),
        format!(r#"mutation {{ enableApiEndpoint(id: "{endpoint_id}") {{ id }} }}"#),
        format!(r#"mutation {{ disableApiEndpoint(id: "{endpoint_id}") {{ id }} }}"#),
    ] {
        let denied = schema.execute(authed_as(tenant_manager_id, mutation)).await;
        assert_eq!(denied.errors.len(), 1, "{:?}", denied.errors);
        assert_eq!(denied.errors[0].message, "forbidden");
    }

    let unchanged = api_endpoint_repo::get_api_endpoint(&pool, endpoint_id)
        .await
        .expect("load unchanged endpoint");
    assert_eq!(unchanged.graphql, "{ health }");
    assert_eq!(unchanged.status, "draft");

    let update = schema
        .execute(authed(format!(
            r#"mutation {{ updateApiEndpoint(id: "{endpoint_id}", input: {{ graphql: "query Trusted {{ health }}" }}) {{ graphql }} }}"#
        )))
        .await;
    assert!(update.errors.is_empty(), "{:?}", update.errors);
    assert_eq!(
        update.data.into_json().expect("update json")["updateApiEndpoint"]["graphql"],
        "query Trusted { health }"
    );

    let enable = schema
        .execute(authed(format!(
            r#"mutation {{ enableApiEndpoint(id: "{endpoint_id}") {{ status }} }}"#
        )))
        .await;
    assert!(enable.errors.is_empty(), "{:?}", enable.errors);
    assert_eq!(
        enable.data.into_json().expect("enable json")["enableApiEndpoint"]["status"],
        "active"
    );
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
        .clone()
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
        .clone()
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
    let missing_path = format!("/api/custom/missing-{suffix}");
    let missing = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&missing_path)
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .expect("missing request"),
        )
        .await
        .expect("missing response");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let associated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_endpoint_executions WHERE endpoint_id = $1 AND status = 'denied'",
    )
    .bind(endpoint.id)
    .fetch_one(&pool)
    .await
    .expect("associated audit count");
    assert_eq!(
        associated, 0,
        "pre-auth denial must not reveal an endpoint id"
    );
    let anonymous: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM api_endpoint_executions
           WHERE endpoint_id IS NULL AND caller_entity_id IS NULL AND status = 'denied'
             AND request_summary->>'path' = ANY($1::text[])"#,
    )
    .bind(vec![path, missing_path])
    .fetch_one(&pool)
    .await
    .expect("anonymous audit count");
    assert_eq!(anonymous, 2);
}

#[tokio::test]
#[ignore]
async fn custom_endpoint_authenticated_denial_does_not_reveal_path_existence() {
    let pool = common::pool().await;
    let active_keys = active_keys(&pool).await;
    let suffix = Uuid::new_v4();
    let caller_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO entities (kind, name, status, attributes)
           VALUES ('human', $1, 'active', '{}')
           RETURNING id"#,
    )
    .bind(format!("endpoint-unprivileged-{suffix}"))
    .fetch_one(&pool)
    .await
    .expect("ordinary entity");
    let token = token_for_entity(&pool, &active_keys, caller_id).await;
    let app = create_router(state(pool.clone(), active_keys));

    let existing_path = format!("/api/custom/private-{suffix}");
    let mut req = endpoint_req(
        &format!("endpoint_private_{suffix}"),
        &existing_path,
        "{ health }",
    );
    req.status = Some("active".into());
    let endpoint = api_endpoint_repo::create_api_endpoint(&pool, req, Some(common::admin_id()))
        .await
        .expect("create active endpoint");
    let missing_path = format!("/api/custom/missing-private-{suffix}");

    for path in [&existing_path, &missing_path] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let existing_denial: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_endpoint_executions WHERE endpoint_id = $1 AND caller_entity_id = $2 AND status = 'denied'",
    )
    .bind(endpoint.id)
    .bind(caller_id)
    .fetch_one(&pool)
    .await
    .expect("existing denial audit count");
    assert_eq!(existing_denial, 1);

    let missing_denial: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM api_endpoint_executions
           WHERE endpoint_id IS NULL AND caller_entity_id = $1 AND status = 'denied'
             AND request_summary->>'path' = $2"#,
    )
    .bind(caller_id)
    .bind(missing_path)
    .fetch_one(&pool)
    .await
    .expect("missing denial audit count");
    assert_eq!(missing_denial, 1);
}
