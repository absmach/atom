use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use atom::{
    certs::enrollment::service::EnrollmentResponse,
    config::Config,
    health::{
        AuditRetentionStatus, ComponentCheck, ComponentStatus, DbPoolStatus, SigningKeyStatus,
        SystemStatus,
    },
    keys::{ActiveKeys, LoadedKey},
    models::session::LoginResponse,
    rate_limit::{RateLimitCategory, RateLimitPolicyStatus, RateLimitStatus},
    state::AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderValue, Method, Request, StatusCode},
};
use chrono::{TimeZone, Utc};
use jsonschema::JSONSchema;
use serde::Serialize;
use serde_json::json;
use serde_yaml::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

// These are the methods Atom explicitly mounts as application handlers. Axum
// synthesizes HEAD for GET routes, while tower-http answers CORS preflight
// OPTIONS requests. Those protocol/middleware behaviours are tested below but
// intentionally are not represented as distinct OpenAPI operations.
const EXPLICIT_APPLICATION_METHODS: [&str; 5] = ["delete", "get", "patch", "post", "put"];
const OPENAPI_OPERATION_METHODS: [&str; 9] = [
    "delete", "get", "head", "options", "patch", "post", "put", "trace", "connect",
];

#[test]
fn contract_openapi_inventory_matches_explicitly_mounted_application_methods() {
    assert_eq!(
        openapi_operations(),
        mounted_operations(),
        "apidocs/openapi.yaml must describe every explicitly mounted application method on the primary and enrollment HTTP routers"
    );
}

#[tokio::test]
async fn contract_axum_head_and_cors_options_are_protocol_generated() {
    let app = atom::routes::create_router(runtime_test_state());

    let head_response = app
        .clone()
        .oneshot(
            Request::head("/health/live")
                .body(Body::empty())
                .expect("HEAD request"),
        )
        .await
        .expect("HEAD response");
    assert_eq!(head_response.status(), StatusCode::OK);
    assert!(
        to_bytes(head_response.into_body(), usize::MAX)
            .await
            .expect("HEAD body")
            .is_empty(),
        "Axum must suppress the GET response body for implicit HEAD"
    );

    let options_response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/auth/login")
                .header(header::ORIGIN, "http://localhost:8080")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, Method::POST.as_str())
                .body(Body::empty())
                .expect("OPTIONS request"),
        )
        .await
        .expect("OPTIONS response");
    assert_eq!(options_response.status(), StatusCode::OK);
    assert_eq!(
        options_response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("http://localhost:8080"))
    );

    let document = openapi_document();
    assert!(document["paths"]["/health/live"]["head"].is_null());
    assert!(document["paths"]["/auth/login"]["options"].is_null());
}

#[test]
fn contract_json_extractor_rejection_statuses_are_documented() {
    let document = openapi_document();

    for path in [
        "/auth/signup",
        "/auth/login",
        "/auth/email/resend",
        "/auth/password/reset/request",
        "/auth/password/reset",
        "/auth/oauth/exchange",
        "/graphql",
        "/pki/enroll",
        "/pki/reenroll",
    ] {
        let responses = response_codes(&document, path, "post");
        assert!(
            responses.contains("400"),
            "{path} must document malformed JSON"
        );
        assert!(
            responses.contains("415"),
            "{path} must document a missing or invalid JSON Content-Type"
        );
        assert!(
            responses.contains("422"),
            "{path} must document DTO deserialization failures"
        );
    }
}

#[test]
fn contract_primary_http_middleware_statuses_are_documented() {
    let document = openapi_document();

    for (path, methods) in openapi_operations() {
        if path.starts_with("/pki/") || path.starts_with("/.well-known/est/") {
            continue;
        }
        for method in methods {
            let responses = response_codes(&document, &path, &method);
            assert!(
                responses.contains("408"),
                "{method} {path} must document the primary listener request timeout"
            );

            let rate_limited = path == "/graphql"
                || path == "/.well-known/jwks.json"
                || path.starts_with("/auth/")
                || path.starts_with("/certs/")
                || path.starts_with("/api/custom/");
            assert_eq!(
                responses.contains("429"),
                rate_limited,
                "{method} {path} rate-limit response must match the mounted middleware category"
            );
        }
    }
}

#[test]
fn contract_body_limited_primary_operations_document_payload_too_large() {
    let document = openapi_document();
    for (path, method) in [
        ("/auth/signup", "post"),
        ("/auth/login", "post"),
        ("/auth/email/resend", "post"),
        ("/auth/password/reset/request", "post"),
        ("/auth/password/reset", "post"),
        ("/auth/oauth/exchange", "post"),
        ("/graphql", "post"),
        ("/certs/issuers/{issuer_id}/ocsp", "post"),
        ("/api/custom/{path}", "get"),
        ("/api/custom/{path}", "post"),
        ("/api/custom/{path}", "put"),
        ("/api/custom/{path}", "patch"),
        ("/api/custom/{path}", "delete"),
    ] {
        assert!(
            response_codes(&document, path, method).contains("413"),
            "{method} {path} must document its request body limit"
        );
    }
}

#[tokio::test]
async fn contract_primary_http_middleware_uses_documented_statuses() {
    let mut body_limit_state = runtime_test_state();
    body_limit_state.config.body_limits.auth_bytes = 1;
    let body_limit_response = atom::routes::create_router(body_limit_state)
        .oneshot(
            Request::post("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .expect("body-limit request"),
        )
        .await
        .expect("body-limit response");
    assert_eq!(body_limit_response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let mut rate_limit_state = runtime_test_state();
    rate_limit_state.config.rate_limits.enabled = true;
    rate_limit_state
        .config
        .rate_limits
        .public_routes
        .max_requests = 0;
    let rate_limit_response = atom::routes::create_router(rate_limit_state)
        .oneshot(
            Request::get("/.well-known/jwks.json")
                .body(Body::empty())
                .expect("rate-limit request"),
        )
        .await
        .expect("rate-limit response");
    assert_eq!(rate_limit_response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rate_limit_response
        .headers()
        .contains_key(header::RETRY_AFTER));

    let mut timeout_state = runtime_test_state();
    timeout_state.config.http_server.request_timeout_secs = 1;
    // Hold the signing-key write lock so the login handler deterministically
    // remains in flight past the configured total request deadline. A zero
    // duration races handlers that can immediately return their own response
    // and therefore does not prove the timeout response contract.
    let key_lock = timeout_state.keys.clone();
    let key_guard = key_lock.write().await;
    let timeout_response = atom::routes::create_router(timeout_state)
        .oneshot(
            Request::post("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"identifier":"timeout-test","secret":"not-used","kind":"password"}"#,
                ))
                .expect("timeout request"),
        )
        .await
        .expect("timeout response");
    drop(key_guard);
    assert_eq!(timeout_response.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn contract_login_route_uses_documented_axum_json_rejection_statuses() {
    for (content_type, body, expected) in [
        (
            None,
            r#"{"identifier":"alice","secret":"secret"}"#,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (Some("application/json"), "{", StatusCode::BAD_REQUEST),
        (
            Some("application/json"),
            "{}",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let mut request = Request::post("/auth/login");
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = atom::routes::create_router(runtime_test_state())
            .oneshot(request.body(Body::from(body)).expect("login request"))
            .await
            .expect("login response");
        assert_eq!(response.status(), expected, "body: {body}");
    }
}

#[tokio::test]
async fn contract_graphql_route_uses_documented_json_request_shape() {
    for (content_type, body, expected) in [
        (
            None,
            r#"{"query":"query Contract { health }"}"#,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            Some("text/plain"),
            r#"{"query":"query Contract { health }"}"#,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            Some("multipart/form-data; boundary=contract"),
            "--contract--",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (Some("application/json"), "{", StatusCode::BAD_REQUEST),
        (
            Some("application/json"),
            "{}",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Some("application/json"),
            r#"{"query":null}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Some("application/json"),
            "[]",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Some("application/json"),
            r#"{"query":"query Contract { health }","operationName":"Contract","variables":null,"extensions":{"contract":"v1"}}"#,
            StatusCode::OK,
        ),
        (
            Some("application/json"),
            r#"{"query":"query Contract { health }","operationName":"Contract","variables":{},"extensions":null}"#,
            StatusCode::OK,
        ),
    ] {
        let mut request = Request::post("/graphql");
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = atom::routes::create_router(runtime_test_state())
            .oneshot(request.body(Body::from(body)).expect("GraphQL request"))
            .await
            .expect("GraphQL response");
        assert_eq!(response.status(), expected, "body: {body}");
    }
}

#[tokio::test]
async fn contract_axum_query_and_uuid_path_rejections_are_plain_text_bad_requests() {
    for request in [
        Request::get("/auth/email/verify")
            .body(Body::empty())
            .expect("missing-query request"),
        Request::get("/certs/issuers/not-a-uuid/crl")
            .body(Body::empty())
            .expect("invalid CRL issuer request"),
        Request::post("/certs/issuers/not-a-uuid/ocsp")
            .body(Body::empty())
            .expect("invalid OCSP issuer request"),
    ] {
        let response = atom::routes::create_router(runtime_test_state())
            .oneshot(request)
            .await
            .expect("extractor rejection response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
    }
}

#[tokio::test]
async fn contract_graphql_authentication_failures_use_graphql_errors_with_http_200() {
    for request in [
        Request::post("/graphql")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer not-a-token")
            .body(Body::from(r#"{"query":"{ health }"}"#))
            .expect("invalid bearer request"),
        Request::post("/graphql")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, "atom_token=not-a-token")
            .body(Body::from(r#"{"query":"{ health }"}"#))
            .expect("untrusted cookie-origin request"),
    ] {
        let response = atom::routes::create_router(runtime_test_state())
            .oneshot(request)
            .await
            .expect("GraphQL authentication error response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("GraphQL error body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("GraphQL JSON body");
        assert!(
            body["errors"]
                .as_array()
                .is_some_and(|errors| !errors.is_empty()),
            "GraphQL transport error must be returned in the errors array: {body}"
        );
    }
}

#[test]
fn contract_openapi_documents_enrollment_authentication_modes() {
    let document = openapi_document();

    assert_eq!(
        security_schemes(&document, "/pki/enroll", "post"),
        BTreeSet::from(["bearerAuth", "cookieAuth"])
    );
    assert_client_certificate_required(&document, "/pki/reenroll", "post");

    for path in [
        "/.well-known/est/simpleenroll",
        "/.well-known/est/serverkeygen",
        "/.well-known/est/csrattrs",
    ] {
        assert_eq!(
            security_schemes(&document, path, operation_method(path)),
            BTreeSet::from(["basicAuth", "bearerAuth"]),
            "{path} must document exactly HTTP Basic or Bearer authentication"
        );
    }
    assert_client_certificate_required(&document, "/.well-known/est/simplereenroll", "post");
    assert!(
        security_schemes(&document, "/.well-known/est/cacerts", "get").is_empty(),
        "EST cacerts is public"
    );
}

#[test]
fn contract_public_runtime_dtos_validate_against_openapi_components() {
    let document = openapi_document();
    let instant = Utc
        .with_ymd_and_hms(2026, 8, 28, 12, 34, 56)
        .single()
        .expect("valid timestamp");
    let entity_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("UUID");
    let session_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("UUID");
    let credential_id = Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("UUID");
    let tenant_id = Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("UUID");
    let issuer_id = Uuid::parse_str("55555555-5555-4555-8555-555555555555").expect("UUID");
    let profile_id = Uuid::parse_str("66666666-6666-4666-8666-666666666666").expect("UUID");

    let login = LoginResponse {
        token: "signed-token".into(),
        entity_id,
        session_id,
        expires_at: instant,
        email_verified: Some(true),
        verification_required: true,
    };
    assert_runtime_value_matches_component(&document, "LoginResponse", &login, true);

    let omitted_login_fields = serde_json::to_value(LoginResponse {
        token: "signed-token".into(),
        entity_id,
        session_id,
        expires_at: instant,
        email_verified: None,
        verification_required: false,
    })
    .expect("LoginResponse serializes");
    assert!(omitted_login_fields.get("email_verified").is_none());
    assert!(omitted_login_fields.get("verification_required").is_none());
    let login_required =
        string_set(&document["components"]["schemas"]["LoginResponse"]["required"]);
    assert!(!login_required.contains("email_verified"));
    assert!(!login_required.contains("verification_required"));
    assert_runtime_value_matches_component_value(
        &document,
        "LoginResponse",
        &omitted_login_fields,
        false,
    );

    let system_status = SystemStatus {
        version: "1.0.0",
        revision: "runtime-only-build-identity",
        status: ComponentStatus::Ok,
        http_ready: component_check(ComponentStatus::Ok),
        grpc_ready: component_check(ComponentStatus::Ok),
        database: component_check(ComponentStatus::Ok),
        migrations: component_check(ComponentStatus::Ok),
        signing_keys: component_check(ComponentStatus::Ok),
        certificate_issuer: component_check(ComponentStatus::Ok),
        cache: component_check(ComponentStatus::Disabled),
        db_pool: DbPoolStatus {
            max_connections: 16,
            min_connections: 1,
            acquire_timeout_secs: 5,
            connect_timeout_secs: 5,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1_800,
            size: 2,
            idle: 1,
        },
        signing_key_state: Some(SigningKeyStatus {
            configured_key_id: "primary".into(),
            encrypted_count: 2,
            plaintext_count: 0,
            total_count: 2,
            plaintext_allowed: false,
        }),
        audit_retention: AuditRetentionStatus {
            enabled: true,
            days: 90,
            cleanup_interval_secs: 3_600,
            cleanup_batch_size: 1_000,
            last_cleanup: Some(json!({"deleted": 4})),
        },
        rate_limits: RateLimitStatus {
            enabled: true,
            policies: vec![RateLimitPolicyStatus {
                category: RateLimitCategory::AuthRoutes,
                max_requests: 100,
                window_secs: 60,
            }],
            trusted_proxy_cidrs: vec!["10.0.0.0/8".into()],
        },
    };
    assert_runtime_value_matches_component(&document, "SystemStatus", &system_status, true);
    let serialized_status = serde_json::to_value(&system_status).expect("SystemStatus serializes");
    assert!(serialized_status.get("version").is_none());
    assert!(serialized_status.get("revision").is_none());

    let enrollment = EnrollmentResponse {
        credential_id,
        entity_id,
        tenant_id: Some(tenant_id),
        issuer_id,
        profile_id,
        profile_name: "device".into(),
        identity_uri: "spiffe://atom.example/tenant/device".into(),
        serial_number: "01ab".into(),
        certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n".into(),
        chain_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n".into(),
        not_after: instant,
        renewal_threshold_seconds: 86_400,
        renewal_due_at: instant,
        idempotent_replay: false,
    };
    assert_runtime_value_matches_component(&document, "EnrollmentResponse", &enrollment, true);
}

#[test]
fn contract_every_openapi_operation_has_a_stable_id_and_success_response() {
    let document = openapi_document();
    for (path, path_item) in document["paths"].as_mapping().expect("OpenAPI paths map") {
        let path = path.as_str().expect("string path");
        let path_item = path_item.as_mapping().expect("path item map");
        for (method, operation) in path_item {
            let Some(method) = method.as_str() else {
                continue;
            };
            if !OPENAPI_OPERATION_METHODS.contains(&method) {
                continue;
            }
            assert!(
                operation["operationId"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty()),
                "{method} {path} must have an operationId"
            );
            let responses = operation["responses"]
                .as_mapping()
                .unwrap_or_else(|| panic!("{method} {path} must have responses"));
            assert!(
                responses
                    .keys()
                    .filter_map(Value::as_str)
                    .any(|status| status.starts_with('2') || status.starts_with('3')),
                "{method} {path} must document a success or redirect status"
            );
        }
    }
}

fn openapi_document() -> Value {
    serde_yaml::from_str(include_str!("../apidocs/openapi.yaml")).expect("valid OpenAPI YAML")
}

fn openapi_operations() -> BTreeMap<String, BTreeSet<String>> {
    let document = openapi_document();
    document["paths"]
        .as_mapping()
        .expect("OpenAPI paths map")
        .iter()
        .map(|(path, path_item)| {
            let methods = path_item
                .as_mapping()
                .expect("path item map")
                .keys()
                .filter_map(Value::as_str)
                .filter(|key| EXPLICIT_APPLICATION_METHODS.contains(key))
                .map(ToOwned::to_owned)
                .collect();
            (
                path.as_str().expect("string OpenAPI path").to_string(),
                methods,
            )
        })
        .collect()
}

fn mounted_operations() -> BTreeMap<String, BTreeSet<String>> {
    let mut operations = BTreeMap::new();
    for source in [
        include_str!("../src/routes.rs"),
        include_str!("../src/certs/enrollment/http.rs"),
        include_str!("../src/certs/enrollment/est.rs"),
    ] {
        for (path, methods) in routes_from_source(source) {
            let previous = operations.insert(path.clone(), methods);
            assert!(previous.is_none(), "route {path} is mounted more than once");
        }
    }
    operations
}

fn routes_from_source(source: &str) -> BTreeMap<String, BTreeSet<String>> {
    let production = source.split("#[cfg(test)]").next().expect("source prefix");
    production
        .split(".route(")
        .skip(1)
        .map(|tail| {
            let start = tail.find('"').expect("route path starts with a quote") + 1;
            let end = tail[start..]
                .find('"')
                .map(|offset| start + offset)
                .expect("route path ends with a quote");
            let methods = EXPLICIT_APPLICATION_METHODS
                .iter()
                .filter(|method| tail.contains(&format!("{method}(")))
                .map(|method| (*method).to_string())
                .collect::<BTreeSet<_>>();
            assert!(
                !methods.is_empty(),
                "route {} has no parsed application method",
                &tail[start..end]
            );
            (openapi_path(&tail[start..end]), methods)
        })
        .collect()
}

fn response_codes(document: &Value, path: &str, method: &str) -> BTreeSet<String> {
    document["paths"][path][method]["responses"]
        .as_mapping()
        .unwrap_or_else(|| panic!("responses for {method} {path}"))
        .keys()
        .map(|status| status.as_str().expect("string response status").to_string())
        .collect()
}

fn security_schemes<'a>(document: &'a Value, path: &str, method: &str) -> BTreeSet<&'a str> {
    document["paths"][path][method]["security"]
        .as_sequence()
        .into_iter()
        .flatten()
        .flat_map(|requirement| {
            requirement
                .as_mapping()
                .expect("security requirement map")
                .keys()
                .map(|scheme| scheme.as_str().expect("string security scheme"))
        })
        .collect()
}

fn assert_client_certificate_required(document: &Value, path: &str, method: &str) {
    assert!(security_schemes(document, path, method).is_empty());
    assert_eq!(
        document["paths"][path][method]["x-atom-client-certificate-required"].as_bool(),
        Some(true),
        "{method} {path} must authenticate the certificate at the TLS transport"
    );
}

fn assert_runtime_value_matches_component(
    document: &Value,
    component: &str,
    value: &impl Serialize,
    expect_every_property: bool,
) {
    let value = serde_json::to_value(value)
        .unwrap_or_else(|error| panic!("{component} runtime value serializes: {error}"));
    assert_runtime_value_matches_component_value(
        document,
        component,
        &value,
        expect_every_property,
    );
}

fn assert_runtime_value_matches_component_value(
    document: &Value,
    component: &str,
    value: &serde_json::Value,
    expect_every_property: bool,
) {
    let component_schema = &document["components"]["schemas"][component];
    let documented_properties = component_schema["properties"]
        .as_mapping()
        .unwrap_or_else(|| panic!("{component} properties"))
        .keys()
        .map(|key| key.as_str().expect("string property"))
        .collect::<BTreeSet<_>>();
    let runtime_properties = value
        .as_object()
        .unwrap_or_else(|| panic!("{component} must serialize as an object"))
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = string_set(&component_schema["required"]);

    assert!(
        required.is_subset(&runtime_properties),
        "{component} serialization omitted required fields: {:?}",
        required.difference(&runtime_properties).collect::<Vec<_>>()
    );
    assert!(
        runtime_properties.is_subset(&documented_properties),
        "{component} serialized undocumented fields: {:?}",
        runtime_properties
            .difference(&documented_properties)
            .collect::<Vec<_>>()
    );
    if expect_every_property {
        assert_eq!(runtime_properties, documented_properties);
    }

    let schemas = serde_json::to_value(&document["components"]["schemas"])
        .expect("OpenAPI component schemas convert to JSON");
    let schema = json!({
        "$ref": format!("#/components/schemas/{component}"),
        "components": { "schemas": schemas },
    });
    let compiled = JSONSchema::compile(&schema)
        .unwrap_or_else(|error| panic!("compile {component} OpenAPI schema: {error}"));
    if let Err(errors) = compiled.validate(value) {
        let errors = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("{component} runtime serialization violates OpenAPI: {errors:?}");
    };
}

fn component_check(status: ComponentStatus) -> ComponentCheck {
    ComponentCheck {
        status,
        message: "contract specimen".into(),
    }
}

fn operation_method(path: &str) -> &str {
    if path.ends_with("csrattrs") {
        "get"
    } else {
        "post"
    }
}

fn string_set(value: &Value) -> BTreeSet<&str> {
    value
        .as_sequence()
        .expect("string sequence")
        .iter()
        .map(|item| item.as_str().expect("string item"))
        .collect()
}

fn openapi_path(axum_path: &str) -> String {
    axum_path
        .split('/')
        .map(|segment| match segment.as_bytes().first() {
            Some(b':') | Some(b'*') => format!("{{{}}}", &segment[1..]),
            _ => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn runtime_test_state() -> AppState {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(10))
        .connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(9)
                .username("atom")
                .password("atom")
                .database("atom_contract_test"),
        );
    let primary = LoadedKey {
        kid: "contract-test".into(),
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
