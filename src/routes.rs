use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderValue, Method},
    middleware,
    response::IntoResponse,
    routing::{any, get, post},
    Extension, Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    api_endpoints::handlers as api_endpoints, certs, graphql, health,
    identity::handlers as identity, keys, rate_limit, state::AppState,
};

pub fn create_router(state: AppState) -> Router {
    let graphql_schema = graphql::build_schema(state.clone());
    let cors_origins = state
        .config
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| {
            HeaderValue::from_str(origin).map_or_else(
                |err| {
                    tracing::warn!(origin, error = %err, "skipping invalid CORS origin");
                    None
                },
                Some,
            )
        })
        .collect::<Vec<_>>();
    let mut cors = CorsLayer::new()
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);
    if !cors_origins.is_empty() {
        cors = cors.allow_origin(AllowOrigin::list(cors_origins));
    }

    let auth_body_limit = state.config.body_limits.auth_bytes;
    let graphql_body_limit = state.config.body_limits.graphql_bytes;
    let custom_body_limit = state.config.body_limits.custom_endpoint_bytes;
    let rate_limit_state = state.clone();

    let app = Router::new()
        // JWKS — unauthenticated, consumed by external verifiers
        .route("/.well-known/jwks.json", get(keys::jwks))
        // Health
        .route("/health", get(health::legacy_health))
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        // Public PKI artifacts
        .route("/certs/ca-chain", get(certs::http::ca_chain))
        .route("/certs/crl", get(certs::http::crl))
        .route("/certs/ocsp", post(certs::http::ocsp))
        // GraphQL
        .route(
            "/graphql",
            post(graphql::graphql_handler).layer(DefaultBodyLimit::max(graphql_body_limit)),
        )
        // Custom API endpoint executor
        .route(
            "/api/custom/*path",
            any(api_endpoints::custom_endpoint).layer(DefaultBodyLimit::max(custom_body_limit)),
        )
        // Auth
        .route("/auth/public-config", get(identity::public_auth_config))
        .route(
            "/auth/signup",
            post(identity::signup).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route(
            "/auth/login",
            post(identity::login).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route("/auth/email/verify", get(identity::verify_email))
        .route(
            "/auth/email/resend",
            post(identity::resend_verification).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route(
            "/auth/password/reset/request",
            post(identity::request_password_reset).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route(
            "/auth/password/reset",
            post(identity::reset_password).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route("/auth/oauth/:provider/start", get(identity::oauth_start))
        .route(
            "/auth/oauth/:provider/callback",
            get(identity::oauth_callback),
        )
        .route(
            "/auth/oauth/exchange",
            post(identity::oauth_exchange).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route(
            "/auth/logout",
            post(identity::logout).layer(DefaultBodyLimit::max(auth_body_limit)),
        )
        .route("/auth/introspect", get(identity::introspect))
        .route("/auth/session", get(identity::current_session))
        .route("/auth/sessions/:id", get(identity::get_session))
        .route(
            "/auth/keys/rotate",
            post(keys::rotate_keys).layer(DefaultBodyLimit::max(auth_body_limit)),
        );

    // Prometheus scrape endpoint. Mounted only when metrics are enabled. It
    // exposes internal operational data and is unauthenticated by design — it
    // must be network-restricted to the scraper (firewall / mesh / private
    // network), see AGENTS.md.
    let app = if state.config.metrics.enabled {
        app.route("/metrics", get(metrics_handler))
    } else {
        app
    };

    app.with_state(state)
        .layer(Extension(graphql_schema))
        .layer(middleware::from_fn_with_state(
            rate_limit_state,
            rate_limit::middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        crate::metrics::render(&state.pool),
    )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use crate::{
        config::{Config, OidcProviderConfig},
        keys::{ActiveKeys, LoadedKey},
        state::AppState,
    };

    use super::create_router;

    #[tokio::test]
    async fn catalog_authz_audit_admin_rest_routes_are_not_registered() {
        let app = create_router(test_state());

        for (method, uri) in [
            ("GET", "/tenants"),
            ("GET", "/entities"),
            ("GET", "/groups"),
            ("GET", "/resources"),
            ("GET", "/roles"),
            ("GET", "/capabilities"),
            ("GET", "/policies"),
            ("GET", "/profiles"),
            ("POST", "/authz/check"),
            ("POST", "/authz/check/bulk"),
            ("POST", "/authz/explain"),
            ("GET", "/audit"),
            ("GET", "/admin/orphan-policies"),
            ("GET", "/admin/unprotected-resources"),
            ("GET", "/admin/expiring-credentials"),
            ("GET", "/graphql/console"),
            ("GET", "/graphql/console/groups"),
            ("GET", "/graphql/playground"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn legacy_graphql_playground_route_is_not_registered() {
        let app = create_router(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/graphql/playground")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn signup_route_respects_disabled_self_registration() {
        let app = create_router(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/signup")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"alice","email":"alice@example.test","password":"test-password-123"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn public_auth_config_reports_enabled_signup_and_providers() {
        let mut state = test_state();
        state.config.self_registration_enabled = true;
        state.config.dev_allow_unverified_email_login = true;
        state.config.oidc_providers = vec![OidcProviderConfig {
            name: "google".into(),
            issuer: "https://accounts.google.com".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            scopes: vec!["openid".into(), "email".into()],
        }];
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/public-config")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(
            body,
            serde_json::json!({
                "signup_enabled": true,
                "self_registration_enabled": true,
                "oauth_providers": ["google"],
                "email_verification_required": true,
                "dev_allow_unverified_email_login": true
            })
        );
    }

    #[tokio::test]
    async fn metrics_route_absent_when_disabled() {
        let mut state = test_state();
        state.config.metrics.enabled = false;
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn metrics_route_renders_series_when_enabled() {
        // Process-global recorder install; idempotent across the test binary.
        crate::metrics::init(true);
        crate::metrics::record_decision(std::time::Duration::from_millis(1), true);

        let state = test_state(); // for_tests() has metrics enabled
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(
            body.contains("atom_authz_decision_duration_seconds"),
            "decision histogram missing from /metrics: {body}"
        );
        assert!(
            body.contains("atom_db_pool_connections"),
            "db pool gauge missing from /metrics: {body}"
        );
    }

    fn test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("create lazy test pool");
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
}
