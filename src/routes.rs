use axum::{
    http::{header, HeaderValue, Method},
    routing::{any, get, post},
    Extension, Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    api_endpoints::handlers as api_endpoints, certs, graphql, identity::handlers as identity, keys,
    state::AppState,
};

pub fn create_router(state: AppState) -> Router {
    let graphql_schema = graphql::build_schema(state.clone());
    let cors_origins = state
        .config
        .cors_allowed_origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin)
                .expect("ATOM_CORS_ALLOWED_ORIGINS contains an invalid origin")
        })
        .collect::<Vec<_>>();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_origins))
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

    let app = Router::new()
        // JWKS — unauthenticated, consumed by external verifiers
        .route("/.well-known/jwks.json", get(keys::jwks))
        // Health
        .route("/health", get(identity::health))
        // Public PKI artifacts
        .route("/certs/ca-chain", get(certs::http::ca_chain))
        .route("/certs/crl", get(certs::http::crl))
        .route("/certs/ocsp", post(certs::http::ocsp))
        // GraphQL
        .route("/graphql", post(graphql::graphql_handler))
        // Custom API endpoint executor
        .route("/api/custom/*path", any(api_endpoints::custom_endpoint))
        // Auth
        .route("/auth/public-config", get(identity::public_auth_config))
        .route("/auth/signup", post(identity::signup))
        .route("/auth/login", post(identity::login))
        .route("/auth/email/verify", get(identity::verify_email))
        .route("/auth/email/resend", post(identity::resend_verification))
        .route(
            "/auth/password/reset/request",
            post(identity::request_password_reset),
        )
        .route("/auth/password/reset", post(identity::reset_password))
        .route("/auth/oauth/:provider/start", get(identity::oauth_start))
        .route(
            "/auth/oauth/:provider/callback",
            get(identity::oauth_callback),
        )
        .route("/auth/oauth/exchange", post(identity::oauth_exchange))
        .route("/auth/logout", post(identity::logout))
        .route("/auth/introspect", get(identity::introspect))
        .route("/auth/session", get(identity::current_session))
        .route("/auth/sessions/:id", get(identity::get_session))
        .route("/auth/keys/rotate", post(keys::rotate_keys));

    app.with_state(state)
        .layer(Extension(graphql_schema))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
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
        config::{Config, OidcProviderConfig, ADMIN_ENTITY_ID},
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
    async fn signup_route_is_disabled_by_default() {
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
        state.config.signup_enabled = true;
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
                "oauth_providers": ["google"],
                "email_verification_required": true,
                "dev_allow_unverified_email_login": true
            })
        );
    }

    fn test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("create lazy test pool");
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
            service_entity_id: crate::config::SERVICE_ENTITY_ID,
            signup_enabled: false,
            dev_allow_unverified_email_login: false,
            public_base_url: "http://localhost:8080".into(),
            cors_allowed_origins: vec!["http://localhost:8080".into()],
            auth_cookie_secure: false,
            auth_cookie_domain: None,
            email_verification_redirect: "http://localhost:8080/auth/email/verify".into(),
            password_reset_redirect: "http://localhost:8080/reset-password".into(),
            invitation_redirect: "http://localhost:8080/invitations/accept".into(),
            oauth_success_redirect: "http://localhost:8080".into(),
            oauth_error_redirect: "http://localhost:8080".into(),
            oidc_providers: vec![],
            smtp: None,
            email_verification_expiry_secs: 86_400,
            invitation_expiry_secs: 604_800,
            oauth_state_expiry_secs: 600,
            auth_exchange_code_expiry_secs: 300,
            certs_enabled: false,
            certs_ca_mode: crate::config::CertsCaMode::FileIntermediateIssuer,
            certs_root_ca_cert_path: None,
            certs_intermediate_ca_cert_path: None,
            certs_intermediate_ca_key_path: None,
            certs_root_ca_key_path: None,
            certs_leaf_default_ttl_secs: 2_592_000,
            certs_leaf_max_ttl_secs: 2_592_000,
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
            None,
        )
    }
}
