//! GitHub OAuth uses a verified email from the API rather than an OIDC ID token.
use crate::{
    config::{Config, OidcProviderConfig},
    error::AppError,
};
use serde::Deserialize;
use url::Url;

fn callback_url(cfg: &Config) -> String {
    format!(
        "{}/auth/oauth/github/callback",
        cfg.public_base_url.trim_end_matches('/')
    )
}

pub(super) fn authorize_url(
    cfg: &Config,
    provider: &OidcProviderConfig,
    state: &str,
    challenge: &str,
) -> Result<String, AppError> {
    let mut url = Url::parse("https://github.com/login/oauth/authorize")
        .map_err(|_| AppError::bad_request("invalid GitHub authorization URL"))?;
    url.query_pairs_mut()
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &callback_url(cfg))
        .append_pair("scope", "read:user user:email")
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.into())
}

#[derive(Deserialize)]
struct Token {
    access_token: String,
    token_type: String,
}
#[derive(Deserialize)]
struct User {
    id: u64,
}
#[derive(Deserialize)]
struct Email {
    email: String,
    primary: bool,
    verified: bool,
}

fn verified_email(emails: Vec<Email>) -> Result<String, AppError> {
    emails
        .into_iter()
        .find(|email| email.primary && email.verified)
        .map(|email| email.email.trim().to_lowercase())
        .filter(|email| !email.is_empty())
        .ok_or_else(|| AppError::unauthorized("GitHub primary email is not verified"))
}

pub(super) async fn exchange(
    cfg: &Config,
    provider: &OidcProviderConfig,
    code: &str,
    verifier: &str,
) -> Result<(String, String), AppError> {
    let client = super::service::oidc_http_client()?;
    exchange_at(
        &client,
        cfg,
        provider,
        code,
        verifier,
        "https://github.com/login/oauth/access_token",
        "https://api.github.com",
    )
    .await
}

async fn exchange_at(
    client: &reqwest::Client,
    cfg: &Config,
    provider: &OidcProviderConfig,
    code: &str,
    verifier: &str,
    token_url: &str,
    api_url: &str,
) -> Result<(String, String), AppError> {
    // Do not echo provider responses or transport errors: they can carry secrets.
    let refused = |_| AppError::unauthorized("GitHub authentication failed");
    let token: Token = client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", provider.client_id.as_str()),
            ("client_secret", provider.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", callback_url(cfg).as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(refused)?
        .error_for_status()
        .map_err(refused)?
        .json()
        .await
        .map_err(refused)?;
    if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.is_empty() {
        return Err(AppError::unauthorized("invalid GitHub token response"));
    }
    let request = |path: &str| {
        client
            .get(format!("{api_url}{path}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "Atom")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(&token.access_token)
    };
    let user: User = request("/user")
        .send()
        .await
        .map_err(refused)?
        .error_for_status()
        .map_err(refused)?
        .json()
        .await
        .map_err(refused)?;
    let emails: Vec<Email> = request("/user/emails")
        .send()
        .await
        .map_err(refused)?
        .error_for_status()
        .map_err(refused)?
        .json()
        .await
        .map_err(refused)?;
    if user.id == 0 {
        return Err(AppError::unauthorized("invalid GitHub user"));
    }
    Ok((user.id.to_string(), verified_email(emails)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_verified_primary_email() {
        assert!(verified_email(vec![Email {
            email: "unverified@example.test".into(),
            primary: true,
            verified: false
        }])
        .is_err());
        assert!(verified_email(vec![Email {
            email: "secondary@example.test".into(),
            primary: false,
            verified: true
        }])
        .is_err());
        assert_eq!(
            verified_email(vec![Email {
                email: " ADA@example.test ".into(),
                primary: true,
                verified: true
            }])
            .expect("verified email"),
            "ada@example.test"
        );
    }
    #[test]
    fn authorization_is_bound_to_state_pkce_and_registered_callback() {
        let cfg = Config::for_tests();
        let provider = OidcProviderConfig {
            name: "github".into(),
            issuer: "https://github.com".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            scopes: vec![],
        };
        let url = Url::parse(
            &authorize_url(&cfg, &provider, "state", "challenge").expect("authorize URL"),
        )
        .expect("URL");
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs.get("state").map(|s| s.as_ref()), Some("state"));
        assert_eq!(
            pairs.get("code_challenge_method").map(|s| s.as_ref()),
            Some("S256")
        );
        assert_eq!(
            pairs.get("redirect_uri").map(|s| s.as_ref()),
            Some(callback_url(&cfg).as_str())
        );
        assert!(!pairs.contains_key("client_secret"));
    }
    #[tokio::test]
    async fn exchanges_code_with_pkce_and_reads_authenticated_user_and_private_email() {
        use axum::{
            extract::Form,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        use std::collections::HashMap;
        let app = Router::new()
            .route("/token", post(|Form(body): Form<HashMap<String, String>>| async move {
                assert_eq!(body.get("code").map(String::as_str), Some("code"));
                assert_eq!(body.get("code_verifier").map(String::as_str), Some("verifier"));
                assert_eq!(body.get("client_secret").map(String::as_str), Some("secret"));
                Json(serde_json::json!({"access_token":"provider-token", "token_type":"bearer"}))
            }))
            .route("/user", get(|headers: HeaderMap| async move {
                assert_eq!(headers.get("authorization").expect("bearer"), "Bearer provider-token");
                Json(serde_json::json!({"id":42,"email":null}))
            }))
            .route("/user/emails", get(|| async {
                Json(serde_json::json!([{"email":"private@example.test","primary":true,"verified":true}]))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server");
        });
        let cfg = Config::for_tests();
        let provider = OidcProviderConfig {
            name: "github".into(),
            issuer: "https://github.com".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            scopes: vec![],
        };
        let result = exchange_at(
            &super::super::service::oidc_http_client().expect("client"),
            &cfg,
            &provider,
            "code",
            "verifier",
            &format!("{base}/token"),
            &base,
        )
        .await;
        server.abort();
        assert_eq!(
            result.expect("GitHub identity"),
            ("42".into(), "private@example.test".into())
        );
    }
}
