use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{
    config::{RateLimitConfig, RateLimitPolicyConfig},
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitCategory {
    AuthRoutes,
    PublicRoutes,
    Graphql,
    CustomEndpoints,
    AdminRoutes,
}

impl RateLimitCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthRoutes => "auth_routes",
            Self::PublicRoutes => "public_routes",
            Self::Graphql => "graphql",
            Self::CustomEndpoints => "custom_endpoints",
            Self::AdminRoutes => "admin_routes",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RateLimitPolicyStatus {
    pub category: RateLimitCategory,
    pub max_requests: u32,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStatus {
    pub enabled: bool,
    pub policies: Vec<RateLimitPolicyStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    category: RateLimitCategory,
    client: String,
}

#[derive(Debug, Clone)]
struct Bucket {
    count: u32,
    reset_at: Instant,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<BucketKey, Bucket>>,
}

impl RateLimiter {
    pub fn check(
        &self,
        category: RateLimitCategory,
        client: String,
        policy: RateLimitPolicyConfig,
    ) -> Result<(), u64> {
        let now = Instant::now();
        let window = Duration::from_secs(policy.window_secs);
        let key = BucketKey { category, client };
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buckets.retain(|_, bucket| bucket.reset_at > now);

        let bucket = buckets.entry(key).or_insert_with(|| Bucket {
            count: 0,
            reset_at: now + window,
        });
        if now >= bucket.reset_at {
            bucket.count = 0;
            bucket.reset_at = now + window;
        }

        if bucket.count >= policy.max_requests {
            return Err(bucket
                .reset_at
                .saturating_duration_since(now)
                .as_secs()
                .max(1));
        }

        bucket.count += 1;
        Ok(())
    }
}

pub async fn middleware(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let cfg = &state.config.rate_limits;
    let Some(category) = category_for_path(req.uri().path()) else {
        return next.run(req).await;
    };
    if !cfg.enabled {
        return next.run(req).await;
    }

    let policy = policy_for_category(cfg, category);
    let client = client_key(req.headers());
    match state.rate_limiter.check(category, client, policy) {
        Ok(()) => next.run(req).await,
        Err(retry_after_secs) => rate_limited_response(retry_after_secs),
    }
}

pub fn status(cfg: &RateLimitConfig) -> RateLimitStatus {
    RateLimitStatus {
        enabled: cfg.enabled,
        policies: vec![
            policy_status(RateLimitCategory::AuthRoutes, cfg.auth_routes),
            policy_status(RateLimitCategory::PublicRoutes, cfg.public_routes),
            policy_status(RateLimitCategory::Graphql, cfg.graphql),
            policy_status(RateLimitCategory::CustomEndpoints, cfg.custom_endpoints),
            policy_status(RateLimitCategory::AdminRoutes, cfg.admin_routes),
        ],
    }
}

fn policy_status(
    category: RateLimitCategory,
    policy: RateLimitPolicyConfig,
) -> RateLimitPolicyStatus {
    RateLimitPolicyStatus {
        category,
        max_requests: policy.max_requests,
        window_secs: policy.window_secs,
    }
}

fn policy_for_category(
    cfg: &RateLimitConfig,
    category: RateLimitCategory,
) -> RateLimitPolicyConfig {
    match category {
        RateLimitCategory::AuthRoutes => cfg.auth_routes,
        RateLimitCategory::PublicRoutes => cfg.public_routes,
        RateLimitCategory::Graphql => cfg.graphql,
        RateLimitCategory::CustomEndpoints => cfg.custom_endpoints,
        RateLimitCategory::AdminRoutes => cfg.admin_routes,
    }
}

fn category_for_path(path: &str) -> Option<RateLimitCategory> {
    if path == "/health" || path == "/health/live" || path == "/health/ready" {
        return None;
    }
    if path == "/graphql" {
        return Some(RateLimitCategory::Graphql);
    }
    if path.starts_with("/api/custom/") {
        return Some(RateLimitCategory::CustomEndpoints);
    }
    if path.starts_with("/certs/") || path == "/.well-known/jwks.json" {
        return Some(RateLimitCategory::PublicRoutes);
    }
    if path == "/auth/public-config"
        || path == "/auth/signup"
        || path == "/auth/login"
        || path.starts_with("/auth/email/")
        || path.starts_with("/auth/password/")
        || path.starts_with("/auth/oauth/")
    {
        return Some(RateLimitCategory::AuthRoutes);
    }
    if path.starts_with("/auth/") {
        return Some(RateLimitCategory::AdminRoutes);
    }
    None
}

fn client_key(headers: &HeaderMap) -> String {
    forwarded_client(headers)
        .or_else(|| hashed_header(headers, header::AUTHORIZATION.as_str()))
        .unwrap_or_else(|| "anonymous".to_string())
}

fn forwarded_client(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("ip:{value}"))
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| format!("ip:{value}"))
        })
}

fn hashed_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut hasher = DefaultHasher::new();
    headers.get(name)?.as_bytes().hash(&mut hasher);
    Some(format!("header:{:x}", hasher.finish()))
}

fn rate_limited_response(retry_after_secs: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({"error": "rate limit exceeded"})),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_denies_after_limit_until_window_resets() {
        let limiter = RateLimiter::default();
        let policy = RateLimitPolicyConfig {
            max_requests: 1,
            window_secs: 60,
        };

        assert!(limiter
            .check(RateLimitCategory::AuthRoutes, "client".into(), policy)
            .is_ok());
        let retry = limiter
            .check(RateLimitCategory::AuthRoutes, "client".into(), policy)
            .expect_err("rate limit");
        assert!(retry > 0);
    }

    #[test]
    fn health_paths_are_not_limited() {
        assert_eq!(category_for_path("/health"), None);
        assert_eq!(category_for_path("/health/live"), None);
        assert_eq!(category_for_path("/health/ready"), None);
    }
}
