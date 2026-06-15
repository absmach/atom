use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use ipnet::IpNet;
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
    pub trusted_proxy_cidrs: Vec<String>,
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
    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0);
    let client = client_key(req.headers(), peer_addr, &cfg.trusted_proxy_cidrs);
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
        trusted_proxy_cidrs: cfg
            .trusted_proxy_cidrs
            .iter()
            .map(ToString::to_string)
            .collect(),
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

fn client_key(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trusted_proxy_cidrs: &[IpNet],
) -> String {
    let Some(peer_addr) = peer_addr else {
        tracing::warn!("rate limit peer address missing; using unknown peer bucket");
        return "ip:unknown-peer".to_string();
    };
    let peer_ip = peer_addr.ip();

    if is_trusted_proxy(peer_ip, trusted_proxy_cidrs) {
        if let Some(forwarded_ip) = forwarded_client(headers, trusted_proxy_cidrs) {
            return format!("ip:{forwarded_ip}");
        }
    }

    format!("ip:{peer_ip}")
}

fn forwarded_client(headers: &HeaderMap, trusted_proxy_cidrs: &[IpNet]) -> Option<IpAddr> {
    forwarded_for_client(headers, trusted_proxy_cidrs).or_else(|| real_ip_client(headers))
}

fn forwarded_for_client(headers: &HeaderMap, trusted_proxy_cidrs: &[IpNet]) -> Option<IpAddr> {
    headers.get("x-forwarded-for").and_then(|value| {
        value.to_str().ok().and_then(|value| {
            value.split(',').rev().find_map(|part| {
                let ip = part.trim().parse::<IpAddr>().ok()?;
                (!is_trusted_proxy(ip, trusted_proxy_cidrs)).then_some(ip)
            })
        })
    })
}

fn real_ip_client(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<IpAddr>().ok())
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxy_cidrs: &[IpNet]) -> bool {
    trusted_proxy_cidrs.iter().any(|cidr| cidr.contains(&ip))
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
    use axum::http::HeaderValue;

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
    fn rate_limited_response_keeps_429_and_retry_after() {
        let response = rate_limited_response(7);

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
    }

    #[test]
    fn health_paths_are_not_limited() {
        assert_eq!(category_for_path("/health"), None);
        assert_eq!(category_for_path("/health/live"), None);
        assert_eq!(category_for_path("/health/ready"), None);
    }

    #[test]
    fn untrusted_peer_ignores_spoofed_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.10"));
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.11"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );

        let key = client_key(
            &headers,
            Some(addr("203.0.113.5:1234")),
            &[cidr("10.0.0.0/8")],
        );

        assert_eq!(key, "ip:203.0.113.5");
    }

    #[test]
    fn trusted_peer_honors_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.10"));

        let key = client_key(&headers, Some(addr("10.1.2.3:1234")), &[cidr("10.0.0.0/8")]);

        assert_eq!(key, "ip:198.51.100.10");
    }

    #[test]
    fn x_forwarded_for_skips_trusted_proxy_hops_from_the_right() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.10, 10.1.1.1, 10.2.2.2"),
        );

        let key = client_key(&headers, Some(addr("10.3.3.3:1234")), &[cidr("10.0.0.0/8")]);

        assert_eq!(key, "ip:198.51.100.10");
    }

    #[test]
    fn invalid_forwarded_headers_fall_back_to_peer_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        headers.insert("x-real-ip", HeaderValue::from_static("also-not-an-ip"));

        let key = client_key(&headers, Some(addr("10.1.2.3:1234")), &[cidr("10.0.0.0/8")]);

        assert_eq!(key, "ip:10.1.2.3");
    }

    #[test]
    fn missing_headers_use_peer_ip_not_anonymous() {
        let key = client_key(&HeaderMap::new(), Some(addr("203.0.113.5:1234")), &[]);

        assert_eq!(key, "ip:203.0.113.5");
    }

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("socket address")
    }

    fn cidr(value: &str) -> IpNet {
        value.parse().expect("cidr")
    }
}
