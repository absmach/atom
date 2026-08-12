//! HTTP callout transport.
//!
//! Builds a per-endpoint `reqwest::Client` at startup (TLS/mTLS applied then),
//! so each call is a single HTTP round-trip and cannot be tripped up by
//! file-not-found errors mid-request. `on_error` and `timeout_ms` are enforced
//! by the runner around this — this module reports outcomes and lets the
//! runner apply the config's policy.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;

use super::config::{EndpointConfig, HttpMethod, HttpTransportConfig, TlsConfig, TransportConfig};
use super::envelope::{CalloutRequest, CalloutResponse, Decision};

/// A built HTTP callout client for one endpoint.
pub struct HttpCallout {
    client: Client,
    url: String,
    method: HttpMethod,
    headers: Vec<(String, String)>,
    /// Kept separate from `client.timeout` so the chain runner can wrap this
    /// with `tokio::time::timeout` for a hard upper bound independent of any
    /// keep-alive / DNS quirks.
    pub timeout: Duration,
}

impl HttpCallout {
    pub fn build(cfg: &EndpointConfig) -> Result<Self> {
        let http = match &cfg.transport {
            TransportConfig::Http(h) => h.clone(),
            TransportConfig::Grpc(_) => {
                anyhow::bail!("HttpCallout::build called on a grpc endpoint");
            }
        };
        let client = build_client(&http, cfg.tls.as_ref(), cfg.timeout_ms)?;
        Ok(Self {
            client,
            url: http.url.clone(),
            method: http.method,
            headers: http.headers.into_iter().collect(),
            timeout: Duration::from_millis(cfg.timeout_ms),
        })
    }

    pub async fn call(&self, req: &CalloutRequest) -> Result<CalloutResponse> {
        let mut builder = match self.method {
            HttpMethod::Post => self.client.post(&self.url).json(req),
            HttpMethod::Get => {
                let query = envelope_to_query(req)?;
                self.client.get(&self.url).query(&query)
            }
        };
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        let resp = builder
            .send()
            .await
            .with_context(|| format!("callout HTTP send to {}", self.url))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "callout HTTP returned non-success status {status}: {}",
                truncate(&body, 512)
            );
        }
        // Two acceptable success shapes:
        //   1. { "decision": "allow" | "deny", "reason": "..." }
        //   2. HTTP 2xx with no body / non-JSON body: treated as ALLOW
        //      (magistrala v0.14 parity — status alone is the signal).
        let text = resp.text().await.unwrap_or_default();
        if text.trim().is_empty() {
            return Ok(CalloutResponse::allow());
        }
        match serde_json::from_str::<CalloutResponse>(&text) {
            Ok(mut r) => {
                if matches!(r.decision, Decision::Deny) && r.reason.trim().is_empty() {
                    r.reason = "callout denied".to_string();
                }
                Ok(r)
            }
            Err(_) => Ok(CalloutResponse::allow()),
        }
    }
}

fn build_client(
    http: &HttpTransportConfig,
    tls: Option<&TlsConfig>,
    timeout_ms: u64,
) -> Result<Client> {
    let mut builder =
        Client::builder().timeout(Duration::from_millis(timeout_ms.saturating_mul(2)));
    if let Some(tls) = tls {
        if tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ca_path) = &tls.ca_path {
            let pem =
                std::fs::read(ca_path).with_context(|| format!("read callout TLS CA {ca_path}"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .with_context(|| format!("parse callout TLS CA {ca_path}"))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        if let (Some(cert_path), Some(key_path)) = (&tls.client_cert_path, &tls.client_key_path) {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("read callout mTLS cert {cert_path}"))?;
            let key_pem = std::fs::read(key_path)
                .with_context(|| format!("read callout mTLS key {key_path}"))?;
            let mut identity_pem = cert_pem;
            identity_pem.push(b'\n');
            identity_pem.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&identity_pem)
                .with_context(|| format!("build callout mTLS identity from {cert_path}"))?;
            builder = builder.identity(identity);
        }
    }
    // Sanity-check the URL early so a typo surfaces at startup, not runtime.
    let _ = url::Url::parse(&http.url).with_context(|| format!("invalid url: {}", http.url))?;
    builder.build().context("build callout HTTP client")
}

fn envelope_to_query(req: &CalloutRequest) -> Result<Vec<(String, String)>> {
    // Flatten the envelope into query-string form: mirrors magistrala v0.14
    // `Request.toURL()` — keys like "operation", "actor.entity_id", "args.input.name".
    let val = serde_json::to_value(req)?;
    let mut out = Vec::new();
    flatten_json(&val, String::new(), &mut out);
    Ok(out)
}

fn flatten_json(val: &serde_json::Value, prefix: String, out: &mut Vec<(String, String)>) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json(v, next, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let next = format!("{prefix}[{i}]");
                flatten_json(v, next, out);
            }
        }
        serde_json::Value::Null => {}
        serde_json::Value::Bool(b) => out.push((prefix, b.to_string())),
        serde_json::Value::Number(n) => out.push((prefix, n.to_string())),
        serde_json::Value::String(s) => out.push((prefix, s.clone())),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callout::config::HttpTransportConfig;
    use crate::callout::envelope::Actor;

    fn dummy_request() -> CalloutRequest {
        CalloutRequest {
            operation: "createEntity".into(),
            surface: "graphql".into(),
            request_id: "r1".into(),
            time: "2026-01-01T00:00:00Z".into(),
            actor: Actor {
                entity_id: "abc".into(),
                ..Default::default()
            },
            args: serde_json::json!({"input": {"name": "gadget"}}),
            extra: serde_json::json!({"entity_type": "entity"}),
        }
    }

    #[test]
    fn envelope_flattens_to_query_pairs() {
        let req = dummy_request();
        let pairs = envelope_to_query(&req).unwrap();
        let m: std::collections::HashMap<_, _> = pairs.into_iter().collect();
        assert_eq!(m.get("operation").map(String::as_str), Some("createEntity"));
        assert_eq!(m.get("surface").map(String::as_str), Some("graphql"));
        assert_eq!(m.get("actor.entity_id").map(String::as_str), Some("abc"));
        assert_eq!(m.get("args.input.name").map(String::as_str), Some("gadget"));
        assert_eq!(
            m.get("extra.entity_type").map(String::as_str),
            Some("entity")
        );
    }

    #[test]
    fn build_client_rejects_invalid_url() {
        let http = HttpTransportConfig {
            url: "not-a-url".to_string(),
            method: HttpMethod::Post,
            headers: Default::default(),
        };
        assert!(build_client(&http, None, 500).is_err());
    }
}
