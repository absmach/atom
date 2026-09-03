//! Callout configuration — YAML file + env overrides.
//!
//! Loaded once at startup (see `main.rs`). Kept separate from `bootstrap.yaml`
//! because the two have different lifecycles: bootstrap is one-shot idempotent
//! seeding, callouts are runtime behavior.

use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

/// Endpoint id used to cross-reference an endpoint definition from an
/// operation entry. Just a string internally; a newtype for clarity in APIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(transparent)]
pub struct EndpointId(pub String);

impl EndpointId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EndpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    #[default]
    Deny,
    Allow,
}

impl OnError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Post,
    Get,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Get => "GET",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TlsConfig {
    /// PEM CA bundle used to verify the peer.
    #[serde(default)]
    pub ca_path: Option<String>,
    /// Client cert PEM (mTLS). Must be set together with `client_key_path`.
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Client key PEM (mTLS).
    #[serde(default)]
    pub client_key_path: Option<String>,
    /// If true, TLS verification is skipped. Never do this in production; the
    /// config loader logs a warning when this is set.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum TransportConfig {
    Http(HttpTransportConfig),
    Grpc(GrpcTransportConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpTransportConfig {
    pub url: String,
    #[serde(default = "default_http_method")]
    pub method: HttpMethod,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_http_method() -> HttpMethod {
    HttpMethod::Post
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GrpcTransportConfig {
    /// gRPC target, e.g. `https://policy.internal:9443` or `http://policy:9443`.
    /// The scheme picks TLS on/off; `dns:///` targets are supported as-is.
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EndpointConfig {
    pub id: EndpointId,
    #[serde(flatten)]
    pub transport: TransportConfig,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub on_error: OnError,
}

fn default_timeout_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SurfaceKind {
    Graphql,
    Grpc,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OperationConfig {
    /// Resolver name (GraphQL) or fully-qualified method ("svc/method") (gRPC).
    pub name: String,
    pub surface: SurfaceKind,
    /// Endpoint ids to invoke, in order. All must ALLOW for the operation to
    /// proceed; the first non-ALLOW aborts.
    pub endpoints: Vec<EndpointId>,
    /// Dot-path whitelist of fields to include in the callout payload.
    /// Paths are rooted at the envelope, e.g. `actor.entity_id`, `args.input.name`.
    /// If empty, no args/actor fields are forwarded (still: operation, surface,
    /// time, request_id, extra).
    #[serde(default)]
    pub include: Vec<String>,
    /// Static key/value pairs merged into the payload's `extra` field.
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Root of `callouts.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CalloutsFile {
    #[serde(default)]
    pub callouts: CalloutsSection,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CalloutsSection {
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    #[serde(default)]
    pub operations: Vec<OperationConfig>,
}

/// Runtime callout configuration: indexed for O(1) lookup by (surface, name).
#[derive(Debug, Clone, Default)]
pub struct CalloutsConfig {
    endpoints: HashMap<EndpointId, EndpointConfig>,
    graphql_ops: HashMap<String, OperationConfig>,
    grpc_ops: HashMap<String, OperationConfig>,
}

impl CalloutsConfig {
    /// Empty (no-op) config — used when `ATOM_CALLOUTS_FILE` is unset or the
    /// callouts subsystem is disabled.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.graphql_ops.is_empty() && self.grpc_ops.is_empty()
    }

    pub fn endpoint(&self, id: &EndpointId) -> Option<&EndpointConfig> {
        self.endpoints.get(id)
    }

    pub fn endpoints(&self) -> impl Iterator<Item = &EndpointConfig> {
        self.endpoints.values()
    }

    /// Look up the operation config for a GraphQL resolver name. Returns
    /// `None` when the resolver has no callout configured — the common case.
    pub fn graphql_op(&self, name: &str) -> Option<&OperationConfig> {
        self.graphql_ops.get(name)
    }

    pub fn grpc_op(&self, method: &str) -> Option<&OperationConfig> {
        self.grpc_ops.get(method)
    }

    /// Build from a parsed file, validating references and env overrides.
    pub fn build(file: CalloutsFile) -> Result<Self> {
        let mut endpoints: HashMap<EndpointId, EndpointConfig> = HashMap::new();
        for ep in file.callouts.endpoints {
            if ep.timeout_ms == 0 {
                bail!("callout endpoint {:?} timeout_ms must be > 0", ep.id);
            }
            if let TransportConfig::Http(ref h) = ep.transport {
                if h.url.trim().is_empty() {
                    bail!("callout endpoint {:?} http url is empty", ep.id);
                }
            }
            if let TransportConfig::Grpc(ref g) = ep.transport {
                if g.address.trim().is_empty() {
                    bail!("callout endpoint {:?} grpc address is empty", ep.id);
                }
            }
            if let Some(ref tls) = ep.tls {
                if tls.insecure_skip_verify {
                    tracing::warn!(
                        endpoint = %ep.id,
                        "callout endpoint has TLS verification disabled; do not use in production"
                    );
                }
                match (tls.client_cert_path.as_ref(), tls.client_key_path.as_ref()) {
                    (Some(_), None) | (None, Some(_)) => bail!(
                        "callout endpoint {:?} tls.client_cert_path and tls.client_key_path must both be set or both unset",
                        ep.id
                    ),
                    _ => {}
                }
            }
            let id = ep.id.clone();
            if endpoints.insert(id.clone(), ep).is_some() {
                bail!("duplicate callout endpoint id: {id}");
            }
        }

        let mut graphql_ops: HashMap<String, OperationConfig> = HashMap::new();
        let mut grpc_ops: HashMap<String, OperationConfig> = HashMap::new();
        for op in file.callouts.operations {
            if op.name.trim().is_empty() {
                bail!("callout operation with empty name");
            }
            if op.endpoints.is_empty() {
                bail!("callout operation {:?} has no endpoints", op.name);
            }
            for ep_id in &op.endpoints {
                if !endpoints.contains_key(ep_id) {
                    bail!(
                        "callout operation {:?} references unknown endpoint {:?}",
                        op.name,
                        ep_id
                    );
                }
            }
            validate_include_paths(&op)?;
            let target = match op.surface {
                SurfaceKind::Graphql => &mut graphql_ops,
                SurfaceKind::Grpc => &mut grpc_ops,
            };
            if target.insert(op.name.clone(), op.clone()).is_some() {
                bail!("duplicate callout operation: {}", op.name);
            }
        }

        Ok(Self {
            endpoints,
            graphql_ops,
            grpc_ops,
        })
    }

    /// Load `callouts.yaml` from disk, apply env overrides, then build.
    /// `None` when `ATOM_CALLOUTS_ENABLED=false` or the file is missing/unset.
    pub async fn load_from_env() -> Result<Self> {
        if !crate::config::env_bool_default("ATOM_CALLOUTS_ENABLED", true)? {
            tracing::info!("callouts disabled (ATOM_CALLOUTS_ENABLED=false)");
            return Ok(Self::empty());
        }
        let path = match std::env::var("ATOM_CALLOUTS_FILE") {
            Ok(v) if !v.trim().is_empty() => v,
            _ => {
                tracing::info!("callouts disabled (ATOM_CALLOUTS_FILE not set)");
                return Ok(Self::empty());
            }
        };
        let file = load_file(Path::new(&path)).await?;
        let mut file = file;
        apply_env_overrides(&mut file)?;
        let cfg = Self::build(file)?;
        tracing::info!(
            endpoints = cfg.endpoints.len(),
            graphql_ops = cfg.graphql_ops.len(),
            grpc_ops = cfg.grpc_ops.len(),
            "callouts configured"
        );
        Ok(cfg)
    }
}

async fn load_file(path: &Path) -> Result<CalloutsFile> {
    // tokio::fs so a wedged mount cannot pin a worker thread at startup.
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("read callouts file {}", path.display()))?;
    serde_yaml::from_slice::<CalloutsFile>(&bytes)
        .with_context(|| format!("parse callouts file {}", path.display()))
}

/// Env overrides: `ATOM_CALLOUT_<UPPER_ID>_URL`, `_ADDRESS`, `_TIMEOUT_MS`.
/// Non-alphanumeric characters in the endpoint id are replaced with `_` for
/// the env-var name (so `policy-gate` → `POLICY_GATE`).
fn apply_env_overrides(file: &mut CalloutsFile) -> Result<()> {
    for ep in &mut file.callouts.endpoints {
        let sanitized = ep
            .id
            .as_str()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let prefix = format!("ATOM_CALLOUT_{sanitized}_");
        if let Ok(v) = std::env::var(format!("{prefix}TIMEOUT_MS")) {
            ep.timeout_ms = v
                .parse()
                .map_err(|e| anyhow!("invalid {prefix}TIMEOUT_MS: {e}"))?;
        }
        match &mut ep.transport {
            TransportConfig::Http(h) => {
                if let Ok(v) = std::env::var(format!("{prefix}URL")) {
                    h.url = v;
                }
            }
            TransportConfig::Grpc(g) => {
                if let Ok(v) = std::env::var(format!("{prefix}ADDRESS")) {
                    g.address = v;
                }
            }
        }
    }
    Ok(())
}

fn validate_include_paths(op: &OperationConfig) -> Result<()> {
    // Paths are dot-separated identifiers. We keep validation deliberately
    // shallow — the filter walks only what actually exists at runtime — but
    // reject obviously-malformed entries so mistakes fail at startup, not
    // during a callout.
    for path in &op.include {
        if path.trim().is_empty() {
            bail!("callout operation {:?} has an empty include path", op.name);
        }
        for segment in path.split('.') {
            if segment.is_empty() {
                bail!(
                    "callout operation {:?} include path {:?} has an empty segment",
                    op.name,
                    path
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_http_endpoint_and_op() {
        let yaml = r#"
callouts:
  endpoints:
    - id: policy
      transport: http
      url: https://policy.example/authz
  operations:
    - name: createEntity
      surface: graphql
      endpoints: [policy]
      include: [actor.entity_id, args.input.name]
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let cfg = CalloutsConfig::build(file).unwrap();
        assert!(cfg.graphql_op("createEntity").is_some());
        assert!(cfg.graphql_op("noSuchThing").is_none());
        let ep = cfg.endpoint(&EndpointId("policy".into())).unwrap();
        assert_eq!(ep.timeout_ms, 500);
        assert!(matches!(ep.on_error, OnError::Deny));
        match &ep.transport {
            TransportConfig::Http(h) => assert!(matches!(h.method, HttpMethod::Post)),
            _ => panic!("expected http transport"),
        }
    }

    #[test]
    fn rejects_operation_referencing_unknown_endpoint() {
        let yaml = r#"
callouts:
  operations:
    - name: createEntity
      surface: graphql
      endpoints: [nope]
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let err = CalloutsConfig::build(file).unwrap_err();
        assert!(err.to_string().contains("unknown endpoint"));
    }

    #[test]
    fn rejects_duplicate_endpoint_id() {
        let yaml = r#"
callouts:
  endpoints:
    - id: policy
      transport: http
      url: https://a
    - id: policy
      transport: http
      url: https://b
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let err = CalloutsConfig::build(file).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_http_with_empty_url() {
        let yaml = r#"
callouts:
  endpoints:
    - id: policy
      transport: http
      url: ""
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let err = CalloutsConfig::build(file).unwrap_err();
        assert!(err.to_string().contains("url is empty"));
    }

    #[test]
    fn rejects_partial_mtls_config() {
        let yaml = r#"
callouts:
  endpoints:
    - id: policy
      transport: http
      url: https://a
      tls:
        client_cert_path: /a/cert.pem
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let err = CalloutsConfig::build(file).unwrap_err();
        assert!(err.to_string().contains("client_cert_path"));
    }

    #[test]
    fn rejects_include_path_with_empty_segment() {
        let yaml = r#"
callouts:
  endpoints:
    - id: policy
      transport: http
      url: https://a
  operations:
    - name: createEntity
      surface: graphql
      endpoints: [policy]
      include: ["actor..entity_id"]
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let err = CalloutsConfig::build(file).unwrap_err();
        assert!(err.to_string().contains("empty segment"));
    }

    #[test]
    fn parses_grpc_transport_and_get_method() {
        let yaml = r#"
callouts:
  endpoints:
    - id: policy-grpc
      transport: grpc
      address: https://policy.internal:9443
      timeout_ms: 250
    - id: policy-get
      transport: http
      url: https://policy.example/authz
      method: GET
      on_error: allow
"#;
        let file: CalloutsFile = serde_yaml::from_str(yaml).unwrap();
        let cfg = CalloutsConfig::build(file).unwrap();
        let grpc = cfg.endpoint(&EndpointId("policy-grpc".into())).unwrap();
        assert_eq!(grpc.timeout_ms, 250);
        match &grpc.transport {
            TransportConfig::Grpc(g) => assert_eq!(g.address, "https://policy.internal:9443"),
            _ => panic!("expected grpc transport"),
        }
        let get = cfg.endpoint(&EndpointId("policy-get".into())).unwrap();
        match &get.transport {
            TransportConfig::Http(h) => assert!(matches!(h.method, HttpMethod::Get)),
            _ => panic!("expected http transport"),
        }
        assert!(matches!(get.on_error, OnError::Allow));
    }
}
