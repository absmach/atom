//! Chain runner — builds callout clients once at startup and dispatches per-op.
//!
//! At startup the runner walks the resolved config, builds one HTTP or gRPC
//! client per endpoint id, and stores them in a hash keyed by id. At request
//! time it looks up the operation, walks its `endpoints:` list in order,
//! sends the envelope to each, and short-circuits on the first non-ALLOW.
//! `on_error` per endpoint controls what happens on transport error/timeout
//! (default: `deny` — matches atom's default-deny invariant).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::config::{CalloutsConfig, EndpointConfig, EndpointId, OnError, TransportConfig};
use super::envelope::{Actor, CalloutRequest, CalloutResponse, Decision};
use super::grpc::GrpcCallout;
use super::http::HttpCallout;
use super::Surface;

/// Outcome returned to the caller (GraphQL extension / gRPC handler).
#[derive(Debug, Clone)]
pub enum CalloutOutcome {
    Allow,
    Deny {
        reason: String,
        endpoint_id: String,
    },
    /// No callout was configured for this operation — the caller proceeds
    /// unchanged. Distinct from `Allow` so we can skip audit + metrics noise
    /// for the (very common) no-op case.
    NotConfigured,
}

enum EndpointClient {
    Http(HttpCallout),
    Grpc(GrpcCallout),
}

impl EndpointClient {
    async fn call(&self, req: &CalloutRequest) -> Result<CalloutResponse> {
        match self {
            Self::Http(c) => c.call(req).await,
            Self::Grpc(c) => c.call(req).await,
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            Self::Http(c) => c.timeout,
            Self::Grpc(c) => c.timeout,
        }
    }
}

/// Callout service — built once at startup, cheap to clone (Arc'd inside).
#[derive(Clone, Default)]
pub struct CalloutService {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    config: CalloutsConfig,
    clients: HashMap<EndpointId, EndpointClient>,
}

impl CalloutService {
    /// Empty (no-op) service — every `check` returns `NotConfigured`.
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Build the service from resolved config, connecting/preparing every
    /// referenced endpoint. Endpoint connect failures are fatal: the operator
    /// asked for callouts and unreachable endpoints must be caught at boot.
    pub async fn build(config: CalloutsConfig) -> Result<Self> {
        if config.is_empty() {
            return Ok(Self::disabled());
        }
        let mut clients: HashMap<EndpointId, EndpointClient> = HashMap::new();
        for ep in config.endpoints() {
            let client = build_endpoint(ep).await?;
            clients.insert(ep.id.clone(), client);
        }
        Ok(Self {
            inner: Some(Arc::new(Inner { config, clients })),
        })
    }

    /// Look up the resolved config for a GraphQL resolver.
    pub fn graphql_op(&self, name: &str) -> Option<&super::config::OperationConfig> {
        self.inner.as_ref()?.config.graphql_op(name)
    }

    pub fn grpc_op(&self, name: &str) -> Option<&super::config::OperationConfig> {
        self.inner.as_ref()?.config.grpc_op(name)
    }

    /// Fire the callout chain for the given operation. Returns immediately
    /// with `NotConfigured` when no operation entry exists (the common case).
    pub async fn check(
        &self,
        surface: Surface,
        name: &str,
        actor: Actor,
        args: serde_json::Value,
    ) -> CalloutOutcome {
        let Some(inner) = self.inner.as_ref() else {
            return CalloutOutcome::NotConfigured;
        };
        let op = match surface {
            Surface::GraphQL => inner.config.graphql_op(name),
            Surface::Grpc => inner.config.grpc_op(name),
        };
        let Some(op) = op else {
            return CalloutOutcome::NotConfigured;
        };
        let req = super::envelope::build(op, surface, actor, args, chrono::Utc::now());
        // Sequential fail-fast — mirrors magistrala v0.14 semantics.
        for ep_id in &op.endpoints {
            let Some(client) = inner.clients.get(ep_id) else {
                // Should be impossible: config.build() rejects unknown refs.
                tracing::error!(endpoint = %ep_id, "callout endpoint missing at runtime");
                return CalloutOutcome::Deny {
                    reason: format!("callout endpoint {ep_id} missing"),
                    endpoint_id: ep_id.to_string(),
                };
            };
            let ep_cfg = inner
                .config
                .endpoint(ep_id)
                .expect("endpoint config present");
            let start = Instant::now();
            let result = tokio::time::timeout(client.timeout(), client.call(&req)).await;
            let elapsed = start.elapsed();
            match result {
                Ok(Ok(resp)) => {
                    crate::metrics::record_callout(
                        &op.name,
                        ep_id.as_str(),
                        transport_label(&ep_cfg.transport),
                        callout_result_label(&resp.decision),
                        elapsed,
                    );
                    match resp.decision {
                        Decision::Allow => continue,
                        Decision::Deny => {
                            return CalloutOutcome::Deny {
                                reason: if resp.reason.is_empty() {
                                    "callout denied".to_string()
                                } else {
                                    resp.reason
                                },
                                endpoint_id: ep_id.to_string(),
                            };
                        }
                    }
                }
                Ok(Err(e)) => {
                    crate::metrics::record_callout(
                        &op.name,
                        ep_id.as_str(),
                        transport_label(&ep_cfg.transport),
                        "transport_error",
                        elapsed,
                    );
                    tracing::warn!(
                        endpoint = %ep_id,
                        error = %e,
                        "callout transport error"
                    );
                    match ep_cfg.on_error {
                        OnError::Allow => continue,
                        OnError::Deny => {
                            return CalloutOutcome::Deny {
                                reason: format!("callout {ep_id} transport error: {e}"),
                                endpoint_id: ep_id.to_string(),
                            };
                        }
                    }
                }
                Err(_) => {
                    crate::metrics::record_callout(
                        &op.name,
                        ep_id.as_str(),
                        transport_label(&ep_cfg.transport),
                        "timeout",
                        elapsed,
                    );
                    tracing::warn!(endpoint = %ep_id, "callout timed out");
                    match ep_cfg.on_error {
                        OnError::Allow => continue,
                        OnError::Deny => {
                            return CalloutOutcome::Deny {
                                reason: format!("callout {ep_id} timed out"),
                                endpoint_id: ep_id.to_string(),
                            };
                        }
                    }
                }
            }
        }
        CalloutOutcome::Allow
    }
}

async fn build_endpoint(cfg: &EndpointConfig) -> Result<EndpointClient> {
    match &cfg.transport {
        TransportConfig::Http(_) => Ok(EndpointClient::Http(HttpCallout::build(cfg)?)),
        TransportConfig::Grpc(_) => Ok(EndpointClient::Grpc(GrpcCallout::build(cfg).await?)),
    }
}

fn transport_label(t: &TransportConfig) -> &'static str {
    match t {
        TransportConfig::Http(_) => "http",
        TransportConfig::Grpc(_) => "grpc",
    }
}

fn callout_result_label(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

/// Convenience wrapper for a call from the state's `CalloutService`.
///
/// Kept as a free function so the GraphQL extension and gRPC handlers can
/// share one call site.
pub async fn check(
    svc: &CalloutService,
    surface: Surface,
    name: &str,
    actor: Actor,
    args: serde_json::Value,
) -> CalloutOutcome {
    svc.check(surface, name, actor, args).await
}
