//! gRPC callout transport.
//!
//! One tonic client per endpoint, kept alive across calls. TLS/mTLS is
//! configured at channel-build time; per-call timeout is enforced by the
//! runner (`tokio::time::timeout`) around the RPC.

use std::time::Duration;

use anyhow::{Context, Result};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};

use super::config::{EndpointConfig, GrpcTransportConfig, TlsConfig, TransportConfig};
use super::envelope::{CalloutRequest, CalloutResponse, Decision};

// Generated code from proto/atom/v1/callout.proto — client only.
// The include! path is picked by tonic-build (package = atom.v1). callout.proto
// shares the atom.v1 package with atom.proto, so both generate into the same
// module; we re-include here so this file has a local `proto` for the callout
// types without depending on src/grpc.rs's module layout.
pub mod proto {
    tonic::include_proto!("atom.v1");
}

use proto::callout_service_client::CalloutServiceClient;
use proto::{
    callout_service_check_response::Decision as ProtoDecision, Actor as ProtoActor,
    CalloutServiceCheckRequest as ProtoRequest,
};

/// A built gRPC callout client for one endpoint.
pub struct GrpcCallout {
    client: CalloutServiceClient<Channel>,
    pub timeout: Duration,
    endpoint_id: String,
}

impl GrpcCallout {
    pub async fn build(cfg: &EndpointConfig) -> Result<Self> {
        let grpc = match &cfg.transport {
            TransportConfig::Grpc(g) => g.clone(),
            TransportConfig::Http(_) => {
                anyhow::bail!("GrpcCallout::build called on an http endpoint");
            }
        };
        let channel = build_channel(&grpc, cfg.tls.as_ref(), cfg.timeout_ms).await?;
        Ok(Self {
            client: CalloutServiceClient::new(channel),
            timeout: Duration::from_millis(cfg.timeout_ms),
            endpoint_id: cfg.id.as_str().to_string(),
        })
    }

    pub async fn call(&self, req: &CalloutRequest) -> Result<CalloutResponse> {
        let proto_req = envelope_to_proto(req)?;
        // The channel-level timeout is a safety net; the runner also wraps the
        // call in tokio::time::timeout for a hard deadline.
        let mut client = self.client.clone();
        let resp = client
            .check(proto_req)
            .await
            .with_context(|| format!("callout gRPC check on {}", self.endpoint_id))?;
        Ok(proto_to_response(resp.into_inner()))
    }
}

async fn build_channel(
    grpc: &GrpcTransportConfig,
    tls: Option<&TlsConfig>,
    timeout_ms: u64,
) -> Result<Channel> {
    let mut endpoint = Endpoint::from_shared(grpc.address.clone())
        .with_context(|| format!("invalid grpc address: {}", grpc.address))?
        .timeout(Duration::from_millis(timeout_ms.saturating_mul(2)))
        .connect_timeout(Duration::from_millis(timeout_ms.saturating_mul(2)));

    if let Some(tls) = tls {
        // tonic's rustls stack does not support "skip verification" out of the
        // box. We reject the combination at build time to avoid silently
        // ignoring the operator's request.
        if tls.insecure_skip_verify {
            anyhow::bail!(
                "grpc callout endpoint has insecure_skip_verify=true, which is not supported for gRPC — use HTTP or provide a CA bundle"
            );
        }
        let mut tls_cfg = ClientTlsConfig::new();
        if let Some(ca_path) = &tls.ca_path {
            let pem = std::fs::read(ca_path)
                .with_context(|| format!("read gRPC callout TLS CA {ca_path}"))?;
            tls_cfg = tls_cfg.ca_certificate(tonic::transport::Certificate::from_pem(pem));
        }
        if let (Some(cert_path), Some(key_path)) = (&tls.client_cert_path, &tls.client_key_path) {
            let cert = std::fs::read(cert_path)
                .with_context(|| format!("read gRPC callout mTLS cert {cert_path}"))?;
            let key = std::fs::read(key_path)
                .with_context(|| format!("read gRPC callout mTLS key {key_path}"))?;
            tls_cfg = tls_cfg.identity(Identity::from_pem(cert, key));
        }
        endpoint = endpoint
            .tls_config(tls_cfg)
            .context("apply gRPC TLS config")?;
    }

    endpoint.connect_lazy().pipe_ok()
}

/// Tiny helper so `.connect_lazy()` (which returns `Channel`, not `Result`)
/// can compose in the `?` chain above.
trait PipeOk<T> {
    fn pipe_ok(self) -> Result<T>;
}
impl PipeOk<Channel> for Channel {
    fn pipe_ok(self) -> Result<Channel> {
        Ok(self)
    }
}

fn envelope_to_proto(req: &CalloutRequest) -> Result<ProtoRequest> {
    Ok(ProtoRequest {
        operation: req.operation.clone(),
        surface: req.surface.clone(),
        request_id: req.request_id.clone(),
        time: req.time.clone(),
        actor: Some(ProtoActor {
            entity_id: req.actor.entity_id.clone(),
            tenant_id: req.actor.tenant_id.clone(),
            scope: req.actor.scope.clone(),
            credential_id: req.actor.credential_id.clone(),
            source_ip: req.actor.source_ip.clone(),
            user_agent: req.actor.user_agent.clone(),
        }),
        args: value_to_struct(&req.args),
        extra: value_to_struct(&req.extra),
    })
}

fn value_to_struct(v: &serde_json::Value) -> Option<prost_types::Struct> {
    match v {
        serde_json::Value::Object(map) => {
            let fields = map
                .iter()
                .map(|(k, v)| (k.clone(), value_to_prost(v)))
                .collect();
            Some(prost_types::Struct { fields })
        }
        serde_json::Value::Null => None,
        // Non-object envelope fields (unlikely but not impossible) become a
        // one-entry struct under "_value".
        other => {
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("_value".to_string(), value_to_prost(other));
            Some(prost_types::Struct {
                fields: fields.into_iter().collect(),
            })
        }
    }
}

fn value_to_prost(v: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match v {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(arr) => {
            let values = arr.iter().map(value_to_prost).collect();
            Kind::ListValue(prost_types::ListValue { values })
        }
        serde_json::Value::Object(map) => {
            let fields = map
                .iter()
                .map(|(k, v)| (k.clone(), value_to_prost(v)))
                .collect();
            Kind::StructValue(prost_types::Struct { fields })
        }
    };
    prost_types::Value { kind: Some(kind) }
}

fn proto_to_response(resp: proto::CalloutServiceCheckResponse) -> CalloutResponse {
    let decision = match ProtoDecision::try_from(resp.decision) {
        Ok(ProtoDecision::Allow) => Decision::Allow,
        // Zero-value (Unspecified) / explicit Deny / unknown → deny
        // (fail-closed on decode ambiguity; the enum's zero value is defined
        // to mean unset, and unset must not accidentally allow).
        Ok(ProtoDecision::Unspecified) | Ok(ProtoDecision::Deny) => Decision::Deny,
        Err(_) => Decision::Deny,
    };
    let reason = if matches!(decision, Decision::Deny) && resp.reason.trim().is_empty() {
        "callout denied".to_string()
    } else {
        resp.reason
    };
    CalloutResponse { decision, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callout::envelope::Actor;

    #[test]
    fn value_to_struct_round_trips_object() {
        let v = serde_json::json!({"a": 1, "b": "x", "c": [true, false]});
        let s = value_to_struct(&v).expect("struct");
        assert!(s.fields.contains_key("a"));
        assert!(s.fields.contains_key("b"));
        assert!(s.fields.contains_key("c"));
    }

    #[test]
    fn envelope_to_proto_maps_all_fields() {
        let req = CalloutRequest {
            operation: "createEntity".into(),
            surface: "graphql".into(),
            request_id: "r1".into(),
            time: "2026-01-01T00:00:00Z".into(),
            actor: Actor {
                entity_id: "abc".into(),
                ..Default::default()
            },
            args: serde_json::json!({"input": {"name": "gadget"}}),
            extra: serde_json::json!({}),
        };
        let p = envelope_to_proto(&req).unwrap();
        assert_eq!(p.operation, "createEntity");
        assert_eq!(p.surface, "graphql");
        assert_eq!(p.actor.unwrap().entity_id, "abc");
        assert!(p.args.is_some());
    }

    #[test]
    fn unknown_decision_is_deny() {
        let resp = proto::CalloutServiceCheckResponse {
            decision: 99,
            reason: String::new(),
        };
        let r = proto_to_response(resp);
        assert!(matches!(r.decision, Decision::Deny));
        assert_eq!(r.reason, "callout denied");
    }
}
