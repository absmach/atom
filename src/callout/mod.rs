//! External policy callouts.
//!
//! At certain configured operations (GraphQL resolvers or gRPC methods) atom
//! consults an external policy service **before** executing the operation. The
//! external service replies with ALLOW or DENY; DENY short-circuits the
//! operation with the returned reason, and any transport error follows the
//! per-endpoint `on_error` policy (default: deny — matches atom's default-deny
//! invariant).
//!
//! Design:
//! - Per-operation opt-in via YAML config (loaded once at startup from
//!   `ATOM_CALLOUTS_FILE`). If an operation is not listed, the interception is
//!   a cheap map lookup that returns early.
//! - HTTP (POST/GET) and gRPC transports share one canonical
//!   [`envelope::CalloutRequest`] shape.
//! - Multiple endpoints per operation run sequentially, fail-fast (all must
//!   allow — matches magistrala v0.14 semantics).
//! - Per-operation field whitelist (`include:`) selects which args make it into
//!   the payload. A hard denylist strips secret/password/key even if the
//!   whitelist would have leaked them.
//! - Fail-closed on transport errors and timeouts.

pub mod config;
pub mod envelope;
pub mod grpc;
pub mod http;
pub mod runner;

pub use config::{
    CalloutsConfig, EndpointConfig, EndpointId, OnError, OperationConfig, TlsConfig,
    TransportConfig,
};
pub use envelope::{Actor, CalloutRequest, CalloutResponse, Decision};
pub use runner::{check, CalloutOutcome, CalloutService};

/// The operation surface — matches the `surface:` field in callouts.yaml and
/// the `surface` field on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    GraphQL,
    Grpc,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GraphQL => "graphql",
            Self::Grpc => "grpc",
        }
    }
}
