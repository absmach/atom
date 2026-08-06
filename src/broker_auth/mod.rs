//! Broker auth callout — Atom implementing FluxMQ's `AuthService` directly.
//!
//! A message broker delegates connect-time credential checks and per-topic
//! access control to an external service over gRPC. Atom serves that contract
//! itself, so a deployment can point a broker straight at Atom with no adapter
//! service in between.
//!
//! The contract is deliberately the broker's, not Atom's: the wire path a
//! broker dials is `/fluxmq.auth.v1.AuthService/...`, derived from the vendored
//! proto's package. Everything Atom needs beyond that — how a topic names an
//! object — is configuration, so Atom never learns a particular deployment's
//! topic vocabulary. See [`topic`] for the grammar.
//!
//! An adapter service is still the right answer where the mapping needs more
//! than a grammar (route resolution, multi-service composition). Both speak the
//! same wire contract, so a deployment picks one by pointing the broker's
//! `auth.external.url` at Atom or at the adapter.

pub mod service;
pub mod topic;

pub use service::BrokerAuth;
pub use topic::{TopicMatch, TopicTemplate, TopicTemplateSet};
