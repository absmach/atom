//! Pluggable delivery for domain events.
//!
//! Mirrors `src/metrics.rs`'s swappable-backend-behind-a-facade shape: the
//! outbox poller (see [`super::spawn_event_publisher`]) only ever goes
//! through the [`EventPublisher`] trait, never a concrete transport. Two
//! implementations ship: [`LogPublisher`] (the default — traces every event,
//! always succeeds, zero external dependency) and [`AmqpPublisher`] (a real
//! broker-backed implementation, used only when `EventsConfig.amqp_url` is
//! configured). Atom never depends on AMQP being present; it's purely
//! optional.
//!
//! `AmqpPublisher` deliberately publishes every event to one fixed
//! `(exchange, routing_key)` target rather than routing per event type: some
//! broker deployments only grant Atom publish access to one pre-provisioned
//! queue via the default exchange and refuse any topology mutation
//! (exchange/queue declare, bind) outright. Publishing to the default
//! exchange (`exchange == ""`) with a fixed routing key is standard AMQP
//! 0-9-1 that works identically against any compliant broker (RabbitMQ
//! included) — consumers distinguish event types using the payload's own
//! `event` field, not AMQP routing.

use axum::async_trait;
use lapin::{
    options::{BasicPublishOptions, ConfirmSelectOptions, ExchangeDeclareOptions},
    tcp::{OwnedIdentity, OwnedTLSConfig},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind,
};

use crate::config::EventsConfig;

use super::DomainEventPayload;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PublishError(pub String);

/// Delivers a batch of domain events to wherever they're consumed.
/// Implementations must not panic; a delivery failure is reported via `Err`
/// so the outbox poller can retry on its next tick without losing the row.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, events: &[DomainEventPayload]) -> Result<(), PublishError>;
}

/// Default publisher: traces every event and always succeeds. Nothing is
/// lost (rows remain queryable in `event_outbox`), but nothing external is
/// contacted — the safe, zero-dependency default for deployments that have
/// not configured a broker.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogPublisher;

#[async_trait]
impl EventPublisher for LogPublisher {
    async fn publish(&self, events: &[DomainEventPayload]) -> Result<(), PublishError> {
        for event in events {
            tracing::info!(
                events.event_id = %event.event_id,
                events.event = %event.event,
                events.target_kind = ?event.target_kind,
                events.target_id = ?event.target_id,
                events.outcome = %event.outcome,
                "domain event"
            );
        }
        Ok(())
    }
}

/// Publishes events to an AMQP broker (e.g. RabbitMQ, FluxMQ) at one fixed
/// `(exchange, routing_key)` target, optionally over mTLS.
pub struct AmqpPublisher {
    channel: Channel,
    exchange: String,
    routing_key: String,
    // Held only to keep the connection alive for the publisher's lifetime;
    // never read directly.
    _connection: Connection,
}

impl std::fmt::Debug for AmqpPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmqpPublisher")
            .field("exchange", &self.exchange)
            .field("routing_key", &self.routing_key)
            .finish()
    }
}

impl AmqpPublisher {
    /// Connects to the broker named in `cfg.amqp_url` and, only when
    /// `cfg.amqp_exchange` is non-empty, declares it as a durable topic
    /// exchange. When `cfg.amqp_exchange` is empty (the default), no
    /// exchange/queue declaration is attempted at all — publishing to the
    /// default exchange requires no topology setup and works even when the
    /// broker connection is restricted to publish-only (see module docs).
    ///
    /// Loads a client TLS identity for mTLS when both
    /// `cfg.amqp_tls_client_cert_path` and `cfg.amqp_tls_client_key_path` are
    /// set (config validation already guarantees they're set together or not
    /// at all — see `config::events_from_env`), and a custom CA bundle to
    /// verify the broker's server certificate when `cfg.amqp_tls_ca_path` is
    /// set. All three are optional and independent of each other.
    ///
    /// Auto-recovers the connection on drops (exponential backoff) rather
    /// than requiring Atom to implement its own reconnect loop.
    pub async fn connect(cfg: &EventsConfig) -> anyhow::Result<Self> {
        let url = cfg
            .amqp_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("EventsConfig.amqp_url is not set"))?;

        let tls_config = amqp_tls_config(cfg)?;
        let runtime = lapin::runtime::default_runtime()?;
        let connection = Connection::connect_with_config(
            url,
            ConnectionProperties::default().enable_auto_recover(),
            tls_config,
            runtime,
        )
        .await?;
        let channel = connection.create_channel().await?;
        // Without confirm mode, a `basic_publish` future resolves once the
        // frame is sent, not once the broker has actually accepted (or
        // rejected) it — a denied or unroutable publish would look
        // indistinguishable from a successful one. Confirm mode makes the
        // returned `PublisherConfirm` a real broker acknowledgment.
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await?;

        if !cfg.amqp_exchange.is_empty() {
            channel
                .exchange_declare(
                    cfg.amqp_exchange.as_str().into(),
                    ExchangeKind::Topic,
                    ExchangeDeclareOptions {
                        durable: true,
                        ..ExchangeDeclareOptions::default()
                    },
                    FieldTable::default(),
                )
                .await?;
        }

        Ok(Self {
            channel,
            exchange: cfg.amqp_exchange.clone(),
            routing_key: cfg.amqp_routing_key.clone(),
            _connection: connection,
        })
    }
}

fn amqp_tls_config(cfg: &EventsConfig) -> anyhow::Result<OwnedTLSConfig> {
    let identity = match (
        &cfg.amqp_tls_client_cert_path,
        &cfg.amqp_tls_client_key_path,
    ) {
        (Some(cert_path), Some(key_path)) => {
            let pem =
                std::fs::read(cert_path).map_err(|e| anyhow::anyhow!("read {cert_path}: {e}"))?;
            let key =
                std::fs::read(key_path).map_err(|e| anyhow::anyhow!("read {key_path}: {e}"))?;
            Some(OwnedIdentity::PKCS8 { pem, key })
        }
        (None, None) => None,
        // config::events_from_env already rejects exactly one being set; a
        // caller constructing EventsConfig directly (e.g. in a test) that
        // violates this invariant gets a clear error here too.
        _ => anyhow::bail!(
            "amqp_tls_client_cert_path and amqp_tls_client_key_path must both be set, or neither"
        ),
    };

    let cert_chain = cfg
        .amqp_tls_ca_path
        .as_deref()
        .map(std::fs::read_to_string)
        .transpose()
        .map_err(|e| anyhow::anyhow!("read CA bundle: {e}"))?;

    Ok(OwnedTLSConfig {
        identity,
        cert_chain,
    })
}

#[async_trait]
impl EventPublisher for AmqpPublisher {
    async fn publish(&self, events: &[DomainEventPayload]) -> Result<(), PublishError> {
        // Two passes rather than one: sending every `basic_publish` frame
        // before awaiting any confirm pipelines the batch into one round
        // trip instead of `events.len()` sequential ones. The first await
        // per event only waits for the frame to be written to the channel,
        // not for the broker's response — that response is the second await,
        // now deferred to its own loop below.
        let mut pending = Vec::with_capacity(events.len());
        for event in events {
            let body = serde_json::to_vec(event)
                .map_err(|e| PublishError(format!("serialize event {}: {e}", event.event_id)))?;
            let confirm = self
                .channel
                .basic_publish(
                    self.exchange.as_str().into(),
                    self.routing_key.as_str().into(),
                    BasicPublishOptions::default(),
                    &body,
                    BasicProperties::default().with_content_type("application/json".into()),
                )
                .await
                .map_err(|e| PublishError(format!("publish event {}: {e}", event.event_id)))?;
            pending.push((event.event_id, confirm));
        }
        for (event_id, confirm) in pending {
            confirm
                .await
                .map_err(|e| PublishError(format!("confirm event {event_id}: {e}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_event() -> DomainEventPayload {
        DomainEventPayload {
            schema_version: super::super::SCHEMA_VERSION,
            event_id: Uuid::new_v4(),
            event: "resource.create".to_string(),
            occurred_at: chrono::Utc::now(),
            source: super::super::EVENT_SOURCE.to_string(),
            actor_entity_id: None,
            tenant_id: None,
            target_kind: Some("resource".to_string()),
            target_id: Some(Uuid::new_v4()),
            outcome: "allow".to_string(),
            details: serde_json::json!({}),
            request_id: None,
        }
    }

    #[tokio::test]
    async fn log_publisher_always_succeeds() {
        let publisher = LogPublisher;
        let events = vec![sample_event(), sample_event()];
        assert!(publisher.publish(&events).await.is_ok());
    }

    #[tokio::test]
    async fn log_publisher_succeeds_on_empty_batch() {
        let publisher = LogPublisher;
        assert!(publisher.publish(&[]).await.is_ok());
    }

    #[test]
    fn amqp_tls_config_rejects_cert_without_key() {
        let cfg = EventsConfig {
            amqp_tls_client_cert_path: Some("/tmp/does-not-matter.pem".to_string()),
            amqp_tls_client_key_path: None,
            ..EventsConfig::default()
        };
        assert!(amqp_tls_config(&cfg).is_err());
    }

    #[test]
    fn amqp_tls_config_is_none_when_unconfigured() {
        let cfg = EventsConfig::default();
        let tls = amqp_tls_config(&cfg).expect("no TLS config is a valid default");
        assert!(tls.identity.is_none());
        assert!(tls.cert_chain.is_none());
    }
}
