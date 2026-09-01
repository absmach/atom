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
    BasicProperties, Channel, Confirmation, Connection, ConnectionProperties, ExchangeKind,
};

use crate::config::EventsConfig;

use super::DomainEventPayload;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct PublishError(pub String);

fn returned_payload(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}

/// Delivers a batch of domain events to wherever they're consumed.
/// Implementations must not panic; a delivery failure is reported per event
/// so the outbox poller can retry failing rows without losing or duplicate-delivering
/// healthy rows.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(
        &self,
        events: &[DomainEventPayload],
    ) -> Result<Vec<Result<(), PublishError>>, PublishError>;
}

/// Default publisher: traces every event and always succeeds. Nothing is
/// lost (rows remain queryable in `event_outbox`), but nothing external is
/// contacted — the safe, zero-dependency default for deployments that have
/// not configured a broker.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogPublisher;

#[async_trait]
impl EventPublisher for LogPublisher {
    async fn publish(
        &self,
        events: &[DomainEventPayload],
    ) -> Result<Vec<Result<(), PublishError>>, PublishError> {
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
        Ok(vec![Ok(()); events.len()])
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
    ///
    /// The whole sequence (TCP/TLS connect, channel open, confirm mode,
    /// optional exchange declare) is bounded by `cfg.publish_timeout_secs` —
    /// the same budget [`super::deliver_outbox_batch`] gives one delivery
    /// tick. Without it, a broker that accepts the TCP connection but stalls
    /// during the handshake would hang Atom's startup indefinitely instead
    /// of failing fast like the rest of the startup sequence.
    pub async fn connect(cfg: &EventsConfig) -> anyhow::Result<Self> {
        let timeout = std::time::Duration::from_secs(cfg.publish_timeout_secs);
        match tokio::time::timeout(timeout, Self::connect_inner(cfg)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(anyhow::anyhow!(
                "connecting to the broker timed out after {timeout:?}"
            )),
        }
    }

    async fn connect_inner(cfg: &EventsConfig) -> anyhow::Result<Self> {
        let url = cfg
            .amqp_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("EventsConfig.amqp_url is not set"))?;

        let tls_config = amqp_tls_config(cfg).await?;
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

/// Reads the TLS material through `tokio::fs`, never `std::fs`.
///
/// This runs inside [`AmqpPublisher::connect`]'s timeout. A blocking read is
/// not cancellable at an await point, so a cert path on a wedged network mount
/// would pin a runtime worker and hang startup straight through the timeout
/// that exists to prevent exactly that.
async fn amqp_tls_config(cfg: &EventsConfig) -> anyhow::Result<OwnedTLSConfig> {
    let identity = match (
        &cfg.amqp_tls_client_cert_path,
        &cfg.amqp_tls_client_key_path,
    ) {
        (Some(cert_path), Some(key_path)) => {
            let pem = tokio::fs::read(cert_path)
                .await
                .map_err(|e| anyhow::anyhow!("read {cert_path}: {e}"))?;
            let key = tokio::fs::read(key_path)
                .await
                .map_err(|e| anyhow::anyhow!("read {key_path}: {e}"))?;
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

    let cert_chain = match cfg.amqp_tls_ca_path.as_deref() {
        Some(ca_path) => Some(
            tokio::fs::read_to_string(ca_path)
                .await
                .map_err(|e| anyhow::anyhow!("read CA bundle: {e}"))?,
        ),
        None => None,
    };

    Ok(OwnedTLSConfig {
        identity,
        cert_chain,
    })
}

#[async_trait]
impl EventPublisher for AmqpPublisher {
    async fn publish(
        &self,
        events: &[DomainEventPayload],
    ) -> Result<Vec<Result<(), PublishError>>, PublishError> {
        let mut pending = Vec::with_capacity(events.len());
        for event in events {
            let body = match serde_json::to_vec(event) {
                Ok(b) => b,
                Err(e) => {
                    pending.push((
                        event.event_id,
                        Err(PublishError(format!(
                            "serialize event {}: {e}",
                            event.event_id
                        ))),
                    ));
                    continue;
                }
            };
            match self
                .channel
                .basic_publish(
                    self.exchange.as_str().into(),
                    self.routing_key.as_str().into(),
                    BasicPublishOptions {
                        mandatory: true,
                        ..BasicPublishOptions::default()
                    },
                    &body,
                    BasicProperties::default()
                        .with_delivery_mode(2)
                        .with_content_type("application/json".into()),
                )
                .await
            {
                Ok(confirm) => pending.push((event.event_id, Ok(confirm))),
                Err(e) => {
                    pending.push((
                        event.event_id,
                        Err(PublishError(format!(
                            "publish event {}: {e}",
                            event.event_id
                        ))),
                    ));
                }
            }
        }

        let mut results = Vec::with_capacity(pending.len());
        for (event_id, confirm_res) in pending {
            match confirm_res {
                Ok(confirm) => match confirm.await {
                    Ok(Confirmation::Ack(None)) => results.push(Ok(())),
                    Ok(Confirmation::Ack(Some(returned))) => {
                        let payload = returned_payload(&returned.data);
                        tracing::warn!(
                            %event_id,
                            exchange = %returned.exchange,
                            routing_key = %returned.routing_key,
                            reply_code = ?returned.reply_code,
                            reply_text = %returned.reply_text,
                            payload = %payload,
                            "AMQP broker returned an unroutable event"
                        );
                        results.push(Err(PublishError(format!(
                            "event {event_id} was returned as unroutable (no queue bound to routing key {:?}); the broker never stored it",
                            self.routing_key
                        ))));
                    }
                    Ok(Confirmation::Nack(_)) => results.push(Err(PublishError(format!(
                        "event {event_id} was nacked by the broker"
                    )))),
                    Ok(Confirmation::NotRequested) => results.push(Err(PublishError(format!(
                        "event {event_id}: broker did not confirm (publisher confirms not active)"
                    )))),
                    Err(e) => {
                        results.push(Err(PublishError(format!("confirm event {event_id}: {e}"))))
                    }
                },
                Err(err) => results.push(Err(err)),
            }
        }
        Ok(results)
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
    fn returned_json_payload_is_rendered_as_text() {
        let payload = br#"{"event":"resource.create","outcome":"allow"}"#;

        assert_eq!(
            returned_payload(payload),
            r#"{"event":"resource.create","outcome":"allow"}"#
        );
    }

    #[test]
    fn returned_non_utf8_payload_is_rendered_without_panicking() {
        assert_eq!(returned_payload(&[b'{', 0xff, b'}']), "{�}");
    }

    #[tokio::test]
    async fn amqp_tls_config_rejects_cert_without_key() {
        let cfg = EventsConfig {
            amqp_tls_client_cert_path: Some("/tmp/does-not-matter.pem".to_string()),
            amqp_tls_client_key_path: None,
            ..EventsConfig::default()
        };
        assert!(amqp_tls_config(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn amqp_tls_config_is_none_when_unconfigured() {
        let cfg = EventsConfig::default();
        let tls = amqp_tls_config(&cfg)
            .await
            .expect("no TLS config is a valid default");
        assert!(tls.identity.is_none());
        assert!(tls.cert_chain.is_none());
    }

    /// Models a broker that's reachable at the TCP layer but stalls during
    /// the AMQP handshake (never replies at all) — a real broker instance
    /// can't be made to do this on demand, but a bare listener that accepts
    /// and then reads-and-discards forever reproduces the same symptom.
    /// `AmqpPublisher::connect` must time out and fail rather than hang.
    #[tokio::test]
    async fn connect_times_out_instead_of_hanging_when_the_broker_stalls() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    // Read whatever the client sends and never reply — the
                    // stall being modeled.
                    while socket.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                });
            }
        });

        let cfg = EventsConfig {
            amqp_url: Some(format!("amqp://guest:guest@{addr}/%2f")),
            publish_timeout_secs: 1,
            ..EventsConfig::default()
        };

        let started = std::time::Instant::now();
        let result = AmqpPublisher::connect(&cfg).await;
        let elapsed = started.elapsed();

        let err = result.expect_err("connect must fail rather than hang");
        assert!(
            err.to_string().contains("timed out"),
            "expected a timeout error, got: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "connect must return promptly once its timeout elapses, took {elapsed:?}"
        );
    }
}
