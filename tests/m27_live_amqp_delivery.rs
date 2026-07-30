//! Live end-to-end proof against a real AMQP broker (FluxMQ or any AMQP
//! 0.9.1-compatible broker, e.g. RabbitMQ). Unlike `tests/m25_event_outbox.rs`
//! (which uses a mock publisher) and `tests/m26_audit_event_publishing.rs`
//! (which only checks the DB row), this test drives a real
//! `AmqpPublisher::connect` against a running broker, delivers a batch, and
//! consumes the message back off a queue — proving actual wire delivery, not
//! just "the publish call returned Ok".
//!
//! Publishes to the default exchange with a fixed routing key (see
//! `src/events/publisher.rs`'s module docs for why) — routing_key doubles as
//! the destination queue name under the default exchange, which is standard
//! AMQP 0-9-1 and requires no exchange declaration or binding at all.
//!
//! Requires a reachable AMQP 0.9.1 broker with no client-cert requirement
//! (see `tests/m28_amqp_mtls_local_principal.rs` for the mTLS variant).
//! Point `TEST_AMQP_URL` at it, e.g.:
//!
//! ```bash
//! DATABASE_URL=postgres://... TEST_AMQP_URL=amqp://guest:guest@localhost:5672/%2f \
//!   cargo test --test m27_live_amqp_delivery -- --ignored
//! ```

mod common;

use atom::config::EventsConfig;
use atom::events::deliver_outbox_batch;
use atom::events::publisher::AmqpPublisher;
use atom::events::DomainEventPayload;
use lapin::{
    options::{BasicGetOptions, QueueDeclareOptions},
    types::FieldTable,
    Connection, ConnectionProperties,
};
use sqlx::PgPool;
use uuid::Uuid;

fn amqp_url() -> String {
    std::env::var("TEST_AMQP_URL").expect("TEST_AMQP_URL must be set to run this live test")
}

async fn insert_outbox_row(pool: &PgPool, payload: &DomainEventPayload) {
    sqlx::query("INSERT INTO event_outbox (id, event, payload) VALUES ($1, $2, $3)")
        .bind(payload.event_id)
        .bind(&payload.event)
        .bind(serde_json::to_value(payload).expect("serialize payload"))
        .execute(pool)
        .await
        .expect("insert event_outbox row");
}

#[tokio::test]
#[ignore]
async fn a_published_event_is_actually_delivered_to_the_broker() {
    let pool = common::pool().await;
    sqlx::query("TRUNCATE TABLE event_outbox")
        .execute(&pool)
        .await
        .expect("truncate event_outbox");

    let url = amqp_url();
    let routing_key = format!("atom-events-test-{}", Uuid::new_v4());

    // Declare the destination queue first — under the default exchange, its
    // name doubles as the routing key Atom publishes with. A real consumer
    // (e.g. a billing service) would declare this once, out of band, exactly
    // like this.
    let consumer_conn = Connection::connect(&url, ConnectionProperties::default())
        .await
        .expect("connect consumer to broker");
    let consumer_channel = consumer_conn
        .create_channel()
        .await
        .expect("create consumer channel");
    consumer_channel
        .queue_declare(
            routing_key.as_str().into(),
            QueueDeclareOptions {
                durable: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("declare queue");

    let cfg = EventsConfig {
        amqp_url: Some(url.clone()),
        amqp_exchange: String::new(), // default exchange — no topology declared
        amqp_routing_key: routing_key.clone(),
        ..EventsConfig::default()
    };
    let publisher = AmqpPublisher::connect(&cfg)
        .await
        .expect("connect AmqpPublisher to broker");

    let event_id = Uuid::new_v4();
    let payload = DomainEventPayload {
        schema_version: 1,
        event_id,
        event: "resource.create".to_string(),
        occurred_at: chrono::Utc::now(),
        source: "atom".to_string(),
        actor_entity_id: None,
        tenant_id: None,
        target_kind: Some("resource".to_string()),
        target_id: Some(Uuid::new_v4()),
        outcome: "allow".to_string(),
        details: serde_json::json!({"kind": "channel"}),
        request_id: None,
    };
    insert_outbox_row(&pool, &payload).await;

    let delivered = deliver_outbox_batch(&pool, &publisher, &cfg)
        .await
        .expect("deliver batch");
    assert_eq!(delivered, 1, "the row must be delivered to the real broker");

    let delivered_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT delivered_at FROM event_outbox WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("fetch delivered_at");
    assert!(
        delivered_at.is_some(),
        "delivered_at must be set after a successful real-broker publish"
    );

    // Now prove the message actually arrived at the broker by pulling it
    // back off the queue — this is the part a mock publisher can never prove.
    let message = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(msg) = consumer_channel
                .basic_get(routing_key.as_str().into(), BasicGetOptions::default())
                .await
                .expect("basic_get")
            {
                return msg;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("timed out waiting for the message to arrive at the broker");

    let received: DomainEventPayload =
        serde_json::from_slice(&message.delivery.data).expect("deserialize delivered payload");
    assert_eq!(received.event_id, event_id);
    assert_eq!(received.event, "resource.create");
    assert_eq!(received.details["kind"], "channel");
}
