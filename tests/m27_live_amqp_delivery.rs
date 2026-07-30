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
    options::{BasicGetOptions, QueueBindOptions, QueueDeclareOptions},
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

fn sample_payload(event: &str) -> DomainEventPayload {
    DomainEventPayload {
        schema_version: 1,
        event_id: Uuid::new_v4(),
        event: event.to_string(),
        occurred_at: chrono::Utc::now(),
        source: "atom".to_string(),
        actor_entity_id: None,
        tenant_id: None,
        target_kind: Some("resource".to_string()),
        target_id: Some(Uuid::new_v4()),
        outcome: "allow".to_string(),
        details: serde_json::json!({"kind": "channel"}),
        request_id: None,
    }
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

    let payload = sample_payload("resource.create");
    let event_id = payload.event_id;
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

/// `AmqpPublisher::publish` sends every event in a batch before awaiting any
/// of their confirms (see its doc comment), rather than one full round trip
/// per event. A single-row batch can't tell that code path apart from a
/// naive sequential one — this test forces a multi-row batch through one
/// `deliver_outbox_batch` call and proves every event still actually reaches
/// the broker.
#[tokio::test]
#[ignore]
async fn a_multi_event_batch_is_pipelined_and_all_events_arrive() {
    let pool = common::pool().await;
    sqlx::query("TRUNCATE TABLE event_outbox")
        .execute(&pool)
        .await
        .expect("truncate event_outbox");

    let url = amqp_url();
    let routing_key = format!("atom-events-test-{}", Uuid::new_v4());

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
        amqp_exchange: String::new(),
        amqp_routing_key: routing_key.clone(),
        ..EventsConfig::default()
    };
    let publisher = AmqpPublisher::connect(&cfg)
        .await
        .expect("connect AmqpPublisher to broker");

    let payloads = [
        sample_payload("resource.create"),
        sample_payload("tenant.delete"),
        sample_payload("auth.login"),
    ];
    for payload in &payloads {
        insert_outbox_row(&pool, payload).await;
    }
    let expected_ids: std::collections::HashSet<Uuid> =
        payloads.iter().map(|p| p.event_id).collect();

    let delivered = deliver_outbox_batch(&pool, &publisher, &cfg)
        .await
        .expect("deliver batch");
    assert_eq!(
        delivered,
        payloads.len(),
        "every row in the batch must be delivered, not just the first"
    );

    let mut received_ids = std::collections::HashSet::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while received_ids.len() < payloads.len() {
            if let Some(msg) = consumer_channel
                .basic_get(routing_key.as_str().into(), BasicGetOptions::default())
                .await
                .expect("basic_get")
            {
                let received: DomainEventPayload = serde_json::from_slice(&msg.delivery.data)
                    .expect("deserialize delivered payload");
                received_ids.insert(received.event_id);
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    })
    .await
    .expect("timed out waiting for every event in the batch to arrive at the broker");

    assert_eq!(
        received_ids, expected_ids,
        "every event published in the pipelined batch must arrive, none dropped or duplicated"
    );

    for payload in &payloads {
        let delivered_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT delivered_at FROM event_outbox WHERE id = $1")
                .bind(payload.event_id)
                .fetch_one(&pool)
                .await
                .expect("fetch delivered_at");
        assert!(
            delivered_at.is_some(),
            "delivered_at must be set for event {}",
            payload.event_id
        );
    }
}

/// Under the default exchange, the routing key doubles as the destination
/// queue name — if nothing has declared a queue with that name, the message
/// is unroutable. Proves `AmqpPublisher` catches this (via `mandatory:
/// true` plus inspecting the returned `Confirmation`, see its doc comment)
/// instead of letting the row be marked delivered just because the broker
/// acked receipt of an otherwise-dropped message.
#[tokio::test]
#[ignore]
async fn publishing_to_an_unroutable_routing_key_is_not_marked_delivered() {
    let pool = common::pool().await;
    sqlx::query("TRUNCATE TABLE event_outbox")
        .execute(&pool)
        .await
        .expect("truncate event_outbox");

    let url = amqp_url();
    // Deliberately no `queue_declare` for this routing key: nothing in the
    // broker is bound to it, so the publish below is unroutable.
    let routing_key = format!("atom-events-test-unroutable-{}", Uuid::new_v4());

    let cfg = EventsConfig {
        amqp_url: Some(url.clone()),
        amqp_exchange: String::new(),
        amqp_routing_key: routing_key.clone(),
        ..EventsConfig::default()
    };
    let publisher = AmqpPublisher::connect(&cfg)
        .await
        .expect("connect AmqpPublisher to broker");

    let payload = sample_payload("resource.create");
    let event_id = payload.event_id;
    insert_outbox_row(&pool, &payload).await;

    let delivered = deliver_outbox_batch(&pool, &publisher, &cfg)
        .await
        .expect("deliver batch");
    assert_eq!(
        delivered, 0,
        "an unroutable publish must not be counted as delivered"
    );

    let delivered_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT delivered_at FROM event_outbox WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("fetch delivered_at");
    assert!(
        delivered_at.is_none(),
        "a message the broker never routed anywhere must not be marked delivered"
    );

    let (attempts, last_error): (i32, Option<String>) =
        sqlx::query_as("SELECT attempts, last_error FROM event_outbox WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("fetch attempts/last_error");
    assert_eq!(attempts, 1);
    assert!(last_error.unwrap().contains("unroutable"));
}

/// Every other test in this file uses the default exchange (`exchange ==
/// ""`), where `AmqpPublisher::connect` skips all topology setup entirely
/// (see its doc comment). Setting `ATOM_EVENTS_AMQP_EXCHANGE` takes a
/// different path — `connect` itself declares a durable topic exchange —
/// which until now only had unit-level config validation, not a live
/// end-to-end proof that declare-then-publish-then-route actually works.
#[tokio::test]
#[ignore]
async fn publishing_to_a_custom_topic_exchange_declares_and_routes_correctly() {
    let pool = common::pool().await;
    sqlx::query("TRUNCATE TABLE event_outbox")
        .execute(&pool)
        .await
        .expect("truncate event_outbox");

    let url = amqp_url();
    let exchange = format!("atom-events-test-exchange-{}", Uuid::new_v4());
    let routing_key = "atom-events-test-custom-routing-key".to_string();

    let cfg = EventsConfig {
        amqp_url: Some(url.clone()),
        amqp_exchange: exchange.clone(),
        amqp_routing_key: routing_key.clone(),
        ..EventsConfig::default()
    };
    // Exercises the exchange_declare branch in AmqpPublisher::connect that
    // the default-exchange tests above never touch. Must happen before the
    // consumer below binds to it — a topic exchange only exists once
    // something declares it, unlike the default exchange.
    let publisher = AmqpPublisher::connect(&cfg)
        .await
        .expect("connect AmqpPublisher and declare the custom exchange");

    // Unlike the default exchange, a topic exchange requires an explicit
    // binding — routing key no longer doubles as the queue name. A real
    // consumer would set this up once, out of band, exactly like this.
    let consumer_conn = Connection::connect(&url, ConnectionProperties::default())
        .await
        .expect("connect consumer to broker");
    let consumer_channel = consumer_conn
        .create_channel()
        .await
        .expect("create consumer channel");
    let queue_name = format!("atom-events-test-queue-{}", Uuid::new_v4());
    consumer_channel
        .queue_declare(
            queue_name.as_str().into(),
            QueueDeclareOptions {
                durable: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("declare queue");
    consumer_channel
        .queue_bind(
            queue_name.as_str().into(),
            exchange.as_str().into(),
            routing_key.as_str().into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("bind queue to the custom exchange");

    let payload = sample_payload("resource.create");
    let event_id = payload.event_id;
    insert_outbox_row(&pool, &payload).await;

    let delivered = deliver_outbox_batch(&pool, &publisher, &cfg)
        .await
        .expect("deliver batch");
    assert_eq!(
        delivered, 1,
        "the row must be delivered via the custom exchange"
    );

    let delivered_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT delivered_at FROM event_outbox WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .expect("fetch delivered_at");
    assert!(delivered_at.is_some());

    let message = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(msg) = consumer_channel
                .basic_get(queue_name.as_str().into(), BasicGetOptions::default())
                .await
                .expect("basic_get")
            {
                return msg;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("timed out waiting for the message to arrive via the custom exchange");

    let received: DomainEventPayload =
        serde_json::from_slice(&message.delivery.data).expect("deserialize delivered payload");
    assert_eq!(received.event_id, event_id);
}
