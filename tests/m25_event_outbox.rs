//! DB-gated tests for the event-outbox delivery mechanics: at-least-once
//! delivery, redelivery after a simulated crash, and failure bookkeeping
//! (`attempts`/`last_error`). Nothing in this file produces `event_outbox`
//! rows via a mutation — that happens automatically now via `audit::write`/
//! `observe_result`/`write_hot_path` (see `tests/m26_audit_event_publishing.rs`
//! for that integration) — so every row here is inserted directly,
//! exercising the poller/delivery function in isolation.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m25_event_outbox -- --ignored
//! ```

mod common;

use atom::config::EventsConfig;
use atom::events::deliver_outbox_batch;
use atom::events::publisher::{EventPublisher, PublishError};
use atom::events::DomainEventPayload;
use axum::async_trait;
use sqlx::PgPool;
use std::sync::Mutex;
use uuid::Uuid;

async fn truncate_event_outbox(pool: &PgPool) {
    sqlx::query("TRUNCATE TABLE event_outbox")
        .execute(pool)
        .await
        .expect("truncate event_outbox");
}

fn test_events_config() -> EventsConfig {
    EventsConfig {
        amqp_url: Some("amqp://ignored-in-tests".to_string()),
        ..EventsConfig::default()
    }
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
        details: serde_json::json!({}),
        request_id: None,
    }
}

async fn insert_outbox_row(pool: &PgPool, payload: &DomainEventPayload) -> Uuid {
    let id = payload.event_id;
    sqlx::query("INSERT INTO event_outbox (id, event, payload) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&payload.event)
        .bind(serde_json::to_value(payload).expect("serialize payload"))
        .execute(pool)
        .await
        .expect("insert event_outbox row");
    id
}

async fn delivered_at(pool: &PgPool, id: Uuid) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT delivered_at FROM event_outbox WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch delivered_at")
}

async fn attempts_and_error(pool: &PgPool, id: Uuid) -> (i32, Option<String>) {
    let row: (i32, Option<String>) =
        sqlx::query_as("SELECT attempts, last_error FROM event_outbox WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("fetch attempts/last_error");
    row
}

/// Records every batch it was asked to publish; can be told to fail the
/// next N calls, to simulate a redelivered/retried batch.
#[derive(Default)]
struct MockPublisher {
    calls: Mutex<Vec<Vec<Uuid>>>,
    fail_next: Mutex<usize>,
}

impl MockPublisher {
    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn event_ids_seen(&self) -> Vec<Uuid> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .copied()
            .collect()
    }

    fn fail_next_n(&self, n: usize) {
        *self.fail_next.lock().unwrap() = n;
    }
}

#[async_trait]
impl EventPublisher for MockPublisher {
    async fn publish(&self, events: &[DomainEventPayload]) -> Result<(), PublishError> {
        self.calls
            .lock()
            .unwrap()
            .push(events.iter().map(|e| e.event_id).collect());

        let mut fail_next = self.fail_next.lock().unwrap();
        if *fail_next > 0 {
            *fail_next -= 1;
            return Err(PublishError("simulated publisher failure".to_string()));
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn delivered_row_is_marked_delivered_exactly_once_per_call() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;
    let payload = sample_payload("resource.create");
    let id = insert_outbox_row(&pool, &payload).await;

    let publisher = MockPublisher::default();
    let delivered = deliver_outbox_batch(&pool, &publisher, &test_events_config())
        .await
        .expect("deliver batch");

    assert_eq!(delivered, 1);
    assert_eq!(publisher.call_count(), 1);
    assert_eq!(publisher.event_ids_seen(), vec![id]);
    assert!(delivered_at(&pool, id).await.is_some());
}

#[tokio::test]
#[ignore]
async fn undelivered_rows_are_not_redelivered_once_marked_delivered() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;
    let payload = sample_payload("resource.create");
    let id = insert_outbox_row(&pool, &payload).await;

    let publisher = MockPublisher::default();
    let cfg = test_events_config();

    let first = deliver_outbox_batch(&pool, &publisher, &cfg).await.unwrap();
    let second = deliver_outbox_batch(&pool, &publisher, &cfg).await.unwrap();

    assert_eq!(first, 1);
    assert_eq!(second, 0, "already-delivered row must not be redelivered");
    assert_eq!(
        publisher.call_count(),
        1,
        "publisher should only be invoked once"
    );
    assert!(delivered_at(&pool, id).await.is_some());
}

/// At-least-once, not exactly-once: a publisher that fails leaves the row
/// undelivered so the *same* event_id is redelivered on the next tick,
/// rather than being lost or duplicated under a new id.
#[tokio::test]
#[ignore]
async fn a_failed_delivery_is_redelivered_with_the_same_event_id() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;
    let payload = sample_payload("resource.create");
    let id = insert_outbox_row(&pool, &payload).await;

    let publisher = MockPublisher::default();
    publisher.fail_next_n(1);
    let cfg = test_events_config();

    let first = deliver_outbox_batch(&pool, &publisher, &cfg).await.unwrap();
    assert_eq!(first, 0, "a failed publish must not mark the row delivered");
    assert!(delivered_at(&pool, id).await.is_none());

    let (attempts, last_error) = attempts_and_error(&pool, id).await;
    assert_eq!(attempts, 1);
    assert!(last_error.unwrap().contains("simulated publisher failure"));

    let second = deliver_outbox_batch(&pool, &publisher, &cfg).await.unwrap();
    assert_eq!(second, 1, "the retried delivery must succeed");
    assert!(delivered_at(&pool, id).await.is_some());

    // Same event_id both times — redelivery, not a duplicate-with-new-id.
    assert_eq!(publisher.event_ids_seen(), vec![id, id]);
}

#[tokio::test]
#[ignore]
async fn arbitrary_event_names_are_all_delivered_no_filtering() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;
    let resource_create = sample_payload("resource.create");
    let tenant_delete = sample_payload("tenant.delete");
    let auth_login = sample_payload("auth.login");
    let id_a = insert_outbox_row(&pool, &resource_create).await;
    let id_b = insert_outbox_row(&pool, &tenant_delete).await;
    let id_c = insert_outbox_row(&pool, &auth_login).await;

    let publisher = MockPublisher::default();
    let delivered = deliver_outbox_batch(&pool, &publisher, &test_events_config())
        .await
        .unwrap();

    assert_eq!(delivered, 3);
    let mut seen = publisher.event_ids_seen();
    seen.sort();
    let mut expected = vec![id_a, id_b, id_c];
    expected.sort();
    assert_eq!(seen, expected);
}

/// Fails only for batches containing one specific event, regardless of how
/// many times it's called — models a row that can never succeed (e.g. a
/// permanently unroutable routing key), unlike `MockPublisher::fail_next_n`
/// which fails a fixed number of calls no matter their content.
struct FailsForId {
    poison_id: Uuid,
}

#[async_trait]
impl EventPublisher for FailsForId {
    async fn publish(&self, events: &[DomainEventPayload]) -> Result<(), PublishError> {
        if events.iter().any(|e| e.event_id == self.poison_id) {
            Err(PublishError("simulated permanent failure".to_string()))
        } else {
            Ok(())
        }
    }
}

/// A row that can never succeed must stop being retried once it hits
/// `outbox_max_attempts`, and — just as important — must stop occupying
/// batch slots once excluded, so a healthy row queued behind it (oldest
/// first) is no longer starved forever.
#[tokio::test]
#[ignore]
async fn an_exhausted_row_stops_being_retried_and_unblocks_newer_rows() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;

    let poison_id = insert_outbox_row(&pool, &sample_payload("resource.create")).await;
    let healthy_id = insert_outbox_row(&pool, &sample_payload("resource.create")).await;

    let publisher = FailsForId { poison_id };
    let cfg = EventsConfig {
        outbox_batch_size: 1,
        outbox_max_attempts: 2,
        ..test_events_config()
    };

    // With batch_size=1, each tick fetches only the oldest still-eligible
    // row. Both ticks below must hit the poison row (it's older) and fail.
    for _ in 0..2 {
        let delivered = deliver_outbox_batch(&pool, &publisher, &cfg).await.unwrap();
        assert_eq!(delivered, 0);
    }
    let (attempts, _) = attempts_and_error(&pool, poison_id).await;
    assert_eq!(attempts, 2, "poison row should have exhausted max_attempts");
    assert!(delivered_at(&pool, poison_id).await.is_none());

    // Now that the poison row has hit the cap, it must be excluded from the
    // SELECT entirely — this tick should reach the healthy row instead of
    // retrying (and re-failing on) the exhausted one forever.
    let delivered = deliver_outbox_batch(&pool, &publisher, &cfg).await.unwrap();
    assert_eq!(delivered, 1, "the healthy row must no longer be starved");
    assert!(delivered_at(&pool, healthy_id).await.is_some());

    // And the poison row itself must never be retried past the cap.
    let (attempts_after, _) = attempts_and_error(&pool, poison_id).await;
    assert_eq!(
        attempts_after, 2,
        "an exhausted row must not be retried further"
    );
}

/// A row whose payload doesn't deserialize into `DomainEventPayload` (e.g.
/// left over from an older schema version) must never be marked delivered —
/// it was never actually handed to the publisher — but a good row in the
/// same batch must still be delivered normally.
#[tokio::test]
#[ignore]
async fn a_row_with_an_unparseable_payload_is_never_marked_delivered() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;

    let bad_id = Uuid::new_v4();
    sqlx::query("INSERT INTO event_outbox (id, event, payload) VALUES ($1, $2, $3)")
        .bind(bad_id)
        .bind("resource.create")
        .bind(serde_json::json!({"this": "does not match DomainEventPayload"}))
        .execute(&pool)
        .await
        .expect("insert malformed event_outbox row");

    let good_payload = sample_payload("resource.create");
    let good_id = insert_outbox_row(&pool, &good_payload).await;

    let publisher = MockPublisher::default();
    let delivered = deliver_outbox_batch(&pool, &publisher, &test_events_config())
        .await
        .expect("deliver batch");

    assert_eq!(delivered, 1, "only the well-formed row counts as delivered");
    assert_eq!(
        publisher.event_ids_seen(),
        vec![good_id],
        "the publisher must never see the unparseable row"
    );

    assert!(delivered_at(&pool, good_id).await.is_some());
    assert!(
        delivered_at(&pool, bad_id).await.is_none(),
        "an unparseable row must not be marked delivered"
    );

    let (attempts, last_error) = attempts_and_error(&pool, bad_id).await;
    assert_eq!(attempts, 1);
    assert!(last_error.unwrap().contains("does not deserialize"));
}

#[tokio::test]
#[ignore]
async fn delivering_with_no_undelivered_rows_is_a_harmless_no_op() {
    let pool = common::pool().await;
    truncate_event_outbox(&pool).await;
    let publisher = MockPublisher::default();
    let delivered = deliver_outbox_batch(&pool, &publisher, &test_events_config())
        .await
        .unwrap();
    assert_eq!(delivered, 0);
    assert_eq!(publisher.call_count(), 0);
}
