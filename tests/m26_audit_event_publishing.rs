//! Proves the actual gap this feature closes: `resource.create` (and other
//! `observe_result`-channeled operations) are never persisted to
//! `audit_logs` today, but must still produce a domain event when publishing
//! is configured — since those are exactly the events an external consumer
//! (e.g. a billing service) cares about. Also proves the reverse: with no
//! broker configured (the default), no `event_outbox` row is written at all,
//! so existing deployments see zero behavior change.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m26_audit_event_publishing -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::{build_schema, AtomSchema},
    keys,
    state::AppState,
};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn state_with_events_enabled(pool: PgPool) -> AppState {
    let mut config = Config::for_tests();
    // Enough to make `EventsConfig::enabled()` true so `audit::observe_result`/
    // `write` enqueue outbox rows — the poller (which would actually dial this
    // URL) is never started in this test, so no real broker is needed.
    config.events.amqp_url = Some("amqp://unused-in-this-test".to_string());
    build_state(pool, config).await
}

async fn state_with_events_disabled(pool: PgPool) -> AppState {
    build_state(pool, Config::for_tests()).await
}

async fn build_state(pool: PgPool, config: Config) -> AppState {
    keys::bootstrap_if_needed(&pool, &config.signing_keys)
        .await
        .expect("bootstrap signing keys");
    let active_keys = keys::load_active_keys(&pool, &config.signing_keys)
        .await
        .expect("load signing keys");
    AppState::new(pool, config, active_keys, None)
}

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

async fn create_resource_via_graphql(schema: &AtomSchema, name: &str) -> Uuid {
    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createResource(input: {{
                kind: "channel",
                name: "{name}",
                attributes: {{ source: "m26-test" }}
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let value: Value = created.data.into_json().expect("json data");
    value["createResource"]["id"]
        .as_str()
        .expect("resource id")
        .parse()
        .expect("resource id is a uuid")
}

async fn outbox_row_for(pool: &PgPool, event: &str, target_id: Uuid) -> Option<Value> {
    sqlx::query_scalar::<_, Value>(
        "SELECT payload FROM event_outbox
         WHERE event = $1 AND (payload->>'target_id')::uuid = $2",
    )
    .bind(event)
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .expect("query event_outbox")
}

/// `resource.create` is `observe_result`-channeled (see `src/graphql/resources.rs`)
/// and is *never* written to `audit_logs` — confirming this still produces a
/// domain event when publishing is enabled is the core correctness claim of
/// this feature: hooking events only into the already-DB-persisted `write`
/// path would have silently missed this (and `tenant.create`, `group.create`).
#[tokio::test]
#[ignore]
async fn resource_create_produces_an_event_even_though_it_is_never_db_audited() {
    let pool = common::pool().await;
    let state = state_with_events_enabled(pool.clone()).await;
    let schema = build_schema(state);
    let name = format!("m26-resource-{}", Uuid::new_v4());

    let resource_id = create_resource_via_graphql(&schema, &name).await;

    let audited: Option<Uuid> = sqlx::query_scalar(
        "SELECT target_id FROM audit_logs WHERE event = 'resource.create' AND target_id = $1",
    )
    .bind(resource_id)
    .fetch_optional(&pool)
    .await
    .expect("query audit_logs");
    assert!(
        audited.is_none(),
        "resource.create is observe_result-channeled and must NOT reach audit_logs \
         (this assertion documents the existing behavior this feature works around)"
    );

    let payload = outbox_row_for(&pool, "resource.create", resource_id)
        .await
        .expect("resource.create must still produce an event_outbox row");
    assert_eq!(payload["event"], "resource.create");
    assert_eq!(payload["target_kind"], "resource");
    assert_eq!(payload["outcome"], "allow");
    assert_eq!(payload["schema_version"], 1);
}

/// With no broker configured (the default for every existing deployment),
/// event publishing must be a complete no-op: zero new rows, regardless of
/// which audit channel the operation uses.
#[tokio::test]
#[ignore]
async fn no_event_outbox_rows_are_written_when_events_are_not_configured() {
    let pool = common::pool().await;
    let state = state_with_events_disabled(pool.clone()).await;
    let schema = build_schema(state);
    let name = format!("m26-resource-disabled-{}", Uuid::new_v4());

    let resource_id = create_resource_via_graphql(&schema, &name).await;

    let payload = outbox_row_for(&pool, "resource.create", resource_id).await;
    assert!(
        payload.is_none(),
        "no event_outbox row should be written when EventsConfig::enabled() is false"
    );
}
