//! Proves the actual gap this feature closes: `resource.create` (and other
//! observe-channeled operations) are never persisted to
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
    audit::{self, AuditEvent, AuditMeta},
    auth::AuthContext,
    config::Config,
    graphql::{build_schema, AtomSchema},
    keys,
    models::enums::AuditOutcome,
    state::AppState,
};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn state_with_events_enabled(pool: PgPool) -> AppState {
    let mut config = Config::for_tests();
    // Enough to make `EventsConfig::enabled()` true so the observe path /
    // `write` enqueue outbox rows — the poller (which would actually dial this
    // URL) is never started in this test, so no real broker is needed.
    config.events.amqp_url = Some("amqp://unused-in-this-test".to_string());
    build_state(pool, config).await
}

async fn state_with_events_disabled(pool: PgPool) -> AppState {
    build_state(pool, Config::for_tests()).await
}

async fn build_state(pool: PgPool, config: Config) -> AppState {
    let _ = sqlx::query("TRUNCATE TABLE signing_keys CASCADE")
        .execute(&pool)
        .await;
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

/// `resource.create` is transactionally observe-enqueued inside `create_resource_with_audit`
/// (see `src/authz/repo.rs`) and is *never* written to `audit_logs` — confirming this produces a
/// domain event when publishing is enabled is the core correctness claim of
/// this feature: hooking events only into the already-DB-persisted `write`
/// path would have silently missed this (and `tenant.create`, `group.create`, `entity.create`).
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
        "resource.create is observe-channeled (not DB-audited) and must NOT reach audit_logs \
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

/// Installs a `BEFORE INSERT` trigger on `table` that raises for exactly one
/// sentinel event name, so a single audit/outbox write can be forced to fail.
///
/// The trigger is global to the database, so it is torn down unconditionally by
/// [`drop_rejecting_trigger`] — including on an assertion failure, which is why
/// the callers below capture their results and clean up before asserting. The
/// sentinel event names are unique per test, so an installed trigger cannot
/// affect any other test's rows even in the window it is live.
async fn install_rejecting_trigger(pool: &PgPool, name: &str, table: &str, event: &str) {
    sqlx::query(&format!(
        r#"CREATE OR REPLACE FUNCTION {name}()
           RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN
             IF NEW.event = '{event}' THEN
               RAISE EXCEPTION 'forced {table} failure';
             END IF;
             RETURN NEW;
           END;
           $$"#
    ))
    .execute(pool)
    .await
    .expect("create rejection function");
    sqlx::query(&format!("DROP TRIGGER IF EXISTS {name} ON {table}"))
        .execute(pool)
        .await
        .expect("drop stale rejection trigger");
    sqlx::query(&format!(
        r#"CREATE TRIGGER {name}
           BEFORE INSERT ON {table}
           FOR EACH ROW EXECUTE FUNCTION {name}()"#
    ))
    .execute(pool)
    .await
    .expect("create rejection trigger");
}

async fn drop_rejecting_trigger(pool: &PgPool, name: &str, table: &str) {
    sqlx::query(&format!("DROP TRIGGER IF EXISTS {name} ON {table}"))
        .execute(pool)
        .await
        .expect("drop rejection trigger");
    sqlx::query(&format!("DROP FUNCTION IF EXISTS {name}()"))
        .execute(pool)
        .await
        .expect("drop rejection function");
}

async fn action_exists(pool: &PgPool, action_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM actions WHERE id = $1)")
        .bind(action_id)
        .fetch_one(pool)
        .await
        .expect("query action existence")
}

/// If outbox insertion fails, the domain mutation must roll back with it. This
/// is the regression boundary that mutate-then-observe could not provide.
#[tokio::test]
#[ignore]
async fn outbox_failure_rolls_back_the_domain_mutation() {
    let pool = common::pool().await;
    install_rejecting_trigger(
        &pool,
        "m26_reject_atomic_test_event",
        "event_outbox",
        "test.atomic.rollback",
    )
    .await;

    let action_id = Uuid::new_v4();
    let action_name = format!("m26-atomic-{action_id}");
    let mut tx = pool.begin().await.expect("begin transaction");
    sqlx::query("INSERT INTO actions (id, name) VALUES ($1, $2)")
        .bind(action_id)
        .bind(&action_name)
        .execute(&mut *tx)
        .await
        .expect("insert action in transaction");
    let result = audit::commit_with_observation(
        tx,
        true,
        &AuditMeta {
            actor_entity_id: Some(common::admin_id()),
            tenant_id: None,
            target_kind: "action",
            target_id: Some(action_id),
            event: "test.atomic.rollback",
        },
        &serde_json::json!({}),
    )
    .await;
    let survived = action_exists(&pool, action_id).await;

    drop_rejecting_trigger(&pool, "m26_reject_atomic_test_event", "event_outbox").await;
    sqlx::query("DELETE FROM actions WHERE id = $1")
        .bind(action_id)
        .execute(&pool)
        .await
        .expect("clean up test action");

    assert!(
        result.is_err(),
        "forced outbox failure must reach the caller"
    );
    assert!(
        !survived,
        "domain mutation must roll back with outbox insert"
    );
}

/// Persisted audit storage is a separate fire-and-forget channel: its failure
/// must not roll back a valid mutation after the outbox transaction commits.
#[tokio::test]
#[ignore]
async fn audit_storage_failure_does_not_fail_the_domain_mutation() {
    let pool = common::pool().await;
    install_rejecting_trigger(
        &pool,
        "m26_reject_audit_test_event",
        "audit_logs",
        "test.audit.fire_and_forget",
    )
    .await;

    let action_id = Uuid::new_v4();
    let action_name = format!("m26-audit-{action_id}");
    let mut tx = pool.begin().await.expect("begin transaction");
    sqlx::query("INSERT INTO actions (id, name) VALUES ($1, $2)")
        .bind(action_id)
        .bind(&action_name)
        .execute(&mut *tx)
        .await
        .expect("insert action in transaction");
    let result = audit::commit_with_audit(
        &pool,
        tx,
        false,
        &AuditEvent {
            actor_entity_id: Some(common::admin_id()),
            tenant_id: None,
            target_kind: Some("action"),
            target_id: Some(action_id),
            event: "test.audit.fire_and_forget",
            outcome: AuditOutcome::Allow,
            details: serde_json::json!({}),
        },
    )
    .await;
    let survived = action_exists(&pool, action_id).await;

    drop_rejecting_trigger(&pool, "m26_reject_audit_test_event", "audit_logs").await;
    sqlx::query("DELETE FROM actions WHERE id = $1")
        .bind(action_id)
        .execute(&pool)
        .await
        .expect("clean up test action");

    result.expect("audit storage failure must not fail the mutation");
    assert!(
        survived,
        "domain mutation must survive audit storage failure"
    );
}

/// A failure event routinely carries ids that do not exist — "tenant not found"
/// is one of the most common reasons an operation fails at all. When
/// `event_outbox.tenant_id`/`actor_entity_id` still had foreign keys into
/// `tenants`/`entities`, the outbox insert was rejected for exactly those rows,
/// so invalid-target failures were the one class of event that could never be
/// published. Migration `007` drops the constraints; this pins that.
#[tokio::test]
#[ignore]
async fn failure_events_publish_even_when_the_tenant_and_actor_do_not_exist() {
    let pool = common::pool().await;
    let events_enabled = true;
    let missing_tenant = Uuid::new_v4();
    let missing_actor = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let event = format!("m26.unknown_tenant.{target_id}");

    audit::observe_error(
        &pool,
        events_enabled,
        &AuditMeta {
            actor_entity_id: Some(missing_actor),
            tenant_id: Some(missing_tenant),
            target_kind: "tenant",
            target_id: Some(target_id),
            event: &event,
        },
        &serde_json::json!({}),
        &atom::error::AppError::not_found(format!("tenant {missing_tenant} not found")),
    )
    .await;

    let payload = outbox_row_for(&pool, &event, target_id)
        .await
        .expect("a failure event with unknown ids must still reach event_outbox");
    assert_eq!(payload["outcome"], "error");
    assert_eq!(
        payload["tenant_id"],
        serde_json::json!(missing_tenant.to_string()),
        "the payload must keep the tenant id the caller actually supplied"
    );
    assert_eq!(
        payload["actor_entity_id"],
        serde_json::json!(missing_actor.to_string())
    );

    // The column copies must survive too — they are what the publisher and any
    // operator query filter on.
    let (row_tenant, row_actor): (Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT tenant_id, actor_entity_id FROM event_outbox WHERE event = $1")
            .bind(&event)
            .fetch_one(&pool)
            .await
            .expect("query outbox columns");
    assert_eq!(row_tenant, Some(missing_tenant));
    assert_eq!(row_actor, Some(missing_actor));

    sqlx::query("DELETE FROM event_outbox WHERE event = $1")
        .bind(&event)
        .execute(&pool)
        .await
        .expect("clean up test outbox row");
}
