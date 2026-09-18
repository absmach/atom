//! Real PostgreSQL tests for the generic GraphQL transaction and lease contract.
mod common;
use async_graphql::{Request, Variables};
use atom::{auth::AuthContext, config::Config, graphql::build_schema, keys, state::AppState};
use serde_json::{json, Value};
use uuid::Uuid;

async fn fixture() -> (sqlx::PgPool, atom::graphql::AtomSchema) {
    let pool = common::pool().await;
    let schema = schema_for_pool(&pool).await;
    (pool, schema)
}

async fn schema_for_pool(pool: &sqlx::PgPool) -> atom::graphql::AtomSchema {
    let config = Config::for_tests();
    keys::bootstrap_if_needed(pool, &config.signing_keys)
        .await
        .expect("keys");
    let keys = keys::load_active_keys(pool, &config.signing_keys)
        .await
        .expect("active keys");
    let mut state = AppState::new(pool.clone(), config, keys, None);
    state.config.events.amqp_url = Some("amqp://test.invalid".into());
    build_schema(state)
}
fn request(query: &str, vars: Value) -> Request {
    Request::new(query)
        .variables(Variables::from_json(vars))
        .data(AuthContext {
            entity_id: common::admin_id(),
            ..Default::default()
        })
}
const COMMIT: &str = "mutation($request: ID!, $changes: [ObjectChangeInput!]!, $guards: [ObjectLeaseGuardInput!]) { commitObjectChanges(requestId: $request, changes: $changes, guards: $guards) }";
fn create(id: Uuid, kind: &str) -> Value {
    json!({"objectKind":kind,"operation":"create","id":id,"kind":if kind=="entity" {"application"} else {"test_record"},"name":format!("test-{id}"),"attributes":{"value":1}})
}
fn update(id: Uuid, revision: i64, value: i64) -> Value {
    json!({"objectKind":"resource","operation":"update","id":id,"expectedRevision":revision,"attributes":{"value":value}})
}
async fn commit(schema: &atom::graphql::AtomSchema, changes: Value) -> Value {
    let response = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),"changes":changes}),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    response.data.into_json().expect("JSON")["commitObjectChanges"].clone()
}
#[tokio::test]
#[ignore]
async fn batch_is_atomic_replayable_and_native_updates_advance_snapshot_revision() {
    let (pool, schema) = fixture().await;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let req = Uuid::new_v4();
    let vars = json!({"request":req,"changes":[create(a,"entity"),create(b,"resource")]});
    let first = schema.execute(request(COMMIT, vars.clone())).await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let again = schema.execute(request(COMMIT, vars.clone())).await;
    assert!(again.errors.is_empty(), "{:?}", again.errors);
    assert_eq!(first.data, again.data);
    let mut changed = vars;
    changed["changes"][0]["attributes"] = json!({"value":9});
    let conflict = schema.execute(request(COMMIT, changed)).await;
    assert_eq!(conflict.errors[0].message, "IDEMPOTENCY_CONFLICT");
    let native=schema.execute(request("mutation($id: ID!) { updateResource(id:$id, input:{attributes:{value:2}}) { id attributes revision } }",json!({"id":b}))).await;
    assert!(native.errors.is_empty(), "{:?}", native.errors);
    let value = native.data.into_json().expect("JSON");
    assert_eq!(value["updateResource"]["revision"], 2);
    assert_eq!(value["updateResource"]["attributes"]["value"], 2);
    let absent = Uuid::new_v4();
    let conflict = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),"changes":[create(absent,"resource"),update(b,1,3)]}),
        ))
        .await;
    assert_eq!(conflict.errors[0].message, "REVISION_CONFLICT");
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM resources WHERE id=$1)")
            .bind(absent)
            .fetch_one(&pool)
            .await
            .expect("exists")
    );
    // Response snapshots remain self-consistent in ordinary list and get paths.
    let read=schema.execute(request("query($id:ID!) { resource(id:$id) { attributes revision } resources(kind:\"test_record\",limit:100) { items { id attributes revision } } }",json!({"id":b}))).await;
    assert!(read.errors.is_empty(), "{:?}", read.errors);
    assert_eq!(
        read.data.into_json().expect("JSON")["resource"]["revision"],
        2
    );
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE target_id=$1 AND event='entity.create'",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audit_count, 0);
}
#[tokio::test]
#[ignore]
async fn concurrent_expected_revision_has_exactly_one_winner() {
    let (_pool, schema) = fixture().await;
    let id = Uuid::new_v4();
    commit(&schema, json!([create(id, "resource")])).await;
    let one = request(
        COMMIT,
        json!({"request":Uuid::new_v4(),"changes":[update(id,1,2)]}),
    );
    let two = request(
        COMMIT,
        json!({"request":Uuid::new_v4(),"changes":[update(id,1,3)]}),
    );
    let (a, b) = tokio::join!(schema.execute(one), schema.execute(two));
    assert_ne!(a.errors.is_empty(), b.errors.is_empty());
    let failure = if a.errors.is_empty() { b } else { a };
    assert_eq!(failure.errors[0].message, "REVISION_CONFLICT");
}
#[tokio::test]
#[ignore]
async fn lease_expiry_fences_stale_workers_and_release_cannot_release_successor() {
    let (pool, schema) = fixture().await;
    let app = Uuid::new_v4();
    let data = Uuid::new_v4();
    commit(
        &schema,
        json!([create(app, "entity"), create(data, "resource")]),
    )
    .await;
    let acquire = "mutation($input:ObjectLeaseInput!) { acquireObjectLease(input:$input) }";
    let holder = Uuid::new_v4();
    let input = json!({"objectKind":"entity","objectId":app,"holderId":holder,"operation":"build","ttlSeconds":120});
    let response = schema
        .execute(request(acquire, json!({"input":input})))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let raw = response.data.into_json().expect("JSON")["acquireObjectLease"].clone();
    let guard =
        json!({"objectKind":"entity","objectId":app,"holderId":holder,"fence":raw["fence"]});
    let other_input = json!({"objectKind":"entity","objectId":app,"holderId":Uuid::new_v4(),"operation":"publish","ttlSeconds":120});
    let held = schema
        .execute(request(acquire, json!({"input":other_input.clone()})))
        .await;
    assert_eq!(held.errors[0].message, "LEASE_HELD");
    let success = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),"changes":[update(data,1,2)],"guards":[guard]}),
        ))
        .await;
    assert!(success.errors.is_empty(), "{:?}", success.errors);
    sqlx::query("UPDATE object_leases SET expires_at=now()-interval '1 second' WHERE object_id=$1")
        .bind(app)
        .execute(&pool)
        .await
        .expect("expire without sleeping");
    let successor = schema
        .execute(request(acquire, json!({"input":other_input})))
        .await;
    assert!(successor.errors.is_empty(), "{:?}", successor.errors);
    assert_eq!(
        successor.data.into_json().expect("JSON")["acquireObjectLease"]["fence"],
        2
    );
    for query in [
        "mutation($guard:ObjectLeaseGuardInput!) { releaseObjectLease(guard:$guard) }",
        "mutation($guard:ObjectLeaseGuardInput!) { renewObjectLease(guard:$guard,ttlSeconds:120) }",
    ] {
        let stale = schema.execute(request(query, json!({"guard":guard}))).await;
        assert_eq!(stale.errors[0].message, "LEASE_LOST");
    }
    let stale = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),"changes":[update(data,2,3)],"guards":[guard]}),
        ))
        .await;
    assert_eq!(stale.errors[0].message, "LEASE_LOST");
}
#[tokio::test]
#[ignore]
async fn access_controls_and_config_management_apply_to_every_batch_target() {
    let (pool, schema) = fixture().await;
    let id = Uuid::new_v4();
    commit(&schema, json!([create(id, "resource")])).await;
    let outsider = Uuid::new_v4();
    sqlx::query("INSERT INTO entities(id,kind,name) VALUES($1,'human',$2)")
        .bind(outsider)
        .bind(format!("outsider-{outsider}"))
        .execute(&pool)
        .await
        .expect("human");
    let forbidden = schema
        .execute(
            Request::new(COMMIT)
                .variables(Variables::from_json(
                    json!({"request":Uuid::new_v4(),"changes":[update(id,1,2)]}),
                ))
                .data(AuthContext {
                    entity_id: outsider,
                    ..Default::default()
                }),
        )
        .await;
    assert_eq!(forbidden.errors[0].message, "forbidden");
    // A scoped token with no grants must not inherit the admin's broad authority.
    let scoped = schema
        .execute(
            Request::new(COMMIT)
                .variables(Variables::from_json(
                    json!({"request":Uuid::new_v4(),"changes":[update(id,1,2)]}),
                ))
                .data(AuthContext {
                    entity_id: common::admin_id(),
                    scoped: true,
                    ceiling: Some(std::sync::Arc::new(atom::authz::repo::CredentialCeiling {
                        entries: vec![],
                    })),
                    ..Default::default()
                }),
        )
        .await;
    assert_eq!(scoped.errors[0].message, "forbidden");
    sqlx::query("UPDATE resources SET managed_by='config' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("managed");
    let managed = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),"changes":[update(id,2,3)]}),
        ))
        .await;
    assert_eq!(managed.errors[0].message, "CONFIG_MANAGED");
    let alias = format!("reserve-{}", Uuid::new_v4());
    let mut one = create(Uuid::new_v4(), "resource");
    let mut two = create(Uuid::new_v4(), "resource");
    one["alias"] = json!(alias);
    two["alias"] = one["alias"].clone();
    let duplicate = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),"changes":[one,two]}),
        ))
        .await;
    assert_eq!(duplicate.errors[0].message, "already exists");
}

#[tokio::test]
#[ignore]
async fn a_committed_delete_can_be_replayed_after_its_target_disappears() {
    let (_pool, schema) = fixture().await;
    let id = Uuid::new_v4();
    commit(&schema, json!([create(id, "resource")])).await;
    let vars = json!({"request":Uuid::new_v4(),"changes":[{
        "objectKind":"resource","operation":"delete","id":id,"expectedRevision":1
    }]});
    let first = schema.execute(request(COMMIT, vars.clone())).await;
    assert!(first.errors.is_empty(), "{:?}", first.errors);
    let again = schema.execute(request(COMMIT, vars)).await;
    assert!(again.errors.is_empty(), "{:?}", again.errors);
    assert_eq!(first.data, again.data);
}

async fn named_fixture() -> (sqlx::PgPool, atom::graphql::AtomSchema, String) {
    let name = format!("coordination-{}", Uuid::new_v4());
    let options = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL")
        .parse::<sqlx::postgres::PgConnectOptions>()
        .expect("database URL")
        .application_name(&name);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .expect("named pool");
    let schema = schema_for_pool(&pool).await;
    (pool, schema, name)
}

async fn wait_for_lock(pool: &sqlx::PgPool, name: &str, event: Option<&str>) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1
                 AND wait_event_type='Lock' AND ($2::text IS NULL OR wait_event=$2))",
            )
            .bind(name)
            .bind(event)
            .fetch_one(pool)
            .await
            .expect("inspect lock wait");
            if waiting {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operation must wait for the expected PostgreSQL lock");
}

#[tokio::test]
#[ignore]
async fn alternate_uuid_guards_contend_on_the_canonical_lease_lock() {
    let (pool, schema) = fixture().await;
    let app = Uuid::new_v4();
    let data = Uuid::new_v4();
    let holder = Uuid::new_v4();
    commit(
        &schema,
        json!([create(app, "entity"), create(data, "resource")]),
    )
    .await;
    let acquired = schema
        .execute(request(
            "mutation($input:ObjectLeaseInput!) { acquireObjectLease(input:$input) }",
            json!({"input":{"objectKind":"entity","objectId":app,"holderId":holder,
                         "operation":"build","ttlSeconds":600}}),
        ))
        .await;
    assert!(acquired.errors.is_empty(), "{:?}", acquired.errors);
    let fence = acquired.data.into_json().expect("JSON")["acquireObjectLease"]["fence"].clone();
    let (_named_pool, named_schema, name) = named_fixture().await;
    let spellings = [
        app.to_string().to_uppercase(),
        app.simple().to_string(),
        app.urn().to_string(),
    ];
    for (index, spelling) in spellings.into_iter().enumerate() {
        let mut blocker = pool.begin().await.expect("blocker");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 17))")
            .bind(format!("lease:entity:{app}"))
            .execute(&mut *blocker)
            .await
            .expect("hold canonical lease lock");
        let schema = named_schema.clone();
        let guard =
            json!({"objectKind":"entity","objectId":spelling,"holderId":holder,"fence":fence});
        let batch = tokio::spawn(async move {
            schema
                .execute(request(
                    COMMIT,
                    json!({"request":Uuid::new_v4(),
                "changes":[update(data, index as i64 + 1, index as i64 + 2)],"guards":[guard]}),
                ))
                .await
        });
        wait_for_lock(&pool, &name, Some("advisory")).await;
        // A differently spelled guard must not bypass the lock used by release
        // or takeover, even though its lease-row lookup parses the UUID.
        assert!(!batch.is_finished());
        blocker.rollback().await.expect("release canonical lock");
        let response = batch.await.expect("batch task");
        assert!(response.errors.is_empty(), "{:?}", response.errors);
    }
}

async fn concurrent_tenant_batches(create_only: bool) {
    let (pool, schema) = fixture().await;
    let mut tenants = [Uuid::new_v4(), Uuid::new_v4()];
    tenants.sort();
    for tenant in tenants {
        sqlx::query("INSERT INTO tenants(id,name) VALUES($1,$2)")
            .bind(tenant)
            .bind(format!("coordination-{tenant}"))
            .execute(&pool)
            .await
            .expect("tenant");
    }
    let mut ids = [
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    ];
    ids.sort();
    let creates = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let mut change = create(*id, "resource");
            change["tenantId"] = json!(tenants[index % 2]);
            change
        })
        .collect::<Vec<_>>();
    if !create_only {
        commit(&schema, json!(creates)).await;
    }
    // Disjoint batches whose object/input order implies A -> B and B -> A.
    let first = if create_only {
        json!([creates[0], creates[3]])
    } else {
        json!([update(ids[0], 1, 2), update(ids[3], 1, 2)])
    };
    let second = if create_only {
        json!([creates[1], creates[2]])
    } else {
        json!([update(ids[1], 1, 2), update(ids[2], 1, 2)])
    };
    let (_pool_a, schema_a, name_a) = named_fixture().await;
    let (_pool_b, schema_b, name_b) = named_fixture().await;
    let mut blocker = pool.begin().await.expect("tenant blocker");
    sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
        .bind(tenants[0])
        .fetch_one(&mut *blocker)
        .await
        .expect("block first tenant");
    let batch_a = tokio::spawn(async move {
        schema_a
            .execute(request(
                COMMIT,
                json!({"request":Uuid::new_v4(),"changes":first}),
            ))
            .await
    });
    wait_for_lock(&pool, &name_a, None).await;
    let batch_b = tokio::spawn(async move {
        schema_b
            .execute(request(
                COMMIT,
                json!({"request":Uuid::new_v4(),"changes":second}),
            ))
            .await
    });
    wait_for_lock(&pool, &name_b, None).await;
    // Both batches must wait on A before touching B. Under the old ordering,
    // batch B held B while waiting on A, setting up a cross-tenant deadlock.
    let mut probe = pool.begin().await.expect("tenant probe");
    sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(tenants[1])
        .fetch_one(&mut *probe)
        .await
        .expect("later tenant must remain unlocked while first tenant is blocked");
    probe.rollback().await.expect("release probe");
    blocker.rollback().await.expect("release first tenant");
    for batch in [batch_a, batch_b] {
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), batch)
            .await
            .expect("batch completes")
            .expect("batch task");
        assert!(response.errors.is_empty(), "{:?}", response.errors);
    }
}

#[tokio::test]
#[ignore]
async fn disjoint_updates_lock_tenants_in_global_order() {
    concurrent_tenant_batches(false).await;
}

#[tokio::test]
#[ignore]
async fn creates_lock_tenants_in_global_order() {
    concurrent_tenant_batches(true).await;
}

#[derive(Clone, Default)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn batch_creates_are_observed_but_only_updates_and_deletes_are_audited() {
    let (pool, schema) = fixture().await;
    let app = Uuid::new_v4();
    let data = Uuid::new_v4();
    let logs = CapturedLogs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    // Other concurrent tests hit these tracing callsites too. A global
    // subscriber avoids racing their cached interest with a scoped dispatcher.
    tracing::subscriber::set_global_default(subscriber).expect("test subscriber");
    commit(
        &schema,
        json!([create(app, "entity"), create(data, "resource")]),
    )
    .await;
    let output = String::from_utf8(logs.0.lock().expect("log buffer").clone()).expect("UTF-8 logs");
    for (event, id) in [("entity.create", app), ("resource.create", data)] {
        assert!(
            output
                .lines()
                .any(|line| line.contains(event) && line.contains(&id.to_string())),
            "missing observation {event}: {output}"
        );
    }
    let mut entity_update = update(app, 1, 2);
    entity_update["objectKind"] = json!("entity");
    commit(&schema, json!([entity_update, update(data, 1, 2)])).await;
    let absent = Uuid::new_v4();
    let failed = schema
        .execute(request(
            COMMIT,
            json!({"request":Uuid::new_v4(),
        "changes":[create(absent,"resource"),update(data,1,3)]}),
        ))
        .await;
    assert_eq!(failed.errors[0].message, "REVISION_CONFLICT");
    commit(
        &schema,
        json!([
            {"objectKind":"entity","operation":"delete","id":app,"expectedRevision":2},
            {"objectKind":"resource","operation":"delete","id":data,"expectedRevision":2}
        ]),
    )
    .await;
    let audits: Vec<String> =
        sqlx::query_scalar("SELECT event FROM audit_logs WHERE target_id=ANY($1) ORDER BY event")
            .bind(vec![app, data, absent])
            .fetch_all(&pool)
            .await
            .expect("audits");
    assert_eq!(
        audits,
        [
            "entity.delete",
            "entity.update",
            "resource.delete",
            "resource.update"
        ]
    );
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event FROM event_outbox WHERE payload->>'target_id'=ANY($1) ORDER BY event",
    )
    .bind(vec![app.to_string(), data.to_string(), absent.to_string()])
    .fetch_all(&pool)
    .await
    .expect("outbox");
    assert_eq!(
        events,
        [
            "entity.create",
            "entity.delete",
            "entity.update",
            "resource.create",
            "resource.delete",
            "resource.update"
        ]
    );
}
