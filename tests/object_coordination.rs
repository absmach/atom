//! Real PostgreSQL tests for the generic GraphQL transaction and lease contract.
mod common;
use async_graphql::{Request, Variables};
use atom::{auth::AuthContext, config::Config, graphql::build_schema, keys, state::AppState};
use serde_json::{json, Value};
use uuid::Uuid;

async fn fixture() -> (sqlx::PgPool, atom::graphql::AtomSchema) {
    let pool = common::pool().await;
    let config = Config::for_tests();
    keys::bootstrap_if_needed(&pool, &config.signing_keys)
        .await
        .expect("keys");
    let keys = keys::load_active_keys(&pool, &config.signing_keys)
        .await
        .expect("active keys");
    let mut state = AppState::new(pool.clone(), config, keys, None);
    state.config.events.amqp_url = Some("amqp://test.invalid".into());
    (pool, build_schema(state))
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
    assert_eq!(audit_count, 1);
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
