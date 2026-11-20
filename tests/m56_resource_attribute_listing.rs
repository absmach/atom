//! `resources` listing: ordering by an attribute value (`orderAttribute`) and
//! any-of attribute filters (`attributesIn`), on the direct list, the
//! authorized (visibility) list and the GraphQL query.
//!
//! Needs a database and is ignored by default; the same bodies run on both
//! backends:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m56_resource_attribute_listing -- --ignored
//! ATOM_TEST_BACKEND=sqlite cargo test --test m56_resource_attribute_listing -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    db::Database,
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    models::{
        access::AuthorizedObjectIdsQuery,
        enums::{DeletedFilter, SortDir},
        resource::{AttributeValueType, ListResources, ResourceAttributeQuery},
    },
    state::AppState,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

struct Fixture {
    pool: Database,
    tenant_id: Uuid,
    subject_id: Uuid,
    prefix: String,
    /// label -> resource id, oldest to newest.
    ids: Vec<(&'static str, Uuid)>,
}

impl Fixture {
    fn name(&self, id: Uuid) -> &'static str {
        self.ids
            .iter()
            .find(|(_, i)| *i == id)
            .map(|(n, _)| *n)
            .expect("known resource")
    }
}

async fn insert_resource(
    pool: &Database,
    tenant_id: Uuid,
    name: &str,
    attributes: Value,
    created_at: chrono::DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    common::db::query_shared(
        "INSERT INTO resources (id, kind, name, tenant_id, attributes, created_at)
         VALUES ($1, 'm56doc', $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(name)
    .bind(tenant_id)
    .bind(attributes)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert resource");
    id
}

/// Eight resources `a`..`h` (created oldest to newest), all readable by the subject.
async fn fixture() -> Fixture {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();
    let prefix = format!("m56-{suffix}");
    let tenant_id = Uuid::new_v4();
    common::db::query_shared("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(format!("{prefix}-tenant"))
        .execute(&pool)
        .await
        .expect("insert tenant");
    let subject_id = Uuid::new_v4();
    common::db::query_shared(
        "INSERT INTO entities (id, kind, name, tenant_id, status)
         VALUES ($1, 'human', $2, $3, 'active')",
    )
    .bind(subject_id)
    .bind(format!("{prefix}-subject"))
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert subject");

    let rows: Vec<(&'static str, Value)> = vec![
        ("a", json!({"score": 10, "slug": "x", "status": "new"})),
        ("b", json!({"score": 30, "slug": "y", "status": "new"})),
        (
            "c",
            json!({"score": 20, "slug": "", "status": "shortlisted"}),
        ),
        ("d", json!({"score": "abc", "slug": "x", "status": "new"})),
        ("e", json!({"slug": "z"})),
        (
            "f",
            json!({"score": null, "slug": "x", "status": "shortlisted"}),
        ),
        ("g", json!({"score": 30, "slug": "x", "status": "new"})),
        ("h", json!({"score": 5.5, "slug": "y", "status": "new"})),
    ];
    let base = Utc::now() - Duration::minutes(10);
    let mut ids = Vec::new();
    for (i, (label, attributes)) in rows.into_iter().enumerate() {
        let id = insert_resource(
            &pool,
            tenant_id,
            &format!("{prefix}-{label}"),
            attributes,
            base + Duration::seconds(i as i64),
        )
        .await;
        grant_read(&pool, tenant_id, subject_id, id).await;
        ids.push((label, id));
    }
    Fixture {
        pool,
        tenant_id,
        subject_id,
        prefix,
        ids,
    }
}

async fn grant_read(pool: &Database, tenant_id: Uuid, subject_id: Uuid, resource_id: Uuid) {
    let block_id: Uuid = common::db::query_scalar(
        "INSERT INTO permission_blocks (tenant_id, scope_mode, object_id, effect)
         VALUES ($1, 'object', $2, 'allow') RETURNING id",
        "INSERT INTO permission_blocks (tenant_id, scope_mode, object_id, effect)
         VALUES ($1, 'object', $2, 'allow') RETURNING id",
    )
    .bind(tenant_id)
    .bind(resource_id)
    .fetch_one(pool)
    .await
    .expect("insert block");
    common::db::query_shared(
        "INSERT INTO permission_block_actions (permission_block_id, action_id)
         SELECT $1, id FROM actions WHERE name = 'read'",
    )
    .bind(block_id)
    .execute(pool)
    .await
    .expect("insert block action");
    common::db::query_shared(
        "INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
         VALUES ($1, 'entity', $2, $3)",
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("insert policy");
}

#[derive(Clone, Default)]
struct Opts {
    q: Option<String>,
    contains: Option<Value>,
    attrs_in: Option<Value>,
    order_attribute: Option<&'static str>,
    order_type: Option<AttributeValueType>,
    dir: SortDir,
    limit: Option<i64>,
    offset: i64,
}

impl Opts {
    fn attrs(&self) -> ResourceAttributeQuery {
        ResourceAttributeQuery::new(
            self.order_attribute.map(str::to_owned),
            self.order_type,
            self.attrs_in.clone(),
        )
        .expect("valid attribute query")
    }
}

/// Labels and total from the direct (platform-admin) list.
async fn direct(f: &Fixture, o: &Opts) -> (Vec<&'static str>, i64) {
    let page = atom::authz::resources::list_resources(
        &f.pool,
        ListResources {
            q: o.q.clone(),
            kind: Some("m56doc".to_string()),
            tenant_id: Some(f.tenant_id),
            attributes_contains: o.contains.clone(),
            parent_group_id: None,
            include_descendants: false,
            deleted: DeletedFilter::Live,
            limit: o.limit.unwrap_or(100),
            offset: o.offset,
            order: Default::default(),
            dir: o.dir,
            attrs: o.attrs(),
        },
    )
    .await
    .expect("direct list");
    let labels = page.items.iter().map(|r| f.label_of(r.id)).collect();
    (labels, page.total)
}

/// Labels and total from the authorized listing, rehydrated in order.
async fn authorized(f: &Fixture, o: &Opts) -> (Vec<&'static str>, i64) {
    let page = atom::authz::repo::authorized_object_ids_with_ceiling(
        &f.pool,
        AuthorizedObjectIdsQuery {
            subject_id: f.subject_id,
            action: "read".to_string(),
            object_kind: "resource".to_string(),
            object_type: Some("resource:m56doc".to_string()),
            tenant_id: Some(f.tenant_id),
            id: None,
            q: o.q.clone(),
            attributes_contains: o.contains.clone(),
            external_id: None,
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id: None,
            include_descendants: false,
            limit: o.limit.unwrap_or(100),
            offset: o.offset,
            entity_order: Default::default(),
            resource_order: Default::default(),
            group_order: Default::default(),
            dir: o.dir,
            resource_attrs: o.attrs(),
        },
        None,
    )
    .await
    .expect("authorized list");
    let items = atom::authz::resources::list_resources_by_ids(&f.pool, &page.ids)
        .await
        .expect("rehydrate");
    (items.iter().map(|r| f.label_of(r.id)).collect(), page.total)
}

impl Fixture {
    fn label_of(&self, id: Uuid) -> &'static str {
        self.name(id)
    }
}

/// Runs `o` on both listings and asserts they agree with `expected`/`total`.
async fn check(f: &Fixture, o: Opts, expected: &[&str], total: i64) {
    let (labels, t) = direct(f, &o).await;
    assert_eq!((labels.as_slice(), t), (expected, total), "direct list");
    let (labels, t) = authorized(f, &o).await;
    assert_eq!((labels.as_slice(), t), (expected, total), "authorized list");
}

fn number(dir: SortDir) -> Opts {
    Opts {
        order_attribute: Some("score"),
        order_type: Some(AttributeValueType::Number),
        dir,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore]
async fn numeric_order_puts_missing_null_and_non_numeric_last_in_both_directions() {
    let f = fixture().await;
    // 30 ties (b older, g newer) break by created_at DESC; d ("abc"), e
    // (missing) and f (null) are all null-like and also break by created_at DESC.
    check(
        &f,
        number(SortDir::Desc),
        &["g", "b", "c", "a", "h", "f", "e", "d"],
        8,
    )
    .await;
    check(
        &f,
        number(SortDir::Asc),
        &["h", "a", "c", "g", "b", "f", "e", "d"],
        8,
    )
    .await;
}

#[tokio::test]
#[ignore]
async fn text_order_compares_attribute_text_with_nulls_last() {
    let f = fixture().await;
    let text = |dir| Opts {
        order_attribute: Some("slug"),
        dir,
        ..Default::default()
    };
    // slug: c "", a/d/f/g "x" (newest first), b/h "y", e "z".
    check(
        &f,
        text(SortDir::Asc),
        &["c", "g", "f", "d", "a", "h", "b", "e"],
        8,
    )
    .await;
    check(
        &f,
        text(SortDir::Desc),
        &["e", "h", "b", "g", "f", "d", "a", "c"],
        8,
    )
    .await;

    // `score` as text: JSON null and a missing key are null (last); numbers
    // compare by their text.
    let (labels, _) = direct(
        &f,
        &Opts {
            order_attribute: Some("score"),
            dir: SortDir::Desc,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(labels[labels.len() - 2..], ["f", "e"]);
    let (auth_labels, _) = authorized(
        &f,
        &Opts {
            order_attribute: Some("score"),
            dir: SortDir::Desc,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(auth_labels, labels);
}

#[tokio::test]
#[ignore]
async fn attribute_order_pages_without_gaps_or_repeats() {
    let f = fixture().await;
    for dir in [SortDir::Desc, SortDir::Asc] {
        let (full, _) = direct(&f, &number(dir)).await;
        for listing in 0..2 {
            let mut stitched = Vec::new();
            for page in 0..3 {
                let o = Opts {
                    limit: Some(3),
                    offset: page * 3,
                    ..number(dir)
                };
                let (labels, total) = if listing == 0 {
                    direct(&f, &o).await
                } else {
                    authorized(&f, &o).await
                };
                assert_eq!(total, 8);
                stitched.extend(labels);
            }
            assert_eq!(stitched, full, "listing {listing}, {dir:?}");
        }
    }
}

#[tokio::test]
#[ignore]
async fn attributes_in_is_or_within_a_key_and_and_across_keys() {
    let f = fixture().await;
    let by = |v: Value| Opts {
        attrs_in: Some(v),
        ..Default::default()
    };
    // Default order is created_at DESC, newest first.
    check(
        &f,
        by(json!({"slug": ["x", "y"]})),
        &["h", "g", "f", "d", "b", "a"],
        6,
    )
    .await;
    check(&f, by(json!({"slug": [""]})), &["c"], 1).await;
    check(
        &f,
        by(json!({"slug": ["x", ""], "status": ["new"]})),
        &["g", "d", "a"],
        3,
    )
    .await;
    check(
        &f,
        by(json!({"slug": ["x", "y"], "status": ["new", "shortlisted"]})),
        &["h", "g", "f", "d", "b", "a"],
        6,
    )
    .await;
    // Missing attribute never matches; unknown values match nothing.
    check(
        &f,
        by(json!({"status": ["new", "shortlisted"]})),
        &["h", "g", "f", "d", "c", "b", "a"],
        7,
    )
    .await;
    check(&f, by(json!({"slug": ["nope"]})), &[], 0).await;
}

#[tokio::test]
#[ignore]
async fn attributes_in_matches_json_equal_values() {
    let f = fixture().await;
    let by = |v: Value| Opts {
        attrs_in: Some(v),
        ..Default::default()
    };
    check(&f, by(json!({"score": ["30"]})), &[], 0).await; // "30" is not 30
    check(&f, by(json!({"score": [30]})), &["g", "b"], 2).await;
    check(
        &f,
        by(json!({"score": [30, 10, 5.5]})),
        &["h", "g", "b", "a"],
        4,
    )
    .await;
    check(&f, by(json!({"score": ["abc"]})), &["d"], 1).await;
    check(&f, by(json!({"score": [null]})), &["f"], 1).await; // explicit null only
}

#[tokio::test]
#[ignore]
async fn attributes_in_combines_with_contains_q_total_and_order() {
    let f = fixture().await;
    check(
        &f,
        Opts {
            attrs_in: Some(json!({"slug": ["x", "y"]})),
            contains: Some(json!({"status": "new"})),
            ..Default::default()
        },
        &["h", "g", "d", "b", "a"],
        5,
    )
    .await;
    check(
        &f,
        Opts {
            attrs_in: Some(json!({"slug": ["x"]})),
            q: Some(format!("{}-g", f.prefix)),
            ..Default::default()
        },
        &["g"],
        1,
    )
    .await;
    check(
        &f,
        Opts {
            attrs_in: Some(json!({"slug": ["y"]})),
            q: Some(format!("{}-g", f.prefix)),
            ..Default::default()
        },
        &[],
        0,
    )
    .await;
    // Total reflects the filter, not the page; order does not change it.
    check(
        &f,
        Opts {
            attrs_in: Some(json!({"slug": ["x", "y"]})),
            limit: Some(2),
            offset: 1,
            ..number(SortDir::Desc)
        },
        &["b", "a"],
        6,
    )
    .await;
}

fn state(pool: Database) -> AppState {
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        Config::for_tests(),
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

fn admin(query: &str, vars: Value) -> Request {
    Request::new(query)
        .variables(async_graphql::Variables::from_json(vars))
        .data(AuthContext {
            entity_id: common::admin_id(),
            tenant_id: None,
            session_id: None,
            ..Default::default()
        })
}

const QUERY: &str =
    "query($t: ID, $in: JSON, $oa: String, $ot: AttributeValueType, $dir: SortDir, $limit: Int) {
  resources(kind: \"m56doc\", tenantId: $t, attributesIn: $in, orderAttribute: $oa,
            orderAttributeType: $ot, dir: $dir, limit: $limit) { total items { name } }
}";

#[tokio::test]
#[ignore]
async fn graphql_orders_filters_and_rejects_invalid_arguments() {
    let f = fixture().await;
    let schema = build_schema(state(f.pool.clone()));
    let t = f.tenant_id.to_string();

    // Admin reads everything in the tenant, including an extra `z` (score 99)
    // that the fixture subject cannot read.
    insert_resource(
        &f.pool,
        f.tenant_id,
        &format!("{}-z", f.prefix),
        json!({"score": 99, "slug": "x", "status": "new"}),
        Utc::now(),
    )
    .await;
    let ok = schema
        .execute(admin(
            QUERY,
            json!({"t": t, "in": {"slug": ["x", "y"]}, "oa": "score", "ot": "NUMBER", "limit": 3}),
        ))
        .await;
    assert!(ok.errors.is_empty(), "{:?}", ok.errors);
    let data = ok.data.into_json().expect("json");
    assert_eq!(data["resources"]["total"], 7);
    let names: Vec<String> = data["resources"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        names,
        vec![
            format!("{}-z", f.prefix),
            format!("{}-g", f.prefix),
            format!("{}-b", f.prefix)
        ]
    );

    // Default direction with orderAttribute is DESC; ASC flips it.
    let asc = schema
        .execute(admin(
            QUERY,
            json!({"t": t, "oa": "score", "ot": "NUMBER", "dir": "asc", "limit": 1}),
        ))
        .await;
    assert!(asc.errors.is_empty(), "{:?}", asc.errors);
    assert_eq!(
        asc.data.into_json().unwrap()["resources"]["items"][0]["name"],
        format!("{}-h", f.prefix)
    );

    for (label, vars) in [
        (
            "injection key",
            json!({"t": t, "oa": "score'); DROP TABLE resources;--"}),
        ),
        ("dotted key", json!({"t": t, "oa": "a.b"})),
        ("type without attribute", json!({"t": t, "ot": "NUMBER"})),
        ("in not an object", json!({"t": t, "in": ["a"]})),
        (
            "in value not an array",
            json!({"t": t, "in": {"slug": "x"}}),
        ),
        ("in empty array", json!({"t": t, "in": {"slug": []}})),
        ("in nested value", json!({"t": t, "in": {"slug": [["x"]]}})),
        ("in bad key", json!({"t": t, "in": {"sl-ug": ["x"]}})),
    ] {
        let response = schema.execute(admin(QUERY, vars)).await;
        assert_eq!(response.errors.len(), 1, "{label}: {:?}", response.errors);
        let code = response.errors[0]
            .extensions
            .as_ref()
            .and_then(|e| e.get("code").cloned());
        assert_eq!(
            code,
            Some(async_graphql::Value::String("BAD_REQUEST".into())),
            "{label}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn authorized_listing_excludes_unreadable_matches_before_ordering_and_paging() {
    let f = fixture().await;
    // Matches every filter and sorts first, but the subject has no read grant.
    insert_resource(
        &f.pool,
        f.tenant_id,
        &format!("{}-z", f.prefix),
        json!({"score": 99, "slug": "x", "status": "new"}),
        Utc::now(),
    )
    .await;
    let o = Opts {
        attrs_in: Some(json!({"slug": ["x", "y"]})),
        limit: Some(2),
        ..number(SortDir::Desc)
    };
    let (labels, total) = authorized(&f, &o).await;
    assert_eq!((labels.as_slice(), total), (["g", "b"].as_slice(), 6));
}
