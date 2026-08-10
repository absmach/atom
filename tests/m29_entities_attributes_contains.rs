//! `attributesContains` filtering on the `entities` and `groups` queries.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m29_entities_attributes_contains -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext, config::Config, graphql::build_schema, keys, models::enums::DeletedFilter,
    state::AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn state(pool: PgPool) -> AppState {
    let config = Config::for_tests();
    keys::bootstrap_if_needed(&pool, &config.signing_keys)
        .await
        .expect("bootstrap signing keys");
    let active_keys = keys::load_active_keys(&pool, &config.signing_keys)
        .await
        .expect("load signing keys");
    AppState::new(pool, config, active_keys, None)
}

fn authed(query: impl Into<String>) -> Request {
    authed_as(common::admin_id(), query)
}

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

async fn make_tenant(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{name}-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_entity(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    kind: &str,
    status: &str,
    attributes: Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, tenant_id, status, attributes)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(id)
    .bind(kind)
    .bind(format!("m29-entity-{id}"))
    .bind(tenant_id)
    .bind(status)
    .bind(attributes)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn make_object_group(
    pool: &PgPool,
    tenant_id: Uuid,
    status: &str,
    attributes: Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO object_groups (id, name, tenant_id, status, attributes)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(id)
    .bind(format!("m29-group-{id}"))
    .bind(tenant_id)
    .bind(status)
    .bind(attributes)
    .execute(pool)
    .await
    .expect("insert object group");
    id
}

/// Object-scoped `read` allow for `subject_id` on one object, mirroring how the
/// GraphQL surface grants a subject visibility of a single entity or group.
async fn grant_read(pool: &PgPool, tenant_id: Uuid, subject_id: Uuid, object_id: Uuid) {
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (tenant_id, scope_mode, object_id, effect)
           VALUES ($1, 'object', $2, 'allow') RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(object_id)
    .fetch_one(pool)
    .await
    .expect("insert read block");
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
           SELECT $1, id FROM actions WHERE name = 'read'"#,
    )
    .bind(block_id)
    .execute(pool)
    .await
    .expect("insert read action");
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("assign read policy");
}

fn listing(data: &Value, query: &str) -> (Vec<String>, i64) {
    let ids = data[query]["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("item id").to_owned())
        .collect();
    let total = data[query]["total"].as_i64().expect("total");
    (ids, total)
}

/// Criteria 1, 2, 4 and 6: containment filters the listing, composes with the
/// other filters, is reflected in `total`, and omitting it filters nothing.
#[tokio::test]
#[ignore]
async fn entities_query_filters_by_attributes_contains() {
    let pool = common::pool().await;
    let tenant_a = make_tenant(&pool, "m29-entity-attrs-a").await;
    let tenant_b = make_tenant(&pool, "m29-entity-attrs-b").await;
    let marker = format!("m29-{}", Uuid::new_v4());
    let schema = build_schema(state(pool.clone()).await);

    let pending_device = make_entity(
        &pool,
        Some(tenant_a),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let provisioned_device = make_entity(
        &pool,
        Some(tenant_a),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "provisioned"}),
    )
    .await;
    let pending_inactive_device = make_entity(
        &pool,
        Some(tenant_a),
        "device",
        "inactive",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let pending_human = make_entity(
        &pool,
        Some(tenant_a),
        "human",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let pending_other_tenant = make_entity(
        &pool,
        Some(tenant_b),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;

    let filtered = schema
        .execute(authed(format!(
            r#"
            {{
              entities(attributesContains: {{ marker: "{marker}", provisioning_state: "pending" }}) {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(filtered.errors.is_empty(), "{:?}", filtered.errors);
    let (ids, total) = listing(&filtered.data.into_json().expect("json data"), "entities");
    assert_eq!(total, 4, "total must reflect the filtered count");
    assert_eq!(ids.len(), 4);
    for expected in [
        pending_device,
        pending_inactive_device,
        pending_human,
        pending_other_tenant,
    ] {
        assert!(
            ids.contains(&expected.to_string()),
            "matching entity {expected} missing from {ids:?}"
        );
    }
    assert!(!ids.contains(&provisioned_device.to_string()));

    // Composes with kind, tenantId and status.
    let composed = schema
        .execute(authed(format!(
            r#"
            {{
              entities(
                kind: device,
                tenantId: "{tenant_a}",
                status: active,
                attributesContains: {{ marker: "{marker}", provisioning_state: "pending" }}
              ) {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(composed.errors.is_empty(), "{:?}", composed.errors);
    let (ids, total) = listing(&composed.data.into_json().expect("json data"), "entities");
    assert_eq!(total, 1);
    assert_eq!(ids, vec![pending_device.to_string()]);

    // Criterion 6: omitting the argument filters nothing.
    let unfiltered = schema
        .execute(authed(format!(
            r#"
            {{
              entities(kind: device, tenantId: "{tenant_a}") {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(unfiltered.errors.is_empty(), "{:?}", unfiltered.errors);
    let (ids, total) = listing(&unfiltered.data.into_json().expect("json data"), "entities");
    assert_eq!(total, 3);
    for expected in [pending_device, provisioned_device, pending_inactive_device] {
        assert!(
            ids.contains(&expected.to_string()),
            "unfiltered listing must contain {expected}, got {ids:?}"
        );
    }
}

/// Criterion 1a: array containment — the gateway view's "which devices are
/// declared on this gateway" query.
#[tokio::test]
#[ignore]
async fn entities_query_attributes_contains_matches_array_membership() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m29-entity-gateways").await;
    let marker = format!("m29-{}", Uuid::new_v4());
    let schema = build_schema(state(pool.clone()).await);

    let on_both = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "gateways": ["gw-a", "gw-b"]}),
    )
    .await;
    let on_gw_a_only = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "gateways": ["gw-a"]}),
    )
    .await;
    let on_gw_b_only = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "gateways": ["gw-b"]}),
    )
    .await;
    let unattached = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "gateways": []}),
    )
    .await;

    let response = schema
        .execute(authed(format!(
            r#"
            {{
              entities(attributesContains: {{ marker: "{marker}", gateways: ["gw-a"] }}) {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"), "entities");

    assert_eq!(total, 2);
    assert!(ids.contains(&on_both.to_string()));
    assert!(ids.contains(&on_gw_a_only.to_string()));
    assert!(!ids.contains(&on_gw_b_only.to_string()));
    assert!(!ids.contains(&unattached.to_string()));
}

/// Criterion 3: the filter composes with authorization on the **live** branch —
/// the subject sees only entities it may read *and* that match, and `total` is
/// the intersection, not either side alone.
#[tokio::test]
#[ignore]
async fn entities_query_attributes_contains_composes_with_authorization() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m29-entity-attrs-authz").await;
    let marker = format!("m29-{}", Uuid::new_v4());
    let schema = build_schema(state(pool.clone()).await);

    let subject_id = make_entity(&pool, Some(tenant_id), "human", "active", json!({})).await;
    let authorized_match = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let unauthorized_match = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let authorized_nonmatch = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "provisioned"}),
    )
    .await;
    grant_read(&pool, tenant_id, subject_id, authorized_match).await;
    grant_read(&pool, tenant_id, subject_id, authorized_nonmatch).await;

    let filtered = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"
            {{
              entities(attributesContains: {{ marker: "{marker}", provisioning_state: "pending" }}) {{
                items {{ id }}
                total
              }}
            }}
            "#
            ),
        ))
        .await;
    assert!(filtered.errors.is_empty(), "{:?}", filtered.errors);
    let (ids, total) = listing(&filtered.data.into_json().expect("json data"), "entities");
    assert_eq!(total, 1, "total must count the authorized matches only");
    assert_eq!(ids, vec![authorized_match.to_string()]);
    assert!(
        !ids.contains(&unauthorized_match.to_string()),
        "a matching but unreadable entity must stay hidden"
    );

    // Without the filter the same subject still sees both entities it may read,
    // so the filter — not the authorization — removed the non-matching one.
    let unfiltered = schema
        .execute(authed_as(
            subject_id,
            r#"
            {
              entities {
                items { id }
                total
              }
            }
            "#,
        ))
        .await;
    assert!(unfiltered.errors.is_empty(), "{:?}", unfiltered.errors);
    let (ids, total) = listing(&unfiltered.data.into_json().expect("json data"), "entities");
    assert_eq!(total, 2);
    assert!(ids.contains(&authorized_match.to_string()));
    assert!(ids.contains(&authorized_nonmatch.to_string()));
}

/// The deleted-filter branch (platform-manage only) applies the filter too.
#[tokio::test]
#[ignore]
async fn entities_query_attributes_contains_applies_on_deleted_branch() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m29-entity-attrs-deleted").await;
    let marker = format!("m29-{}", Uuid::new_v4());
    let schema = build_schema(state(pool.clone()).await);

    let pending = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let provisioned = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "provisioned"}),
    )
    .await;
    for entity_id in [pending, provisioned] {
        atom::identity::repo::delete_entity(&pool, entity_id, None)
            .await
            .expect("soft delete entity");
    }

    let response = schema
        .execute(authed(format!(
            r#"
            {{
              entities(
                deleted: deleted,
                attributesContains: {{ marker: "{marker}", provisioning_state: "pending" }}
              ) {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"), "entities");

    assert_eq!(total, 1);
    assert_eq!(ids, vec![pending.to_string()]);
}

/// Criterion 5: `groups(attributesContains: …)` behaves equivalently, including
/// composition with the other filters, `total`, and the omitted-argument case.
#[tokio::test]
#[ignore]
async fn groups_query_filters_by_attributes_contains() {
    let pool = common::pool().await;
    let tenant_a = make_tenant(&pool, "m29-group-attrs-a").await;
    let tenant_b = make_tenant(&pool, "m29-group-attrs-b").await;
    let marker = format!("m29-{}", Uuid::new_v4());
    let schema = build_schema(state(pool.clone()).await);

    let site_north = make_object_group(
        &pool,
        tenant_a,
        "active",
        json!({"marker": marker, "site": "north"}),
    )
    .await;
    let site_south = make_object_group(
        &pool,
        tenant_a,
        "active",
        json!({"marker": marker, "site": "south"}),
    )
    .await;
    let site_north_inactive = make_object_group(
        &pool,
        tenant_a,
        "inactive",
        json!({"marker": marker, "site": "north"}),
    )
    .await;
    let site_north_other_tenant = make_object_group(
        &pool,
        tenant_b,
        "active",
        json!({"marker": marker, "site": "north"}),
    )
    .await;

    let filtered = schema
        .execute(authed(format!(
            r#"
            {{
              groups(attributesContains: {{ marker: "{marker}", site: "north" }}) {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(filtered.errors.is_empty(), "{:?}", filtered.errors);
    let (ids, total) = listing(&filtered.data.into_json().expect("json data"), "groups");
    assert_eq!(total, 3);
    for expected in [site_north, site_north_inactive, site_north_other_tenant] {
        assert!(
            ids.contains(&expected.to_string()),
            "matching group {expected} missing from {ids:?}"
        );
    }
    assert!(!ids.contains(&site_south.to_string()));

    // Composes with tenantId and status.
    let composed = schema
        .execute(authed(format!(
            r#"
            {{
              groups(
                tenantId: "{tenant_a}",
                status: active,
                attributesContains: {{ marker: "{marker}", site: "north" }}
              ) {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(composed.errors.is_empty(), "{:?}", composed.errors);
    let (ids, total) = listing(&composed.data.into_json().expect("json data"), "groups");
    assert_eq!(total, 1);
    assert_eq!(ids, vec![site_north.to_string()]);

    // Criterion 6 for groups: omitting the argument filters nothing.
    let unfiltered = schema
        .execute(authed(format!(
            r#"
            {{
              groups(tenantId: "{tenant_a}") {{
                items {{ id }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(unfiltered.errors.is_empty(), "{:?}", unfiltered.errors);
    let (ids, total) = listing(&unfiltered.data.into_json().expect("json data"), "groups");
    assert_eq!(total, 3);
    for expected in [site_north, site_south, site_north_inactive] {
        assert!(
            ids.contains(&expected.to_string()),
            "unfiltered listing must contain {expected}, got {ids:?}"
        );
    }
}

/// Criterion 5 on the live branch: the group filter composes with authorization
/// the same way the entity one does.
#[tokio::test]
#[ignore]
async fn groups_query_attributes_contains_composes_with_authorization() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m29-group-attrs-authz").await;
    let marker = format!("m29-{}", Uuid::new_v4());
    let schema = build_schema(state(pool.clone()).await);

    let subject_id = make_entity(&pool, Some(tenant_id), "human", "active", json!({})).await;
    let authorized_match = make_object_group(
        &pool,
        tenant_id,
        "active",
        json!({"marker": marker, "site": "north"}),
    )
    .await;
    let unauthorized_match = make_object_group(
        &pool,
        tenant_id,
        "active",
        json!({"marker": marker, "site": "north"}),
    )
    .await;
    let authorized_nonmatch = make_object_group(
        &pool,
        tenant_id,
        "active",
        json!({"marker": marker, "site": "south"}),
    )
    .await;
    grant_read(&pool, tenant_id, subject_id, authorized_match).await;
    grant_read(&pool, tenant_id, subject_id, authorized_nonmatch).await;

    let response = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"
            {{
              groups(attributesContains: {{ marker: "{marker}", site: "north" }}) {{
                items {{ id }}
                total
              }}
            }}
            "#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"), "groups");

    assert_eq!(total, 1);
    assert_eq!(ids, vec![authorized_match.to_string()]);
    assert!(!ids.contains(&unauthorized_match.to_string()));
    assert!(!ids.contains(&authorized_nonmatch.to_string()));
}

/// The repository call the resolver makes on the deleted branch: a `None`
/// filter must leave the listing untouched (regression guard for criterion 6).
#[tokio::test]
#[ignore]
async fn list_entities_without_attributes_contains_is_unfiltered() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m29-entity-attrs-none").await;
    let marker = format!("m29-{}", Uuid::new_v4());

    let pending = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "pending"}),
    )
    .await;
    let provisioned = make_entity(
        &pool,
        Some(tenant_id),
        "device",
        "active",
        json!({"marker": marker, "provisioning_state": "provisioned"}),
    )
    .await;

    let list = atom::identity::repo::list_entities(
        &pool,
        atom::models::entity::ListEntities {
            q: None,
            kind: None,
            profile_id: None,
            tenant_id: Some(tenant_id),
            attributes_contains: None,
            status: None,
            deleted: DeletedFilter::Live,
            parent_group_id: None,
            include_descendants: false,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list entities");

    assert_eq!(list.total, 2);
    let ids: Vec<Uuid> = list.items.iter().map(|entity| entity.id).collect();
    assert!(ids.contains(&pending));
    assert!(ids.contains(&provisioned));
}
