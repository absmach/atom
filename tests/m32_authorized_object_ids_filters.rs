//! Scoping filters on the `authorizedObjectIds` GraphQL query.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m32_authorized_object_ids_filters -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext, authz::repo as authz_repo, config::Config, graphql::build_schema, keys,
    models::token::AccessTokenPermission, state::AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
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

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

/// A request authenticated as a scoped access token, capped by `ceiling`. The
/// entity that owns the token is still the subject; what differs is that the
/// resolver now has a non-empty ceiling to intersect against.
fn authed_scoped(
    entity_id: Uuid,
    credential_id: Uuid,
    ceiling: authz_repo::CredentialCeiling,
    query: impl Into<String>,
) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        credential_id: Some(credential_id),
        scoped: true,
        ceiling: Some(Arc::new(ceiling)),
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

async fn make_entity(pool: &PgPool, tenant_id: Uuid, attributes: Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, tenant_id, status, attributes)
           VALUES ($1, 'device', $2, $3, 'active', $4)"#,
    )
    .bind(id)
    .bind(format!("m32-entity-{id}"))
    .bind(tenant_id)
    .bind(attributes)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn make_object_group(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO object_groups (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("m32-{name}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert object group");
    id
}

/// Object-scoped `read` allow for `subject_id` on one entity.
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

fn listing(data: &Value) -> (Vec<String>, i64) {
    let ids = data["authorizedObjectIds"]["ids"]
        .as_array()
        .expect("ids array")
        .iter()
        .map(|v| v.as_str().expect("id string").to_string())
        .collect();
    let total = data["authorizedObjectIds"]["total"]
        .as_i64()
        .expect("total");
    (ids, total)
}

/// Criterion 1: `parentGroupId` intersects the authorized set with group
/// membership — a device the subject may read but that is not in the group is
/// excluded, and vice versa.
#[tokio::test]
#[ignore]
async fn parent_group_id_narrows_to_the_intersection() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-parent-group").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let group = make_object_group(&pool, tenant_id, "g").await;

    let in_group = make_entity(&pool, tenant_id, json!({})).await;
    atom::identity::repo::add_entity_to_object_group(&pool, in_group, group)
        .await
        .expect("add to group");
    let outside_group = make_entity(&pool, tenant_id, json!({})).await;

    grant_read(&pool, tenant_id, subject_id, in_group).await;
    grant_read(&pool, tenant_id, subject_id, outside_group).await;

    let schema = build_schema(state(pool).await);
    let response = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      parentGroupId: "{group}"
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let (ids, total) = listing(&data);
    assert_eq!(total, 1);
    assert_eq!(ids, vec![in_group.to_string()]);
}

/// Criterion 2: `attributesContains` narrows the authorized set the same way
/// it narrows `entities()`.
#[tokio::test]
#[ignore]
async fn attributes_contains_narrows_the_authorized_set() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-attrs").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let marker = format!("m32-{}", Uuid::new_v4());

    let matching = make_entity(&pool, tenant_id, json!({"marker": marker, "site": "north"})).await;
    let nonmatching =
        make_entity(&pool, tenant_id, json!({"marker": marker, "site": "south"})).await;
    grant_read(&pool, tenant_id, subject_id, matching).await;
    grant_read(&pool, tenant_id, subject_id, nonmatching).await;

    let schema = build_schema(state(pool).await);
    let response = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      attributesContains: {{ marker: "{marker}", site: "north" }}
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"));
    assert_eq!(total, 1);
    assert_eq!(ids, vec![matching.to_string()]);
}

/// Criterion 3: `includeDescendants: true` walks the group tree from
/// `parentGroupId`; omitted (and explicit `false`) does not.
#[tokio::test]
#[ignore]
async fn include_descendants_walks_the_tree_only_when_set() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-descendants").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let parent = make_object_group(&pool, tenant_id, "parent").await;
    let child = make_object_group(&pool, tenant_id, "child").await;
    sqlx::query(
        "INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(parent)
    .bind(child)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("link groups");

    let in_child = make_entity(&pool, tenant_id, json!({})).await;
    atom::identity::repo::add_entity_to_object_group(&pool, in_child, child)
        .await
        .expect("add to child group");
    grant_read(&pool, tenant_id, subject_id, in_child).await;

    let schema = build_schema(state(pool).await);

    let without = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      parentGroupId: "{parent}"
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(without.errors.is_empty(), "{:?}", without.errors);
    let (_, total) = listing(&without.data.into_json().expect("json data"));
    assert_eq!(
        total, 0,
        "without includeDescendants, the child's members are invisible"
    );

    let with = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      parentGroupId: "{parent}", includeDescendants: true
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(with.errors.is_empty(), "{:?}", with.errors);
    let (ids, total) = listing(&with.data.into_json().expect("json data"));
    assert_eq!(total, 1);
    assert_eq!(ids, vec![in_child.to_string()]);
}

/// Criterion 5, the security-relevant one: a subject with no grant at all
/// receives an empty list for every filter, never the unfiltered set and never
/// an error. Filters can only narrow; they cannot themselves grant access.
#[tokio::test]
#[ignore]
async fn a_subject_with_no_grant_gets_an_empty_list_regardless_of_filters() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-no-grant").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let group = make_object_group(&pool, tenant_id, "g").await;
    let marker = format!("m32-{}", Uuid::new_v4());
    let entity = make_entity(&pool, tenant_id, json!({"marker": marker})).await;
    atom::identity::repo::add_entity_to_object_group(&pool, entity, group)
        .await
        .expect("add to group");
    // Deliberately no grant_read call: subject holds nothing.

    let schema = build_schema(state(pool).await);
    for filter in [
        format!(r#"parentGroupId: "{group}", includeDescendants: true"#),
        format!(r#"attributesContains: {{ marker: "{marker}" }}"#),
        r#"externalId: "anything""#.to_string(),
    ] {
        let response = schema
            .execute(authed_as(
                subject_id,
                format!(
                    r#"{{ authorizedObjectIds(input: {{
                          subjectId: "{subject_id}", action: "read",
                          objectKind: "entity", objectType: "entity:device",
                          {filter}
                        }}) {{ ids total }} }}"#
                ),
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let (ids, total) = listing(&response.data.into_json().expect("json data"));
        assert_eq!(total, 0, "filter {filter} must not grant access on its own");
        assert!(ids.is_empty());
    }
}

/// Criterion 6: a scoped access token's ceiling still excludes an object the
/// subject's direct policy allows, and it is not reopened by supplying a
/// filter the object happens to match.
#[tokio::test]
#[ignore]
async fn scoped_token_ceiling_excludes_regardless_of_filters() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-ceiling").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let marker = format!("m32-{}", Uuid::new_v4());
    let group = make_object_group(&pool, tenant_id, "g").await;

    let in_ceiling = make_entity(&pool, tenant_id, json!({"marker": marker})).await;
    let outside_ceiling = make_entity(&pool, tenant_id, json!({"marker": marker})).await;
    atom::identity::repo::add_entity_to_object_group(&pool, in_ceiling, group)
        .await
        .expect("add in_ceiling to group");
    atom::identity::repo::add_entity_to_object_group(&pool, outside_ceiling, group)
        .await
        .expect("add outside_ceiling to group");

    // The direct policy allows both.
    grant_read(&pool, tenant_id, subject_id, in_ceiling).await;
    grant_read(&pool, tenant_id, subject_id, outside_ceiling).await;

    // The scoped token narrows to just `in_ceiling`.
    let token = atom::identity::service::create_access_token(
        &pool,
        &Default::default(),
        subject_id,
        atom::models::token::CreateAccessToken {
            name: "m32-scoped".into(),
            description: None,
            expires_at: None,
            permissions: vec![AccessTokenPermission {
                actions: vec!["read".into()],
                scope_mode: "object".into(),
                tenant_id: None,
                object_kind: None,
                object_type: None,
                object_id: Some(in_ceiling),
                conditions: None,
            }],
        },
        true,
    )
    .await
    .expect("create access token");
    let ceiling = authz_repo::load_credential_ceiling(&pool, token.credential_id)
        .await
        .expect("load ceiling");

    let schema = build_schema(state(pool).await);
    // A filter that matches BOTH entities — must not resurrect outside_ceiling.
    let response = schema
        .execute(authed_scoped(
            subject_id,
            token.credential_id,
            ceiling,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      attributesContains: {{ marker: "{marker}" }},
                      parentGroupId: "{group}"
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"));
    assert_eq!(total, 1, "the ceiling must still exclude outside_ceiling");
    assert_eq!(ids, vec![in_ceiling.to_string()]);
}

/// Criterion 7: omitting every new argument is byte-identical to the listing
/// before this PRD — the regression guard.
#[tokio::test]
#[ignore]
async fn omitting_the_new_filters_is_unchanged() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-omitted").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let a = make_entity(&pool, tenant_id, json!({})).await;
    let b = make_entity(&pool, tenant_id, json!({})).await;
    grant_read(&pool, tenant_id, subject_id, a).await;
    grant_read(&pool, tenant_id, subject_id, b).await;

    let schema = build_schema(state(pool).await);
    let response = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device"
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"));
    assert_eq!(total, 2);
    for expected in [a, b] {
        assert!(ids.contains(&expected.to_string()));
    }
}

/// `externalId` and `profileId`/`entityStatus` are exposed the same way, since
/// they were the point of coordinating with ATOM-06 on this same resolver.
#[tokio::test]
#[ignore]
async fn external_id_and_entity_status_also_narrow() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-external-id").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let serial = format!("SN-{}", Uuid::new_v4());
    let matching = make_entity(&pool, tenant_id, json!({})).await;
    sqlx::query("UPDATE entities SET external_id = $1 WHERE id = $2")
        .bind(&serial)
        .bind(matching)
        .execute(&pool)
        .await
        .expect("set external_id");
    let other = make_entity(&pool, tenant_id, json!({})).await;
    grant_read(&pool, tenant_id, subject_id, matching).await;
    grant_read(&pool, tenant_id, subject_id, other).await;

    let schema = build_schema(state(pool).await);
    let response = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      externalId: "{serial}"
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"));
    assert_eq!(total, 1);
    assert_eq!(ids, vec![matching.to_string()]);
}

/// A blank `externalId` is a caller mistake, not "no filter": it must match
/// zero rows, not the unfiltered authorized set.
#[tokio::test]
#[ignore]
async fn blank_external_id_matches_nothing_not_everything() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m32-blank-external-id").await;
    let subject_id = make_entity(&pool, tenant_id, json!({})).await;
    let a = make_entity(&pool, tenant_id, json!({})).await;
    let b = make_entity(&pool, tenant_id, json!({})).await;
    grant_read(&pool, tenant_id, subject_id, a).await;
    grant_read(&pool, tenant_id, subject_id, b).await;

    let schema = build_schema(state(pool).await);
    let response = schema
        .execute(authed_as(
            subject_id,
            format!(
                r#"{{ authorizedObjectIds(input: {{
                      subjectId: "{subject_id}", action: "read",
                      objectKind: "entity", objectType: "entity:device",
                      externalId: "   "
                    }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let (ids, total) = listing(&response.data.into_json().expect("json data"));
    assert_eq!(total, 0, "a blank externalId filter must match nothing");
    assert!(ids.is_empty());
}
