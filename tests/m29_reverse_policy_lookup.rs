//! Reverse policy lookup: `directPolicies(objectId:)`.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m29_reverse_policy_lookup -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    config::Config,
    graphql::build_schema,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

fn state(pool: PgPool) -> AppState {
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

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

fn authed(query: impl Into<String>) -> Request {
    authed_as(common::admin_id(), query)
}

// ─── fixtures ────────────────────────────────────────────────────────────────
//
// Written straight to SQL so a test can build shapes the mutation API guards
// against (a tenant-scoped block over the same object, for instance) and so the
// fixture stays readable next to the assertion it supports.

async fn tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("reverse-lookup-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn entity(pool: &PgPool, tenant_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("reverse-lookup-{kind}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn resource(pool: &PgPool, tenant_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(kind)
        .bind(format!("reverse-lookup-{kind}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn object_group(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO object_groups (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("reverse-lookup-group-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert object group");
    id
}

async fn set_group_parent(pool: &PgPool, tenant_id: Uuid, child_id: Uuid, parent_id: Uuid) {
    sqlx::query(
        "INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(parent_id)
    .bind(child_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert object group hierarchy");
}

async fn add_entity_to_group(pool: &PgPool, tenant_id: Uuid, group_id: Uuid, entity_id: Uuid) {
    sqlx::query(
        "INSERT INTO object_group_entities (group_id, entity_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(group_id)
    .bind(entity_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert object group entity");
}

async fn add_resource_to_group(pool: &PgPool, tenant_id: Uuid, group_id: Uuid, resource_id: Uuid) {
    sqlx::query(
        "INSERT INTO object_group_resources (group_id, resource_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(group_id)
    .bind(resource_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert object group resource");
}

struct BlockSpec {
    scope_mode: &'static str,
    tenant_id: Option<Uuid>,
    object_kind: Option<&'static str>,
    object_type: Option<&'static str>,
    object_id: Option<Uuid>,
    group_id: Option<Uuid>,
}

impl BlockSpec {
    fn new(scope_mode: &'static str, tenant_id: Option<Uuid>) -> Self {
        Self {
            scope_mode,
            tenant_id,
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
        }
    }

    fn object(mut self, object_id: Uuid) -> Self {
        self.object_id = Some(object_id);
        self
    }

    fn group(mut self, group_id: Uuid) -> Self {
        self.group_id = Some(group_id);
        self
    }

    fn kind(mut self, object_kind: &'static str) -> Self {
        self.object_kind = Some(object_kind);
        self
    }

    fn object_type(mut self, object_type: &'static str) -> Self {
        self.object_type = Some(object_type);
        self
    }
}

async fn block(pool: &PgPool, spec: BlockSpec) -> Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
             (scope_mode, tenant_id, object_kind, object_type, object_id, group_id, effect)
           VALUES ($1, $2, $3, $4, $5, $6, 'allow')
           RETURNING id"#,
    )
    .bind(spec.scope_mode)
    .bind(spec.tenant_id)
    .bind(spec.object_kind)
    .bind(spec.object_type)
    .bind(spec.object_id)
    .bind(spec.group_id)
    .fetch_one(pool)
    .await
    .expect("insert permission block")
}

async fn policy(pool: &PgPool, tenant_id: Option<Uuid>, subject_id: Uuid, block_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .fetch_one(pool)
    .await
    .expect("insert direct policy")
}

async fn seeded_action(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seeded action")
}

async fn attach_action(pool: &PgPool, block_id: Uuid, action_id: Uuid) {
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(action_id)
    .execute(pool)
    .await
    .expect("insert permission block action");
}

/// One subject + one block + one policy, so every fixture row in a test is
/// distinguishable by the policy id it produced.
async fn granted(pool: &PgPool, tenant_id: Uuid, spec: BlockSpec) -> Uuid {
    granted_to(pool, tenant_id, spec, None).await.1
}

/// As [`granted`], optionally wiring an action onto the block so the PDP can
/// decide on it too. Returns `(subject, policy)`.
async fn granted_to(
    pool: &PgPool,
    tenant_id: Uuid,
    spec: BlockSpec,
    action_id: Option<Uuid>,
) -> (Uuid, Uuid) {
    let subject = entity(pool, tenant_id, "human").await;
    let block_id = block(pool, spec).await;
    if let Some(action_id) = action_id {
        attach_action(pool, block_id, action_id).await;
    }
    (
        subject,
        policy(pool, Some(tenant_id), subject, block_id).await,
    )
}

fn ids(data: &Value) -> Vec<String> {
    data["directPolicies"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("policy id").to_owned())
        .collect()
}

fn total(data: &Value) -> i64 {
    data["directPolicies"]["total"].as_i64().expect("total")
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// A device reachable four ways — a direct object block, direct group
/// membership, descendant group membership, and a tenant-scoped block — and
/// only the three blocks that *name* it come back.
#[tokio::test]
#[ignore]
async fn object_lookup_returns_naming_blocks_and_excludes_class_scoped_ones() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;

    let parent_group = object_group(&pool, tenant_id).await;
    let child_group = object_group(&pool, tenant_id).await;
    set_group_parent(&pool, tenant_id, child_group, parent_group).await;

    let device = entity(&pool, tenant_id, "device").await;
    add_entity_to_group(&pool, tenant_id, child_group, device).await;

    let direct_object = granted(
        &pool,
        tenant_id,
        BlockSpec::new("object", Some(tenant_id)).object(device),
    )
    .await;
    let group_member = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_direct_objects", Some(tenant_id))
            .group(child_group)
            .kind("entity")
            .object_type("entity:device"),
    )
    .await;
    let group_descendant = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_descendant_objects", Some(tenant_id))
            .group(parent_group)
            .kind("entity")
            .object_type("entity:device"),
    )
    .await;

    // Reach the device without naming it. None of these may be returned.
    let tenant_scoped = granted(&pool, tenant_id, BlockSpec::new("tenant", Some(tenant_id))).await;
    let kind_scoped = granted(
        &pool,
        tenant_id,
        BlockSpec::new("object_kind", Some(tenant_id)).kind("entity"),
    )
    .await;
    let type_scoped = granted(
        &pool,
        tenant_id,
        BlockSpec::new("object_type", Some(tenant_id))
            .kind("entity")
            .object_type("entity:device"),
    )
    .await;
    let subject = entity(&pool, tenant_id, "human").await;
    let platform_block = block(&pool, BlockSpec::new("platform", None)).await;
    let platform_scoped = policy(&pool, None, subject, platform_block).await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");

    let returned = ids(&data);
    for expected in [direct_object, group_member, group_descendant] {
        assert!(
            returned.contains(&expected.to_string()),
            "expected policy {expected} in {returned:?}"
        );
    }
    for excluded in [tenant_scoped, kind_scoped, type_scoped, platform_scoped] {
        assert!(
            !returned.contains(&excluded.to_string()),
            "policy {excluded} reaches the device without naming it and must not be returned"
        );
    }
    assert_eq!(total(&data), 3, "exactly the three naming blocks match");
}

/// Exercises a 3-deep tree at every level. `group_descendant_objects` matches
/// through strict ancestors only — an object sitting directly in the block's
/// own group is the `group_direct_objects` case, which is how the PDP
/// (`grant_scope_matches`, migration 001) draws the line.
#[tokio::test]
#[ignore]
async fn direct_and_descendant_group_scopes_split_the_tree_at_each_level() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;

    let root = object_group(&pool, tenant_id).await;
    let middle = object_group(&pool, tenant_id).await;
    let leaf = object_group(&pool, tenant_id).await;
    set_group_parent(&pool, tenant_id, middle, root).await;
    set_group_parent(&pool, tenant_id, leaf, middle).await;

    let device = entity(&pool, tenant_id, "device").await;
    add_entity_to_group(&pool, tenant_id, leaf, device).await;

    let mut expected = Vec::new();
    let mut unexpected = Vec::new();
    for (group_id, level) in [(leaf, "leaf"), (middle, "middle"), (root, "root")] {
        let direct = granted(
            &pool,
            tenant_id,
            BlockSpec::new("group_direct_objects", Some(tenant_id))
                .group(group_id)
                .kind("entity")
                .object_type("entity:device"),
        )
        .await;
        let descendant = granted(
            &pool,
            tenant_id,
            BlockSpec::new("group_descendant_objects", Some(tenant_id))
                .group(group_id)
                .kind("entity")
                .object_type("entity:device"),
        )
        .await;
        // Direct membership holds only at the leaf; descendant matching holds
        // only strictly above it.
        if level == "leaf" {
            expected.push(direct);
            unexpected.push(descendant);
        } else {
            unexpected.push(direct);
            expected.push(descendant);
        }
    }

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let returned = ids(&data);

    for id in &expected {
        assert!(returned.contains(&id.to_string()), "missing {id}");
    }
    for id in &unexpected {
        assert!(!returned.contains(&id.to_string()), "unexpected {id}");
    }
    assert_eq!(total(&data), expected.len() as i64);
}

/// `group` and group hierarchy scope modes name group objects, so looking up a
/// child group must return the direct group, direct child, and descendant group
/// policies that cover it.
#[tokio::test]
#[ignore]
async fn object_lookup_includes_group_hierarchy_scopes_for_group_objects() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;

    let root = object_group(&pool, tenant_id).await;
    let parent = object_group(&pool, tenant_id).await;
    let child = object_group(&pool, tenant_id).await;
    set_group_parent(&pool, tenant_id, parent, root).await;
    set_group_parent(&pool, tenant_id, child, parent).await;

    let direct_group = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group", Some(tenant_id)).group(child),
    )
    .await;
    let child_scope = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_child_groups", Some(tenant_id)).group(parent),
    )
    .await;
    let descendant_from_parent = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_descendant_groups", Some(tenant_id)).group(parent),
    )
    .await;
    let descendant_from_root = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_descendant_groups", Some(tenant_id)).group(root),
    )
    .await;

    let sibling_parent = object_group(&pool, tenant_id).await;
    let unrelated_child_scope = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_child_groups", Some(tenant_id)).group(sibling_parent),
    )
    .await;
    let unrelated_direct_group = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group", Some(tenant_id)).group(sibling_parent),
    )
    .await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{child}") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let returned = ids(&data);

    for expected in [
        direct_group,
        child_scope,
        descendant_from_parent,
        descendant_from_root,
    ] {
        assert!(
            returned.contains(&expected.to_string()),
            "expected group hierarchy policy {expected} in {returned:?}"
        );
    }
    for unexpected in [unrelated_child_scope, unrelated_direct_group] {
        assert!(
            !returned.contains(&unexpected.to_string()),
            "an unrelated group must not name the child group"
        );
    }
    assert_eq!(total(&data), 4);

    let narrowed_away = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{child}", objectKind: "resource") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(
        narrowed_away.errors.is_empty(),
        "{:?}",
        narrowed_away.errors
    );
    let data = narrowed_away.data.into_json().expect("json data");
    assert_eq!(
        total(&data),
        0,
        "objectKind must narrow implicit group scopes"
    );

    let matching_type = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{child}", objectKind: "group", objectType: "group:object") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(
        matching_type.errors.is_empty(),
        "{:?}",
        matching_type.errors
    );
    let data = matching_type.data.into_json().expect("json data");
    assert_eq!(total(&data), 4);
}

/// A group block only names the objects of its declared kind and type, and
/// the co-filters narrow further.
#[tokio::test]
#[ignore]
async fn object_kind_and_type_co_filters_narrow_the_lookup() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let group_id = object_group(&pool, tenant_id).await;

    let device = entity(&pool, tenant_id, "device").await;
    let channel = resource(&pool, tenant_id, "channel").await;
    add_entity_to_group(&pool, tenant_id, group_id, device).await;
    add_resource_to_group(&pool, tenant_id, group_id, channel).await;

    let device_block = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_direct_objects", Some(tenant_id))
            .group(group_id)
            .kind("entity")
            .object_type("entity:device"),
    )
    .await;
    let channel_block = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_direct_objects", Some(tenant_id))
            .group(group_id)
            .kind("resource")
            .object_type("resource:channel"),
    )
    .await;
    let sensor_block = granted(
        &pool,
        tenant_id,
        BlockSpec::new("group_direct_objects", Some(tenant_id))
            .group(group_id)
            .kind("entity")
            .object_type("entity:sensor"),
    )
    .await;

    let schema = build_schema(state(pool));

    // The block's own kind/type already excludes the co-tenants of the group.
    let unfiltered = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(unfiltered.errors.is_empty(), "{:?}", unfiltered.errors);
    let data = unfiltered.data.into_json().expect("json data");
    assert_eq!(ids(&data), vec![device_block.to_string()]);
    for other in [channel_block, sensor_block] {
        assert!(!ids(&data).contains(&other.to_string()));
    }

    // Matching co-filters keep it.
    let matching = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}", objectKind: "entity", objectType: "entity:device") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(matching.errors.is_empty(), "{:?}", matching.errors);
    let data = matching.data.into_json().expect("json data");
    assert_eq!(ids(&data), vec![device_block.to_string()]);

    // A non-matching type narrows it away.
    let narrowed = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}", objectKind: "entity", objectType: "entity:sensor") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(narrowed.errors.is_empty(), "{:?}", narrowed.errors);
    let data = narrowed.data.into_json().expect("json data");
    assert_eq!(total(&data), 0);

    // Looking the channel up from the same group returns only its own block.
    let by_resource = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{channel}", objectKind: "resource") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(by_resource.errors.is_empty(), "{:?}", by_resource.errors);
    let data = by_resource.data.into_json().expect("json data");
    assert_eq!(ids(&data), vec![channel_block.to_string()]);
}

/// A `scope_mode: "object"` block identifies its target by id alone and may
/// record no kind, so the co-filters cannot narrow it — it names the object
/// either way. One that *does* record a kind is narrowable like any other.
#[tokio::test]
#[ignore]
async fn co_filters_narrow_object_blocks_only_where_the_block_records_a_kind() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let device = entity(&pool, tenant_id, "device").await;

    let untyped = granted(
        &pool,
        tenant_id,
        BlockSpec::new("object", Some(tenant_id)).object(device),
    )
    .await;
    let typed = granted(
        &pool,
        tenant_id,
        BlockSpec::new("object", Some(tenant_id))
            .object(device)
            .kind("entity")
            .object_type("entity:device"),
    )
    .await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}", objectKind: "resource") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let returned = ids(&data);
    assert!(
        returned.contains(&untyped.to_string()),
        "a block naming the id without recording a kind still names it"
    );
    assert!(
        !returned.contains(&typed.to_string()),
        "a block that records entity must not survive an objectKind: resource filter"
    );
}

#[tokio::test]
#[ignore]
async fn object_and_subject_filters_intersect() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let device = entity(&pool, tenant_id, "device").await;
    let other_device = entity(&pool, tenant_id, "device").await;

    let alice = entity(&pool, tenant_id, "human").await;
    let bob = entity(&pool, tenant_id, "human").await;

    let device_block = block(
        &pool,
        BlockSpec::new("object", Some(tenant_id)).object(device),
    )
    .await;
    let other_block = block(
        &pool,
        BlockSpec::new("object", Some(tenant_id)).object(other_device),
    )
    .await;

    let alice_on_device = policy(&pool, Some(tenant_id), alice, device_block).await;
    let bob_on_device = policy(&pool, Some(tenant_id), bob, device_block).await;
    let alice_on_other = policy(&pool, Some(tenant_id), alice, other_block).await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}", subjectId: "{alice}", subjectKind: entity) {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    assert_eq!(ids(&data), vec![alice_on_device.to_string()]);
    assert_eq!(total(&data), 1);
    let returned = ids(&data);
    assert!(!returned.contains(&bob_on_device.to_string()));
    assert!(!returned.contains(&alice_on_other.to_string()));
}

/// The reverse direction is the same policy-read operation on the tenant as
/// the forward one, and is refused without it.
#[tokio::test]
#[ignore]
async fn callers_without_policy_read_are_refused() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let device = entity(&pool, tenant_id, "device").await;
    let outsider = entity(&pool, tenant_id, "human").await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed_as(
            outsider,
            format!(r#"{{ directPolicies(objectId: "{device}") {{ total items {{ id }} }} }}"#),
        ))
        .await;
    assert!(
        !response.errors.is_empty(),
        "a caller without policy-read must be refused"
    );
}

/// Without `objectId` the listing is the subject-forward query it has always
/// been, class-scoped blocks included.
#[tokio::test]
#[ignore]
async fn omitting_object_id_leaves_the_subject_listing_unchanged() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let device = entity(&pool, tenant_id, "device").await;
    let subject = entity(&pool, tenant_id, "human").await;

    let object_block = block(
        &pool,
        BlockSpec::new("object", Some(tenant_id)).object(device),
    )
    .await;
    let tenant_block = block(&pool, BlockSpec::new("tenant", Some(tenant_id))).await;
    let on_object = policy(&pool, Some(tenant_id), subject, object_block).await;
    let on_tenant = policy(&pool, Some(tenant_id), subject, tenant_block).await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(subjectId: "{subject}", subjectKind: entity) {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().expect("json data");
    let returned = ids(&data);
    assert!(returned.contains(&on_object.to_string()));
    assert!(
        returned.contains(&on_tenant.to_string()),
        "the tenant-scoped block is only excluded by the object filter"
    );
    assert_eq!(total(&data), 2);
}

/// The co-filters are inert without `objectId`, so accepting them alone would
/// hand back the unfiltered listing. Refuse instead of answering wrongly.
#[tokio::test]
#[ignore]
async fn co_filters_without_an_object_id_are_rejected() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));

    for filter in [r#"objectKind: "entity""#, r#"objectType: "entity:device""#] {
        let response = schema
            .execute(authed(format!(
                r#"{{ directPolicies({filter}) {{ total items {{ id }} }} }}"#
            )))
            .await;
        assert!(
            !response.errors.is_empty(),
            "{filter} alone must be rejected, not silently ignored"
        );
    }
}

/// A namespaced `objectType` is the repo-wide convention; a bare sub-kind would
/// otherwise match nothing and read as "no one has access".
#[tokio::test]
#[ignore]
async fn a_bare_object_type_is_rejected() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let device = entity(&pool, tenant_id, "device").await;

    let schema = build_schema(state(pool));
    let response = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}", objectType: "device") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(!response.errors.is_empty());
    assert!(
        response.errors[0].message.contains("namespaced"),
        "{:?}",
        response.errors
    );
}

/// The revocation case the query exists for: a widely shared object must
/// paginate, not silently truncate.
#[tokio::test]
#[ignore]
async fn a_widely_shared_object_paginates() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let device = entity(&pool, tenant_id, "device").await;
    let block_id = block(
        &pool,
        BlockSpec::new("object", Some(tenant_id)).object(device),
    )
    .await;

    let mut created = Vec::new();
    for _ in 0..7 {
        let subject = entity(&pool, tenant_id, "human").await;
        created.push(
            policy(&pool, Some(tenant_id), subject, block_id)
                .await
                .to_string(),
        );
    }
    created.sort();

    let schema = build_schema(state(pool));
    let mut seen = Vec::new();
    for offset in [0, 3, 6] {
        let response = schema
            .execute(authed(format!(
                r#"{{ directPolicies(objectId: "{device}", limit: 3, offset: {offset}) {{ total items {{ id }} }} }}"#
            )))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().expect("json data");
        assert_eq!(total(&data), 7, "total counts every policy, not one page");
        seen.extend(ids(&data));
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen, created, "pagination covers every policy exactly once");
}

/// The reverse lookup re-expresses the group scope modes in its own SQL rather
/// than going through `subject_effective_grants` — that expansion is keyed by
/// subject and cannot answer the object direction. This pins it against the PDP
/// so the two cannot drift: across a 3-level tree, a policy is returned by
/// `directPolicies(objectId:)` exactly when `authzCheck` says it grants.
#[tokio::test]
#[ignore]
async fn group_scope_matching_agrees_with_the_pdp() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let read = seeded_action(&pool, "read").await;

    let root = object_group(&pool, tenant_id).await;
    let middle = object_group(&pool, tenant_id).await;
    let leaf = object_group(&pool, tenant_id).await;
    set_group_parent(&pool, tenant_id, middle, root).await;
    set_group_parent(&pool, tenant_id, leaf, middle).await;

    let device = entity(&pool, tenant_id, "device").await;
    add_entity_to_group(&pool, tenant_id, leaf, device).await;

    let mut cases = Vec::new();
    for (group_id, level) in [(leaf, "leaf"), (middle, "middle"), (root, "root")] {
        for scope_mode in ["group_direct_objects", "group_descendant_objects"] {
            let (subject, policy_id) = granted_to(
                &pool,
                tenant_id,
                BlockSpec::new(scope_mode, Some(tenant_id))
                    .group(group_id)
                    .kind("entity")
                    .object_type("entity:device"),
                Some(read),
            )
            .await;
            cases.push((format!("{scope_mode}@{level}"), subject, policy_id));
        }
    }

    let schema = build_schema(state(pool));
    let listed = schema
        .execute(authed(format!(
            r#"{{ directPolicies(objectId: "{device}") {{ total items {{ id }} }} }}"#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let returned = ids(&listed.data.into_json().expect("json data"));

    let case_count = cases.len();
    let mut allowed_count = 0;
    for (label, subject, policy_id) in cases {
        let checked = schema
            .execute(authed(format!(
                r#"mutation {{ authzCheck(input: {{ subjectId: "{subject}", action: "read", objectKind: "entity", objectId: "{device}" }}) {{ allowed }} }}"#
            )))
            .await;
        assert!(checked.errors.is_empty(), "{label}: {:?}", checked.errors);
        let allowed = checked.data.into_json().expect("json data")["authzCheck"]["allowed"]
            .as_bool()
            .expect("allowed");
        assert_eq!(
            returned.contains(&policy_id.to_string()),
            allowed,
            "{label}: reverse lookup and PDP disagree"
        );
        allowed_count += usize::from(allowed);
    }
    assert!(
        allowed_count > 0 && allowed_count < case_count,
        "parity must be exercised in both directions, not trivially all-deny"
    );
}
