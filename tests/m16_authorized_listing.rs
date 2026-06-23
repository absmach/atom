//! Authorized listing tests for the SQL authz filter.
//!
//! These tests require a reachable Postgres at `DATABASE_URL` and are ignored
//! by default:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m16_authorized_listing -- --ignored
//! ```

mod common;

use atom::models::access::AuthorizedObjectIdsQuery;
use uuid::Uuid;

async fn make_tenant(pool: &sqlx::PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{name}-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_entity(pool: &sqlx::PgPool, tenant_id: Uuid, kind: &str, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("{name}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn make_resource(pool: &sqlx::PgPool, tenant_id: Uuid, kind: &str, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(kind)
        .bind(format!("{name}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn make_group(pool: &sqlx::PgPool, tenant_id: Uuid, group_type: &str, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let table = if group_type == "principal" {
        "principal_groups"
    } else {
        "object_groups"
    };
    let sql = format!("INSERT INTO {table} (id, name, tenant_id) VALUES ($1, $2, $3)");
    sqlx::query(&sql)
        .bind(id)
        .bind(format!("{name}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert group");
    id
}

async fn action_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("action")
}

async fn make_role_with_block(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    applies_to: &str,
    object_kind: Option<&str>,
    object_type: Option<&str>,
    group_id: Option<Uuid>,
    action_id: Uuid,
) -> Uuid {
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("role-{role_id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert role");

    let scope_mode = match applies_to {
        "object_group_type" => "group_direct_objects",
        "object_group_tree_type" => "group_descendant_objects",
        "object_group_child_kind" => "group_child_groups",
        "object_group_descendant_kind" => "group_descendant_groups",
        other => other,
    };
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
           (scope_mode, object_kind, object_type, tenant_id, group_id, effect)
           VALUES ($1, $2, $3, $4, $5, 'allow')
           RETURNING id"#,
    )
    .bind(scope_mode)
    .bind(object_kind)
    .bind(object_type)
    .bind(Some(tenant_id))
    .bind(group_id)
    .fetch_one(pool)
    .await
    .expect("insert permission block");

    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(role_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("insert role permission block");

    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(action_id)
    .execute(pool)
    .await
    .expect("insert permission action");

    role_id
}

async fn assign_role_to_entity(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
    role_id: Uuid,
) {
    sqlx::query(
        r#"INSERT INTO role_assignments
           (tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .bind(role_id)
    .execute(pool)
    .await
    .expect("assign role to entity");
}

async fn assign_role_to_group(pool: &sqlx::PgPool, tenant_id: Uuid, group_id: Uuid, role_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO role_assignments
           (tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, 'group', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(role_id)
    .execute(pool)
    .await
    .expect("assign role to group");
}

async fn authorized(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    action: &str,
    object_kind: &str,
    object_type: Option<&str>,
    tenant_id: Uuid,
) -> Vec<Uuid> {
    atom::authz::repo::authorized_object_ids(
        pool,
        AuthorizedObjectIdsQuery {
            subject_id,
            action: action.to_string(),
            object_kind: object_kind.to_string(),
            object_type: object_type.map(ToOwned::to_owned),
            tenant_id: Some(tenant_id),
            q: None,
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id: None,
            include_descendants: false,
            limit: 100,
            offset: 0,
        },
    )
    .await
    .expect("authorized listing")
    .ids
}

#[tokio::test]
#[ignore]
async fn authorized_resource_kinds_include_custom_readable_kinds_only() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m16-resource-kinds").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    make_resource(&pool, tenant_id, "channel", "channel").await;
    make_resource(&pool, tenant_id, "custom_stream", "custom-stream").await;
    make_resource(&pool, tenant_id, "rule", "unreadable-rule").await;
    let read_id = action_id(&pool, "read").await;

    for kind in ["channel", "custom_stream"] {
        let role_id = make_role_with_block(
            &pool,
            tenant_id,
            "object_type",
            Some("resource"),
            Some(&format!("resource:{kind}")),
            None,
            read_id,
        )
        .await;
        assign_role_to_entity(&pool, tenant_id, subject_id, role_id).await;
    }

    let kinds = atom::authz::repo::authorized_resource_kinds(&pool, subject_id, Some(tenant_id))
        .await
        .expect("authorized resource kinds");

    assert_eq!(kinds, vec!["channel", "custom_stream"]);
}

#[tokio::test]
#[ignore]
async fn authorized_listing_uses_role_permissions_and_deny_overrides() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m17-deny").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    let allowed_channel_id = make_resource(&pool, tenant_id, "channel", "allowed-channel").await;
    let denied_channel_id = make_resource(&pool, tenant_id, "channel", "denied-channel").await;
    let rule_id = make_resource(&pool, tenant_id, "rule", "rule").await;
    let read_id = action_id(&pool, "read").await;

    let role_id = make_role_with_block(
        &pool,
        tenant_id,
        "object_type",
        Some("resource"),
        Some("resource:channel"),
        None,
        read_id,
    )
    .await;
    assign_role_to_entity(&pool, tenant_id, subject_id, role_id).await;

    let deny_block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
           (tenant_id, scope_mode, object_id, effect)
           VALUES ($1, 'object', $2, 'deny')
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(denied_channel_id)
    .fetch_one(&pool)
    .await
    .expect("insert deny block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(deny_block_id)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("insert deny action");
    sqlx::query(
        r#"INSERT INTO direct_policies
           (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(deny_block_id)
    .execute(&pool)
    .await
    .expect("deny object");

    let channel_ids = authorized(
        &pool,
        subject_id,
        "read",
        "resource",
        Some("resource:channel"),
        tenant_id,
    )
    .await;
    assert_eq!(channel_ids, vec![allowed_channel_id]);

    let rule_ids = authorized(
        &pool,
        subject_id,
        "read",
        "resource",
        Some("resource:rule"),
        tenant_id,
    )
    .await;
    assert!(rule_ids.is_empty(), "channel role must not list rules");

    let _ = sqlx::query("DELETE FROM resources WHERE id = ANY($1::uuid[])")
        .bind(&[allowed_channel_id, denied_channel_id, rule_id][..])
        .execute(&pool)
        .await;
}

#[tokio::test]
#[ignore]
async fn authorized_listing_supports_principal_and_object_groups() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m17-groups").await;
    let direct_subject_id = make_entity(&pool, tenant_id, "human", "direct-subject").await;
    let tree_subject_id = make_entity(&pool, tenant_id, "human", "tree-subject").await;
    let direct_device_id = make_entity(&pool, tenant_id, "device", "direct-device").await;
    let child_device_id = make_entity(&pool, tenant_id, "device", "child-device").await;
    let read_id = action_id(&pool, "read").await;

    let direct_principal_group_id =
        make_group(&pool, tenant_id, "principal", "direct-principals").await;
    let tree_principal_group_id =
        make_group(&pool, tenant_id, "principal", "tree-principals").await;
    let parent_object_group_id = make_group(&pool, tenant_id, "object", "parent-object").await;
    let child_object_group_id = make_group(&pool, tenant_id, "object", "child-object").await;

    sqlx::query(
        "INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2), ($3, $4)",
    )
    .bind(direct_principal_group_id)
    .bind(direct_subject_id)
    .bind(tree_principal_group_id)
    .bind(tree_subject_id)
    .execute(&pool)
    .await
    .expect("insert principal group members");

    sqlx::query(
        "INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(parent_object_group_id)
    .bind(child_object_group_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert object hierarchy");

    sqlx::query(
        "INSERT INTO object_group_entities (group_id, entity_id, tenant_id) VALUES ($1, $2, $3), ($4, $5, $6)",
    )
    .bind(parent_object_group_id)
    .bind(direct_device_id)
    .bind(tenant_id)
    .bind(child_object_group_id)
    .bind(child_device_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert object parents");

    let direct_role_id = make_role_with_block(
        &pool,
        tenant_id,
        "object_group_type",
        Some("entity"),
        Some("entity:device"),
        Some(parent_object_group_id),
        read_id,
    )
    .await;
    let tree_role_id = make_role_with_block(
        &pool,
        tenant_id,
        "object_group_tree_type",
        Some("entity"),
        Some("entity:device"),
        Some(parent_object_group_id),
        read_id,
    )
    .await;

    assign_role_to_group(&pool, tenant_id, direct_principal_group_id, direct_role_id).await;
    assign_role_to_group(&pool, tenant_id, tree_principal_group_id, tree_role_id).await;

    let direct_ids = authorized(
        &pool,
        direct_subject_id,
        "read",
        "entity",
        Some("entity:device"),
        tenant_id,
    )
    .await;
    assert_eq!(direct_ids, vec![direct_device_id]);

    let tree_ids = authorized(
        &pool,
        tree_subject_id,
        "read",
        "entity",
        Some("entity:device"),
        tenant_id,
    )
    .await;
    assert_eq!(tree_ids, vec![child_device_id]);
}

/// A deny assigned to an *ancestor* principal group must remove the object from
/// the listing, matching the PDP. The subject reaches the deny only through a
/// parent of its direct group, so the listing's subject_groups CTE must resolve
/// principal-group membership recursively (it previously used direct members
/// only, so the deny was invisible and the object was wrongly listed).
#[tokio::test]
#[ignore]
async fn authorized_listing_honours_ancestor_group_deny() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m16-ancestor-deny").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    let channel_id = make_resource(&pool, tenant_id, "channel", "channel").await;
    let read_id = action_id(&pool, "read").await;

    // Direct allow: subject can read channels (object alone would be listable).
    let allow_role = make_role_with_block(
        &pool,
        tenant_id,
        "object_type",
        Some("resource"),
        Some("resource:channel"),
        None,
        read_id,
    )
    .await;
    assign_role_to_entity(&pool, tenant_id, subject_id, allow_role).await;

    // Subject is a direct member of the child group; the parent is its ancestor.
    let parent_group = make_group(&pool, tenant_id, "principal", "parent").await;
    let child_group = make_group(&pool, tenant_id, "principal", "child").await;
    sqlx::query(
        "INSERT INTO principal_group_hierarchy (parent_id, child_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(parent_group)
    .bind(child_group)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("principal hierarchy");
    sqlx::query("INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2)")
        .bind(child_group)
        .bind(subject_id)
        .execute(&pool)
        .await
        .expect("child membership");

    // Deny read on the channel, assigned to the ancestor (parent) group.
    let deny_block: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (tenant_id, scope_mode, object_id, effect)
           VALUES ($1, 'object', $2, 'deny') RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(channel_id)
    .fetch_one(&pool)
    .await
    .expect("insert deny block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(deny_block)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("deny action");
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'group', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(parent_group)
    .bind(deny_block)
    .execute(&pool)
    .await
    .expect("assign deny to parent group");

    let ids = authorized(
        &pool,
        subject_id,
        "read",
        "resource",
        Some("resource:channel"),
        tenant_id,
    )
    .await;
    assert!(
        ids.is_empty(),
        "a deny on an ancestor principal group must remove the object from the listing, got: {ids:?}"
    );

    let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(channel_id)
        .execute(&pool)
        .await;
}

/// An exact-object block whose assignment is bounded to a different tenant than
/// the object's owner must not surface the object in a listing — the listing now
/// compares the assignment edge's tenant with the candidate object's tenant, as
/// the PDP and gates do.
#[tokio::test]
#[ignore]
async fn authorized_listing_honours_assignment_tenant_boundary() {
    let pool = common::pool().await;
    let owner_tenant = make_tenant(&pool, "m16-owner").await; // owns the object
    let other_tenant = make_tenant(&pool, "m16-other").await; // the assignment boundary
    let subject_id = make_entity(&pool, other_tenant, "human", "subject").await;
    let channel_id = make_resource(&pool, owner_tenant, "channel", "channel").await;
    let read_id = action_id(&pool, "read").await;

    // Exact-object read allow on the owner_tenant object.
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (scope_mode, object_id, effect)
           VALUES ('object', $1, 'allow') RETURNING id"#,
    )
    .bind(channel_id)
    .fetch_one(&pool)
    .await
    .expect("insert object block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("block action");
    // Assignment bounded to other_tenant — not the object's owner.
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(other_tenant)
    .bind(subject_id)
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("cross-tenant direct policy");

    let ids = authorized(
        &pool,
        subject_id,
        "read",
        "resource",
        Some("resource:channel"),
        owner_tenant,
    )
    .await;
    assert!(
        !ids.contains(&channel_id),
        "a cross-tenant exact-object grant must not surface the object, got: {ids:?}"
    );

    // Control: rebind the assignment to the object's tenant → now listed.
    sqlx::query("UPDATE direct_policies SET tenant_id = $1 WHERE permission_block_id = $2")
        .bind(owner_tenant)
        .bind(block_id)
        .execute(&pool)
        .await
        .expect("rebind");
    let ids = authorized(
        &pool,
        subject_id,
        "read",
        "resource",
        Some("resource:channel"),
        owner_tenant,
    )
    .await;
    assert!(
        ids.contains(&channel_id),
        "a same-tenant exact-object grant must surface the object"
    );

    let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(channel_id)
        .execute(&pool)
        .await;
}

async fn authorized_groups(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    tenant_id: Uuid,
    group_type: Option<&str>,
    parent_group_id: Option<Uuid>,
    limit: i64,
) -> atom::models::access::AuthorizedObjectIdsResponse {
    atom::authz::repo::authorized_object_ids(
        pool,
        AuthorizedObjectIdsQuery {
            subject_id,
            action: "read".to_string(),
            object_kind: "group".to_string(),
            object_type: None,
            tenant_id: Some(tenant_id),
            q: None,
            profile_id: None,
            entity_status: None,
            group_type: group_type.map(ToOwned::to_owned),
            parent_group_id,
            include_descendants: false,
            limit,
            offset: 0,
        },
    )
    .await
    .expect("authorized group listing")
}

async fn link_object_groups(pool: &sqlx::PgPool, tenant_id: Uuid, parent_id: Uuid, child_id: Uuid) {
    sqlx::query(
        "INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(parent_id)
    .bind(child_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("link object groups");
}

/// The core #8 fix: an `object_kind = 'group'` grant lists every matching group
/// with a correct `total` and honours `limit`/`offset`, instead of the old
/// per-item PDP loop that paged first and then under-filled the page and
/// reported only the page's authorized count as the total.
#[tokio::test]
#[ignore]
async fn authorized_group_listing_object_kind_paginates_with_total() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m8-group-object-kind").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    let read_id = action_id(&pool, "read").await;

    let mut group_ids = Vec::new();
    for i in 0..3 {
        group_ids.push(make_group(&pool, tenant_id, "object", &format!("og-{i}")).await);
    }

    let role_id = make_role_with_block(
        &pool,
        tenant_id,
        "object_kind",
        Some("group"),
        None,
        None,
        read_id,
    )
    .await;
    assign_role_to_entity(&pool, tenant_id, subject_id, role_id).await;

    let page = authorized_groups(&pool, subject_id, tenant_id, Some("object"), None, 2).await;
    assert_eq!(page.total, 3, "total must reflect the full authorized set");
    assert_eq!(page.ids.len(), 2, "limit must cap the page, not the count");
    for id in &page.ids {
        assert!(group_ids.contains(id));
    }
}

/// `group_child_groups` (→ `group_child_kind`) lists only the parent's direct
/// child groups — not the parent itself, not deeper descendants.
#[tokio::test]
#[ignore]
async fn authorized_group_listing_child_kind_lists_direct_children_only() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m8-group-child-kind").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    let read_id = action_id(&pool, "read").await;

    let parent = make_group(&pool, tenant_id, "object", "parent").await;
    let child_a = make_group(&pool, tenant_id, "object", "child-a").await;
    let child_b = make_group(&pool, tenant_id, "object", "child-b").await;
    let grandchild = make_group(&pool, tenant_id, "object", "grandchild").await;
    link_object_groups(&pool, tenant_id, parent, child_a).await;
    link_object_groups(&pool, tenant_id, parent, child_b).await;
    link_object_groups(&pool, tenant_id, child_a, grandchild).await;

    let role_id = make_role_with_block(
        &pool,
        tenant_id,
        "object_group_child_kind",
        None,
        None,
        Some(parent),
        read_id,
    )
    .await;
    assign_role_to_entity(&pool, tenant_id, subject_id, role_id).await;

    let listing = authorized_groups(&pool, subject_id, tenant_id, Some("object"), None, 100).await;
    let mut ids = listing.ids;
    ids.sort();
    let mut expected = vec![child_a, child_b];
    expected.sort();
    assert_eq!(ids, expected);
    assert_eq!(listing.total, 2);
}

/// `group_descendant_groups` (→ `group_descendant_kind`) lists every descendant
/// group of the scoped parent, at any depth, but not the parent itself.
#[tokio::test]
#[ignore]
async fn authorized_group_listing_descendant_kind_lists_whole_subtree() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m8-group-descendant-kind").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    let read_id = action_id(&pool, "read").await;

    let parent = make_group(&pool, tenant_id, "object", "parent").await;
    let child = make_group(&pool, tenant_id, "object", "child").await;
    let grandchild = make_group(&pool, tenant_id, "object", "grandchild").await;
    link_object_groups(&pool, tenant_id, parent, child).await;
    link_object_groups(&pool, tenant_id, child, grandchild).await;

    let role_id = make_role_with_block(
        &pool,
        tenant_id,
        "object_group_descendant_kind",
        None,
        None,
        Some(parent),
        read_id,
    )
    .await;
    assign_role_to_entity(&pool, tenant_id, subject_id, role_id).await;

    let listing = authorized_groups(&pool, subject_id, tenant_id, Some("object"), None, 100).await;
    let mut ids = listing.ids;
    ids.sort();
    let mut expected = vec![child, grandchild];
    expected.sort();
    assert_eq!(
        ids, expected,
        "descendant scope must cover the whole subtree"
    );
    assert_eq!(listing.total, 2);
}

/// An object-level deny on one group overrides a broad `object_kind` allow,
/// removing just that group from the listing — matching PDP deny-override.
#[tokio::test]
#[ignore]
async fn authorized_group_listing_object_deny_overrides_allow() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "m8-group-deny").await;
    let subject_id = make_entity(&pool, tenant_id, "human", "subject").await;
    let read_id = action_id(&pool, "read").await;

    let allowed = make_group(&pool, tenant_id, "object", "allowed").await;
    let denied = make_group(&pool, tenant_id, "object", "denied").await;

    let allow_role = make_role_with_block(
        &pool,
        tenant_id,
        "object_kind",
        Some("group"),
        None,
        None,
        read_id,
    )
    .await;
    assign_role_to_entity(&pool, tenant_id, subject_id, allow_role).await;

    let deny_block: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (tenant_id, scope_mode, object_id, effect)
           VALUES ($1, 'object', $2, 'deny') RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(denied)
    .fetch_one(&pool)
    .await
    .expect("insert deny block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(deny_block)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("deny action");
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(deny_block)
    .execute(&pool)
    .await
    .expect("assign deny");

    let listing = authorized_groups(&pool, subject_id, tenant_id, Some("object"), None, 100).await;
    assert_eq!(
        listing.ids,
        vec![allowed],
        "deny must remove only the denied group"
    );
    assert_eq!(listing.total, 1);
}
