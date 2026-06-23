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
