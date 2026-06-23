//! Regression tests for permission-block ownership (Finding 4 / action #6).
//!
//! Permission blocks are shared and immutable: one block can be linked to many
//! roles. Before the fix, role-scoped operations ran `DELETE FROM
//! permission_blocks` by role, which cascaded through `role_permission_blocks`
//! and so destroyed blocks still linked to *other* roles. The destructive paths
//! now unlink from the role and garbage-collect only blocks left unreferenced,
//! and an explicit block delete refuses a block still in use.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m1_block_ownership -- --ignored
//! ```

mod common;

use atom::models::enums::Effect;
use atom::models::policy::CreatePermissionBlock;
use atom::models::role::CreateRole;
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn read_capability_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read cap")
}

async fn make_tenant(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("own-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_role(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    atom::authz::repo::create_role(
        pool,
        CreateRole {
            name: format!("own-role-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role")
    .id
}

async fn make_block(pool: &sqlx::PgPool, tenant_id: Uuid, read_cap: Uuid) -> Uuid {
    atom::authz::repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "object_type".into(),
            object_kind: Some("resource".into()),
            object_type: Some("resource:channel".into()),
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({}),
            action_ids: vec![read_cap],
        },
    )
    .await
    .expect("create block")
    .id
}

async fn block_exists(pool: &sqlx::PgPool, block_id: Uuid) -> bool {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM permission_blocks WHERE id = $1")
        .bind(block_id)
        .fetch_one(pool)
        .await
        .expect("count blocks");
    count > 0
}

async fn role_links_block(pool: &sqlx::PgPool, role_id: Uuid, block_id: Uuid) -> bool {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permission_blocks WHERE role_id = $1 AND permission_block_id = $2",
    )
    .bind(role_id)
    .bind(block_id)
    .fetch_one(pool)
    .await
    .expect("count links");
    count > 0
}

/// Removing a capability from one role must not destroy a block another role
/// still links. Before the fix the block was deleted outright and cascaded out
/// of every role.
#[tokio::test]
#[ignore]
async fn shared_block_survives_role_capability_removal() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let read_cap = read_capability_id(&p).await;
    let block_id = make_block(&p, tenant_id, read_cap).await;
    let role_a = make_role(&p, tenant_id).await;
    let role_b = make_role(&p, tenant_id).await;

    atom::authz::repo::replace_role_permission_block_links(&p, role_a, &[block_id])
        .await
        .expect("link to A");
    atom::authz::repo::replace_role_permission_block_links(&p, role_b, &[block_id])
        .await
        .expect("link to B");

    atom::authz::repo::remove_role_capability(&p, role_a, read_cap)
        .await
        .expect("remove cap from A");

    assert!(
        block_exists(&p, block_id).await,
        "a block still linked to role B must survive removal from role A"
    );
    assert!(
        !role_links_block(&p, role_a, block_id).await,
        "role A must no longer link the block"
    );
    assert!(
        role_links_block(&p, role_b, block_id).await,
        "role B must still link the block"
    );
}

/// A block owned by a single role is garbage-collected when that role drops it,
/// so unlink-and-GC does not leak orphans.
#[tokio::test]
#[ignore]
async fn orphaned_block_is_collected_on_capability_removal() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let read_cap = read_capability_id(&p).await;
    let block_id = make_block(&p, tenant_id, read_cap).await;
    let role = make_role(&p, tenant_id).await;

    atom::authz::repo::replace_role_permission_block_links(&p, role, &[block_id])
        .await
        .expect("link");
    atom::authz::repo::remove_role_capability(&p, role, read_cap)
        .await
        .expect("remove cap");

    assert!(
        !block_exists(&p, block_id).await,
        "a block left unreferenced after unlink must be garbage-collected"
    );
}

/// An explicit block delete refuses a block still linked to a role; once
/// unlinked, the delete succeeds.
#[tokio::test]
#[ignore]
async fn delete_permission_block_refuses_referenced_block() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let read_cap = read_capability_id(&p).await;
    let block_id = make_block(&p, tenant_id, read_cap).await;
    let role = make_role(&p, tenant_id).await;

    atom::authz::repo::replace_role_permission_block_links(&p, role, &[block_id])
        .await
        .expect("link");

    let err = atom::authz::repo::delete_permission_block(&p, block_id)
        .await
        .expect_err("delete must be refused while referenced");
    assert!(
        err.to_string().contains("still linked"),
        "expected a still-linked refusal, got: {err}"
    );
    assert!(
        block_exists(&p, block_id).await,
        "block must survive refusal"
    );

    // Unlink, then the delete is allowed.
    atom::authz::repo::replace_role_permission_block_links(&p, role, &[])
        .await
        .expect("unlink");
    atom::authz::repo::delete_permission_block(&p, block_id)
        .await
        .expect("delete after unlink");
    assert!(!block_exists(&p, block_id).await, "block must be gone");
}
