//! Regression tests for control-plane gates over the single canonical grant
//! expansion (Findings 2 / 5).
//!
//! Before routing `has_capability_in_scope` through `effective_grants_for_subject`,
//! the gate ran a coarse `EXISTS` over `effective_access_edges()` that:
//!   * expanded only *direct* group membership, so a role reaching the subject
//!     through a *parent* group false-denied every gate (Finding 5); and
//!   * matched a role on action containment alone (`effective_role_actions()`),
//!     ignoring the linked block's effect — so a role holding only a *deny*
//!     block for an action still satisfied the gate for it (Finding 2 over-permit).
//!
//! Both behaviours are now driven by the block's own scope/effect carried
//! through the canonical expansion.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m4_gates -- --ignored
//! ```

mod common;

use atom::auth::{has_capability_in_scope, Scope};
use atom::models::enums::{Effect, SubjectKind};
use atom::models::group::CreateGroup;
use atom::models::policy::{CreatePermissionBlock, CreateRoleAssignment};
use atom::models::role::CreateRole;
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn manage_capability_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("manage cap")
}

async fn make_tenant(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("gate-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_human(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'human', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("gate-ent-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn make_principal_group(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    atom::identity::repo::create_group(
        pool,
        CreateGroup {
            id: None,
            name: format!("gate-grp-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            group_type: Some("principal".to_string()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create group")
    .id
}

/// Create a tenant-scoped role carrying a single block (the given effect) for
/// `manage`, and return the role id.
async fn role_with_manage_block(pool: &sqlx::PgPool, tenant_id: Uuid, effect: Effect) -> Uuid {
    let manage = manage_capability_id(pool).await;
    let role = atom::authz::repo::create_role(
        pool,
        CreateRole {
            name: format!("gate-role-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");

    let block = atom::authz::repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "tenant".into(),
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
            effect,
            conditions: json!({}),
            action_ids: vec![manage],
        },
    )
    .await
    .expect("create block");

    atom::authz::repo::replace_role_permission_block_links(pool, role.id, &[block.id])
        .await
        .expect("link block");
    role.id
}

/// Best-effort tidy of the rows this suite creates. Ordered so member/hierarchy
/// rows go before the groups they reference; role/block links are removed by the
/// role cascade. Each statement is independent so a residual FK can't abort the rest.
async fn cleanup(pool: &sqlx::PgPool, tenant_id: Uuid) {
    let _ = sqlx::query("DELETE FROM role_assignments WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM direct_policies WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "DELETE FROM principal_group_members pgm USING principal_groups g \
         WHERE pgm.group_id = g.id AND g.tenant_id = $1",
    )
    .bind(tenant_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM principal_group_hierarchy WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM principal_groups WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM roles WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

/// A role assigned to a *parent* principal group must satisfy a gate for a
/// subject who reaches that group only through a child group. The pre-refactor
/// gate expanded direct membership only and false-denied this.
#[tokio::test]
#[ignore]
async fn role_via_parent_group_satisfies_gate() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let actor = make_human(&p, tenant_id).await;

    let parent = make_principal_group(&p, tenant_id).await;
    let child = make_principal_group(&p, tenant_id).await;
    atom::identity::repo::set_group_parent(&p, child, parent)
        .await
        .expect("set parent");
    // Membership is added before the parent group holds any grant, so the
    // join itself is not gated by the role we attach next.
    atom::identity::repo::add_group_member(&p, child, actor)
        .await
        .expect("add member");

    let role = role_with_manage_block(&p, tenant_id, Effect::Allow).await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Group,
            subject_id: parent,
            role_id: role,
        },
    )
    .await
    .expect("assign role to parent group");

    assert!(
        has_capability_in_scope(&p, actor, "manage", Scope::Tenant(tenant_id))
            .await
            .expect("gate"),
        "a role on a parent group must satisfy the gate for a member of a child group"
    );

    cleanup(&p, tenant_id).await;
}

/// A role whose only block for `manage` is a *deny* must not satisfy the gate
/// for `manage`. The pre-refactor gate matched on action containment and
/// ignored the block effect, so it over-permitted here.
#[tokio::test]
#[ignore]
async fn role_with_only_deny_block_does_not_satisfy_gate() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let actor = make_human(&p, tenant_id).await;

    let deny_role = role_with_manage_block(&p, tenant_id, Effect::Deny).await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: actor,
            role_id: deny_role,
        },
    )
    .await
    .expect("assign deny role");

    assert!(
        !has_capability_in_scope(&p, actor, "manage", Scope::Tenant(tenant_id))
            .await
            .expect("deny gate"),
        "a role holding only a deny block must not satisfy the gate for that action"
    );

    // Sanity: a *separate* actor holding an allow block at the same scope does
    // satisfy the gate, so the negative result above is the deny effect taking
    // hold, not a setup error. (A distinct actor is required because a deny
    // overrides an allow, so reusing `actor` would still gate-deny.)
    let allow_actor = make_human(&p, tenant_id).await;
    let allow_role = role_with_manage_block(&p, tenant_id, Effect::Allow).await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: allow_actor,
            role_id: allow_role,
        },
    )
    .await
    .expect("assign allow role");

    assert!(
        has_capability_in_scope(&p, allow_actor, "manage", Scope::Tenant(tenant_id))
            .await
            .expect("allow gate"),
        "an allow block at the gate scope must satisfy the gate"
    );

    cleanup(&p, tenant_id).await;
}
