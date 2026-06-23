//! Regression tests for the authorization-filtered tenant listing
//! (`list_tenants_for_entity`).
//!
//! The listing used synthetic role-allow edges plus action containment and only
//! direct group membership, so a role-linked *deny* on a tenant was ignored
//! (the tenant stayed visible) and a role reaching the caller through a *parent*
//! group was missed (the tenant was hidden). It now reads the canonical grant
//! model: real block effect/conditions, recursive groups, the assignment tenant
//! boundary, and deny-override.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m19_tenant_listing -- --ignored
//! ```

mod common;

use atom::models::enums::{Effect, GrantKind, ScopeKind, SubjectKind};
use atom::models::policy::{CreatePolicyBinding, CreateRoleAssignment};
use atom::models::role::CreateRole;
use atom::models::tenant::ListTenants;
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn make_tenant(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("m19-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_human(pool: &sqlx::PgPool, tenant_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'human', $2, $3, 'active')")
        .bind(id)
        .bind(format!("m19-ent-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn read_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read cap")
}

async fn make_principal_group(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    atom::identity::repo::create_group(
        pool,
        atom::models::group::CreateGroup {
            id: None,
            name: format!("m19-grp-{}", Uuid::new_v4()),
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

/// Link a single tenant-scoped block (the given effect) for `read` to a fresh
/// role and return the role id.
async fn read_role(pool: &sqlx::PgPool, tenant_id: Uuid, effect: &str) -> Uuid {
    let read = read_id(pool).await;
    let role = atom::authz::repo::create_role(
        pool,
        CreateRole {
            name: format!("m19-role-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, effect) VALUES ('tenant', $1, $2) RETURNING id",
    )
    .bind(tenant_id)
    .bind(effect)
    .fetch_one(pool)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(read)
    .execute(pool)
    .await
    .expect("block action");
    atom::authz::repo::replace_role_permission_block_links(pool, role.id, &[block])
        .await
        .expect("link");
    role.id
}

async fn visible_tenant_ids(pool: &sqlx::PgPool, entity_id: Uuid) -> Vec<Uuid> {
    atom::tenants::repo::list_tenants_for_entity(
        pool,
        entity_id,
        ListTenants {
            q: None,
            name: None,
            alias: None,
            status: None,
            limit: 100,
            offset: 0,
        },
    )
    .await
    .expect("list tenants")
    .items
    .into_iter()
    .map(|t| t.id)
    .collect()
}

/// A role-linked deny on a tenant must hide it, even with a tenant-wide read
/// allow present. Before the fix the synthetic role edge dropped the deny, so
/// the allow won. A second caller with only the allow still sees the tenant,
/// isolating the deny as the cause.
#[tokio::test]
#[ignore]
async fn role_linked_tenant_deny_hides_tenant_from_listing() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let denied_caller = make_human(&p, Some(target)).await;
    let allowed_caller = make_human(&p, Some(target)).await;

    // Both callers get a tenant-scoped read allow → the tenant is visible.
    for caller in [denied_caller, allowed_caller] {
        atom::authz::repo::create_policy(
            &p,
            CreatePolicyBinding {
                tenant_id: Some(target),
                subject_kind: SubjectKind::Entity,
                subject_id: caller,
                grant_kind: GrantKind::Capability,
                grant_id: read_id(&p).await,
                scope_kind: ScopeKind::Tenant,
                scope_ref: Some(target.to_string()),
                effect: Effect::Allow,
                conditions: json!({}),
            },
        )
        .await
        .expect("tenant read allow");
    }

    // Only the first caller also holds a role with a tenant-scoped deny-read.
    let deny_role = read_role(&p, target, "deny").await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(target),
            subject_kind: SubjectKind::Entity,
            subject_id: denied_caller,
            role_id: deny_role,
        },
    )
    .await
    .expect("assign deny role");

    assert!(
        !visible_tenant_ids(&p, denied_caller)
            .await
            .contains(&target),
        "a role-linked tenant deny must hide the tenant"
    );
    assert!(
        visible_tenant_ids(&p, allowed_caller)
            .await
            .contains(&target),
        "the tenant read allow alone must keep the tenant visible"
    );
}

/// A role granting tenant read that reaches the caller only through a parent
/// principal group must make the tenant visible. Before the fix the listing
/// expanded direct membership only, so the tenant was missed.
#[tokio::test]
#[ignore]
async fn tenant_visible_via_parent_group_role() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;

    let parent = make_principal_group(&p, target).await;
    let child = make_principal_group(&p, target).await;
    atom::identity::repo::set_group_parent(&p, child, parent)
        .await
        .expect("set parent");
    atom::identity::repo::add_group_member(&p, child, caller)
        .await
        .expect("add member");

    let allow_role = read_role(&p, target, "allow").await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(target),
            subject_kind: SubjectKind::Group,
            subject_id: parent,
            role_id: allow_role,
        },
    )
    .await
    .expect("assign role to parent group");

    let visible_ids = visible_tenant_ids(&p, caller).await;
    assert!(
        visible_ids.contains(&target),
        "a tenant readable via a parent-group role must be listed, got: {visible_ids:?}"
    );
}

async fn manage_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("manage cap")
}

/// Insert a permission block (raw, bypassing applicability validation) and link
/// it to `caller` via a direct policy bounded to `tenant`.
async fn direct_block(
    pool: &sqlx::PgPool,
    tenant: Uuid,
    caller: Uuid,
    scope_mode: &str,
    object_kind: Option<&str>,
    effect: &str,
    action: Uuid,
) {
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, object_kind, effect) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(scope_mode)
    .bind(tenant)
    .bind(object_kind)
    .bind(effect)
    .fetch_one(pool)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(action)
    .execute(pool)
    .await
    .expect("block action");
    sqlx::query("INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(tenant)
        .bind(caller)
        .bind(block)
        .execute(pool)
        .await
        .expect("direct policy");
}

/// A manage deny must not hide a tenant the caller can read: deny-override is
/// per-action. Before the fix the listing checked allow(read|manage) then
/// deny(read|manage) uncorrelated, so the manage deny removed the tenant.
#[tokio::test]
#[ignore]
async fn read_allow_not_hidden_by_manage_deny() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;

    direct_block(
        &p,
        target,
        caller,
        "tenant",
        None,
        "allow",
        read_id(&p).await,
    )
    .await;
    direct_block(
        &p,
        target,
        caller,
        "tenant",
        None,
        "deny",
        manage_id(&p).await,
    )
    .await;

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "a read allow must keep the tenant visible despite a separate manage deny"
    );
}

/// A direct object_kind='tenant' read grant must make the tenant visible — the
/// PDP matches object_kind scope against the tenant object's kind.
#[tokio::test]
#[ignore]
async fn tenant_visible_via_object_kind_grant() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;

    direct_block(
        &p,
        target,
        caller,
        "object_kind",
        Some("tenant"),
        "allow",
        read_id(&p).await,
    )
    .await;

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "an object_kind='tenant' read grant must list the tenant"
    );
}

/// A role-linked object_kind='tenant' read grant must make the tenant visible —
/// role_grants must carry object_kind scopes, not collapse them to NULL.
#[tokio::test]
#[ignore]
async fn tenant_visible_via_role_object_kind_grant() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;
    let read = read_id(&p).await;

    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("m19-ok-role-{}", Uuid::new_v4()),
            tenant_id: Some(target),
            description: None,
        },
    )
    .await
    .expect("create role");
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, object_kind, effect) VALUES ('object_kind', $1, 'tenant', 'allow') RETURNING id",
    )
    .bind(target)
    .fetch_one(&p)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(read)
    .execute(&p)
    .await
    .expect("block action");
    atom::authz::repo::replace_role_permission_block_links(&p, role.id, &[block])
        .await
        .expect("link");
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(target),
            subject_kind: SubjectKind::Entity,
            subject_id: caller,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "a role-linked object_kind='tenant' read grant must list the tenant"
    );
}
