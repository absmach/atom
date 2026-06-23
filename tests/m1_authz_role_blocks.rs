//! Regression tests for role-linked permission blocks carrying their own
//! effect and conditions through expansion (Finding 1).
//!
//! Before the fix, `effective_access_edges()` hard-coded role-assignment edges
//! to `allow`/`{}` and `ExpandedRoleGrant` dropped the block's effect and
//! conditions, so a role-linked deny block was silently ignored and a
//! role-linked conditional-allow block became an unconditional allow.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m1_authz_role_blocks -- --ignored
//! ```

mod common;

use atom::models::enums::{Effect, GrantKind, ScopeKind, SubjectKind};
use atom::models::policy::{
    AuthzRequest, CreatePermissionBlock, CreatePolicyBinding, CreateRoleAssignment,
};
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
        .bind(format!("rb-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_channel(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', $2, $3)")
        .bind(id)
        .bind(format!("rb-res-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn make_service_entity(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("rb-ent-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn cleanup(pool: &sqlx::PgPool, tenant_id: Uuid, entity_id: Uuid, resource_id: Uuid) {
    // role_assignments / role_permission_blocks / permission_blocks / direct_policies
    // owned by this tenant are removed by the tenant cascade where applicable; clean
    // the explicit rows we created to keep the test database tidy.
    let _ = sqlx::query("DELETE FROM role_assignments WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM direct_policies WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(resource_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(entity_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM roles WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

/// A role-linked deny block must override a direct allow. Before the fix the
/// role edge dropped the block's `deny` effect, so the direct allow won.
#[tokio::test]
#[ignore]
async fn role_linked_deny_block_overrides_direct_allow() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let entity_id = make_service_entity(&p, tenant_id).await;
    let channel_id = make_channel(&p, tenant_id).await;
    let read_cap = read_capability_id(&p).await;

    // Direct allow: read on resource:channel.
    atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            grant_kind: GrantKind::Capability,
            grant_id: read_cap,
            scope_kind: ScopeKind::ObjectType,
            scope_ref: Some("resource:channel".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create direct allow");

    // Role carrying a DENY block for read on resource:channel.
    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("rb-role-deny-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");

    let deny_block = atom::authz::repo::create_permission_block(
        &p,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "object_type".into(),
            object_kind: Some("resource".into()),
            object_type: Some("resource:channel".into()),
            object_id: None,
            group_id: None,
            effect: Effect::Deny,
            conditions: json!({}),
            action_ids: vec![read_cap],
        },
    )
    .await
    .expect("create deny block");

    atom::authz::repo::replace_role_permission_block_links(&p, role.id, &[deny_block.id])
        .await
        .expect("link deny block");

    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");

    let req = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(channel_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req)
        .await
        .expect("evaluate");
    assert!(
        !resp.allowed,
        "role-linked deny block must override the direct allow: {}",
        resp.reason
    );

    cleanup(&p, tenant_id, entity_id, channel_id).await;
}

/// A role-linked conditional-allow block must honour its conditions. Before the
/// fix the role edge dropped the block's conditions, granting unconditionally.
#[tokio::test]
#[ignore]
async fn role_linked_conditional_allow_block_honours_conditions() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let entity_id = make_service_entity(&p, tenant_id).await;
    let channel_id = make_channel(&p, tenant_id).await;
    let read_cap = read_capability_id(&p).await;

    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("rb-role-cond-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");

    // Conditional allow: read on resource:channel, only when context.mfa == true.
    let cond_block = atom::authz::repo::create_permission_block(
        &p,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "object_type".into(),
            object_kind: Some("resource".into()),
            object_type: Some("resource:channel".into()),
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({"context.mfa": true}),
            action_ids: vec![read_cap],
        },
    )
    .await
    .expect("create conditional block");

    atom::authz::repo::replace_role_permission_block_links(&p, role.id, &[cond_block.id])
        .await
        .expect("link conditional block");

    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");

    // Condition unmet → must be denied.
    let deny_req = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(channel_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &deny_req)
        .await
        .expect("evaluate unmet");
    assert!(
        !resp.allowed,
        "role-linked conditional allow must NOT grant when condition is unmet: {}",
        resp.reason
    );

    // Condition met → allowed.
    let allow_req = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(channel_id),
        object_kind: None,
        object_id: None,
        context: json!({"mfa": true}),
    };
    let resp = atom::authz::engine::evaluate(&p, &allow_req)
        .await
        .expect("evaluate met");
    assert!(
        resp.allowed,
        "role-linked conditional allow must grant when condition is met: {}",
        resp.reason
    );

    // explain must reach the same decision as evaluate for both cases: both go
    // through the single canonical grant expansion and the shared matcher, so a
    // disagreement would mean explain has drifted from the real decision.
    let explained_unmet = atom::authz::engine::explain(&p, &deny_req)
        .await
        .expect("explain unmet");
    assert!(
        !explained_unmet.allowed,
        "explain must agree with evaluate (deny when condition unmet): {}",
        explained_unmet.reason
    );
    let explained_met = atom::authz::engine::explain(&p, &allow_req)
        .await
        .expect("explain met");
    assert!(
        explained_met.allowed,
        "explain must agree with evaluate (allow when condition met): {}",
        explained_met.reason
    );

    cleanup(&p, tenant_id, entity_id, channel_id).await;
}

/// An explain binding identifies both the assignment that conferred access and
/// the backing block. With shared blocks the assignment id is what tells callers
/// *which* grant applied; the refactor must not collapse it into the block id.
#[tokio::test]
#[ignore]
async fn explain_binding_carries_assignment_and_block_ids() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let entity_id = make_service_entity(&p, tenant_id).await;
    let channel_id = make_channel(&p, tenant_id).await;
    let read_cap = read_capability_id(&p).await;

    let policy = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            grant_kind: GrantKind::Capability,
            grant_id: read_cap,
            scope_kind: ScopeKind::ObjectType,
            scope_ref: Some("resource:channel".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create direct policy");

    let block_id: Uuid =
        sqlx::query_scalar("SELECT permission_block_id FROM direct_policies WHERE id = $1")
            .bind(policy.id)
            .fetch_one(&p)
            .await
            .expect("policy block id");

    let resp = atom::authz::engine::explain(
        &p,
        &AuthzRequest {
            subject_id: entity_id,
            action: "read".into(),
            resource_id: Some(channel_id),
            object_kind: None,
            object_id: None,
            context: json!({}),
        },
    )
    .await
    .expect("explain");

    assert!(resp.allowed, "{}", resp.reason);
    let matched = resp.matched_binding.expect("matched binding present");
    assert_eq!(
        matched.id, policy.id,
        "binding id must identify the direct-policy assignment"
    );
    assert_eq!(
        matched.block_id, block_id,
        "binding must also carry the backing block id"
    );

    cleanup(&p, tenant_id, entity_id, channel_id).await;
}
