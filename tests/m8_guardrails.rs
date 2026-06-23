//! M8 integration tests — capability assignment guardrails.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m8_guardrails -- --ignored
//! ```

mod common;

use atom::models::{
    enums::{Effect, GrantKind, ScopeKind, SubjectKind},
    group::CreateGroup,
    policy::{CreatePolicyBinding, CreateRoleAssignment},
    role::{CreateRole, CreateRolePermissionBlock},
};
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn capability_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("action")
}

async fn entity(pool: &sqlx::PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("m8-{kind}-{id}"))
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn tenant_entity(pool: &sqlx::PgPool, tenant_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("m8-tenant-{kind}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert tenant entity");
    id
}

async fn tenant(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("m8-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn resource(pool: &sqlx::PgPool, tenant_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(kind)
        .bind(format!("m8-{kind}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

#[tokio::test]
#[ignore]
async fn direct_policy_rejects_device_manage_resource_and_persists_no_row() {
    let p = pool().await;
    let device = entity(&p, "device").await;
    let req = CreatePolicyBinding {
        tenant_id: None,
        subject_kind: SubjectKind::Entity,
        subject_id: device,
        grant_kind: GrantKind::Capability,
        grant_id: capability_id(&p, "manage").await,
        scope_kind: ScopeKind::ObjectKind,
        scope_ref: Some("resource".into()),
        effect: Effect::Allow,
        conditions: json!({}),
    };

    let err = atom::authz::repo::create_policy(&p, req)
        .await
        .expect_err("guardrail should reject");
    assert!(err.to_string().contains("guardrail rejected"));

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM direct_policies WHERE subject_id = $1")
            .bind(device)
            .fetch_one(&p)
            .await
            .expect("count");
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore]
async fn role_capability_addition_rejects_existing_device_role_holder() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let device = tenant_entity(&p, tenant_id, "device").await;
    let manage_id = capability_id(&p, "manage").await;
    let role = atom::authz::repo::create_role_with_permission_blocks(
        &p,
        CreateRole {
            name: format!("m8-role-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
        &[CreateRolePermissionBlock {
            applies_to: "object_kind".to_string(),
            object_id: None,
            object_kind: Some("resource".to_string()),
            object_type: None,
            tenant_id: Some(tenant_id),
            group_id: None,
            capability_ids: vec![manage_id],
        }],
        &[],
    )
    .await
    .expect("role");

    let err = atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: device,
            role_id: role.id,
        },
    )
    .await
    .expect_err("guardrail should reject role assignment");
    assert!(err.to_string().contains("guardrail rejected"));
}

#[tokio::test]
#[ignore]
async fn group_membership_rejects_new_device_that_would_inherit_denied_policy() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let human = tenant_entity(&p, tenant_id, "human").await;
    let device = tenant_entity(&p, tenant_id, "device").await;
    let group = atom::identity::repo::create_group(
        &p,
        CreateGroup {
            id: None,
            name: format!("m8-group-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            group_type: Some("principal".to_string()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("group");

    atom::identity::repo::add_group_member(&p, group.id, human)
        .await
        .expect("human member allowed");
    atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Group,
            subject_id: group.id,
            grant_kind: GrantKind::Capability,
            grant_id: capability_id(&p, "manage").await,
            scope_kind: ScopeKind::ObjectKind,
            scope_ref: Some("resource".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("group policy accepted for existing human");

    let err = atom::identity::repo::add_group_member(&p, group.id, device)
        .await
        .expect_err("guardrail should reject device membership");
    assert!(err.to_string().contains("guardrail rejected"));
}

#[tokio::test]
#[ignore]
async fn channel_scoped_role_rejects_rule_only_capability() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let publish_id = capability_id(&p, "publish").await;
    let execute_id = capability_id(&p, "execute").await;

    atom::authz::repo::create_role_with_permission_blocks(
        &p,
        CreateRole {
            name: format!("m8-channel-publisher-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
        &[CreateRolePermissionBlock {
            applies_to: "object_type".to_string(),
            object_id: None,
            object_kind: Some("resource".to_string()),
            object_type: Some("resource:channel".to_string()),
            tenant_id: Some(tenant_id),
            group_id: None,
            capability_ids: vec![publish_id],
        }],
        &[],
    )
    .await
    .expect("publish is valid for channels");

    let err = atom::authz::repo::create_role_with_permission_blocks(
        &p,
        CreateRole {
            name: format!("m8-channel-execute-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
        &[CreateRolePermissionBlock {
            applies_to: "object_type".to_string(),
            object_id: None,
            object_kind: Some("resource".to_string()),
            object_type: Some("resource:channel".to_string()),
            tenant_id: Some(tenant_id),
            group_id: None,
            capability_ids: vec![execute_id],
        }],
        &[],
    )
    .await
    .expect_err("execute is not valid for channels");
    assert!(err
        .to_string()
        .contains("capability execute is not applicable to resource:channel"));
}

#[tokio::test]
#[ignore]
async fn exact_object_permission_block_uses_real_object_type() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let rule_id = resource(&p, tenant_id, "rule").await;
    let publish_id = capability_id(&p, "publish").await;
    let execute_id = capability_id(&p, "execute").await;

    atom::authz::repo::create_role_with_permission_blocks(
        &p,
        CreateRole {
            name: format!("m8-rule-executor-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
        &[CreateRolePermissionBlock {
            applies_to: "object".to_string(),
            object_id: Some(rule_id),
            object_kind: None,
            object_type: None,
            tenant_id: None,
            group_id: None,
            capability_ids: vec![execute_id],
        }],
        &[],
    )
    .await
    .expect("execute is valid for rules");

    let err = atom::authz::repo::create_role_with_permission_blocks(
        &p,
        CreateRole {
            name: format!("m8-rule-publisher-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
        &[CreateRolePermissionBlock {
            applies_to: "object".to_string(),
            object_id: Some(rule_id),
            object_kind: None,
            object_type: None,
            tenant_id: None,
            group_id: None,
            capability_ids: vec![publish_id],
        }],
        &[],
    )
    .await
    .expect_err("publish is not valid for rules");
    assert!(err
        .to_string()
        .contains("capability publish is not applicable to resource:rule"));
}

/// Adding a capability to a role must be guardrail-checked against every entity
/// that holds the role, including those reaching it through a *parent* group.
///
/// Regression for `validate_role_capability` expanding group membership
/// recursively: before the fix it joined only direct members of the assigned
/// group, so a device sitting in a child group of the assigned parent group was
/// invisible and the prohibited capability was added anyway.
#[tokio::test]
#[ignore]
async fn role_capability_addition_rejects_device_via_parent_group() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let device = tenant_entity(&p, tenant_id, "device").await;
    let manage_id = capability_id(&p, "manage").await;

    // An absolute deny for device `manage` at tenant scope — the scope a role
    // assignment edge carries, which is what `validate_role_capability` reads.
    sqlx::query(
        "INSERT INTO action_assignment_rules
            (entity_kind, action_name, object_kind, object_type, decision, is_absolute)
         VALUES ('device', 'manage', 'tenant', NULL, 'deny', TRUE)",
    )
    .execute(&p)
    .await
    .expect("insert custom rule");

    let make_group = |name: String| {
        atom::identity::repo::create_group(
            &p,
            CreateGroup {
                id: None,
                name,
                tenant_id: Some(tenant_id),
                group_type: Some("principal".to_string()),
                description: None,
                attributes: json!({}),
            },
        )
    };
    let parent = make_group(format!("m8-parent-{}", Uuid::new_v4()))
        .await
        .expect("parent group");
    let child = make_group(format!("m8-child-{}", Uuid::new_v4()))
        .await
        .expect("child group");
    atom::identity::repo::set_group_parent(&p, child.id, parent.id)
        .await
        .expect("set parent");
    // Device joins the child group before the role carries the prohibited
    // capability, so the join itself is clean.
    atom::identity::repo::add_group_member(&p, child.id, device)
        .await
        .expect("device joins child group");

    // An empty tenant role assigned to the parent group.
    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("m8-parent-role-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("role");
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Group,
            subject_id: parent.id,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role to parent group");

    // Adding `manage` must be rejected: the device holds the role through the
    // child→parent chain and is absolutely denied device `manage` at tenant scope.
    let err = atom::authz::repo::add_role_capability(&p, role.id, manage_id)
        .await
        .expect_err("guardrail should reject capability addition for transitive device holder");
    assert!(
        err.to_string().contains("guardrail rejected"),
        "expected guardrail rejection, got: {err}"
    );
}

/// Two-connection race: a block-link mutation that adds a prohibited block to a
/// role must serialize with a concurrent role assignment, so the combination
/// guardrails forbid cannot slip through on stale state. Both mutators take a
/// FOR UPDATE lock on the role; the assignment can only validate after the
/// block link commits, and then it sees the prohibited block and is rejected.
#[tokio::test]
#[ignore]
async fn concurrent_block_link_and_role_assignment_serialize() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let device = tenant_entity(&p, tenant_id, "device").await;
    let manage = capability_id(&p, "manage").await;

    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("m8-race-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");

    // Connection A: hold the role lock and link a device-prohibited block
    // (manage on resource) in an open transaction — an in-flight block-link
    // mutation that has not committed yet.
    let mut tx = p.begin().await.expect("begin tx");
    sqlx::query("SELECT id FROM roles WHERE id = $1 FOR UPDATE")
        .bind(role.id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock role");
    let block: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (scope_mode, object_kind, tenant_id, effect)
           VALUES ('object_kind', 'resource', $1, 'allow') RETURNING id"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(manage)
    .execute(&mut *tx)
    .await
    .expect("block action");
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(role.id)
    .bind(block)
    .execute(&mut *tx)
    .await
    .expect("link block");

    // Connection B: assign the role to the device. create_role_assignment locks
    // the same role, so it blocks until A commits, then validates.
    let p2 = p.clone();
    let role_id = role.id;
    let handle = tokio::spawn(async move {
        atom::authz::repo::create_role_assignment(
            &p2,
            CreateRoleAssignment {
                tenant_id: Some(tenant_id),
                subject_kind: SubjectKind::Entity,
                subject_id: device,
                role_id,
            },
        )
        .await
    });

    // Let B reach (and block on) the role lock, then commit the block link.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    tx.commit().await.expect("commit block link");

    let result = handle.await.expect("join assignment task");
    let err = result.expect_err("assignment must be rejected once the prohibited block is linked");
    assert!(
        err.to_string().contains("guardrail rejected"),
        "expected a guardrail rejection, got: {err}"
    );
}
