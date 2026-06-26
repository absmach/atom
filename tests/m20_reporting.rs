//! Regression coverage for reporting surfaces that describe stored assignments.
//!
//! `myTenantRoles` is assignment metadata, not an authorization decision. It
//! must therefore preserve empty, conditional, and deny-bearing role
//! definitions without pretending their actions are currently allowed.

mod common;

use atom::models::{
    enums::SubjectKind, group::CreateGroup, policy::CreateRoleAssignment, role::CreateRole,
};
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn tenant(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("m20-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn human(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status)
         VALUES ($1, 'human', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("m20-human-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert human");
    id
}

async fn principal_group(pool: &sqlx::PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    atom::identity::repo::create_group(
        pool,
        CreateGroup {
            id: None,
            name: name.to_owned(),
            tenant_id: Some(tenant_id),
            group_type: Some("principal".to_owned()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create principal group")
    .id
}

#[tokio::test]
#[ignore]
async fn tenant_role_report_is_assignment_metadata_with_recursive_groups() {
    let pool = pool().await;
    let target_tenant = tenant(&pool).await;
    let other_tenant = tenant(&pool).await;
    let entity_id = human(&pool, target_tenant).await;

    let parent_name = format!("m20-parent-{}", Uuid::new_v4());
    let child_name = format!("m20-child-{}", Uuid::new_v4());
    let parent = principal_group(&pool, target_tenant, &parent_name).await;
    let child = principal_group(&pool, target_tenant, &child_name).await;
    atom::identity::repo::set_group_parent(&pool, child, parent)
        .await
        .expect("set group parent");
    atom::identity::repo::add_group_member(&pool, child, entity_id)
        .await
        .expect("add group member");

    let conditional_deny_role = atom::authz::repo::create_role(
        &pool,
        CreateRole {
            name: format!("m20-conditional-deny-{}", Uuid::new_v4()),
            tenant_id: Some(target_tenant),
            description: None,
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect("create conditional deny role");
    let read_action: Uuid =
        sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("read action");
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, effect, conditions)
         VALUES ('tenant', $1, 'deny', $2) RETURNING id",
    )
    .bind(target_tenant)
    .bind(json!({"context.region": {"eq": "eu"}}))
    .fetch_one(&pool)
    .await
    .expect("insert conditional deny block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(read_action)
    .execute(&pool)
    .await
    .expect("link block action");
    atom::authz::repo::replace_role_permission_block_links(
        &pool,
        conditional_deny_role.id,
        &[block],
    )
    .await
    .expect("link role block");
    atom::authz::repo::create_role_assignment(
        &pool,
        CreateRoleAssignment {
            tenant_id: Some(target_tenant),
            subject_kind: SubjectKind::Group,
            subject_id: parent,
            role_id: conditional_deny_role.id,
        },
    )
    .await
    .expect("assign role to parent group");

    let empty_role = atom::authz::repo::create_role(
        &pool,
        CreateRole {
            name: format!("m20-empty-{}", Uuid::new_v4()),
            tenant_id: Some(target_tenant),
            description: None,
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect("create empty role");
    atom::authz::repo::create_role_assignment(
        &pool,
        CreateRoleAssignment {
            tenant_id: Some(target_tenant),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            role_id: empty_role.id,
        },
    )
    .await
    .expect("assign empty role");

    let foreign_role = atom::authz::repo::create_role(
        &pool,
        CreateRole {
            name: format!("m20-foreign-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect("create foreign role");
    sqlx::query(
        "INSERT INTO role_assignments (tenant_id, subject_kind, subject_id, role_id)
         VALUES ($1, 'entity', $2, $3)",
    )
    .bind(other_tenant)
    .bind(entity_id)
    .bind(foreign_role.id)
    .execute(&pool)
    .await
    .expect("insert foreign-boundary assignment");

    let roles = atom::tenants::repo::list_tenant_role_assignments(&pool, target_tenant, entity_id)
        .await
        .expect("list tenant role assignments");

    let conditional = roles
        .iter()
        .find(|role| role.role_id == conditional_deny_role.id)
        .expect("recursive parent-group assignment is reported");
    assert_eq!(conditional.actions, vec!["read"]);
    assert_eq!(
        conditional.assignment_paths,
        vec![format!("group:{parent_name} -> {child_name}")]
    );

    let empty = roles
        .iter()
        .find(|role| role.role_id == empty_role.id)
        .expect("empty assigned role is reported");
    assert!(empty.actions.is_empty());
    assert_eq!(empty.assignment_paths, vec!["direct"]);

    assert!(
        roles.iter().all(|role| role.role_id != foreign_role.id),
        "an assignment bounded to another tenant must not appear"
    );
}
