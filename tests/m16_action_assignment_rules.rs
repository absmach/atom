//! DB-gated tests for action assignment guardrail management.

mod common;

use atom::{
    authz::repo,
    error::AppError,
    models::{
        action_assignment_rule::{CreateActionAssignmentRule, ListActionAssignmentRules},
        enums::{ActionAssignmentDecision, Effect, EntityKind, ObjectKind, SubjectKind},
        policy::{CreateDirectPolicy, CreatePermissionBlock, CreateRoleAssignment},
        role::CreateRole,
    },
};

#[tokio::test]
#[ignore]
async fn repo_validates_action_assignment_rule_creation() {
    let p = common::pool().await;
    let action_name = format!("m16-action-{}", uuid::Uuid::new_v4());
    sqlx::query("INSERT INTO actions (name, description) VALUES ($1, 'm16 test action')")
        .bind(&action_name)
        .execute(&p)
        .await
        .expect("insert action");

    let created = repo::create_action_assignment_rule(
        &p,
        CreateActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: action_name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: Some("resource:channel".into()),
            decision: ActionAssignmentDecision::Allow,
            is_absolute: false,
        },
    )
    .await
    .expect("create rule");
    assert_eq!(created.action_name, action_name);

    let listed = repo::list_action_assignment_rules(
        &p,
        ListActionAssignmentRules {
            tenant_id: None,
            entity_kind: Some(EntityKind::Device),
            action_name: Some(created.action_name.clone()),
            object_kind: Some(ObjectKind::Resource),
            object_type: Some("resource:channel".into()),
            decision: Some(ActionAssignmentDecision::Allow),
            limit: 10,
            offset: 0,
        },
    )
    .await
    .expect("list rules");
    assert_eq!(listed.total, 1);

    let duplicate = repo::create_action_assignment_rule(
        &p,
        CreateActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: created.action_name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: Some("resource:channel".into()),
            decision: ActionAssignmentDecision::Deny,
            is_absolute: false,
        },
    )
    .await
    .expect_err("duplicate rule rejected");
    assert!(matches!(duplicate, AppError::Conflict(_)));

    let unknown = repo::create_action_assignment_rule(
        &p,
        CreateActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: "missing-action".into(),
            object_kind: ObjectKind::Resource,
            object_type: None,
            decision: ActionAssignmentDecision::Allow,
            is_absolute: false,
        },
    )
    .await
    .expect_err("unknown action rejected");
    assert!(matches!(unknown, AppError::BadRequest(_)));

    let invalid_object_type = repo::create_action_assignment_rule(
        &p,
        CreateActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: created.action_name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: Some("entity:device".into()),
            decision: ActionAssignmentDecision::Allow,
            is_absolute: false,
        },
    )
    .await
    .expect_err("invalid object type rejected");
    assert!(matches!(invalid_object_type, AppError::BadRequest(_)));

    let tenant_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("m16-tenant-{tenant_id}"))
        .execute(&p)
        .await
        .expect("insert tenant");

    for req in [
        CreateActionAssignmentRule {
            tenant_id: Some(tenant_id),
            entity_kind: EntityKind::Device,
            action_name: created.action_name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: None,
            decision: ActionAssignmentDecision::Allow,
            is_absolute: false,
        },
        CreateActionAssignmentRule {
            tenant_id: Some(tenant_id),
            entity_kind: EntityKind::Device,
            action_name: created.action_name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: None,
            decision: ActionAssignmentDecision::Deny,
            is_absolute: true,
        },
        CreateActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: created.action_name.clone(),
            object_kind: ObjectKind::Resource,
            object_type: None,
            decision: ActionAssignmentDecision::RequireOverride,
            is_absolute: false,
        },
    ] {
        let err = repo::create_action_assignment_rule(&p, req)
            .await
            .expect_err("invalid v1 rule rejected");
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    let deleted = repo::delete_action_assignment_rule(&p, created.id)
        .await
        .expect("delete rule");
    assert_eq!(deleted.id, created.id);
}

#[tokio::test]
#[ignore]
async fn guardrails_apply_to_direct_policy_and_role_permission_block_links() {
    let p = common::pool().await;
    // object_kind permission blocks require a tenant (schema CHECK), so scope
    // the whole scenario to one tenant. The seeded device→manage→resource deny
    // is an absolute global rule, so it still fires for a tenant-scoped grant.
    let tenant_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("m16-tenant-{tenant_id}"))
        .execute(&p)
        .await
        .expect("insert tenant");

    let device_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'device', $2, $3, 'active')",
    )
    .bind(device_id)
    .bind(format!("m16-device-{device_id}"))
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert device");

    let manage_action_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage'")
            .fetch_one(&p)
            .await
            .expect("manage action");

    let block = repo::create_permission_block(
        &p,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "object_kind".into(),
            object_kind: Some("resource".into()),
            object_type: None,
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: serde_json::json!({}),
            action_ids: vec![manage_action_id],
        },
    )
    .await
    .expect("create permission block");

    let direct_policy = repo::create_direct_policy(
        &p,
        CreateDirectPolicy {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: device_id,
            permission_block_id: block.id,
        },
    )
    .await
    .expect_err("direct policy guardrail rejected");
    assert!(matches!(direct_policy, AppError::BadRequest(_)));

    let role = repo::create_role(
        &p,
        CreateRole {
            name: format!("m16-role-{}", uuid::Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");
    repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: device_id,
            role_id: role.id,
        },
    )
    .await
    .expect("create empty role assignment");

    let role_link = repo::replace_role_permission_block_links(&p, role.id, &[block.id])
        .await
        .expect_err("role link guardrail rejected");
    assert!(matches!(role_link, AppError::BadRequest(_)));
}
