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
    policy::CreatePolicyBinding,
    role::CreateRole,
};
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn capability_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM capabilities WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("capability")
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
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_bindings WHERE subject_id = $1")
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
    let device = entity(&p, "device").await;
    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("m8-role-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
            scope_kind: None,
            scope_ref: None,
        },
    )
    .await
    .expect("role");

    atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: device,
            grant_kind: GrantKind::Role,
            grant_id: role.id,
            scope_kind: ScopeKind::ObjectKind,
            scope_ref: Some("resource".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("role binding");

    let err =
        atom::authz::repo::add_role_capability(&p, role.id, capability_id(&p, "manage").await)
            .await
            .expect_err("guardrail should reject role cap");
    assert!(err.to_string().contains("guardrail rejected"));
}

#[tokio::test]
#[ignore]
async fn group_membership_rejects_new_device_that_would_inherit_denied_policy() {
    let p = pool().await;
    let human = entity(&p, "human").await;
    let device = entity(&p, "device").await;
    let group = atom::identity::repo::create_group(
        &p,
        CreateGroup {
            id: None,
            name: format!("m8-group-{}", Uuid::new_v4()),
            tenant_id: None,
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
            tenant_id: None,
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
