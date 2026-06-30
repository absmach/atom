//! M4 integration tests — platform/tenant inheritance and scope-aware gates.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m4_inheritance -- --ignored
//! ```

mod common;

use atom::{
    auth::{has_capability_in_scope, Scope},
    models::{
        enums::{Effect, GrantKind, ScopeKind, SubjectKind},
        policy::{AuthzRequest, CreatePolicyBinding},
        tenant::CreateTenant,
    },
};
use common::{admin_id, pool};
use serde_json::json;
use uuid::Uuid;

async fn capability_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("capability {name}: {e}"))
}

async fn tenant(pool: &sqlx::PgPool) -> Uuid {
    atom::tenants::repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: format!("m4-{}", Uuid::new_v4()),
            alias: None,
            tags: vec![],
            attributes: serde_json::Value::Null,
        },
        None,
    )
    .await
    .expect("create tenant")
    .id
}

async fn entity(pool: &sqlx::PgPool, tenant_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'human', $2, $3, 'active')")
        .bind(id)
        .bind(format!("m4-ent-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn channel(pool: &sqlx::PgPool, tenant_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', $2, $3)")
        .bind(id)
        .bind(format!("m4-chan-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn bind(
    pool: &sqlx::PgPool,
    tenant_id: Option<Uuid>,
    subject_id: Uuid,
    capability: &str,
    scope_kind: ScopeKind,
    scope_ref: Option<String>,
) -> Uuid {
    atom::authz::repo::create_policy(
        pool,
        CreatePolicyBinding {
            tenant_id,
            subject_kind: SubjectKind::Entity,
            subject_id,
            grant_kind: GrantKind::Capability,
            grant_id: capability_id(pool, capability).await,
            scope_kind,
            scope_ref,
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create policy")
    .id
}

async fn check(pool: &sqlx::PgPool, subject_id: Uuid, action: &str, resource_id: Uuid) -> bool {
    atom::authz::engine::evaluate(
        pool,
        &AuthzRequest {
            subject_id,
            action: action.to_string(),
            resource_id: Some(resource_id),
            object_kind: None,
            object_id: None,
            context: json!({}),
        },
        None,
    )
    .await
    .expect("evaluate")
    .allowed
}

#[tokio::test]
#[ignore]
async fn tenant_scope_inherits_only_inside_that_tenant() {
    let p = pool().await;
    let t1 = tenant(&p).await;
    let t2 = tenant(&p).await;
    let actor = entity(&p, None).await;
    let r1 = channel(&p, Some(t1)).await;
    let r2 = channel(&p, Some(t2)).await;
    let global = channel(&p, None).await;

    bind(
        &p,
        Some(t1),
        actor,
        "manage",
        ScopeKind::Tenant,
        Some(t1.to_string()),
    )
    .await;

    assert!(check(&p, actor, "manage", r1).await);
    assert!(!check(&p, actor, "manage", r2).await);
    assert!(!check(&p, actor, "manage", global).await);
}

#[tokio::test]
#[ignore]
async fn platform_gate_inherits_manage_into_any_tenant() {
    let p = pool().await;
    let t = tenant(&p).await;

    assert!(
        has_capability_in_scope(&p, admin_id(), "manage", Scope::Tenant(t))
            .await
            .expect("scope gate"),
        "seeded platform admin manage grant must inherit into tenant scope"
    );
}

#[tokio::test]
#[ignore]
async fn tenant_policy_manage_does_not_leak_to_other_tenants_or_platform() {
    let p = pool().await;
    let t1 = tenant(&p).await;
    let t2 = tenant(&p).await;
    let actor = entity(&p, None).await;

    bind(
        &p,
        Some(t1),
        actor,
        "policy.manage",
        ScopeKind::Tenant,
        Some(t1.to_string()),
    )
    .await;

    assert!(
        has_capability_in_scope(&p, actor, "policy.manage", Scope::Tenant(t1))
            .await
            .expect("own tenant")
    );
    assert!(
        !has_capability_in_scope(&p, actor, "policy.manage", Scope::Tenant(t2))
            .await
            .expect("other tenant")
    );
    assert!(
        !has_capability_in_scope(&p, actor, "policy.manage", Scope::Platform)
            .await
            .expect("platform")
    );
}

#[tokio::test]
#[ignore]
async fn tenant_owned_object_kind_policy_is_bounded_by_policy_tenant_id() {
    let p = pool().await;
    let t1 = tenant(&p).await;
    let t2 = tenant(&p).await;
    let actor = entity(&p, None).await;
    let r1 = channel(&p, Some(t1)).await;
    let r2 = channel(&p, Some(t2)).await;

    bind(
        &p,
        Some(t1),
        actor,
        "read",
        ScopeKind::ObjectKind,
        Some("resource".into()),
    )
    .await;

    assert!(check(&p, actor, "read", r1).await);
    assert!(
        !check(&p, actor, "read", r2).await,
        "tenant-owned object_kind policy must not leak across tenant_id"
    );
}

#[tokio::test]
#[ignore]
async fn manage_at_tenant_scope_does_not_satisfy_platform_lifecycle_gate() {
    let p = pool().await;
    let t = tenant(&p).await;
    let actor = entity(&p, None).await;

    bind(
        &p,
        Some(t),
        actor,
        "manage",
        ScopeKind::Tenant,
        Some(t.to_string()),
    )
    .await;

    assert!(
        !has_capability_in_scope(&p, actor, "manage", Scope::Platform)
            .await
            .expect("platform lifecycle gate")
    );
    assert!(
        has_capability_in_scope(&p, actor, "manage", Scope::Tenant(t))
            .await
            .expect("tenant gate")
    );
}
