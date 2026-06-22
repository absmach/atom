//! M6 integration tests — ABAC operators and expanded context.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m6_conditions -- --ignored
//! ```

mod common;

use atom::models::{
    enums::{Effect, GrantKind, ScopeKind, SubjectKind},
    policy::{AuthzRequest, CreatePolicyBinding},
    tenant::CreateTenant,
};
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn capability_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("capability")
}

async fn tenant(pool: &sqlx::PgPool) -> Uuid {
    atom::tenants::repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: format!("m6-{}", Uuid::new_v4()),
            alias: None,
            tags: vec![],
            attributes: json!({"tier": "gold"}),
        },
        None,
    )
    .await
    .expect("create tenant")
    .id
}

async fn entity(pool: &sqlx::PgPool, kind: &str, attrs: serde_json::Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status, attributes) VALUES ($1, $2, $3, 'active', $4)",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("m6-ent-{id}"))
    .bind(attrs)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn channel(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO resources (id, kind, name, tenant_id, attributes) VALUES ($1, 'channel', $2, $3, $4)",
    )
    .bind(id)
    .bind(format!("m6-channel-{id}"))
    .bind(tenant_id)
    .bind(json!({"tags": ["production"], "temperature": 42}))
    .execute(pool)
    .await
    .expect("insert resource");
    id
}

async fn bind_read(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    tenant_id: Uuid,
    conditions: serde_json::Value,
) -> Uuid {
    atom::authz::repo::create_policy(
        pool,
        CreatePolicyBinding {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id,
            grant_kind: GrantKind::Capability,
            grant_id: capability_id(pool, "read").await,
            scope_kind: ScopeKind::Tenant,
            scope_ref: Some(tenant_id.to_string()),
            effect: Effect::Allow,
            conditions,
        },
    )
    .await
    .expect("create policy")
    .id
}

async fn check(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    resource_id: Uuid,
    context: serde_json::Value,
) -> bool {
    atom::authz::engine::evaluate(
        pool,
        &AuthzRequest {
            subject_id,
            action: "read".into(),
            resource_id: Some(resource_id),
            object_kind: None,
            object_id: None,
            context,
        },
    )
    .await
    .expect("evaluate")
    .allowed
}

#[tokio::test]
#[ignore]
async fn non_object_conditions_are_rejected_on_write() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let actor = entity(&p, "human", json!({})).await;

    // A non-object conditions value is malformed policy: the write path must
    // reject it so the PDP never has to fail closed on stored data.
    let err = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: actor,
            grant_kind: GrantKind::Capability,
            grant_id: capability_id(&p, "read").await,
            scope_kind: ScopeKind::Tenant,
            scope_ref: Some(tenant_id.to_string()),
            effect: Effect::Allow,
            conditions: json!("oops"),
        },
    )
    .await
    .expect_err("non-object conditions must be rejected");
    assert!(
        format!("{err:?}").contains("conditions must be a JSON object"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn timestamp_operator_against_request_context_gates_access() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let actor = entity(&p, "human", json!({})).await;
    let resource = channel(&p, tenant_id).await;

    bind_read(
        &p,
        actor,
        tenant_id,
        json!({"context.time": {"gte": "2026-01-01T00:00:00Z"}}),
    )
    .await;

    assert!(check(&p, actor, resource, json!({"time": "2026-04-29T12:00:00Z"})).await);
    assert!(!check(&p, actor, resource, json!({"time": "2025-12-31T23:59:59Z"})).await);
}

#[tokio::test]
#[ignore]
async fn object_type_tenant_status_and_contains_conditions_apply() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let actor = entity(&p, "human", json!({"department": "ops"})).await;
    let resource = channel(&p, tenant_id).await;

    bind_read(
        &p,
        actor,
        tenant_id,
        json!({
            "entity.attributes.department": {"in": ["ops", "security"]},
            "object.type": "resource:channel",
            "tenant.status": "active",
            "object.attributes.tags": {"contains": "production"},
            "object.attributes.temperature": {"gte": 40}
        }),
    )
    .await;

    assert!(check(&p, actor, resource, json!({})).await);
}

#[tokio::test]
#[ignore]
async fn missing_expanded_context_field_fails_closed() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let actor = entity(&p, "human", json!({})).await;
    let resource = channel(&p, tenant_id).await;

    bind_read(
        &p,
        actor,
        tenant_id,
        json!({"tenant.attributes.missing": "value"}),
    )
    .await;

    assert!(!check(&p, actor, resource, json!({})).await);
}
