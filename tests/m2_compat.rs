//! M2 integration tests.
//!
//! Verifies entity-as-object authorization: `object_kind` / `object_type`
//! scopes and platform inheritance run end-to-end through the PDP.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m2_compat -- --ignored
//! ```

mod common;

use atom::models::enums::{Effect, GrantKind, ScopeKind, SubjectKind};
use atom::models::policy::{AuthzRequest, CreatePolicyBinding};
use common::{admin_id, pool};
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
        .bind(format!("m2-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_active_entity(pool: &sqlx::PgPool, tenant_id: Option<Uuid>, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, $2, $3, $4, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("m2-ent-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

#[tokio::test]
#[ignore]
async fn entity_as_object_can_be_authorised_via_object_kind_form() {
    let p = pool().await;
    let cap_id = manage_capability_id(&p).await;
    let alice = make_active_entity(&p, None, "human").await;
    let device = make_active_entity(&p, None, "device").await;

    // Alice can manage this specific device entity.
    let binding = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: alice,
            grant_kind: GrantKind::Capability,
            grant_id: cap_id,
            scope_kind: ScopeKind::Object,
            scope_ref: Some(device.to_string()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create policy");

    let req = AuthzRequest {
        subject_id: alice,
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(device),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req)
        .await
        .expect("evaluate");
    assert!(
        resp.allowed,
        "alice should manage the device entity: {}",
        resp.reason
    );

    // A different entity should be denied.
    let other_device = make_active_entity(&p, None, "device").await;
    let deny = AuthzRequest {
        subject_id: alice,
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(other_device),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &deny)
        .await
        .expect("evaluate");
    assert!(!resp.allowed);

    let _ = sqlx::query("DELETE FROM direct_policies WHERE id = $1")
        .bind(binding.id)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = ANY($1::uuid[])")
        .bind(&[alice, device, other_device][..])
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn entity_subtype_scope_uses_namespaced_object_type() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let cap_id = manage_capability_id(&p).await;
    let alice = make_active_entity(&p, Some(tenant_id), "human").await;
    let device1 = make_active_entity(&p, Some(tenant_id), "device").await;
    let device2 = make_active_entity(&p, Some(tenant_id), "device").await;
    let svc = make_active_entity(&p, Some(tenant_id), "service").await;

    // Alice manages every device entity (object_type=entity:device).
    let binding = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: alice,
            grant_kind: GrantKind::Capability,
            grant_id: cap_id,
            scope_kind: ScopeKind::ObjectType,
            scope_ref: Some("entity:device".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create policy");

    for d in [device1, device2] {
        let req = AuthzRequest {
            subject_id: alice,
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("entity".into()),
            object_id: Some(d),
            context: json!({}),
        };
        let resp = atom::authz::engine::evaluate(&p, &req)
            .await
            .expect("evaluate");
        assert!(resp.allowed, "device must match: {}", resp.reason);
    }

    // The service entity must NOT match entity:device.
    let req = AuthzRequest {
        subject_id: alice,
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(svc),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req)
        .await
        .expect("evaluate");
    assert!(
        !resp.allowed,
        "service must NOT match entity:device, got {}",
        resp.reason
    );

    let _ = sqlx::query("DELETE FROM direct_policies WHERE id = $1")
        .bind(binding.id)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = ANY($1::uuid[])")
        .bind(&[alice, device1, device2, svc][..])
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn admin_platform_inherits_into_entity_objects() {
    // Regression: admin's seeded scope_kind=platform binding must authorise
    // checks against entity-as-object too, not just resources.
    let p = pool().await;
    let target = make_active_entity(&p, None, "device").await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(target),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req)
        .await
        .expect("evaluate");
    assert!(
        resp.allowed,
        "admin should manage any entity via platform scope: {}",
        resp.reason
    );

    let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(target)
        .execute(&p)
        .await;
}
