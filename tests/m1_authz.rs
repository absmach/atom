//! M1 functional/end-to-end authz tests.
//!
//! Verifies the PDP authorises correctly with canonical scope_kind variants
//! (`object_type`, `object`, `object_kind`)
//! evaluate as expected against real database state.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m1_authz -- --ignored
//! ```

mod common;

use atom::models::enums::{Effect, GrantKind, ScopeKind, SubjectKind};
use atom::models::policy::{AuthzRequest, CreatePolicyBinding};
use common::{admin_id, pool};
use serde_json::json;
use uuid::Uuid;

async fn read_capability_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM capabilities WHERE name = 'read' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read cap")
}

async fn make_resource(pool: &sqlx::PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(kind)
        .bind(format!("m1-res-{id}"))
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn make_active_entity(pool: &sqlx::PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("m1-ent-{id}"))
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

#[tokio::test]
#[ignore]
async fn admin_platform_binding_authorises() {
    let p = pool().await;
    let resource_id = make_resource(&p, "channel").await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "read".into(),
        resource_id: Some(resource_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req)
        .await
        .expect("evaluate");
    assert!(
        resp.allowed,
        "admin's platform binding should authorise read on a channel: {}",
        resp.reason
    );

    let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(resource_id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn object_type_binding_matches_namespaced_resource_subkind() {
    let p = pool().await;
    let entity_id = make_active_entity(&p, "service").await;
    let channel_id = make_resource(&p, "channel").await;
    let other_id = make_resource(&p, "device_config").await;
    let read_cap = read_capability_id(&p).await;

    // Grant read on every channel via object_type=resource:channel.
    let binding = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: None,
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
    .expect("create policy");

    // Allowed on the channel.
    let allow_req = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(channel_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &allow_req)
        .await
        .expect("evaluate channel");
    assert!(resp.allowed, "channel must be allowed: {}", resp.reason);

    // Denied on a non-channel.
    let deny_req = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(other_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &deny_req)
        .await
        .expect("evaluate device_config");
    assert!(
        !resp.allowed,
        "device_config must NOT be matched by resource:channel: {}",
        resp.reason
    );

    // Cleanup
    let _ = sqlx::query("DELETE FROM policy_bindings WHERE id = $1")
        .bind(binding.id)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM resources WHERE id = ANY($1::uuid[])")
        .bind(&[channel_id, other_id][..])
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(entity_id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn object_binding_matches_specific_resource_uuid() {
    let p = pool().await;
    let entity_id = make_active_entity(&p, "service").await;
    let resource_id = make_resource(&p, "channel").await;
    let other_id = make_resource(&p, "channel").await;
    let read_cap = read_capability_id(&p).await;

    let binding = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            grant_kind: GrantKind::Capability,
            grant_id: read_cap,
            scope_kind: ScopeKind::Object,
            scope_ref: Some(resource_id.to_string()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create policy");

    let allow = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(resource_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    assert!(
        atom::authz::engine::evaluate(&p, &allow)
            .await
            .expect("evaluate")
            .allowed
    );

    let deny = AuthzRequest {
        subject_id: entity_id,
        action: "read".into(),
        resource_id: Some(other_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    assert!(
        !atom::authz::engine::evaluate(&p, &deny)
            .await
            .expect("evaluate")
            .allowed
    );

    let _ = sqlx::query("DELETE FROM policy_bindings WHERE id = $1")
        .bind(binding.id)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM resources WHERE id = ANY($1::uuid[])")
        .bind(&[resource_id, other_id][..])
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(entity_id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn object_kind_binding_matches_every_resource_kind() {
    let p = pool().await;
    let entity_id = make_active_entity(&p, "service").await;
    let chan = make_resource(&p, "channel").await;
    let cfg = make_resource(&p, "device_config").await;
    let read_cap = read_capability_id(&p).await;

    let binding = atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            grant_kind: GrantKind::Capability,
            grant_id: read_cap,
            scope_kind: ScopeKind::ObjectKind,
            scope_ref: Some("resource".into()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("create policy");

    for r in [chan, cfg] {
        let req = AuthzRequest {
            subject_id: entity_id,
            action: "read".into(),
            resource_id: Some(r),
            object_kind: None,
            object_id: None,
            context: json!({}),
        };
        let resp = atom::authz::engine::evaluate(&p, &req)
            .await
            .expect("evaluate");
        assert!(
            resp.allowed,
            "object_kind=resource should match every resource kind, got {}",
            resp.reason
        );
    }

    let _ = sqlx::query("DELETE FROM policy_bindings WHERE id = $1")
        .bind(binding.id)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM resources WHERE id = ANY($1::uuid[])")
        .bind(&[chan, cfg][..])
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(entity_id)
        .execute(&p)
        .await;
}
