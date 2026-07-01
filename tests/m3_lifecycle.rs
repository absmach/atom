//! M3 integration tests — tenant lifecycle enforcement in the PDP.
//!
//! TEN-14, AZ-16, AUD-8: every authz check on an object owned by a tenant
//! that is not `active` must deny with a reason naming the state, and
//! the deny must surface tenant_id + tenant_status in `response.details`
//! so audit can record the lifecycle reason structurally.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m3_lifecycle -- --ignored
//! ```

mod common;

use atom::models::enums::TenantStatus;
use atom::models::policy::AuthzRequest;
use atom::models::tenant::CreateTenant;
use common::{admin_id, pool};
use serde_json::json;
use uuid::Uuid;

async fn fresh_tenant(pool: &sqlx::PgPool) -> uuid::Uuid {
    let t = atom::tenants::repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: format!("m3-{}", Uuid::new_v4()),
            alias: None,
            tags: vec![],
            attributes: serde_json::Value::Null,
        },
        None,
    )
    .await
    .expect("create tenant");
    t.id
}

async fn freeze_to(pool: &sqlx::PgPool, tenant_id: uuid::Uuid, status: TenantStatus) {
    match status {
        TenantStatus::Active | TenantStatus::Inactive | TenantStatus::Frozen => {
            atom::tenants::repo::change_tenant_status(pool, tenant_id, status, None)
                .await
                .expect("change status");
        }
        TenantStatus::Deleted => {
            atom::tenants::repo::soft_delete_tenant(pool, tenant_id, None)
                .await
                .expect("delete tenant");
        }
    }
}

async fn channel_in(pool: &sqlx::PgPool, tenant_id: uuid::Uuid) -> uuid::Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', $2, $3)")
        .bind(id)
        .bind(format!("m3-chan-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

#[tokio::test]
#[ignore]
async fn inactive_tenant_denies_with_lifecycle_reason() {
    let p = pool().await;
    let t = fresh_tenant(&p).await;
    freeze_to(&p, t, TenantStatus::Inactive).await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("tenant".into()),
        object_id: Some(t),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req, None)
        .await
        .expect("eval");
    assert!(!resp.allowed);
    assert_eq!(resp.reason, "tenant is inactive");
    let details = resp.details.expect("M3 details required");
    assert_eq!(details["tenant_status"], "inactive");
    assert_eq!(details["tenant_id"], serde_json::json!(t.to_string()));

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(t)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn frozen_tenant_denies_with_lifecycle_reason() {
    let p = pool().await;
    let t = fresh_tenant(&p).await;
    freeze_to(&p, t, TenantStatus::Frozen).await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("tenant".into()),
        object_id: Some(t),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req, None)
        .await
        .expect("eval");
    assert!(!resp.allowed);
    assert_eq!(resp.reason, "tenant is frozen");
    assert_eq!(resp.details.unwrap()["tenant_status"], "frozen");

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(t)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn deleted_tenant_denies_with_lifecycle_reason() {
    let p = pool().await;
    let t = fresh_tenant(&p).await;
    freeze_to(&p, t, TenantStatus::Deleted).await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("tenant".into()),
        object_id: Some(t),
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req, None)
        .await
        .expect("eval");
    assert!(!resp.allowed);
    assert_eq!(resp.reason, "tenant is deleted");
    assert_eq!(resp.details.unwrap()["tenant_status"], "deleted");

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(t)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn frozen_tenant_blocks_authz_on_objects_inside_it() {
    // A resource scoped to a frozen tenant must deny — the lifecycle check
    // applies via the parent's tenant_id, not just to tenant-as-object.
    let p = pool().await;
    let t = fresh_tenant(&p).await;
    let chan = channel_in(&p, t).await;
    freeze_to(&p, t, TenantStatus::Frozen).await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "publish".into(),
        resource_id: Some(chan),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req, None)
        .await
        .expect("eval");
    assert!(!resp.allowed);
    assert_eq!(resp.reason, "tenant is frozen");

    let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(chan)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(t)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn platform_resource_unaffected_by_tenant_lifecycle() {
    // A resource with tenant_id = NULL (platform-scoped) must NOT be denied
    // by the lifecycle check.
    let p = pool().await;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(id)
        .bind(format!("m3-platform-{id}"))
        .execute(&p)
        .await
        .expect("insert resource");

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "publish".into(),
        resource_id: Some(id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate(&p, &req, None)
        .await
        .expect("eval");
    assert!(
        resp.allowed,
        "platform resource must be unaffected by lifecycle check: {}",
        resp.reason
    );

    let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn explain_surfaces_lifecycle_reason_too() {
    let p = pool().await;
    let t = fresh_tenant(&p).await;
    freeze_to(&p, t, TenantStatus::Frozen).await;

    let req = AuthzRequest {
        subject_id: admin_id(),
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("tenant".into()),
        object_id: Some(t),
        context: json!({}),
    };
    let resp = atom::authz::engine::explain(&p, &req)
        .await
        .expect("explain");
    assert!(!resp.allowed);
    assert_eq!(resp.reason, "tenant is frozen");
    assert!(resp.matched_binding.is_none());

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(t)
        .execute(&p)
        .await;
}
