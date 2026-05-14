//! M5 integration tests — tenant-admin bootstrap.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m5_bootstrap -- --ignored
//! ```

mod common;

use atom::models::{policy::AuthzRequest, tenant::CreateTenant};
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn human(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'human', $2, 'active')")
        .bind(id)
        .bind(format!("m5-human-{id}"))
        .execute(pool)
        .await
        .expect("insert human");
    id
}

async fn device(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'device', $2, 'active')",
    )
    .bind(id)
    .bind(format!("m5-device-{id}"))
    .execute(pool)
    .await
    .expect("insert device");
    id
}

async fn create_tenant(pool: &sqlx::PgPool, creator_id: Uuid) -> Uuid {
    atom::tenants::repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: format!("m5-{}", Uuid::new_v4()),
            route: None,
            tags: vec![],
            attributes: serde_json::Value::Null,
        },
        Some(creator_id),
    )
    .await
    .expect("create tenant")
    .id
}

#[tokio::test]
#[ignore]
async fn tenant_creation_bootstraps_admin_role_capabilities_binding_and_membership() {
    let p = pool().await;
    let creator = human(&p).await;
    let tenant_id = create_tenant(&p, creator).await;

    let role_id: Uuid =
        sqlx::query_scalar("SELECT id FROM roles WHERE tenant_id = $1 AND name = 'tenant-admin'")
            .bind(tenant_id)
            .fetch_one(&p)
            .await
            .expect("tenant-admin role");

    let capabilities: Vec<String> = sqlx::query_scalar(
        r#"SELECT c.name
           FROM role_capabilities rc
           JOIN capabilities c ON c.id = rc.capability_id
           WHERE rc.role_id = $1
           ORDER BY c.name"#,
    )
    .bind(role_id)
    .fetch_all(&p)
    .await
    .expect("role capabilities");
    assert_eq!(
        capabilities,
        vec![
            "audit.read",
            "credential.manage",
            "manage",
            "policy.manage",
            "role.manage",
        ]
    );
    assert!(!capabilities.iter().any(|c| c == "tenant.manage"));

    let binding_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM policy_bindings
           WHERE tenant_id = $1
             AND subject_kind = 'entity'
             AND subject_id = $2
             AND grant_kind = 'role'
             AND grant_id = $3
             AND scope_kind = 'tenant'
             AND scope_ref = $4"#,
    )
    .bind(tenant_id)
    .bind(creator)
    .bind(role_id)
    .bind(tenant_id.to_string())
    .fetch_one(&p)
    .await
    .expect("binding count");
    assert_eq!(binding_count, 1);

    let membership_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id = $1 AND entity_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(creator)
    .fetch_one(&p)
    .await
    .expect("membership count");
    assert_eq!(membership_count, 1);
}

#[tokio::test]
#[ignore]
async fn non_human_creator_gets_binding_but_no_tenant_membership() {
    let p = pool().await;
    let creator = device(&p).await;
    let tenant_id = create_tenant(&p, creator).await;

    let binding_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM policy_bindings WHERE tenant_id = $1 AND subject_id = $2",
    )
    .bind(tenant_id)
    .bind(creator)
    .fetch_one(&p)
    .await
    .expect("binding count");
    assert_eq!(binding_count, 1);

    let membership_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id = $1 AND entity_id = $2",
    )
    .bind(tenant_id)
    .bind(creator)
    .fetch_one(&p)
    .await
    .expect("membership count");
    assert_eq!(membership_count, 0);
}

#[tokio::test]
#[ignore]
async fn creator_can_immediately_manage_own_tenant_but_not_another_tenant() {
    let p = pool().await;
    let creator = human(&p).await;
    let tenant_id = create_tenant(&p, creator).await;
    let other_tenant_id = create_tenant(&p, human(&p).await).await;

    let own = atom::authz::engine::evaluate(
        &p,
        &AuthzRequest {
            subject_id: creator,
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("tenant".into()),
            object_id: Some(tenant_id),
            context: json!({}),
        },
    )
    .await
    .expect("own tenant authz");
    assert!(own.allowed, "own tenant should allow: {}", own.reason);

    let other = atom::authz::engine::evaluate(
        &p,
        &AuthzRequest {
            subject_id: creator,
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("tenant".into()),
            object_id: Some(other_tenant_id),
            context: json!({}),
        },
    )
    .await
    .expect("other tenant authz");
    assert!(
        !other.allowed,
        "tenant-admin bootstrap must not leak to another tenant"
    );
}
