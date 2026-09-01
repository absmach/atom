//! Configurable capabilities for Atom-created tenant-admin roles.

mod common;

use atom::bootstrap::{apply, BootstrapCapability, BootstrapConfig, BootstrapTenantDefaults};
use atom::config::{Config, ADMIN_ENTITY_ID};
use atom::models::tenant::CreateTenant;
use atom::tenants::repo::create_tenant;
use common::pool;
use uuid::Uuid;

fn config(name: &str) -> BootstrapConfig {
    BootstrapConfig {
        tenant_defaults: BootstrapTenantDefaults {
            admin_capabilities: vec![name.to_string()],
        },
        capabilities: vec![BootstrapCapability {
            name: name.to_string(),
            description: None,
            applicability: vec![],
        }],
        ..Default::default()
    }
}

async fn create_test_tenant(pool: &sqlx::PgPool) -> Uuid {
    create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: format!("tenant-admin-defaults-{}", Uuid::new_v4()),
            alias: None,
            tags: vec![],
            attributes: serde_json::Value::Null,
        },
        Some(ADMIN_ENTITY_ID),
    )
    .await
    .expect("create tenant")
    .id
}

async fn tenant_admin_has(pool: &sqlx::PgPool, tenant_id: Uuid, capability: &str) -> bool {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1
               FROM roles r
               JOIN role_permission_blocks rpb ON rpb.role_id = r.id
               JOIN permission_block_actions pba
                 ON pba.permission_block_id = rpb.permission_block_id
               JOIN actions a ON a.id = pba.action_id
               WHERE r.tenant_id = $1
                 AND r.managed_by = 'system:tenant-admin'
                 AND a.name = $2
           )"#,
    )
    .bind(tenant_id)
    .bind(capability)
    .fetch_one(pool)
    .await
    .expect("tenant-admin capability lookup")
}

#[tokio::test]
#[ignore]
async fn configured_capability_reaches_existing_and_new_tenants() {
    let pool = pool().await;
    let existing_tenant = create_test_tenant(&pool).await;
    let capability = format!("alarm.acknowledge.{}", Uuid::new_v4());
    let signing_keys = Config::for_tests().signing_keys;

    apply(&pool, &signing_keys, &config(&capability))
        .await
        .expect("apply tenant defaults");
    assert!(tenant_admin_has(&pool, existing_tenant, &capability).await);

    let new_tenant = create_test_tenant(&pool).await;
    assert!(tenant_admin_has(&pool, new_tenant, &capability).await);

    apply(&pool, &signing_keys, &config(&capability))
        .await
        .expect("idempotent reapply");
    assert!(tenant_admin_has(&pool, existing_tenant, &capability).await);
}

#[tokio::test]
#[ignore]
async fn unknown_tenant_admin_default_is_rejected() {
    let pool = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let capability = format!("missing.{}", Uuid::new_v4());
    let cfg = BootstrapConfig {
        tenant_defaults: BootstrapTenantDefaults {
            admin_capabilities: vec![capability.clone()],
        },
        ..Default::default()
    };

    let err = apply(&pool, &signing_keys, &cfg)
        .await
        .expect_err("unknown default must fail");
    assert!(err
        .to_string()
        .contains("unknown tenant_defaults.admin_capabilities"));
}
