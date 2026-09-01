//! Configurable capabilities for Atom-created tenant-admin roles.

mod common;

use atom::bootstrap::{
    apply, BootstrapActionAssignmentRule, BootstrapCapability,
    BootstrapCapabilityApplicability, BootstrapConfig, BootstrapTenantDefaults,
};
use atom::config::{Config, ADMIN_ENTITY_ID};
use atom::models::enums::{ActionAssignmentDecision, EntityKind, ObjectKind};
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

fn defaults(names: &[&str]) -> BootstrapConfig {
    BootstrapConfig {
        tenant_defaults: BootstrapTenantDefaults {
            admin_capabilities: names.iter().map(|name| (*name).to_string()).collect(),
        },
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
async fn tenant_admin_defaults_are_safe_and_idempotent() {
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

    let shared_block: Uuid = sqlx::query_scalar(
        r#"SELECT rpb.permission_block_id
           FROM roles r
           JOIN role_permission_blocks rpb ON rpb.role_id = r.id
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE r.tenant_id = $1 AND r.managed_by = 'system:tenant-admin'
             AND pb.managed_by = 'system:tenant-admin'"#,
    )
    .bind(existing_tenant)
    .fetch_one(&pool)
    .await
    .expect("system tenant-admin block");
    let other_role = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(other_role)
        .bind(format!("shared-block-role-{}", Uuid::new_v4()))
        .bind(existing_tenant)
        .execute(&pool)
        .await
        .expect("create role sharing old block");
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(other_role)
    .bind(shared_block)
    .execute(&pool)
    .await
    .expect("share old tenant-admin block");

    let replacement_capability = format!("alarm.silence.{}", Uuid::new_v4());
    apply(&pool, &signing_keys, &config(&replacement_capability))
        .await
        .expect("replace tenant defaults");
    assert!(tenant_admin_has(&pool, existing_tenant, &replacement_capability).await);
    assert!(!tenant_admin_has(&pool, existing_tenant, &capability).await);
    let shared_block_gained_replacement: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1 FROM permission_block_actions pba
               JOIN actions a ON a.id = pba.action_id
               WHERE pba.permission_block_id = $1 AND a.name = $2
           )"#,
    )
    .bind(shared_block)
    .bind(&replacement_capability)
    .fetch_one(&pool)
    .await
    .expect("shared block action lookup");
    assert!(!shared_block_gained_replacement);

    apply(&pool, &signing_keys, &defaults(&["manage"]))
        .await
        .expect("temporarily list built-in capability");
    apply(&pool, &signing_keys, &BootstrapConfig::default())
        .await
        .expect("remove built-in from extra defaults");
    assert!(tenant_admin_has(&pool, existing_tenant, "manage").await);

    let reconcile_denied_capability = format!("alarm.force.{}", Uuid::new_v4());
    let reconcile_denied_cfg = BootstrapConfig {
        tenant_defaults: BootstrapTenantDefaults {
            admin_capabilities: vec![reconcile_denied_capability.clone()],
        },
        capabilities: vec![BootstrapCapability {
            name: reconcile_denied_capability.clone(),
            description: None,
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Tenant,
                object_type: None,
            }],
        }],
        action_assignment_rules: vec![BootstrapActionAssignmentRule {
            tenant_id: Some(existing_tenant),
            entity_kind: EntityKind::Human,
            action_name: reconcile_denied_capability,
            object_kind: ObjectKind::Tenant,
            object_type: None,
            decision: ActionAssignmentDecision::Deny,
            is_absolute: false,
        }],
        ..Default::default()
    };
    let err = apply(&pool, &signing_keys, &reconcile_denied_cfg)
        .await
        .expect_err("guardrail must reject existing tenant reconciliation");
    assert!(err.to_string().contains("guardrail rejected"));

    let denied_capability = format!("alarm.delete.{}", Uuid::new_v4());
    let denied_tenant = Uuid::new_v4();
    let denied_cfg = BootstrapConfig {
        tenant_defaults: BootstrapTenantDefaults {
            admin_capabilities: vec![denied_capability.clone()],
        },
        capabilities: vec![BootstrapCapability {
            name: denied_capability.clone(),
            description: None,
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Tenant,
                object_type: None,
            }],
        }],
        action_assignment_rules: vec![BootstrapActionAssignmentRule {
            tenant_id: Some(denied_tenant),
            entity_kind: EntityKind::Human,
            action_name: denied_capability,
            object_kind: ObjectKind::Tenant,
            object_type: None,
            decision: ActionAssignmentDecision::Deny,
            is_absolute: false,
        }],
        ..Default::default()
    };
    apply(&pool, &signing_keys, &denied_cfg)
        .await
        .expect("install tenant-scoped denial");
    let err = create_tenant(
        &pool,
        CreateTenant {
            id: Some(denied_tenant),
            name: format!("denied-tenant-{}", Uuid::new_v4()),
            alias: None,
            tags: vec![],
            attributes: serde_json::Value::Null,
        },
        Some(ADMIN_ENTITY_ID),
    )
    .await
    .expect_err("guardrail must reject tenant-admin default");
    assert!(format!("{err:?}").contains("guardrail rejected"));
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
