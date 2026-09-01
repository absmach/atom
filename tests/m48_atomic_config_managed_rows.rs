//! Transactional ownership guards for bootstrap-managed rows.
//!
//! Each regression stages an uncommitted bootstrap ownership stamp, starts the
//! real API repository mutation, then commits the stamp. A plain pooled
//! precheck would see the old NULL marker and eventually mutate the row; the
//! correct same-transaction guard waits and re-reads `managed_by='config'`.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m48_atomic_config_managed_rows -- --ignored
//! ```

mod common;

use std::{fmt::Debug, future::Future};

use atom::{
    authz::repo as authz_repo,
    config::Config,
    error::AppError,
    identity::{repo as identity_repo, service as identity_service},
    models::{
        capability::UpdateCapability, entity::UpdateEntity, group::UpdateGroup,
        resource::UpdateResource, role::UpdateRole, tenant::UpdateTenant, token::CreateSharedKey,
    },
    tenants::repo as tenant_repo,
};
use common::pool;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

fn assert_config_conflict(err: AppError) {
    match err {
        AppError::Conflict(message) => assert!(
            message.contains("bootstrap config"),
            "unexpected conflict: {message}"
        ),
        other => panic!("expected bootstrap ownership conflict, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn credential_create_waits_for_config_slot_ownership_and_then_conflicts() {
    let p = pool().await;
    let tenant_id = active_tenant(&p, "credential-slot").await;
    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(entity_id)
    .bind(format!("m48-credential-{entity_id}"))
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert entity");
    let credential_id = Uuid::new_v4();
    let hash =
        identity_service::hash_secret(b"managed-machine-secret").expect("hash managed password");
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)",
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(hash)
    .execute(&p)
    .await
    .expect("insert password");

    let mut stamp = p.begin().await.expect("begin bootstrap-like credential tx");
    identity_repo::lock_active_entity(&mut stamp, entity_id)
        .await
        .expect("lock entity")
        .expect("active entity");
    sqlx::query("UPDATE credentials SET managed_by = 'config' WHERE id = $1")
        .bind(credential_id)
        .execute(&mut *stamp)
        .await
        .expect("stage credential ownership");

    let p2 = p.clone();
    let create = tokio::spawn(async move {
        identity_service::create_password(&p2, entity_id, "replacement-machine-secret").await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !create.is_finished(),
        "credential create must wait behind the bootstrap entity lock"
    );
    stamp.commit().await.expect("commit credential ownership");
    assert_config_conflict(
        create
            .await
            .expect("join credential create")
            .expect_err("config-owned slot must reject API create"),
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active'",
    )
    .bind(entity_id)
    .fetch_one(&p)
    .await
    .expect("active password count");
    assert_eq!(active, 1);
}

#[tokio::test]
#[ignore]
async fn shared_key_reveal_waits_for_config_stamp_and_hides_the_secret() {
    let p = pool().await;
    let tenant_id = active_tenant(&p, "shared-key-reveal").await;
    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(entity_id)
    .bind(format!("m48-shared-key-{entity_id}"))
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert service entity");
    let signing_keys = Config::for_tests().signing_keys;
    let shared = identity_service::create_shared_key(
        &p,
        &signing_keys,
        entity_id,
        CreateSharedKey {
            expires_at: None,
            description: Some("bootstrap race fixture".into()),
            key: Some("managed-shared-key-secret-123".into()),
        },
    )
    .await
    .expect("create shared key");

    let mut stamp = p.begin().await.expect("begin bootstrap-like credential tx");
    identity_repo::lock_active_entity(&mut stamp, entity_id)
        .await
        .expect("lock entity")
        .expect("active entity");
    sqlx::query("UPDATE credentials SET managed_by = 'config' WHERE id = $1")
        .bind(shared.credential_id)
        .execute(&mut *stamp)
        .await
        .expect("stage shared-key ownership");

    let p2 = p.clone();
    let signing_keys2 = signing_keys.clone();
    let reveal = tokio::spawn(async move {
        identity_service::reveal_shared_key(&p2, &signing_keys2, entity_id, shared.credential_id)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !reveal.is_finished(),
        "reveal must wait for the concurrent ownership stamp"
    );
    stamp.commit().await.expect("commit shared-key ownership");
    assert!(matches!(
        reveal
            .await
            .expect("join reveal")
            .expect_err("config-owned shared key must not be revealed"),
        AppError::NotFound(_)
    ));
}

async fn active_tenant(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("m48-{label}-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn stage_config_stamp(
    pool: &PgPool,
    table: &'static str,
    id: Uuid,
    tenant_id: Option<Uuid>,
) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.expect("begin bootstrap-like tx");
    if let Some(tenant_id) = tenant_id {
        sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await
            .expect("lock owning tenant");
    }
    let result = sqlx::query(&format!(
        "UPDATE {table} SET managed_by = 'config' WHERE id = $1"
    ))
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("stage config ownership stamp");
    assert_eq!(result.rows_affected(), 1, "fixture row must exist");
    tx
}

async fn assert_waits_then_conflicts<T, F>(stamp_tx: Transaction<'static, Postgres>, mutation: F)
where
    T: Debug + Send + 'static,
    F: Future<Output = Result<T, AppError>> + Send + 'static,
{
    let handle = tokio::spawn(mutation);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !handle.is_finished(),
        "mutation must wait behind bootstrap's ownership lock"
    );
    stamp_tx.commit().await.expect("commit config stamp");
    assert_config_conflict(
        handle
            .await
            .expect("join mutation")
            .expect_err("mutation must re-read the committed config marker"),
    );
}

#[tokio::test]
#[ignore]
async fn row_updates_recheck_config_ownership_inside_the_write_transaction() {
    let p = pool().await;

    let tenant_id = active_tenant(&p, "tenant-update").await;
    let stamp = stage_config_stamp(&p, "tenants", tenant_id, None).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        tenant_repo::update_tenant(
            &p2,
            tenant_id,
            UpdateTenant {
                name: Some("must-not-land".into()),
                alias: None,
                tags: None,
                attributes: None,
            },
            None,
        )
        .await
    })
    .await;

    let owner_tenant = active_tenant(&p, "owned-rows").await;

    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(entity_id)
    .bind(format!("m48-entity-{entity_id}"))
    .bind(owner_tenant)
    .execute(&p)
    .await
    .expect("insert entity");
    let stamp = stage_config_stamp(&p, "entities", entity_id, Some(owner_tenant)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        identity_repo::update_entity(
            &p2,
            entity_id,
            UpdateEntity {
                name: Some("must-not-land".into()),
                kind: None,
                alias: None,
                external_id: None,
                tenant_id: None,
                profile_id: None,
                profile_version_id: None,
                status: None,
                attributes: None,
            },
        )
        .await
    })
    .await;

    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'device', $2, $3)")
        .bind(resource_id)
        .bind(format!("m48-resource-{resource_id}"))
        .bind(owner_tenant)
        .execute(&p)
        .await
        .expect("insert resource");
    let stamp = stage_config_stamp(&p, "resources", resource_id, Some(owner_tenant)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::update_resource(
            &p2,
            resource_id,
            UpdateResource {
                name: Some("must-not-land".into()),
                alias: None,
                attributes: None,
            },
        )
        .await
    })
    .await;

    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO principal_groups (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(group_id)
        .bind(format!("m48-group-{group_id}"))
        .bind(owner_tenant)
        .execute(&p)
        .await
        .expect("insert group");
    let stamp = stage_config_stamp(&p, "principal_groups", group_id, Some(owner_tenant)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        identity_repo::update_group(
            &p2,
            group_id,
            UpdateGroup {
                name: Some("must-not-land".into()),
                description: None,
                status: None,
                attributes: None,
            },
        )
        .await
    })
    .await;

    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("m48-role-{role_id}"))
        .bind(owner_tenant)
        .execute(&p)
        .await
        .expect("insert role");
    let stamp = stage_config_stamp(&p, "roles", role_id, Some(owner_tenant)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::update_role(
            &p2,
            role_id,
            UpdateRole {
                name: Some("must-not-land".into()),
                description: None,
            },
        )
        .await
    })
    .await;

    let action_id = Uuid::new_v4();
    sqlx::query("INSERT INTO actions (id, name) VALUES ($1, $2)")
        .bind(action_id)
        .bind(format!("m48.action.{action_id}"))
        .execute(&p)
        .await
        .expect("insert action");
    let stamp = stage_config_stamp(&p, "actions", action_id, None).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::update_capability(
            &p2,
            action_id,
            UpdateCapability {
                name: None,
                description: Some("must-not-land".into()),
                applicability: None,
            },
        )
        .await
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn row_deletes_recheck_config_ownership_inside_the_write_transaction() {
    let p = pool().await;
    let tenant_id = active_tenant(&p, "delete-rows").await;
    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(entity_id)
    .bind(format!("m48-delete-entity-{entity_id}"))
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert entity");

    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, tenant_id, scope_mode, effect) \
         VALUES ($1, $2, 'tenant', 'allow')",
    )
    .bind(block_id)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert permission block");
    let stamp = stage_config_stamp(&p, "permission_blocks", block_id, Some(tenant_id)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::delete_permission_block(&p2, block_id).await
    })
    .await;

    let rule_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO action_assignment_rules
             (id, tenant_id, entity_kind, action_name, object_kind, decision)
           VALUES ($1, $2, 'service', 'read', 'resource', 'deny')"#,
    )
    .bind(rule_id)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert assignment rule");
    let stamp = stage_config_stamp(&p, "action_assignment_rules", rule_id, Some(tenant_id)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::delete_action_assignment_rule(&p2, rule_id).await
    })
    .await;

    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("m48-delete-role-{role_id}"))
        .bind(tenant_id)
        .execute(&p)
        .await
        .expect("insert role");
    let assignment_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO role_assignments
             (id, tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, $2, 'entity', $3, $4)"#,
    )
    .bind(assignment_id)
    .bind(tenant_id)
    .bind(entity_id)
    .bind(role_id)
    .execute(&p)
    .await
    .expect("insert role assignment");
    let stamp = stage_config_stamp(&p, "role_assignments", assignment_id, Some(tenant_id)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::delete_role_assignment(&p2, assignment_id).await
    })
    .await;

    let direct_block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, tenant_id, scope_mode, effect) \
         VALUES ($1, $2, 'tenant', 'allow')",
    )
    .bind(direct_block_id)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert direct-policy block");
    let policy_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO direct_policies
             (id, tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, $2, 'entity', $3, $4)"#,
    )
    .bind(policy_id)
    .bind(tenant_id)
    .bind(entity_id)
    .bind(direct_block_id)
    .execute(&p)
    .await
    .expect("insert direct policy");
    let stamp = stage_config_stamp(&p, "direct_policies", policy_id, Some(tenant_id)).await;
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::delete_direct_policy(&p2, policy_id).await
    })
    .await;

    let action_id = Uuid::new_v4();
    let object_type = format!("resource:m48-{action_id}");
    sqlx::query("INSERT INTO actions (id, name) VALUES ($1, $2)")
        .bind(action_id)
        .bind(format!("m48.applicability.{action_id}"))
        .execute(&p)
        .await
        .expect("insert applicability action");
    sqlx::query(
        "INSERT INTO action_applicability (action_id, object_kind, object_type) \
         VALUES ($1, 'resource', $2)",
    )
    .bind(action_id)
    .bind(&object_type)
    .execute(&p)
    .await
    .expect("insert applicability");

    let mut stamp = p.begin().await.expect("begin applicability stamp");
    sqlx::query("SELECT id FROM actions WHERE id = $1 FOR UPDATE")
        .bind(action_id)
        .fetch_one(&mut *stamp)
        .await
        .expect("lock action");
    sqlx::query(
        r#"UPDATE action_applicability SET managed_by = 'config'
           WHERE action_id = $1 AND object_kind = 'resource' AND object_type = $2"#,
    )
    .bind(action_id)
    .bind(&object_type)
    .execute(&mut *stamp)
    .await
    .expect("stage applicability stamp");
    let p2 = p.clone();
    assert_waits_then_conflicts(stamp, async move {
        authz_repo::remove_capability_applicability(
            &p2,
            action_id,
            "resource".into(),
            Some(object_type),
        )
        .await
    })
    .await;
}
