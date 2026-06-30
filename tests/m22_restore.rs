//! Restore (soft-delete reversal) integration tests.
//!
//! Require a reachable Postgres at `DATABASE_URL`; `#[ignore]` by default:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m22_restore -- --ignored
//! ```

mod common;

use atom::{config::PurgeConfig, error::AppError};
use uuid::Uuid;

async fn make_entity(pool: &sqlx::PgPool, name: &str, tenant_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'service', $2, $3, 'active')")
        .bind(id)
        .bind(name)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn make_tenant(pool: &sqlx::PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

#[tokio::test]
#[ignore]
async fn restore_entity_reverses_soft_delete_but_keeps_credentials_revoked() {
    let pool = common::pool().await;
    let id = make_entity(&pool, &format!("rs-entity-{}", Uuid::new_v4()), None).await;
    let cred_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'access_token', $3, 'active')")
        .bind(cred_id)
        .bind(id)
        .bind(format!("rs-key-{cred_id}"))
        .execute(&pool)
        .await
        .expect("insert credential");

    atom::identity::repo::delete_entity(&pool, id, None)
        .await
        .expect("soft delete entity");
    assert!(atom::identity::repo::get_entity(&pool, id).await.is_err());

    atom::identity::repo::restore_entity(&pool, id, None)
        .await
        .expect("restore entity");

    // Visible and active again, tombstone cleared.
    let entity = atom::identity::repo::get_entity(&pool, id)
        .await
        .expect("entity readable after restore");
    assert_eq!(entity.id, id);
    let (status, deleted_at, deleted_by): (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<Uuid>,
    ) = sqlx::query_as("SELECT status, deleted_at, deleted_by FROM entities WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("entity row");
    assert_eq!(status, "active", "restore must reactivate the entity");
    assert!(deleted_at.is_none(), "tombstone must be cleared");
    assert!(deleted_by.is_none(), "deleted_by must be cleared");

    // Credentials revoked on delete are NOT reinstated — re-auth is required.
    let cred_status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&pool)
        .await
        .expect("credential");
    assert_eq!(
        cred_status, "revoked",
        "restore must not silently reinstate revoked credentials"
    );
}

#[tokio::test]
#[ignore]
async fn restore_entity_is_blocked_when_name_was_re_taken() {
    let pool = common::pool().await;
    let name = format!("rs-collide-{}", Uuid::new_v4());
    let first = make_entity(&pool, &name, None).await;
    atom::identity::repo::delete_entity(&pool, first, None)
        .await
        .expect("delete first");
    // A live entity re-takes the freed name during the retention window.
    let _second = make_entity(&pool, &name, None).await;

    let err = atom::identity::repo::restore_entity(&pool, first, None)
        .await
        .expect_err("restore must fail on name collision");
    assert!(
        matches!(err, AppError::Conflict(_)),
        "expected conflict, got {err:?}"
    );
    // First entity stays tombstoned (atomic rollback).
    assert!(atom::identity::repo::get_entity(&pool, first)
        .await
        .is_err());
}

#[tokio::test]
#[ignore]
async fn restore_entity_is_blocked_while_tenant_is_soft_deleted() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("rs-ten-{}", Uuid::new_v4())).await;
    let id = make_entity(
        &pool,
        &format!("rs-child-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;

    atom::identity::repo::delete_entity(&pool, id, None)
        .await
        .expect("delete entity");
    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("delete tenant");

    let err = atom::identity::repo::restore_entity(&pool, id, None)
        .await
        .expect_err("restore must fail under a soft-deleted tenant");
    assert!(
        matches!(err, AppError::Conflict(_)),
        "expected conflict, got {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn restore_missing_entity_is_not_found() {
    let pool = common::pool().await;
    let err = atom::identity::repo::restore_entity(&pool, Uuid::new_v4(), None)
        .await
        .expect_err("restoring an unknown id must fail");
    assert!(
        matches!(err, AppError::NotFound(_)),
        "expected not found, got {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn restore_already_live_entity_is_not_found() {
    let pool = common::pool().await;
    let id = make_entity(&pool, &format!("rs-live-{}", Uuid::new_v4()), None).await;
    // Never deleted — there is no tombstone to reverse.
    let err = atom::identity::repo::restore_entity(&pool, id, None)
        .await
        .expect_err("restoring a live entity must fail");
    assert!(
        matches!(err, AppError::NotFound(_)),
        "expected not found, got {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn restore_role_makes_it_readable_again() {
    let pool = common::pool().await;
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("rs-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");

    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");
    assert!(atom::authz::repo::get_role(&pool, role_id).await.is_err());

    atom::authz::repo::restore_role(&pool, role_id, None)
        .await
        .expect("restore role");
    assert!(
        atom::authz::repo::get_role(&pool, role_id).await.is_ok(),
        "role must be readable after restore"
    );
}

#[tokio::test]
#[ignore]
async fn restore_resource_makes_it_readable_again() {
    let pool = common::pool().await;
    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(resource_id)
        .bind(format!("rs-res-{resource_id}"))
        .execute(&pool)
        .await
        .expect("insert resource");

    atom::authz::repo::delete_resource(&pool, resource_id, None)
        .await
        .expect("delete resource");
    assert!(atom::authz::repo::get_resource(&pool, resource_id)
        .await
        .is_err());

    atom::authz::repo::restore_resource(&pool, resource_id, None)
        .await
        .expect("restore resource");
    assert!(
        atom::authz::repo::get_resource(&pool, resource_id)
            .await
            .is_ok(),
        "resource must be readable after restore"
    );
}

#[tokio::test]
#[ignore]
async fn restore_group_makes_it_readable_again() {
    let pool = common::pool().await;
    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO principal_groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(format!("rs-grp-{group_id}"))
        .execute(&pool)
        .await
        .expect("insert group");

    atom::identity::repo::delete_group(&pool, group_id, None)
        .await
        .expect("delete group");
    assert!(atom::identity::repo::get_group(&pool, group_id)
        .await
        .is_err());

    atom::identity::repo::restore_group(&pool, group_id, None)
        .await
        .expect("restore group");
    assert!(
        atom::identity::repo::get_group(&pool, group_id)
            .await
            .is_ok(),
        "group must be readable after restore"
    );
}

#[tokio::test]
#[ignore]
async fn restore_tenant_reactivates_and_unhides_children() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("rs-rt-{}", Uuid::new_v4())).await;
    let child = make_entity(
        &pool,
        &format!("rs-rt-child-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let api_key_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'access_token', $3, 'active')")
        .bind(api_key_id)
        .bind(child)
        .bind(format!("rs-rt-key-{api_key_id}"))
        .execute(&pool)
        .await
        .expect("insert api credential");
    let cert_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'certificate', $3, 'active')")
        .bind(cert_id)
        .bind(child)
        .bind(format!("{:032x}", cert_id.as_u128()))
        .execute(&pool)
        .await
        .expect("insert certificate credential");

    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("delete tenant");
    // Child was never individually tombstoned, only hidden via the tenant.
    assert!(atom::tenants::repo::get_tenant(&pool, tenant_id)
        .await
        .is_err());

    let restored = atom::tenants::repo::restore_tenant(&pool, tenant_id, None)
        .await
        .expect("restore tenant");
    assert_eq!(restored.id, tenant_id);

    let (status, deleted_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deleted_at FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("tenant row");
    assert_eq!(status, "active", "restore must reactivate the tenant");
    assert!(deleted_at.is_none(), "tombstone must be cleared");

    // Child is visible again now that the tenant is live.
    assert!(
        atom::identity::repo::get_entity(&pool, child).await.is_ok(),
        "child entity must reappear once its tenant is restored"
    );

    // The non-certificate credential is reactivated (existing API key works
    // again) and its revocation marker is cleared, so the tenant is operational.
    let (api_status, api_metadata): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, metadata FROM credentials WHERE id = $1")
            .bind(api_key_id)
            .fetch_one(&pool)
            .await
            .expect("api credential");
    assert_eq!(
        api_status, "active",
        "restore must reactivate child API keys"
    );
    assert!(
        api_metadata.get("revocation_reason").is_none(),
        "restore must clear the tenant_deleted marker"
    );

    // The certificate stays revoked — its revocation is published via the CRL
    // and must not be silently undone; re-issue is required.
    let cert_status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(cert_id)
        .fetch_one(&pool)
        .await
        .expect("certificate credential");
    assert_eq!(
        cert_status, "revoked",
        "restore must not reinstate revoked certificates"
    );
}

#[tokio::test]
#[ignore]
async fn purge_entity_physically_removes_a_tombstoned_row_and_cascades() {
    let pool = common::pool().await;
    let id = make_entity(&pool, &format!("pg-entity-{}", Uuid::new_v4()), None).await;
    let cred_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'access_token', $3, 'active')")
        .bind(cred_id)
        .bind(id)
        .bind(format!("pg-key-{cred_id}"))
        .execute(&pool)
        .await
        .expect("insert credential");

    atom::identity::repo::delete_entity(&pool, id, None)
        .await
        .expect("soft delete entity");
    atom::identity::repo::purge_entity(&pool, id)
        .await
        .expect("purge entity");

    // Row and its cascaded credential are physically gone.
    let entity_exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM entities WHERE id = $1")
        .bind(id)
        .fetch_optional(&pool)
        .await
        .expect("entity lookup");
    assert!(entity_exists.is_none(), "purged entity row must be removed");
    let cred_exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_optional(&pool)
        .await
        .expect("credential lookup");
    assert!(cred_exists.is_none(), "FK cascade must drop credentials");
}

#[tokio::test]
#[ignore]
async fn purge_requires_a_prior_soft_delete() {
    let pool = common::pool().await;
    let id = make_entity(&pool, &format!("pg-live-{}", Uuid::new_v4()), None).await;
    // Live row — no tombstone, so purge must refuse rather than hard-delete.
    let err = atom::identity::repo::purge_entity(&pool, id)
        .await
        .expect_err("purging a live entity must fail");
    assert!(
        matches!(err, AppError::NotFound(_)),
        "expected not found, got {err:?}"
    );
    assert!(
        atom::identity::repo::get_entity(&pool, id).await.is_ok(),
        "the live entity must survive a refused purge"
    );
}

#[tokio::test]
#[ignore]
async fn purge_role_removes_it_and_gcs_orphaned_blocks() {
    let pool = common::pool().await;
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("pg-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, effect) VALUES ($1, 'platform', 'allow')",
    )
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("insert permission block");
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("link block to role");

    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("soft delete role");
    atom::authz::repo::purge_role(&pool, role_id)
        .await
        .expect("purge role");

    let role_exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(&pool)
        .await
        .expect("role lookup");
    assert!(role_exists.is_none(), "purged role row must be removed");
    let block_exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM permission_blocks WHERE id = $1")
            .bind(block_id)
            .fetch_optional(&pool)
            .await
            .expect("block lookup");
    assert!(
        block_exists.is_none(),
        "orphaned permission block must be GC'd on role purge"
    );
}

/// Inserts an object-scoped permission block granting access *on* `object_id`.
async fn make_object_block(pool: &sqlx::PgPool, object_id: Uuid) -> Uuid {
    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, object_id, effect)
         VALUES ($1, 'object', $2, 'allow')",
    )
    .bind(block_id)
    .bind(object_id)
    .execute(pool)
    .await
    .expect("insert object-scoped block");
    block_id
}

async fn row_exists(pool: &sqlx::PgPool, sql: &str, id: Uuid) -> bool {
    sqlx::query_scalar::<_, Uuid>(sql)
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("existence lookup")
        .is_some()
}

#[tokio::test]
#[ignore]
async fn purge_entity_clears_object_blocks_and_subject_grants() {
    let pool = common::pool().await;
    let entity = make_entity(&pool, &format!("pg-authz-{}", Uuid::new_v4()), None).await;
    let other = make_entity(&pool, &format!("pg-other-{}", Uuid::new_v4()), None).await;

    // Object-scoped block granting access ON the entity, referenced two ways:
    // via a direct policy and via a role link. Both must disappear with it.
    let object_block = make_object_block(&pool, entity).await;
    let dp_on = Uuid::new_v4();
    sqlx::query("INSERT INTO direct_policies (id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(dp_on)
        .bind(other)
        .bind(object_block)
        .execute(&pool)
        .await
        .expect("direct policy referencing object block");
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("pg-authz-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(role_id)
    .bind(object_block)
    .execute(&pool)
    .await
    .expect("role link to object block");

    // Grants TO the entity as a subject (bare-UUID references, no FK).
    let subject_block = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, effect) VALUES ($1, 'platform', 'allow')",
    )
    .bind(subject_block)
    .execute(&pool)
    .await
    .expect("insert platform block");
    let dp_to = Uuid::new_v4();
    sqlx::query("INSERT INTO direct_policies (id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(dp_to)
        .bind(entity)
        .bind(subject_block)
        .execute(&pool)
        .await
        .expect("direct policy granting to entity");
    let ra_to = Uuid::new_v4();
    sqlx::query("INSERT INTO role_assignments (id, subject_kind, subject_id, role_id) VALUES ($1, 'entity', $2, $3)")
        .bind(ra_to)
        .bind(entity)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("role assignment to entity");

    atom::identity::repo::delete_entity(&pool, entity, None)
        .await
        .expect("soft delete entity");
    atom::identity::repo::purge_entity(&pool, entity)
        .await
        .expect("purge entity");

    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            object_block
        )
        .await,
        "object-scoped block must be removed when its object is purged"
    );
    assert!(
        !row_exists(&pool, "SELECT id FROM direct_policies WHERE id = $1", dp_on).await,
        "direct policy referencing the object block must cascade away"
    );
    let role_link_present: Option<Uuid> = sqlx::query_scalar(
        "SELECT role_id FROM role_permission_blocks WHERE permission_block_id = $1",
    )
    .bind(object_block)
    .fetch_optional(&pool)
    .await
    .expect("role link lookup");
    assert!(
        role_link_present.is_none(),
        "role link to the object block must cascade away"
    );
    assert!(
        !row_exists(&pool, "SELECT id FROM direct_policies WHERE id = $1", dp_to).await,
        "direct policy granting to the purged subject must be removed"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM role_assignments WHERE id = $1",
            ra_to
        )
        .await,
        "role assignment to the purged subject must be removed"
    );

    // Unrelated rows survive: the role itself and the platform block it pointed
    // to were not tied to the purged entity.
    assert!(
        row_exists(&pool, "SELECT id FROM roles WHERE id = $1", role_id).await,
        "the role must survive — only its assignment to the entity is removed"
    );
}

#[tokio::test]
#[ignore]
async fn purge_resource_clears_object_scoped_blocks() {
    let pool = common::pool().await;
    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(resource_id)
        .bind(format!("pg-res-authz-{resource_id}"))
        .execute(&pool)
        .await
        .expect("insert resource");
    let block = make_object_block(&pool, resource_id).await;

    atom::authz::repo::delete_resource(&pool, resource_id, None)
        .await
        .expect("soft delete resource");
    atom::authz::repo::purge_resource(&pool, resource_id)
        .await
        .expect("purge resource");

    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            block
        )
        .await,
        "object-scoped block must be removed when its resource is purged"
    );
}

#[tokio::test]
#[ignore]
async fn purge_role_clears_object_scoped_blocks() {
    let pool = common::pool().await;
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("pg-role-obj-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    // A block scoped to the role *as an object* (object_id = role), distinct from
    // blocks the role grants. It has no FK, so purge must remove it explicitly.
    let block = make_object_block(&pool, role_id).await;

    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("soft delete role");
    atom::authz::repo::purge_role(&pool, role_id)
        .await
        .expect("purge role");

    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            block
        )
        .await,
        "object-scoped block on the role must be removed when the role is purged"
    );
}

#[tokio::test]
#[ignore]
async fn purge_tenant_clears_child_authz_references() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("pg-ten-authz-{}", Uuid::new_v4())).await;
    let child = make_entity(
        &pool,
        &format!("pg-ten-child-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    // Grant ON the child (object-scoped block) and TO the child (direct policy).
    let object_block = make_object_block(&pool, child).await;
    let dp_to = Uuid::new_v4();
    sqlx::query("INSERT INTO direct_policies (id, tenant_id, subject_kind, subject_id, permission_block_id) VALUES ($1, $2, 'entity', $3, $4)")
        .bind(dp_to)
        .bind(tenant_id)
        .bind(child)
        .bind(object_block)
        .execute(&pool)
        .await
        .expect("direct policy to child");

    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete tenant");
    atom::tenants::repo::purge_tenant(&pool, tenant_id)
        .await
        .expect("purge tenant");

    assert!(
        !row_exists(&pool, "SELECT id FROM entities WHERE id = $1", child).await,
        "child entity must be physically removed with the tenant"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            object_block
        )
        .await,
        "object-scoped block on a tenant child must not survive tenant purge"
    );
    assert!(
        !row_exists(&pool, "SELECT id FROM direct_policies WHERE id = $1", dp_to).await,
        "direct policy referencing a purged child must not survive tenant purge"
    );
}

#[tokio::test]
#[ignore]
async fn background_purge_clears_authz_references() {
    let pool = common::pool().await;
    let entity = make_entity(&pool, &format!("bg-purge-{}", Uuid::new_v4()), None).await;
    let object_block = make_object_block(&pool, entity).await;
    let ra_to = Uuid::new_v4();
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("bg-purge-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    sqlx::query("INSERT INTO role_assignments (id, subject_kind, subject_id, role_id) VALUES ($1, 'entity', $2, $3)")
        .bind(ra_to)
        .bind(entity)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("role assignment to entity");

    // Soft delete, then age the tombstone past the retention window.
    atom::identity::repo::delete_entity(&pool, entity, None)
        .await
        .expect("soft delete entity");
    sqlx::query("UPDATE entities SET deleted_at = now() - interval '100 days' WHERE id = $1")
        .bind(entity)
        .execute(&pool)
        .await
        .expect("age tombstone");

    let cfg = PurgeConfig {
        enabled: true,
        retention_days: 90,
        interval_secs: 1,
        batch_size: 1000,
    };
    atom::purge::purge_expired(&pool, cfg)
        .await
        .expect("background purge");

    assert!(
        !row_exists(&pool, "SELECT id FROM entities WHERE id = $1", entity).await,
        "expired tombstone must be physically purged"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            object_block
        )
        .await,
        "background purge must clear object-scoped blocks on purged entities"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM role_assignments WHERE id = $1",
            ra_to
        )
        .await,
        "background purge must clear role assignments to purged subjects"
    );
}

#[tokio::test]
#[ignore]
async fn purge_entity_clears_blocks_targeting_its_policy_objects() {
    let pool = common::pool().await;
    let entity = make_entity(&pool, &format!("pg-pol-{}", Uuid::new_v4()), None).await;
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("pg-pol-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    // A role assignment whose subject is the entity. The assignment row is itself
    // a 'policy' protected object, so a block can target it by object_id.
    let assignment_id = Uuid::new_v4();
    sqlx::query("INSERT INTO role_assignments (id, subject_kind, subject_id, role_id) VALUES ($1, 'entity', $2, $3)")
        .bind(assignment_id)
        .bind(entity)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("role assignment");
    let block_on_policy = make_object_block(&pool, assignment_id).await;

    atom::identity::repo::delete_entity(&pool, entity, None)
        .await
        .expect("soft delete entity");
    atom::identity::repo::purge_entity(&pool, entity)
        .await
        .expect("purge entity");

    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM role_assignments WHERE id = $1",
            assignment_id
        )
        .await,
        "the subject's role assignment must be removed"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            block_on_policy
        )
        .await,
        "a block targeting the removed assignment (a policy object) must not survive"
    );
}

#[tokio::test]
#[ignore]
async fn delete_direct_policy_clears_blocks_targeting_it() {
    let pool = common::pool().await;
    let subject = make_entity(&pool, &format!("dp-subj-{}", Uuid::new_v4()), None).await;
    let granted_block = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, effect) VALUES ($1, 'platform', 'allow')",
    )
    .bind(granted_block)
    .execute(&pool)
    .await
    .expect("insert granted block");
    let policy_id = Uuid::new_v4();
    sqlx::query("INSERT INTO direct_policies (id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(policy_id)
        .bind(subject)
        .bind(granted_block)
        .execute(&pool)
        .await
        .expect("insert direct policy");
    // A block that grants access *on* the direct policy (object_id = policy).
    let block_on_policy = make_object_block(&pool, policy_id).await;

    atom::authz::repo::delete_direct_policy(&pool, policy_id)
        .await
        .expect("delete direct policy");

    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            block_on_policy
        )
        .await,
        "deleting a direct policy must remove blocks targeting it as an object"
    );
}

#[tokio::test]
#[ignore]
async fn cascaded_policy_deletion_clears_blocks_targeting_it() {
    // A direct policy removed *indirectly* (its block cascade-deletes it) is still
    // a policy object; the migration-002 trigger must sweep blocks targeting it.
    let pool = common::pool().await;
    let entity = make_entity(&pool, &format!("casc-{}", Uuid::new_v4()), None).await;
    let other = make_entity(&pool, &format!("casc-other-{}", Uuid::new_v4()), None).await;

    // Block granting ON the entity; a direct policy is built on top of it so that
    // purging the entity (which deletes the block) cascade-deletes the policy.
    let block_on_entity = make_object_block(&pool, entity).await;
    let policy_id = Uuid::new_v4();
    sqlx::query("INSERT INTO direct_policies (id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(policy_id)
        .bind(other)
        .bind(block_on_entity)
        .execute(&pool)
        .await
        .expect("direct policy on the entity-scoped block");
    // A block targeting that policy as an object.
    let block_on_policy = make_object_block(&pool, policy_id).await;

    atom::identity::repo::delete_entity(&pool, entity, None)
        .await
        .expect("soft delete entity");
    atom::identity::repo::purge_entity(&pool, entity)
        .await
        .expect("purge entity");

    // purge deletes block_on_entity → cascades the policy → trigger sweeps block_on_policy.
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM direct_policies WHERE id = $1",
            policy_id
        )
        .await,
        "policy built on the purged object's block must cascade away"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            block_on_policy
        )
        .await,
        "block targeting a cascade-deleted policy must not survive"
    );
}

#[tokio::test]
#[ignore]
async fn remove_tenant_member_clears_blocks_targeting_its_assignment() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("rtm-{}", Uuid::new_v4())).await;
    let member = make_entity(
        &pool,
        &format!("rtm-member-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("rtm-role-{role_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("insert role");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status) VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(member)
    .execute(&pool)
    .await
    .expect("insert membership");
    let assignment_id = Uuid::new_v4();
    sqlx::query("INSERT INTO role_assignments (id, tenant_id, subject_kind, subject_id, role_id) VALUES ($1, $2, 'entity', $3, $4)")
        .bind(assignment_id)
        .bind(tenant_id)
        .bind(member)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("role assignment for member");
    let block_on_assignment = make_object_block(&pool, assignment_id).await;

    atom::tenants::repo::remove_tenant_member(&pool, tenant_id, member)
        .await
        .expect("remove tenant member");

    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM role_assignments WHERE id = $1",
            assignment_id
        )
        .await,
        "the member's role assignment must be removed"
    );
    assert!(
        !row_exists(
            &pool,
            "SELECT id FROM permission_blocks WHERE id = $1",
            block_on_assignment
        )
        .await,
        "block targeting the bulk-removed assignment must not survive"
    );
}

#[tokio::test]
#[ignore]
async fn tenant_restore_does_not_undo_an_explicit_credential_revocation() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("tr-expl-{}", Uuid::new_v4())).await;
    let child = make_entity(
        &pool,
        &format!("tr-expl-child-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let cred_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'access_token', $3, 'active')")
        .bind(cred_id)
        .bind(child)
        .bind(format!("tr-expl-key-{cred_id}"))
        .execute(&pool)
        .await
        .expect("insert credential");

    // Tenant delete marks the credential tenant_deleted; an admin then explicitly
    // revokes it, which must overwrite that provenance.
    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete tenant");
    atom::identity::service::revoke_credential(&pool, child, cred_id)
        .await
        .expect("explicit revoke");

    atom::tenants::repo::restore_tenant(&pool, tenant_id, None)
        .await
        .expect("restore tenant");

    let (status, reason): (String, Option<String>) = sqlx::query_as(
        "SELECT status, metadata->>'revocation_reason' FROM credentials WHERE id = $1",
    )
    .bind(cred_id)
    .fetch_one(&pool)
    .await
    .expect("credential row");
    assert_eq!(
        status, "revoked",
        "an explicitly revoked credential must stay revoked after tenant restore"
    );
    assert_eq!(reason.as_deref(), Some("manual"));
}

#[tokio::test]
#[ignore]
async fn tenant_restore_does_not_reactivate_credentials_of_a_deleted_child() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("tr-del-{}", Uuid::new_v4())).await;
    let child = make_entity(
        &pool,
        &format!("tr-del-child-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let cred_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'access_token', $3, 'active')")
        .bind(cred_id)
        .bind(child)
        .bind(format!("tr-del-key-{cred_id}"))
        .execute(&pool)
        .await
        .expect("insert credential");

    // Tenant delete revokes the credential, then the child is individually
    // deleted. Restoring the tenant must NOT reactivate a deleted child's
    // credentials — restoreEntity (with reissue) is required for that.
    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete tenant");
    atom::identity::repo::delete_entity(&pool, child, None)
        .await
        .expect("delete child entity");

    atom::tenants::repo::restore_tenant(&pool, tenant_id, None)
        .await
        .expect("restore tenant");

    let status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&pool)
        .await
        .expect("credential row");
    assert_eq!(
        status, "revoked",
        "a deleted child's credential must not be reactivated by tenant restore"
    );
    let child_deleted: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM entities WHERE id = $1")
            .bind(child)
            .fetch_one(&pool)
            .await
            .expect("child row");
    assert!(
        child_deleted.is_some(),
        "the individually deleted child stays tombstoned"
    );
}
