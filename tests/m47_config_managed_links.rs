//! Config-managed relationship ownership.
//!
//! Link tables do not carry their own `managed_by` column. Their declarative
//! owner does: groups own member sets, a hierarchy child owns its parent edge,
//! roles own permission-block links, and permission blocks own action links.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m47_config_managed_links -- --ignored
//! ```

mod common;

use atom::{
    authz::repo as authz_repo, error::AppError, identity::repo as identity_repo,
    tenants::repo as tenant_repo,
};
use common::pool;
use sqlx::PgPool;
use uuid::Uuid;

fn assert_config_conflict(err: AppError) {
    match err {
        AppError::Conflict(message) => assert!(
            message.contains("bootstrap config"),
            "unexpected conflict: {message}"
        ),
        other => panic!("expected config ownership conflict, got {other:?}"),
    }
}

async fn tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("m47-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn entity(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, 'service', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("m47-entity-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn resource(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'device', $2, $3)")
        .bind(id)
        .bind(format!("m47-resource-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn principal_group(pool: &PgPool, tenant_id: Uuid, managed: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO principal_groups (id, name, tenant_id, managed_by)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(id)
    .bind(format!("m47-principal-{id}"))
    .bind(tenant_id)
    .bind(managed.then_some("config"))
    .execute(pool)
    .await
    .expect("insert principal group");
    id
}

async fn object_group(pool: &PgPool, tenant_id: Uuid, managed: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO object_groups (id, name, tenant_id, managed_by)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(id)
    .bind(format!("m47-object-{id}"))
    .bind(tenant_id)
    .bind(managed.then_some("config"))
    .execute(pool)
    .await
    .expect("insert object group");
    id
}

async fn role(pool: &PgPool, managed: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, managed_by) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("m47-role-{id}"))
        .bind(managed.then_some("config"))
        .execute(pool)
        .await
        .expect("insert role");
    id
}

async fn permission_block(pool: &PgPool, managed: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO permission_blocks (id, scope_mode, effect, managed_by)
           VALUES ($1, 'platform', 'allow', $2)"#,
    )
    .bind(id)
    .bind(managed.then_some("config"))
    .execute(pool)
    .await
    .expect("insert permission block");
    id
}

async fn action(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actions (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("m47.action.{id}"))
        .execute(pool)
        .await
        .expect("insert action");
    id
}

#[tokio::test]
#[ignore]
async fn config_owned_memberships_reject_api_drift_and_clear_is_atomic() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let entity_id = entity(&p, tenant_id).await;
    let resource_id = resource(&p, tenant_id).await;
    let config_principal = principal_group(&p, tenant_id, true).await;
    let api_principal = principal_group(&p, tenant_id, false).await;

    assert_config_conflict(
        identity_repo::add_group_member(&p, config_principal, entity_id)
            .await
            .expect_err("API must not add to a config-owned principal member set"),
    );
    identity_repo::add_group_member(&p, api_principal, entity_id)
        .await
        .expect("API-owned principal group remains mutable");
    identity_repo::remove_group_member(&p, api_principal, entity_id)
        .await
        .expect("API-owned principal membership can be removed");

    sqlx::query("INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2)")
        .bind(config_principal)
        .bind(entity_id)
        .execute(&p)
        .await
        .expect("seed declarative principal membership");
    assert_config_conflict(
        identity_repo::remove_group_member(&p, config_principal, entity_id)
            .await
            .expect_err("API must not remove a declarative principal membership"),
    );
    identity_repo::add_group_member(&p, api_principal, entity_id)
        .await
        .expect("restore API principal membership for bulk-clear test");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status) VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&p)
    .await
    .expect("seed tenant membership");
    assert_config_conflict(
        tenant_repo::remove_tenant_member(&p, tenant_id, entity_id)
            .await
            .expect_err("tenant-member bulk clear must honor config group ownership"),
    );
    let principal_links: Vec<Uuid> = sqlx::query_scalar(
        "SELECT group_id FROM principal_group_members WHERE entity_id = $1 ORDER BY group_id",
    )
    .bind(entity_id)
    .fetch_all(&p)
    .await
    .expect("read principal memberships after rejected bulk clear");
    assert!(principal_links.contains(&config_principal));
    assert!(
        principal_links.contains(&api_principal),
        "bulk clear must not partially delete API-owned memberships"
    );

    // The same tenant-member operation clears direct role assignments. A
    // config-stamped assignment is an independently protected link even after
    // no config-owned group membership remains.
    sqlx::query("DELETE FROM principal_group_members WHERE group_id = $1 AND entity_id = $2")
        .bind(config_principal)
        .bind(entity_id)
        .execute(&p)
        .await
        .expect("remove test-only config group edge directly");
    let managed_role = Uuid::new_v4();
    let managed_assignment = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(managed_role)
        .bind(format!("m47-tenant-role-{managed_role}"))
        .bind(tenant_id)
        .execute(&p)
        .await
        .expect("insert tenant role");
    sqlx::query(
        r#"INSERT INTO role_assignments
             (id, tenant_id, subject_kind, subject_id, role_id, managed_by)
           VALUES ($1, $2, 'entity', $3, $4, 'config')"#,
    )
    .bind(managed_assignment)
    .bind(tenant_id)
    .bind(entity_id)
    .bind(managed_role)
    .execute(&p)
    .await
    .expect("insert config role assignment");
    assert_config_conflict(
        tenant_repo::remove_tenant_member(&p, tenant_id, entity_id)
            .await
            .expect_err("tenant-member bulk clear must honor config role assignment ownership"),
    );
    let assignment_still_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM role_assignments WHERE id = $1)")
            .bind(managed_assignment)
            .fetch_one(&p)
            .await
            .expect("read role assignment after rejected bulk clear");
    assert!(assignment_still_exists);

    let config_object = object_group(&p, tenant_id, true).await;
    let api_object = object_group(&p, tenant_id, false).await;
    assert_config_conflict(
        identity_repo::add_entity_to_object_group(&p, entity_id, config_object)
            .await
            .expect_err("API must not add an entity to a config-owned object member set"),
    );
    identity_repo::add_entity_to_object_group(&p, entity_id, api_object)
        .await
        .expect("API-owned object membership remains mutable");
    sqlx::query(
        r#"INSERT INTO object_group_entities (group_id, entity_id, tenant_id)
           VALUES ($1, $2, $3)"#,
    )
    .bind(config_object)
    .bind(entity_id)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("seed declarative entity membership");

    assert_config_conflict(
        identity_repo::clear_entity_object_groups(&p, entity_id)
            .await
            .expect_err("clear-all must fail when any owner is config-managed"),
    );
    let entity_groups = identity_repo::get_entity_object_groups(&p, entity_id)
        .await
        .expect("list entity groups");
    assert!(entity_groups.contains(&config_object));
    assert!(
        entity_groups.contains(&api_object),
        "the API-owned edge must not be partially deleted before the conflict"
    );
    identity_repo::remove_entity_from_object_group(&p, entity_id, api_object)
        .await
        .expect("one API-owned edge can be removed without touching config ownership");

    assert_config_conflict(
        authz_repo::add_resource_to_object_group(&p, resource_id, config_object)
            .await
            .expect_err("API must not add a resource to a config-owned member set"),
    );
    authz_repo::add_resource_to_object_group(&p, resource_id, api_object)
        .await
        .expect("API-owned resource membership remains mutable");
    sqlx::query(
        r#"INSERT INTO object_group_resources (group_id, resource_id, tenant_id)
           VALUES ($1, $2, $3)"#,
    )
    .bind(config_object)
    .bind(resource_id)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("seed declarative resource membership");
    assert_config_conflict(
        authz_repo::clear_resource_object_groups(&p, resource_id)
            .await
            .expect_err("resource clear-all must fail atomically"),
    );
    let resource_groups = authz_repo::get_resource_object_groups(&p, resource_id)
        .await
        .expect("list resource groups");
    assert!(resource_groups.contains(&config_object));
    assert!(resource_groups.contains(&api_object));
}

#[tokio::test]
#[ignore]
async fn hierarchy_role_and_action_links_honor_their_config_owner() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let config_child = object_group(&p, tenant_id, true).await;
    let api_parent = object_group(&p, tenant_id, false).await;

    assert_config_conflict(
        identity_repo::set_group_parent(&p, config_child, api_parent)
            .await
            .expect_err("a config-owned child parent edge is read-only"),
    );
    sqlx::query(
        r#"INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id)
           VALUES ($1, $2, $3)"#,
    )
    .bind(api_parent)
    .bind(config_child)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("seed declarative hierarchy edge");
    assert_config_conflict(
        identity_repo::remove_group_parent(&p, config_child)
            .await
            .expect_err("a declarative child parent edge cannot be removed"),
    );

    let api_child = object_group(&p, tenant_id, false).await;
    let config_parent = object_group(&p, tenant_id, true).await;
    identity_repo::set_group_parent(&p, api_child, config_parent)
        .await
        .expect("the child owns the edge, so an API child may use a config parent");
    identity_repo::remove_group_parent(&p, api_child)
        .await
        .expect("API-owned child edge remains mutable");

    let config_role = role(&p, true).await;
    let api_role = role(&p, false).await;
    let old_block = permission_block(&p, false).await;
    let new_block = permission_block(&p, false).await;
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(config_role)
    .bind(old_block)
    .execute(&p)
    .await
    .expect("seed declarative role link");
    assert_config_conflict(
        authz_repo::replace_role_permission_block_links(&p, config_role, &[new_block])
            .await
            .expect_err("a config-owned role link set is read-only"),
    );
    let retained: Vec<Uuid> = sqlx::query_scalar(
        "SELECT permission_block_id FROM role_permission_blocks WHERE role_id = $1",
    )
    .bind(config_role)
    .fetch_all(&p)
    .await
    .expect("read config role links");
    assert_eq!(retained, vec![old_block]);
    authz_repo::replace_role_permission_block_links(&p, api_role, &[new_block])
        .await
        .expect("API-owned role links remain mutable");

    let config_block = permission_block(&p, true).await;
    let config_action = action(&p).await;
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(config_block)
    .bind(config_action)
    .execute(&p)
    .await
    .expect("seed declarative block action link");
    assert_config_conflict(
        authz_repo::delete_capability(&p, config_action)
            .await
            .expect_err("action deletion must not cascade a config-owned block link"),
    );
    assert_config_conflict(
        authz_repo::delete_permission_block(&p, config_block)
            .await
            .expect_err("config-owned permission block deletion must be transactional"),
    );

    let api_block = permission_block(&p, false).await;
    let api_action = action(&p).await;
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(api_block)
    .bind(api_action)
    .execute(&p)
    .await
    .expect("seed API block action link");
    authz_repo::delete_capability(&p, api_action)
        .await
        .expect("API-owned action link remains mutable");
}

#[tokio::test]
#[ignore]
async fn api_membership_waits_for_concurrent_bootstrap_stamp_and_then_conflicts() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let group_id = principal_group(&p, tenant_id, false).await;
    let entity_id = entity(&p, tenant_id).await;

    // Model the final bootstrap ownership step while holding the canonical
    // tenant -> group order. The marker is uncommitted when the API starts.
    let mut bootstrap_tx = p.begin().await.expect("begin bootstrap-like tx");
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(tenant_id)
        .fetch_one(&mut *bootstrap_tx)
        .await
        .expect("lock tenant");
    sqlx::query("SELECT id FROM principal_groups WHERE id = $1 FOR UPDATE")
        .bind(group_id)
        .fetch_one(&mut *bootstrap_tx)
        .await
        .expect("lock group");
    sqlx::query("UPDATE principal_groups SET managed_by = 'config' WHERE id = $1")
        .bind(group_id)
        .execute(&mut *bootstrap_tx)
        .await
        .expect("stage config ownership stamp");

    let p2 = p.clone();
    let handle =
        tokio::spawn(
            async move { identity_repo::add_group_member(&p2, group_id, entity_id).await },
        );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(
        !handle.is_finished(),
        "API mutation must wait behind bootstrap's tenant/owner locks"
    );

    bootstrap_tx.commit().await.expect("commit config stamp");
    assert_config_conflict(
        handle
            .await
            .expect("join API mutation")
            .expect_err("API must re-read ownership after waiting"),
    );
    let linked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM principal_group_members WHERE group_id = $1 AND entity_id = $2)",
    )
    .bind(group_id)
    .bind(entity_id)
    .fetch_one(&p)
    .await
    .expect("inspect membership");
    assert!(!linked, "the rejected API mutation must not leave an edge");
}
