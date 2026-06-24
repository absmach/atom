//! Soft-delete + purge integration tests.
//!
//! Require a reachable Postgres at `DATABASE_URL`; `#[ignore]` by default:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m21_soft_delete -- --ignored
//! ```

mod common;

use atom::{
    config::PurgeConfig,
    models::{
        entity::ListEntities, enums::DeletedFilter, group::ListGroups, resource::ListResources,
        role::ListRoles, tenant::ListTenants,
    },
};
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
async fn soft_delete_entity_hides_it_and_revokes_access() {
    let pool = common::pool().await;
    let id = make_entity(&pool, &format!("sd-entity-{}", Uuid::new_v4()), None).await;
    let cred_id = Uuid::new_v4();
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'api_key', $3, 'active')")
        .bind(cred_id)
        .bind(id)
        .bind(format!("key-{cred_id}"))
        .execute(&pool)
        .await
        .expect("insert credential");
    let session_id = Uuid::new_v4();
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(session_id)
        .bind(id)
        .execute(&pool)
        .await
        .expect("insert session");

    atom::identity::repo::delete_entity(&pool, id, None)
        .await
        .expect("soft delete entity");

    // Hidden from reads.
    assert!(atom::identity::repo::get_entity(&pool, id).await.is_err());

    // Tombstone set; credential revoked; session revoked — all immediately.
    let deleted_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM entities WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("entity row still present");
    assert!(deleted_at.is_some(), "entity should carry a tombstone");

    let cred_status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&pool)
        .await
        .expect("credential");
    assert_eq!(cred_status, "revoked");

    let revoked: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .expect("session");
    assert!(revoked.is_some(), "session should be revoked");
}

#[tokio::test]
#[ignore]
async fn name_is_reusable_after_soft_delete() {
    let pool = common::pool().await;
    let name = format!("sd-reuse-{}", Uuid::new_v4());
    let first = make_entity(&pool, &name, None).await;
    atom::identity::repo::delete_entity(&pool, first, None)
        .await
        .expect("delete first");
    // Re-creating with the same (name, tenant) must succeed now that the unique
    // index is partial on deleted_at IS NULL.
    let second = make_entity(&pool, &name, None).await;
    assert_ne!(first, second);
}

#[tokio::test]
#[ignore]
async fn soft_deleted_role_and_resource_are_hidden() {
    let pool = common::pool().await;

    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("sd-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");
    assert!(atom::authz::repo::get_role(&pool, role_id).await.is_err());

    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(resource_id)
        .bind(format!("sd-res-{resource_id}"))
        .execute(&pool)
        .await
        .expect("insert resource");
    atom::authz::repo::delete_resource(&pool, resource_id, None)
        .await
        .expect("delete resource");
    assert!(atom::authz::repo::get_resource(&pool, resource_id)
        .await
        .is_err());
}

#[tokio::test]
#[ignore]
async fn deleted_filter_lists_soft_deleted_objects() {
    let pool = common::pool().await;

    let tenant_name = format!("sd-filter-tenant-{}", Uuid::new_v4());
    let tenant_id = make_tenant(&pool, &tenant_name).await;
    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("delete tenant");
    let live_tenants = atom::tenants::repo::list_tenants(
        &pool,
        ListTenants {
            q: Some(tenant_name.clone()),
            name: None,
            alias: None,
            status: None,
            deleted: DeletedFilter::Live,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list live tenants");
    assert!(live_tenants
        .items
        .iter()
        .all(|tenant| tenant.id != tenant_id));
    let deleted_tenants = atom::tenants::repo::list_tenants(
        &pool,
        ListTenants {
            q: Some(tenant_name),
            name: None,
            alias: None,
            status: None,
            deleted: DeletedFilter::Deleted,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list deleted tenants");
    assert!(deleted_tenants
        .items
        .iter()
        .any(|tenant| tenant.id == tenant_id));

    let entity_name = format!("sd-filter-entity-{}", Uuid::new_v4());
    let entity_id = make_entity(&pool, &entity_name, None).await;
    atom::identity::repo::delete_entity(&pool, entity_id, None)
        .await
        .expect("delete entity");
    let live_entities = atom::identity::repo::list_entities(
        &pool,
        ListEntities {
            q: Some(entity_name.clone()),
            kind: None,
            profile_id: None,
            tenant_id: None,
            status: None,
            deleted: DeletedFilter::Live,
            parent_group_id: None,
            include_descendants: false,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list live entities");
    assert!(live_entities
        .items
        .iter()
        .all(|entity| entity.id != entity_id));
    let deleted_entities = atom::identity::repo::list_entities(
        &pool,
        ListEntities {
            q: Some(entity_name),
            kind: None,
            profile_id: None,
            tenant_id: None,
            status: None,
            deleted: DeletedFilter::Deleted,
            parent_group_id: None,
            include_descendants: false,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list deleted entities");
    assert!(deleted_entities
        .items
        .iter()
        .any(|entity| entity.id == entity_id));

    let group_name = format!("sd-filter-group-{}", Uuid::new_v4());
    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO object_groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(&group_name)
        .execute(&pool)
        .await
        .expect("insert group");
    atom::identity::repo::delete_group(&pool, group_id, None)
        .await
        .expect("delete group");
    let live_groups = atom::identity::repo::list_groups(
        &pool,
        ListGroups {
            q: Some(group_name.clone()),
            tenant_id: None,
            group_type: Some("object".to_string()),
            parent_id: None,
            status: None,
            deleted: DeletedFilter::Live,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list live groups");
    assert!(live_groups.items.iter().all(|group| group.id != group_id));
    let deleted_groups = atom::identity::repo::list_groups(
        &pool,
        ListGroups {
            q: Some(group_name),
            tenant_id: None,
            group_type: Some("object".to_string()),
            parent_id: None,
            status: None,
            deleted: DeletedFilter::Deleted,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list deleted groups");
    assert!(deleted_groups
        .items
        .iter()
        .any(|group| group.id == group_id));

    let resource_name = format!("sd-filter-resource-{}", Uuid::new_v4());
    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(resource_id)
        .bind(&resource_name)
        .execute(&pool)
        .await
        .expect("insert resource");
    atom::authz::repo::delete_resource(&pool, resource_id, None)
        .await
        .expect("delete resource");
    let live_resources = atom::authz::repo::list_resources(
        &pool,
        ListResources {
            q: Some(resource_name.clone()),
            kind: None,
            tenant_id: None,
            parent_group_id: None,
            include_descendants: false,
            deleted: DeletedFilter::Live,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list live resources");
    assert!(live_resources
        .items
        .iter()
        .all(|resource| resource.id != resource_id));
    let deleted_resources = atom::authz::repo::list_resources(
        &pool,
        ListResources {
            q: Some(resource_name),
            kind: None,
            tenant_id: None,
            parent_group_id: None,
            include_descendants: false,
            deleted: DeletedFilter::Deleted,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list deleted resources");
    assert!(deleted_resources
        .items
        .iter()
        .any(|resource| resource.id == resource_id));

    let role_name = format!("sd-filter-role-{}", Uuid::new_v4());
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(&role_name)
        .execute(&pool)
        .await
        .expect("insert role");
    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");
    let live_roles = atom::authz::repo::list_roles(
        &pool,
        ListRoles {
            tenant_id: None,
            derived_kind: None,
            q: Some(role_name.clone()),
            deleted: DeletedFilter::Live,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list live roles");
    assert!(live_roles.items.iter().all(|role| role.id != role_id));
    let deleted_roles = atom::authz::repo::list_roles(
        &pool,
        ListRoles {
            tenant_id: None,
            derived_kind: None,
            q: Some(role_name),
            deleted: DeletedFilter::Deleted,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list deleted roles");
    assert!(deleted_roles.items.iter().any(|role| role.id == role_id));
}

#[tokio::test]
#[ignore]
async fn purge_physically_removes_expired_tombstones_only() {
    let pool = common::pool().await;
    let old = make_entity(&pool, &format!("sd-old-{}", Uuid::new_v4()), None).await;
    let recent = make_entity(&pool, &format!("sd-recent-{}", Uuid::new_v4()), None).await;

    // Tombstone both, but age only `old` past the retention window.
    sqlx::query("UPDATE entities SET deleted_at = now() - interval '100 days' WHERE id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .expect("age old");
    sqlx::query("UPDATE entities SET deleted_at = now() WHERE id = $1")
        .bind(recent)
        .execute(&pool)
        .await
        .expect("tombstone recent");

    let cfg = PurgeConfig {
        enabled: true,
        retention_days: 90,
        interval_secs: 1,
        batch_size: 1000,
    };
    atom::purge::purge_expired(&pool, cfg).await.expect("purge");

    let old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM entities WHERE id = $1)")
            .bind(old)
            .fetch_one(&pool)
            .await
            .expect("check old");
    let recent_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM entities WHERE id = $1)")
            .bind(recent)
            .fetch_one(&pool)
            .await
            .expect("check recent");
    assert!(!old_exists, "expired tombstone must be purged");
    assert!(recent_exists, "tombstone within retention must survive");
}

#[tokio::test]
#[ignore]
async fn soft_deleted_role_stops_granting_in_the_pdp() {
    use atom::models::policy::AuthzRequest;
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-grant-{}", Uuid::new_v4())).await;
    let subject = make_entity(
        &pool,
        &format!("sd-subj-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let target = make_entity(
        &pool,
        &format!("sd-tgt-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let read_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("read action");

    // Role granting read on entities in the tenant, assigned to the subject.
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("sd-grant-role-{role_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("role");
    let block_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, object_kind, tenant_id, effect)
         VALUES ('object_kind', 'entity', $1, 'allow') RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("block action");
    sqlx::query(
        "INSERT INTO role_permission_blocks (role_id, permission_block_id) VALUES ($1, $2)",
    )
    .bind(role_id)
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("link");
    sqlx::query("INSERT INTO role_assignments (tenant_id, subject_kind, subject_id, role_id) VALUES ($1, 'entity', $2, $3)")
        .bind(tenant_id)
        .bind(subject)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("assign");

    let req = AuthzRequest {
        subject_id: subject,
        action: "read".to_string(),
        resource_id: None,
        object_kind: Some("entity".to_string()),
        object_id: Some(target),
        context: serde_json::Value::Null,
    };

    let before = atom::authz::engine::evaluate(&pool, &req)
        .await
        .expect("evaluate before");
    assert!(before.allowed, "role should grant read before deletion");

    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");

    let after = atom::authz::engine::evaluate(&pool, &req)
        .await
        .expect("evaluate after");
    assert!(
        !after.allowed,
        "a soft-deleted role must not grant in the PDP"
    );
}

#[tokio::test]
#[ignore]
async fn soft_deleted_role_is_not_assignable_or_listed() {
    use atom::models::enums::SubjectKind;
    use atom::models::policy::{CreateRoleAssignment, ListRoleAssignments};
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-asg-{}", Uuid::new_v4())).await;
    let subject = make_entity(
        &pool,
        &format!("sd-asgsubj-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    // Make the subject a tenant member so the subject boundary passes.
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status) VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(subject)
    .execute(&pool)
    .await
    .expect("membership");

    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("sd-asg-role-{role_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("role");

    let req = || CreateRoleAssignment {
        tenant_id: Some(tenant_id),
        subject_kind: SubjectKind::Entity,
        subject_id: subject,
        role_id,
    };

    // Assignable while the role is live.
    atom::authz::repo::create_role_assignment(&pool, req())
        .await
        .expect("assign live role");

    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");

    // Creating a new assignment to the deleted role is rejected (no zombie rows).
    assert!(
        atom::authz::repo::create_role_assignment(&pool, req())
            .await
            .is_err(),
        "a soft-deleted role must not be assignable"
    );

    // Listing excludes assignments whose role is deleted.
    let listed = atom::authz::repo::list_role_assignments(
        &pool,
        ListRoleAssignments {
            tenant_id: Some(tenant_id),
            subject_kind: None,
            subject_id: None,
            role_id: Some(role_id),
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list");
    assert_eq!(
        listed.total, 0,
        "assignments to a deleted role must not list"
    );
    assert!(listed.items.is_empty());
}

#[tokio::test]
#[ignore]
async fn assignment_to_soft_deleted_subject_is_rejected_and_unlisted() {
    use atom::models::enums::SubjectKind;
    use atom::models::policy::{CreateRoleAssignment, ListRoleAssignments};
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-subj-asg-{}", Uuid::new_v4())).await;
    let subject = make_entity(
        &pool,
        &format!("sd-asgvic-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status) VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(subject)
    .execute(&pool)
    .await
    .expect("membership");
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("sd-subj-role-{role_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("role");

    let req = || CreateRoleAssignment {
        tenant_id: Some(tenant_id),
        subject_kind: SubjectKind::Entity,
        subject_id: subject,
        role_id,
    };
    atom::authz::repo::create_role_assignment(&pool, req())
        .await
        .expect("assign live subject");

    atom::identity::repo::delete_entity(&pool, subject, None)
        .await
        .expect("delete subject");

    assert!(
        atom::authz::repo::create_role_assignment(&pool, req())
            .await
            .is_err(),
        "a soft-deleted subject must not be assignable"
    );
    let listed = atom::authz::repo::list_role_assignments(
        &pool,
        ListRoleAssignments {
            tenant_id: Some(tenant_id),
            subject_kind: None,
            subject_id: Some(subject),
            role_id: None,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .expect("list");
    assert_eq!(
        listed.total, 0,
        "assignments to a deleted subject must not list"
    );
}

#[tokio::test]
#[ignore]
async fn soft_delete_tenant_marks_and_revokes_child_sessions() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-tenant-{}", Uuid::new_v4())).await;
    let entity_id = make_entity(
        &pool,
        &format!("sd-child-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;
    let session_id = Uuid::new_v4();
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')")
        .bind(session_id)
        .bind(entity_id)
        .execute(&pool)
        .await
        .expect("insert session");

    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete tenant");

    let (status, deleted_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deleted_at FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("tenant row");
    assert_eq!(status, "deleted");
    assert!(deleted_at.is_some());

    let revoked: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .expect("session");
    assert!(revoked.is_some(), "child session should be revoked");

    // Tenant is hidden from reads.
    assert!(atom::tenants::repo::get_tenant(&pool, tenant_id)
        .await
        .is_err());
}

#[tokio::test]
#[ignore]
async fn listing_excludes_objects_under_soft_deleted_tenant() {
    use atom::models::access::AuthorizedObjectIdsQuery;
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-ten-list-{}", Uuid::new_v4())).await;
    let subject = make_entity(&pool, &format!("sd-ten-subj-{}", Uuid::new_v4()), None).await;
    let target = make_entity(
        &pool,
        &format!("sd-ten-tgt-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;

    // Platform read grant: subject can read entities across all tenants.
    let block_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, effect) VALUES ('platform', 'allow') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("block");
    let read_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("read action");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("block action");
    sqlx::query("INSERT INTO direct_policies (subject_kind, subject_id, permission_block_id) VALUES ('entity', $1, $2)")
        .bind(subject)
        .bind(block_id)
        .execute(&pool)
        .await
        .expect("policy");

    let lists_target = || async {
        atom::authz::repo::authorized_object_ids(
            &pool,
            AuthorizedObjectIdsQuery {
                subject_id: subject,
                action: "read".to_string(),
                object_kind: "entity".to_string(),
                object_type: None,
                tenant_id: None,
                q: None,
                profile_id: None,
                entity_status: None,
                group_type: None,
                parent_group_id: None,
                include_descendants: false,
                limit: 500,
                offset: 0,
            },
        )
        .await
        .expect("listing")
        .ids
        .contains(&target)
    };

    assert!(
        lists_target().await,
        "target should list while tenant is active"
    );

    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete tenant");

    assert!(
        !lists_target().await,
        "objects under a soft-deleted tenant must not be listed (PDP denies them)"
    );
}

#[tokio::test]
#[ignore]
async fn tombstoned_tenant_cannot_be_reactivated_or_authorized() {
    use atom::models::{
        access::AuthorizedObjectIdsQuery, enums::TenantStatus, policy::AuthzRequest,
        tenant::UpdateTenant,
    };

    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-ten-react-{}", Uuid::new_v4())).await;
    let subject = make_entity(
        &pool,
        &format!("sd-ten-react-subj-{}", Uuid::new_v4()),
        None,
    )
    .await;
    let target = make_entity(
        &pool,
        &format!("sd-ten-react-tgt-{}", Uuid::new_v4()),
        Some(tenant_id),
    )
    .await;

    let block_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, effect) VALUES ('platform', 'allow') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("block");
    let read_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("read action");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(read_id)
    .execute(&pool)
    .await
    .expect("block action");
    sqlx::query("INSERT INTO direct_policies (subject_kind, subject_id, permission_block_id) VALUES ('entity', $1, $2)")
        .bind(subject)
        .bind(block_id)
        .execute(&pool)
        .await
        .expect("policy");

    let lists_target = || async {
        atom::authz::repo::authorized_object_ids(
            &pool,
            AuthorizedObjectIdsQuery {
                subject_id: subject,
                action: "read".to_string(),
                object_kind: "entity".to_string(),
                object_type: None,
                tenant_id: None,
                q: None,
                profile_id: None,
                entity_status: None,
                group_type: None,
                parent_group_id: None,
                include_descendants: false,
                limit: 500,
                offset: 0,
            },
        )
        .await
        .expect("listing")
        .ids
        .contains(&target)
    };

    assert!(
        lists_target().await,
        "target should list while tenant is active"
    );

    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete tenant");

    assert!(
        atom::tenants::repo::change_tenant_status(&pool, tenant_id, TenantStatus::Active, None)
            .await
            .is_err(),
        "a tombstoned tenant must not be re-enabled"
    );
    assert!(
        atom::tenants::repo::update_tenant(
            &pool,
            tenant_id,
            UpdateTenant {
                name: Some(format!("reactivated-{}", Uuid::new_v4())),
                alias: None,
                tags: None,
                attributes: None,
            },
            None,
        )
        .await
        .is_err(),
        "a tombstoned tenant must not be editable"
    );

    // Simulate the historical bug shape: status active, tombstone still present.
    sqlx::query("UPDATE tenants SET status = 'active' WHERE id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("force inconsistent status");

    assert!(
        !lists_target().await,
        "deleted_at must keep listings closed even if status is active"
    );

    let decision = atom::authz::engine::evaluate(
        &pool,
        &AuthzRequest {
            subject_id: subject,
            action: "read".to_string(),
            resource_id: None,
            object_kind: Some("entity".to_string()),
            object_id: Some(target),
            context: serde_json::Value::Null,
        },
    )
    .await
    .expect("evaluate");
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "tenant is deleted");
}

#[tokio::test]
#[ignore]
async fn purge_tenant_removes_owned_objects_instead_of_orphaning_them() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-purge-ten-{}", Uuid::new_v4())).await;
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("sd-purge-role-{role_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("role");
    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', $2, $3)")
        .bind(resource_id)
        .bind(format!("sd-purge-res-{resource_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("resource");
    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO object_groups (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(group_id)
        .bind(format!("sd-purge-grp-{group_id}"))
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("group");

    atom::tenants::repo::soft_delete_tenant(&pool, tenant_id, None)
        .await
        .expect("soft delete");
    atom::tenants::repo::purge_tenant(&pool, tenant_id)
        .await
        .expect("purge tenant");

    // Tenant-owned rows must be gone, not relinked to NULL (global).
    for (table, id) in [
        ("roles", role_id),
        ("resources", resource_id),
        ("object_groups", group_id),
    ] {
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE id = $1)"
        ))
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("check");
        assert!(
            !exists,
            "{table} row must be purged with the tenant, not orphaned"
        );
    }
}
