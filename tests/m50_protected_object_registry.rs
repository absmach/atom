mod common;

use atom::{
    auth::AuthContext,
    authz::repo as authz_repo,
    models::{
        access::AuthorizedObjectIdsQuery,
        enums::DeletedFilter,
        policy::{ListDirectPolicies, ListRoleAssignments},
        role::ListRoles,
    },
    protected_objects,
};
use uuid::Uuid;

const ADMIN_ENTITY_ID: &str = "00000000-0000-0000-0000-000000000001";
const ADMIN_ROLE_ID: &str = "00000000-0000-0000-0000-000000000002";
const ADMIN_ROLE_ASSIGNMENT_ID: &str = "00000000-0000-0000-0000-00000000000a";

#[test]
fn migration_pins_the_complete_protected_source_boundary() {
    let migration = include_str!("../migrations/026_global_protected_object_registry.sql");
    for (table, kind) in [
        ("tenants", "tenant"),
        ("entities", "entity"),
        ("resources", "resource"),
        ("principal_groups", "group"),
        ("object_groups", "group"),
        ("roles", "role"),
        ("credentials", "credential"),
        ("direct_policies", "policy"),
        ("role_assignments", "policy"),
        ("api_endpoints", "api_endpoint"),
    ] {
        assert!(
            migration.contains(&format!("source_table = '{table}'")),
            "missing registry source {table}"
        );
        assert!(
            migration.contains(&format!("object_kind = '{kind}'")),
            "missing protected kind {kind}"
        );
    }
    assert!(migration.contains("AFTER INSERT"));
    assert!(migration.contains("AFTER DELETE"));
    assert!(migration.contains("BEFORE UPDATE OF id"));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn migration_remaps_the_legacy_admin_assignment_collision() {
    let pool = common::pool().await;
    let assignment_id: Uuid = sqlx::query_scalar(
        r#"SELECT id
           FROM role_assignments
           WHERE tenant_id IS NULL
             AND subject_kind = 'entity'
             AND subject_id = $1
             AND role_id = $2"#,
    )
    .bind(Uuid::parse_str(ADMIN_ENTITY_ID).expect("admin entity UUID"))
    .bind(Uuid::parse_str(ADMIN_ROLE_ID).expect("admin role UUID"))
    .fetch_one(&pool)
    .await
    .expect("seeded admin assignment");
    assert_eq!(
        assignment_id,
        Uuid::parse_str(ADMIN_ROLE_ASSIGNMENT_ID).expect("admin assignment UUID")
    );

    let admin = protected_objects::lookup(
        &pool,
        Uuid::parse_str(ADMIN_ENTITY_ID).expect("admin entity UUID"),
    )
    .await
    .expect("admin lookup")
    .expect("registered admin");
    assert_eq!(admin.object_kind, "entity");

    let assignment = protected_objects::lookup(&pool, assignment_id)
        .await
        .expect("assignment lookup")
        .expect("registered assignment");
    assert_eq!(assignment.object_kind, "policy");
    assert_eq!(assignment.source_table, "role_assignments");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn admin_flat_object_listings_execute_for_every_v1_kind() {
    let pool = common::pool().await;
    let admin_id = Uuid::parse_str(ADMIN_ENTITY_ID).expect("admin entity UUID");
    let admin = AuthContext {
        entity_id: admin_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    };
    let endpoint_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO api_endpoints
             (id, key, name, method, path, operation_kind, graphql)
           VALUES ($1, $2, $3, 'GET', $4, 'query', 'query { health }')"#,
    )
    .bind(endpoint_id)
    .bind(format!("flat-list-{endpoint_id}"))
    .bind("Flat listing endpoint")
    .bind(format!("/api/custom/flat-list-{endpoint_id}"))
    .execute(&pool)
    .await
    .expect("insert endpoint candidate");

    let roles = authz_repo::list_roles_authorized(
        &pool,
        &admin,
        ListRoles {
            tenant_id: None,
            derived_kind: None,
            q: None,
            deleted: DeletedFilter::Live,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("authorized role listing");
    assert!(roles
        .items
        .iter()
        .any(|role| role.id == Uuid::parse_str(ADMIN_ROLE_ID).unwrap()));

    let assignments = authz_repo::list_role_assignments_authorized(
        &pool,
        &admin,
        ListRoleAssignments {
            tenant_id: None,
            subject_kind: None,
            subject_id: None,
            role_id: None,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("authorized role-assignment listing");
    assert!(assignments
        .items
        .iter()
        .any(|assignment| { assignment.id == Uuid::parse_str(ADMIN_ROLE_ASSIGNMENT_ID).unwrap() }));

    authz_repo::list_direct_policies_authorized(
        &pool,
        &admin,
        ListDirectPolicies {
            tenant_id: None,
            subject_kind: None,
            subject_id: None,
            permission_block_id: None,
            object_id: None,
            object_kind: None,
            object_type: None,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("authorized direct-policy listing");

    for (kind, expected_id) in [
        ("role", Uuid::parse_str(ADMIN_ROLE_ID).unwrap()),
        ("policy", Uuid::parse_str(ADMIN_ROLE_ASSIGNMENT_ID).unwrap()),
        ("api_endpoint", endpoint_id),
    ] {
        let page = authz_repo::authorized_object_ids(
            &pool,
            &admin,
            AuthorizedObjectIdsQuery {
                subject_id: admin_id,
                action: "read".into(),
                object_kind: kind.into(),
                object_type: None,
                tenant_id: None,
                id: None,
                q: None,
                attributes_contains: None,
                external_id: None,
                profile_id: None,
                entity_status: None,
                group_type: None,
                parent_group_id: None,
                include_descendants: false,
                limit: 100,
                offset: 0,
                entity_order: Default::default(),
                resource_order: Default::default(),
                group_order: Default::default(),
                dir: Default::default(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("authorized {kind} listing: {error:?}"));
        assert!(page.ids.contains(&expected_id), "missing {kind} candidate");
    }

    sqlx::query("DELETE FROM api_endpoints WHERE id = $1")
        .bind(endpoint_id)
        .execute(&pool)
        .await
        .expect("delete endpoint candidate");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn registry_rejects_cross_kind_uuid_reuse() {
    let pool = common::pool().await;
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("registry-tenant-{id}"))
        .execute(&mut *tx)
        .await
        .expect("insert tenant");
    let error = sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("registry-role-{id}"))
        .execute(&mut *tx)
        .await
        .expect_err("the UUID must already be reserved");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|db| db.code())
            .as_deref(),
        Some("23505")
    );
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn soft_delete_keeps_reservation_and_physical_delete_releases_it() {
    let pool = common::pool().await;
    let id = Uuid::new_v4();

    let mut soft_delete = pool.begin().await.expect("begin soft-delete case");
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'device', $2)")
        .bind(id)
        .bind(format!("registry-resource-{id}"))
        .execute(&mut *soft_delete)
        .await
        .expect("insert resource");
    sqlx::query("UPDATE resources SET deleted_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *soft_delete)
        .await
        .expect("soft delete resource");
    let error = sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("reserved-role-{id}"))
        .execute(&mut *soft_delete)
        .await
        .expect_err("a tombstone must retain its UUID");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|db| db.code())
            .as_deref(),
        Some("23505")
    );
    soft_delete
        .rollback()
        .await
        .expect("rollback soft-delete case");

    let mut purge = pool.begin().await.expect("begin purge case");
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'device', $2)")
        .bind(id)
        .bind(format!("purged-resource-{id}"))
        .execute(&mut *purge)
        .await
        .expect("insert resource");
    sqlx::query("DELETE FROM resources WHERE id = $1")
        .bind(id)
        .execute(&mut *purge)
        .await
        .expect("physically delete resource");
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("released-role-{id}"))
        .execute(&mut *purge)
        .await
        .expect("physical deletion releases the UUID");
    purge.rollback().await.expect("rollback purge case");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn api_endpoint_is_registered_with_its_tenant() {
    let pool = common::pool().await;
    let tenant_id = Uuid::new_v4();
    let endpoint_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(format!("registry-endpoint-tenant-{tenant_id}"))
        .execute(&mut *tx)
        .await
        .expect("insert tenant");
    sqlx::query(
        r#"INSERT INTO api_endpoints
             (id, tenant_id, key, name, method, path, operation_kind, graphql)
           VALUES ($1, $2, $3, $4, 'GET', $5, 'query', 'query { health }')"#,
    )
    .bind(endpoint_id)
    .bind(tenant_id)
    .bind(format!("endpoint-{endpoint_id}"))
    .bind("Registry endpoint")
    .bind(format!("/api/custom/registry-{endpoint_id}"))
    .execute(&mut *tx)
    .await
    .expect("insert endpoint");

    let identity = protected_objects::lookup_on_connection(&mut tx, endpoint_id)
        .await
        .expect("lookup")
        .expect("registered endpoint");
    assert_eq!(identity.object_kind, "api_endpoint");
    assert_eq!(identity.source_table, "api_endpoints");
    assert_eq!(identity.tenant_id, Some(tenant_id));
    assert!(identity.live);
    tx.rollback().await.expect("rollback");
}
