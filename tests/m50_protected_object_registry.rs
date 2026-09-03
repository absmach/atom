//! Launch-baseline coverage for the global protected-object registry.

mod common;

use atom::protected_objects;
use uuid::Uuid;

const ADMIN_ENTITY_ID: &str = "00000000-0000-0000-0000-000000000001";
const ADMIN_ROLE_ID: &str = "00000000-0000-0000-0000-000000000002";
const ADMIN_ROLE_ASSIGNMENT_ID: &str = "00000000-0000-0000-0000-00000000000a";

#[test]
fn launch_baseline_defines_every_protected_object_source() {
    let migration = include_str!("../migrations/001_initial.sql");
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
        assert!(migration.contains(&format!("source_table = '{table}'")));
        assert!(migration.contains(&format!("object_kind = '{kind}'")));
    }
    assert!(migration.contains("AFTER INSERT"));
    assert!(migration.contains("AFTER DELETE"));
    assert!(migration.contains("BEFORE UPDATE OF id"));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn seeded_admin_and_assignment_have_distinct_registered_ids() {
    let pool = common::pool().await;
    let admin_id = Uuid::parse_str(ADMIN_ENTITY_ID).expect("admin entity UUID");
    let role_id = Uuid::parse_str(ADMIN_ROLE_ID).expect("admin role UUID");
    let assignment_id: Uuid = sqlx::query_scalar(
        r#"SELECT id FROM role_assignments
           WHERE tenant_id IS NULL AND subject_kind = 'entity'
             AND subject_id = $1 AND role_id = $2"#,
    )
    .bind(admin_id)
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .expect("seeded admin assignment");
    assert_eq!(
        assignment_id,
        Uuid::parse_str(ADMIN_ROLE_ASSIGNMENT_ID).expect("admin assignment UUID")
    );

    let admin = protected_objects::lookup(&pool, admin_id)
        .await
        .expect("admin lookup")
        .expect("registered admin");
    let assignment = protected_objects::lookup(&pool, assignment_id)
        .await
        .expect("assignment lookup")
        .expect("registered assignment");
    assert_eq!(admin.object_kind, "entity");
    assert_eq!(assignment.object_kind, "policy");
    assert_eq!(assignment.source_table, "role_assignments");
}
