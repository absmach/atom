//! Schema integration tests.
//!
//! Verifies the initial schema ships the right columns, tables, capability
//! seeds, and CHECK constraints. All tests are `#[ignore]`; run with:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m1_schema -- --ignored
//! ```

mod common;

use common::{admin_id, admin_role_id, pool};

#[tokio::test]
#[ignore]
async fn migrations_are_idempotent() {
    // pool() runs migrations once; running again should be a no-op.
    let p = pool().await;
    sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .expect("load migrations")
        .run(&p)
        .await
        .expect("re-applying migrations must be idempotent");
}

#[tokio::test]
#[ignore]
async fn policy_bindings_has_tenant_id_column() {
    let p = pool().await;
    let row = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'policy_bindings' AND column_name = 'tenant_id'",
    )
    .fetch_optional(&p)
    .await
    .expect("query column");
    assert!(row.is_some(), "policy_bindings.tenant_id missing");
}

#[tokio::test]
#[ignore]
async fn audit_logs_has_tenant_id_column() {
    let p = pool().await;
    let row = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'audit_logs' AND column_name = 'tenant_id'",
    )
    .fetch_optional(&p)
    .await
    .expect("query column");
    assert!(row.is_some(), "audit_logs.tenant_id missing");
}

#[tokio::test]
#[ignore]
async fn tenant_memberships_table_exists_and_supports_insert() {
    let p = pool().await;

    // Create a throwaway tenant + entity so we have something to link.
    let t_id = uuid::Uuid::new_v4();
    let e_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(t_id)
        .bind(format!("m1-mem-{t_id}"))
        .execute(&p)
        .await
        .expect("insert tenant");
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'human', $2, 'active')")
        .bind(e_id)
        .bind(format!("m1-mem-{e_id}"))
        .execute(&p)
        .await
        .expect("insert entity");

    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status, local_name, attributes)
         VALUES ($1, $2, 'active', 'alice', '{}'::jsonb)",
    )
    .bind(t_id)
    .bind(e_id)
    .execute(&p)
    .await
    .expect("insert membership");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id = $1 AND entity_id = $2",
    )
    .bind(t_id)
    .bind(e_id)
    .fetch_one(&p)
    .await
    .expect("count");
    assert_eq!(count, 1);

    // Idempotency: PRIMARY KEY rejects duplicate.
    let dup = sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(t_id)
    .bind(e_id)
    .execute(&p)
    .await
    .expect("insert with on-conflict");
    assert_eq!(dup.rows_affected(), 0, "PK should reject duplicate");

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(t_id)
        .execute(&p)
        .await;
    let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
        .bind(e_id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn capability_assignment_rules_table_exists_with_object_type() {
    let p = pool().await;

    let row = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'capability_assignment_rules' AND column_name = 'object_type'",
    )
    .fetch_optional(&p)
    .await
    .expect("query column");
    assert!(
        row.is_some(),
        "capability_assignment_rules.object_type missing"
    );

    // The PRD-incorrect column 'resource_kind' should NOT exist.
    let bad = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'capability_assignment_rules' AND column_name = 'resource_kind'",
    )
    .fetch_optional(&p)
    .await
    .expect("query column");
    assert!(
        bad.is_none(),
        "capability_assignment_rules must not have a resource_kind column"
    );

    // Insert and read back a default rule.
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO capability_assignment_rules
           (id, entity_kind, capability_name, object_kind, object_type, decision, is_absolute)
         VALUES ($1, 'device', 'publish', 'resource', 'resource:channel', 'allow', true)",
    )
    .bind(id)
    .execute(&p)
    .await
    .expect("insert rule");

    let decision: String =
        sqlx::query_scalar("SELECT decision FROM capability_assignment_rules WHERE id = $1")
            .bind(id)
            .fetch_one(&p)
            .await
            .expect("read decision");
    assert_eq!(decision, "allow");

    let _ = sqlx::query("DELETE FROM capability_assignment_rules WHERE id = $1")
        .bind(id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn admin_seed_uses_platform_scope() {
    let p = pool().await;
    let scope: String = sqlx::query_scalar(
        "SELECT scope_kind::text FROM policy_bindings
         WHERE subject_id = $1 AND grant_id = $2",
    )
    .bind(admin_id())
    .bind(admin_role_id())
    .fetch_one(&p)
    .await
    .expect("admin binding must exist");
    assert_eq!(
        scope, "platform",
        "admin binding must use canonical platform scope"
    );
}

#[tokio::test]
#[ignore]
async fn all_canonical_capabilities_are_seeded() {
    let p = pool().await;
    let expected = [
        "read",
        "write",
        "delete",
        "publish",
        "subscribe",
        "execute",
        "manage",
        "list",
        "credential.manage",
        "credential.revoke",
        "signing_key.rotate",
        "audit.read",
        "policy.manage",
        "role.manage",
        "tenant.manage",
    ];
    for name in expected {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM capabilities WHERE name = $1")
            .bind(name)
            .fetch_one(&p)
            .await
            .expect("query");
        assert!(count >= 1, "capability {name} not seeded");
    }
}

#[tokio::test]
#[ignore]
async fn check_constraint_rejects_invalid_scope_kind() {
    let p = pool().await;
    // Use an arbitrary entity/cap; the row must fail the CHECK before any FK
    // is consulted. Bind valid uuids so we hit only the CHECK violation.
    let cap_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM capabilities WHERE name = 'manage' LIMIT 1")
            .fetch_one(&p)
            .await
            .expect("manage cap");

    let result = sqlx::query(
        "INSERT INTO policy_bindings
           (id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect)
         VALUES ($1, 'entity', $2, 'capability', $3, 'all', NULL, 'allow')",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(admin_id())
    .bind(cap_id)
    .execute(&p)
    .await;

    assert!(
        result.is_err(),
        "scope_kind='all' must be rejected by the canonical scope CHECK"
    );
}

#[tokio::test]
#[ignore]
async fn check_constraint_accepts_all_new_scope_kinds() {
    let p = pool().await;
    let cap_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM capabilities WHERE name = 'manage' LIMIT 1")
            .fetch_one(&p)
            .await
            .expect("manage cap");

    for kind in ["platform", "tenant", "object_kind", "object_type", "object"] {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO policy_bindings
               (id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect)
             VALUES ($1, 'entity', $2, 'capability', $3, $4, NULL, 'allow')",
        )
        .bind(id)
        .bind(admin_id())
        .bind(cap_id)
        .bind(kind)
        .execute(&p)
        .await
        .unwrap_or_else(|e| panic!("scope_kind={kind} should be accepted: {e}"));

        // Clean up so the test is repeatable.
        let _ = sqlx::query("DELETE FROM policy_bindings WHERE id = $1")
            .bind(id)
            .execute(&p)
            .await;
    }
}
