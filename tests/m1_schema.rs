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
async fn final_access_tables_have_tenant_boundaries() {
    let p = pool().await;
    for table in [
        "permission_blocks",
        "roles",
        "role_assignments",
        "direct_policies",
        "principal_groups",
        "object_groups",
    ] {
        let row = sqlx::query(
            "SELECT column_name FROM information_schema.columns
             WHERE table_name = $1 AND column_name = 'tenant_id'",
        )
        .bind(table)
        .fetch_optional(&p)
        .await
        .expect("query column");
        assert!(row.is_some(), "{table}.tenant_id missing");
    }
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
async fn action_assignment_rules_table_exists_with_object_type() {
    let p = pool().await;

    let row = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'action_assignment_rules' AND column_name = 'object_type'",
    )
    .fetch_optional(&p)
    .await
    .expect("query column");
    assert!(row.is_some(), "action_assignment_rules.object_type missing");

    // The PRD-incorrect column 'resource_kind' should NOT exist.
    let bad = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'action_assignment_rules' AND column_name = 'resource_kind'",
    )
    .fetch_optional(&p)
    .await
    .expect("query column");
    assert!(
        bad.is_none(),
        "action_assignment_rules must not have a resource_kind column"
    );

    // Insert and read back a default rule.
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO action_assignment_rules
           (id, entity_kind, action_name, object_kind, object_type, decision, is_absolute)
         VALUES ($1, 'device', 'publish', 'resource', 'resource:channel', 'allow', true)",
    )
    .bind(id)
    .execute(&p)
    .await
    .expect("insert rule");

    let decision: String =
        sqlx::query_scalar("SELECT decision FROM action_assignment_rules WHERE id = $1")
            .bind(id)
            .fetch_one(&p)
            .await
            .expect("read decision");
    assert_eq!(decision, "allow");

    let dup = sqlx::query(
        "INSERT INTO action_assignment_rules
           (id, entity_kind, action_name, object_kind, object_type, decision, is_absolute)
         VALUES ($1, 'device', 'publish', 'resource', 'resource:channel', 'allow', true)",
    )
    .bind(uuid::Uuid::new_v4())
    .execute(&p)
    .await
    .expect_err("duplicate rule must be rejected");
    let duplicate_code = dup
        .as_database_error()
        .and_then(|err| err.code())
        .map(|code| code.into_owned());
    assert_eq!(duplicate_code.as_deref(), Some("23505"));

    let _ = sqlx::query("DELETE FROM action_assignment_rules WHERE id = $1")
        .bind(id)
        .execute(&p)
        .await;
}

#[tokio::test]
#[ignore]
async fn admin_seed_uses_platform_scope() {
    let p = pool().await;
    let scope: String = sqlx::query_scalar(
        r#"SELECT pb.scope_mode
           FROM role_assignments ra
           JOIN role_permission_blocks rpb ON rpb.role_id = ra.role_id
           JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
           WHERE ra.subject_id = $1 AND ra.role_id = $2"#,
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
async fn all_canonical_actions_are_seeded() {
    let p = pool().await;
    let expected = [
        "read",
        "write",
        "delete",
        "publish",
        "subscribe",
        "execute",
        "manage",
        "create",
        "revoke",
        "rotate",
        "policy.manage",
        "role.manage",
        "authz.check",
    ];
    for name in expected {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE name = $1")
            .bind(name)
            .fetch_one(&p)
            .await
            .expect("query");
        assert!(count >= 1, "action {name} not seeded");
    }
}

#[tokio::test]
#[ignore]
async fn check_constraint_rejects_invalid_scope_mode() {
    let p = pool().await;

    let result = sqlx::query(
        "INSERT INTO permission_blocks (scope_mode, effect)
         VALUES ('all', 'allow')",
    )
    .execute(&p)
    .await;

    assert!(
        result.is_err(),
        "scope_mode='all' must be rejected by the canonical scope CHECK"
    );
}

#[tokio::test]
#[ignore]
async fn check_constraint_accepts_all_new_scope_modes() {
    let p = pool().await;
    let tenant_id = uuid::Uuid::new_v4();
    let group_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("m1-scope-{tenant_id}"))
        .execute(&p)
        .await
        .expect("insert tenant");
    sqlx::query(
        "INSERT INTO object_groups (id, name, tenant_id)
         VALUES ($1, 'm1-scope-group', $2)",
    )
    .bind(group_id)
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("insert object group");

    let inserts = [
        ("platform", None, None, None, None, None),
        ("tenant", Some(tenant_id), None, None, None, None),
        (
            "object_kind",
            Some(tenant_id),
            Some("resource"),
            None,
            None,
            None,
        ),
        (
            "object_type",
            Some(tenant_id),
            Some("resource"),
            Some("resource:channel"),
            None,
            None,
        ),
        (
            "object",
            Some(tenant_id),
            Some("resource"),
            None,
            Some(uuid::Uuid::new_v4()),
            None,
        ),
        ("group", Some(tenant_id), None, None, None, Some(group_id)),
        (
            "group_direct_objects",
            Some(tenant_id),
            Some("resource"),
            Some("resource:channel"),
            None,
            Some(group_id),
        ),
        (
            "group_descendant_objects",
            Some(tenant_id),
            Some("resource"),
            Some("resource:channel"),
            None,
            Some(group_id),
        ),
        (
            "group_child_groups",
            Some(tenant_id),
            None,
            None,
            None,
            Some(group_id),
        ),
        (
            "group_descendant_groups",
            Some(tenant_id),
            None,
            None,
            None,
            Some(group_id),
        ),
    ];

    for (mode, tenant, object_kind, object_type, object_id, group) in inserts {
        sqlx::query(
            "INSERT INTO permission_blocks
               (scope_mode, tenant_id, object_kind, object_type, object_id, group_id, effect)
             VALUES ($1, $2, $3, $4, $5, $6, 'allow')",
        )
        .bind(mode)
        .bind(tenant)
        .bind(object_kind)
        .bind(object_type)
        .bind(object_id)
        .bind(group)
        .execute(&p)
        .await
        .unwrap_or_else(|e| panic!("scope_mode={mode} should be accepted: {e}"));
    }

    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&p)
        .await;
}
