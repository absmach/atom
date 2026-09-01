mod common;

use std::{borrow::Cow, path::Path};

use atom::{
    auth::AuthContext,
    authz::{engine, repo as authz_repo},
    models::{
        access::AuthorizedObjectIdsQuery,
        enums::DeletedFilter,
        policy::{AuthzRequest, ListDirectPolicies, ListRoleAssignments},
        role::ListRoles,
    },
    protected_objects,
};
use sqlx::{migrate::Migrator, Connection, Executor, PgConnection, PgPool};
use url::Url;
use uuid::Uuid;

const ADMIN_ENTITY_ID: &str = "00000000-0000-0000-0000-000000000001";
const ADMIN_ROLE_ID: &str = "00000000-0000-0000-0000-000000000002";
const ADMIN_ROLE_ASSIGNMENT_ID: &str = "00000000-0000-0000-0000-00000000000a";
const PRE_REGISTRY_MIGRATION_VERSION: i64 = 25;

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
    assert!(migration.contains("UPDATE permission_blocks"));
    assert!(migration.contains("UPDATE credential_permission_limits"));
    assert!(migration.contains("object_kind NOT IN ('entity', 'policy')"));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL and CREATE DATABASE"]
async fn migration_remaps_policy_ceilings_and_preserves_entity_ceilings() {
    let admin_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let scratch = format!("atom_m50_ceiling_{}", Uuid::new_v4().simple());
    let scratch_url = database_url_with_name(&admin_url, &scratch).expect("scratch database URL");

    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("connect for scratch database");
    admin
        .execute(format!(r#"CREATE DATABASE "{scratch}""#).as_str())
        .await
        .expect("create scratch database");

    let result = verify_ceiling_remap(&scratch_url).await;

    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)"#).as_str())
        .await;
    admin.close().await.expect("close admin connection");
    result.expect("migration 026 preserves the classified ceiling target");
}

async fn verify_ceiling_remap(scratch_url: &str) -> Result<(), String> {
    let mut conn = PgConnection::connect(scratch_url)
        .await
        .map_err(|error| format!("connect scratch: {error}"))?;
    let migrator = Migrator::new(Path::new("./migrations"))
        .await
        .map_err(|error| format!("load migrations: {error}"))?;
    apply_through(&mut conn, &migrator, PRE_REGISTRY_MIGRATION_VERSION).await?;

    let admin_entity_id = Uuid::parse_str(ADMIN_ENTITY_ID).expect("admin entity UUID");
    let legacy_assignment_id = admin_entity_id;
    let remapped_assignment_id =
        Uuid::parse_str(ADMIN_ROLE_ASSIGNMENT_ID).expect("admin assignment UUID");
    let policy_credential_id = Uuid::new_v4();
    let entity_credential_id = Uuid::new_v4();
    let policy_limit_id = Uuid::new_v4();
    let entity_limit_id = Uuid::new_v4();
    let policy_manage_action_id: Uuid =
        sqlx::query_scalar("SELECT id FROM actions WHERE name = 'policy.manage'")
            .fetch_one(&mut conn)
            .await
            .map_err(|error| format!("load policy.manage action: {error}"))?;

    for (credential_id, label) in [
        (policy_credential_id, "policy"),
        (entity_credential_id, "entity"),
    ] {
        sqlx::query(
            r#"INSERT INTO credentials (id, entity_id, kind, identifier, scoped)
               VALUES ($1, $2, 'access_token', $3, true)"#,
        )
        .bind(credential_id)
        .bind(admin_entity_id)
        .bind(format!("m50-{label}-{credential_id}"))
        .execute(&mut conn)
        .await
        .map_err(|error| format!("seed {label} scoped credential: {error}"))?;
    }

    for (limit_id, credential_id, object_kind) in [
        (policy_limit_id, policy_credential_id, "policy"),
        (entity_limit_id, entity_credential_id, "entity"),
    ] {
        sqlx::query(
            r#"INSERT INTO credential_permission_limits
                 (id, credential_id, scope_mode, object_kind, object_id)
               VALUES ($1, $2, 'object', $3, $4)"#,
        )
        .bind(limit_id)
        .bind(credential_id)
        .bind(object_kind)
        .bind(legacy_assignment_id)
        .execute(&mut conn)
        .await
        .map_err(|error| format!("seed {object_kind} ceiling: {error}"))?;
        sqlx::query(
            r#"INSERT INTO credential_permission_limit_actions (limit_id, action_id)
               VALUES ($1, $2)"#,
        )
        .bind(limit_id)
        .bind(policy_manage_action_id)
        .execute(&mut conn)
        .await
        .map_err(|error| format!("seed {object_kind} ceiling action: {error}"))?;
    }

    migrator
        .run_direct(&mut conn)
        .await
        .map_err(|error| format!("apply migration 026: {error}"))?;

    let ceiling_targets: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"SELECT credential_id, object_id
           FROM credential_permission_limits
           WHERE id = ANY($1)
           ORDER BY credential_id"#,
    )
    .bind(vec![policy_limit_id, entity_limit_id])
    .fetch_all(&mut conn)
    .await
    .map_err(|error| format!("load migrated ceilings: {error}"))?;
    if !ceiling_targets.contains(&(policy_credential_id, remapped_assignment_id))
        || !ceiling_targets.contains(&(entity_credential_id, admin_entity_id))
    {
        return Err(format!(
            "migration 026 changed the wrong ceiling targets: {ceiling_targets:?}"
        ));
    }

    conn.close()
        .await
        .map_err(|error| format!("close migration connection: {error}"))?;
    let pool = PgPool::connect(scratch_url)
        .await
        .map_err(|error| format!("connect runtime pool: {error}"))?;
    let policy_ceiling = authz_repo::load_credential_ceiling(&pool, policy_credential_id)
        .await
        .map_err(|error| format!("load policy ceiling: {error}"))?;
    let entity_ceiling = authz_repo::load_credential_ceiling(&pool, entity_credential_id)
        .await
        .map_err(|error| format!("load entity ceiling: {error}"))?;

    let policy_request = AuthzRequest {
        subject_id: admin_entity_id,
        action: "policy.manage".into(),
        resource_id: None,
        object_kind: Some("policy".into()),
        object_id: Some(remapped_assignment_id),
        context: serde_json::Value::Null,
    };
    let entity_request = AuthzRequest {
        subject_id: admin_entity_id,
        action: "policy.manage".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(admin_entity_id),
        context: serde_json::Value::Null,
    };
    let policy_on_policy =
        engine::evaluate_with_ceiling(&pool, &policy_request, Some(&policy_ceiling))
            .await
            .map_err(|error| format!("evaluate policy ceiling on policy: {error}"))?;
    let policy_on_entity =
        engine::evaluate_with_ceiling(&pool, &entity_request, Some(&policy_ceiling))
            .await
            .map_err(|error| format!("evaluate policy ceiling on entity: {error}"))?;
    let entity_on_entity =
        engine::evaluate_with_ceiling(&pool, &entity_request, Some(&entity_ceiling))
            .await
            .map_err(|error| format!("evaluate entity ceiling on entity: {error}"))?;
    let entity_on_policy =
        engine::evaluate_with_ceiling(&pool, &policy_request, Some(&entity_ceiling))
            .await
            .map_err(|error| format!("evaluate entity ceiling on policy: {error}"))?;
    pool.close().await;

    if !policy_on_policy.allowed
        || policy_on_entity.allowed
        || !entity_on_entity.allowed
        || entity_on_policy.allowed
    {
        return Err(format!(
            "migrated ceilings do not preserve runtime targets: policy/policy={}, policy/entity={}, entity/entity={}, entity/policy={}",
            policy_on_policy.allowed,
            policy_on_entity.allowed,
            entity_on_entity.allowed,
            entity_on_policy.allowed
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires DATABASE_URL and CREATE DATABASE"]
async fn preflight_and_migration_reject_unclassified_legacy_ceiling_targets() {
    let admin_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let scratch = format!("atom_m50_ambiguous_{}", Uuid::new_v4().simple());
    let scratch_url = database_url_with_name(&admin_url, &scratch).expect("scratch database URL");

    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("connect for scratch database");
    admin
        .execute(format!(r#"CREATE DATABASE "{scratch}""#).as_str())
        .await
        .expect("create scratch database");

    let result = verify_unclassified_ceiling_is_blocked(&scratch_url).await;

    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)"#).as_str())
        .await;
    admin.close().await.expect("close admin connection");
    result.expect("unclassified legacy ceilings block migration 026 without mutation");
}

async fn verify_unclassified_ceiling_is_blocked(scratch_url: &str) -> Result<(), String> {
    let mut conn = PgConnection::connect(scratch_url)
        .await
        .map_err(|error| format!("connect scratch: {error}"))?;
    let migrator = Migrator::new(Path::new("./migrations"))
        .await
        .map_err(|error| format!("load migrations: {error}"))?;
    apply_through(&mut conn, &migrator, PRE_REGISTRY_MIGRATION_VERSION).await?;

    let credential_id = Uuid::new_v4();
    let null_kind_limit_id = Uuid::new_v4();
    let invalid_kind_limit_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, scoped)
           VALUES ($1, $2, 'access_token', $3, true)"#,
    )
    .bind(credential_id)
    .bind(Uuid::parse_str(ADMIN_ENTITY_ID).expect("admin entity UUID"))
    .bind(format!("m50-unclassified-{credential_id}"))
    .execute(&mut conn)
    .await
    .map_err(|error| format!("seed scoped credential: {error}"))?;
    for (limit_id, object_kind) in [
        (null_kind_limit_id, None),
        (invalid_kind_limit_id, Some("resource")),
    ] {
        sqlx::query(
            r#"INSERT INTO credential_permission_limits
                 (id, credential_id, scope_mode, object_kind, object_id)
               VALUES ($1, $2, 'object', $3, $4)"#,
        )
        .bind(limit_id)
        .bind(credential_id)
        .bind(object_kind)
        .bind(Uuid::parse_str(ADMIN_ENTITY_ID).expect("legacy assignment UUID"))
        .execute(&mut conn)
        .await
        .map_err(|error| format!("seed unclassified ceiling: {error}"))?;
    }

    let pool = PgPool::connect(scratch_url)
        .await
        .map_err(|error| format!("connect preflight pool: {error}"))?;
    let preflight_error =
        match protected_objects::preflight_global_protected_object_ids(&pool).await {
            Ok(()) => {
                pool.close().await;
                return Err(
                    "startup preflight accepted unclassified legacy ceiling targets".to_string(),
                );
            }
            Err(error) => error.to_string(),
        };
    pool.close().await;
    if !preflight_error.contains("credential_permission_limits")
        || !preflight_error.contains("object_kind=NULL")
        || !preflight_error.contains("object_kind=resource")
    {
        return Err(format!(
            "startup preflight omitted unclassified ceiling detail: {preflight_error}"
        ));
    }

    let migration_error = match migrator.run_direct(&mut conn).await {
        Ok(()) => {
            return Err("migration 026 accepted unclassified legacy ceiling targets".to_string())
        }
        Err(error) => error.to_string(),
    };
    if !migration_error.contains("unclassified exact-object reference") {
        return Err(format!(
            "unexpected migration 026 rejection: {migration_error}"
        ));
    }

    let unchanged_targets: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT object_id
           FROM credential_permission_limits
           WHERE id = ANY($1)
           ORDER BY id"#,
    )
    .bind(vec![null_kind_limit_id, invalid_kind_limit_id])
    .fetch_all(&mut conn)
    .await
    .map_err(|error| format!("verify rejected ceiling targets: {error}"))?;
    let legacy_id = Uuid::parse_str(ADMIN_ENTITY_ID).expect("legacy assignment UUID");
    if unchanged_targets != vec![legacy_id, legacy_id] {
        return Err(format!(
            "failed migration modified ambiguous ceiling targets: {unchanged_targets:?}"
        ));
    }
    let assignment_id: Uuid = sqlx::query_scalar(
        r#"SELECT id FROM role_assignments
           WHERE subject_id = $1 AND role_id = $2 AND tenant_id IS NULL"#,
    )
    .bind(legacy_id)
    .bind(Uuid::parse_str(ADMIN_ROLE_ID).expect("admin role UUID"))
    .fetch_one(&mut conn)
    .await
    .map_err(|error| format!("verify rejected assignment remap: {error}"))?;
    if assignment_id != legacy_id {
        return Err(format!(
            "failed migration changed seeded assignment id to {assignment_id}"
        ));
    }
    conn.close()
        .await
        .map_err(|error| format!("close scratch connection: {error}"))?;
    Ok(())
}

async fn apply_through(
    conn: &mut PgConnection,
    migrator: &Migrator,
    version: i64,
) -> Result<(), String> {
    let migrations = migrator
        .iter()
        .filter(|migration| migration.version <= version)
        .cloned()
        .collect::<Vec<_>>();
    if migrations.last().map(|migration| migration.version) != Some(version) {
        return Err(format!("migration {version} must remain available"));
    }
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
    .run_direct(conn)
    .await
    .map_err(|error| format!("apply migrations through {version}: {error}"))
}

fn database_url_with_name(base: &str, database: &str) -> Result<String, String> {
    let mut url = Url::parse(base).map_err(|error| format!("parse DATABASE_URL: {error}"))?;
    url.set_path(&format!("/{database}"));
    Ok(url.to_string())
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
