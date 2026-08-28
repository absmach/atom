//! Config-file bootstrap integration tests (issue #27).
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m25_config_bootstrap -- --ignored
//! ```

mod common;

use atom::bootstrap::{
    apply, preflight_legacy_email_uniqueness, BootstrapActionAssignmentRule, BootstrapCapability,
    BootstrapCapabilityApplicability, BootstrapConfig, BootstrapCredential, BootstrapDirectPolicy,
    BootstrapEntity, BootstrapGroup, BootstrapObjectGroup, BootstrapPermissionBlock,
    BootstrapResource, BootstrapRole, BootstrapRoleAssignment, BootstrapScope, BootstrapSubject,
    BootstrapTenant, ScopeMode,
};
use atom::config::Config;
use atom::models::enums::{
    ActionAssignmentDecision, EntityKind, EntityStatus, ObjectKind, SubjectKind, TenantStatus,
};
use atom::models::policy::AuthzRequest;
use atom::models::token::CreateSharedKey;
use common::pool;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn count_active_credentials(pool: &sqlx::PgPool, entity_id: Uuid, kind: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active'",
    )
    .bind(entity_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .expect("count credentials")
}

async fn single_connection_pool() -> sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("single-connection bootstrap pool");
    sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .expect("load migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    pool
}

#[tokio::test]
#[ignore]
async fn v1_upgrade_preflight_rejects_case_insensitive_legacy_email_collisions() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    // One physical connection keeps the temporary legacy schema visible when
    // the public preflight acquires its connection.
    let p = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("preflight pool");
    let mut conn = p.acquire().await.expect("preflight connection");
    sqlx::query("CREATE TEMP TABLE _sqlx_migrations (version bigint, success boolean)")
        .execute(&mut *conn)
        .await
        .expect("temporary migration table");
    sqlx::query(
        r#"CREATE TEMP TABLE entities (
               id uuid PRIMARY KEY,
               kind text NOT NULL,
               attributes jsonb NOT NULL DEFAULT '{}',
               deleted_at timestamptz
           )"#,
    )
    .execute(&mut *conn)
    .await
    .expect("temporary entities table");
    sqlx::query(
        r#"CREATE TEMP TABLE entity_emails (
               entity_id uuid NOT NULL,
               email text NOT NULL,
               deleted_at timestamptz
           )"#,
    )
    .execute(&mut *conn)
    .await
    .expect("temporary email table");
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind) VALUES ($1, 'human'), ($2, 'human')")
        .bind(first)
        .bind(second)
        .execute(&mut *conn)
        .await
        .expect("legacy entities");
    sqlx::query(
        "INSERT INTO entity_emails (entity_id, email) VALUES ($1, 'Legacy@Example.com'), ($2, 'legacy@example.com')",
    )
    .bind(first)
    .bind(second)
    .execute(&mut *conn)
    .await
    .expect("legacy collision");
    drop(conn);

    let err = preflight_legacy_email_uniqueness(&p)
        .await
        .expect_err("collision must block migration");
    assert!(err.to_string().contains("legacy@example.com"));
    assert!(err.to_string().contains(&first.to_string()));
    assert!(err.to_string().contains(&second.to_string()));
    assert!(err.to_string().contains("did not modify"));

    let mut conn = p.acquire().await.expect("preflight connection");
    sqlx::query("INSERT INTO _sqlx_migrations (version, success) VALUES (25, true)")
        .execute(&mut *conn)
        .await
        .expect("mark migration applied");
    drop(conn);
    preflight_legacy_email_uniqueness(&p)
        .await
        .expect("already-applied migration must be a no-op");
}

fn credentials_config(human: Uuid, service: Uuid) -> BootstrapConfig {
    BootstrapConfig {
        entities: vec![
            BootstrapEntity {
                id: human,
                kind: EntityKind::Human,
                name: format!("bootstrap-human-{human}"),
                alias: None,
                status: EntityStatus::Active,
                attributes: Some(serde_json::json!({ "system": true })),
                tenant_id: None,
                credentials: vec![BootstrapCredential::Password {
                    secret: "bootstrap-pw-123456".to_string(),
                }],
            },
            BootstrapEntity {
                id: service,
                kind: EntityKind::Service,
                name: format!("bootstrap-service-{service}"),
                alias: None,
                status: EntityStatus::Active,
                attributes: None,
                tenant_id: None,
                credentials: vec![BootstrapCredential::SharedKey {
                    key: "bootstrap-machine-secret".to_string(),
                    description: Some("integration test".to_string()),
                }],
            },
        ],
        ..Default::default()
    }
}

#[tokio::test]
#[ignore]
async fn bootstrap_creates_entities_and_credentials() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();
    let cfg = credentials_config(human, service);

    apply(&p, &signing_keys, &cfg)
        .await
        .expect("apply bootstrap");

    let human_kind: String = sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
        .bind(human)
        .fetch_one(&p)
        .await
        .expect("human entity exists");
    assert_eq!(human_kind, "human");

    let service_kind: String = sqlx::query_scalar("SELECT kind FROM entities WHERE id = $1")
        .bind(service)
        .fetch_one(&p)
        .await
        .expect("service entity exists");
    assert_eq!(service_kind, "service");

    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
    assert_eq!(count_active_credentials(&p, service, "shared_key").await, 1);

    let password_err = atom::identity::service::create_password(&p, human, "another-password-123")
        .await
        .expect_err("API password creation must respect config ownership");
    assert!(matches!(password_err, atom::error::AppError::Conflict(_)));
    let shared_key_err = atom::identity::service::create_shared_key(
        &p,
        &signing_keys,
        service,
        CreateSharedKey {
            expires_at: None,
            description: None,
            key: Some("another-machine-secret".to_string()),
        },
    )
    .await
    .expect_err("API shared-key creation must respect config ownership");
    assert!(matches!(shared_key_err, atom::error::AppError::Conflict(_)));
}

#[tokio::test]
#[ignore]
async fn bootstrap_is_idempotent() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();
    let cfg = credentials_config(human, service);

    // Apply twice; the second run must not create duplicate rows.
    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    apply(&p, &signing_keys, &cfg).await.expect("second apply");

    let entity_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entities WHERE id = $1")
        .bind(human)
        .fetch_one(&p)
        .await
        .expect("count human");
    assert_eq!(entity_count, 1);

    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
    assert_eq!(count_active_credentials(&p, service, "shared_key").await, 1);
}

#[tokio::test]
#[ignore]
async fn concurrent_identical_bootstrap_reconciles_each_credential_once() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();
    let access_token_id = Uuid::new_v4();
    let access_token = format!("atom_{}_{}", access_token_id.simple(), "a".repeat(64));
    let mut cfg = credentials_config(human, service);
    cfg.entities[1]
        .credentials
        .push(BootstrapCredential::AccessToken {
            token: access_token,
            name: "concurrent-bootstrap-token".to_string(),
            description: Some("concurrent bootstrap test".to_string()),
        });

    let (first, second) = tokio::join!(
        apply(&p, &signing_keys, &cfg),
        apply(&p, &signing_keys, &cfg)
    );
    first.expect("first concurrent apply");
    second.expect("second concurrent apply");

    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
    assert_eq!(count_active_credentials(&p, service, "shared_key").await, 1);
    let access_token_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM credentials
           WHERE id = $1 AND entity_id = $2
             AND kind = 'access_token' AND status = 'active'"#,
    )
    .bind(access_token_id)
    .bind(service)
    .fetch_one(&p)
    .await
    .expect("count concurrent bootstrap access token");
    assert_eq!(access_token_count, 1);
}

#[tokio::test]
#[ignore]
async fn bootstrap_human_email_is_canonical_and_semantic_drift_is_rejected() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let original_email = format!("Owner-{human}@Example.COM");
    let normalized_email = original_email.to_ascii_lowercase();
    let mut cfg = BootstrapConfig {
        entities: vec![BootstrapEntity {
            id: human,
            kind: EntityKind::Human,
            name: format!("bootstrap-human-{human}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: Some(json!({ "email": original_email })),
            tenant_id: None,
            credentials: vec![],
        }],
        ..Default::default()
    };

    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    let canonical: String =
        sqlx::query_scalar("SELECT email FROM entity_emails WHERE entity_id = $1")
            .bind(human)
            .fetch_one(&p)
            .await
            .expect("canonical email");
    assert_eq!(canonical, normalized_email);

    // Reusing an ID with changed stored semantics is not idempotency.
    cfg.entities[0].attributes = Some(json!({ "email": format!("other-{human}@example.com") }));
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("semantic drift");
    assert!(err.to_string().contains("different semantics"));
    let after: String = sqlx::query_scalar("SELECT email FROM entity_emails WHERE entity_id = $1")
        .bind(human)
        .fetch_one(&p)
        .await
        .expect("canonical email after rerun");
    assert_eq!(after, normalized_email);
}

#[tokio::test]
#[ignore]
async fn bootstrap_duplicate_human_email_fails_without_inserting_second_entity() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let email = format!("duplicate-{first}@example.com");
    let entity = |id, email: String| BootstrapEntity {
        id,
        kind: EntityKind::Human,
        name: format!("bootstrap-human-{id}"),
        alias: None,
        status: EntityStatus::Active,
        attributes: Some(json!({ "email": email })),
        tenant_id: None,
        credentials: vec![],
    };

    let first_cfg = BootstrapConfig {
        entities: vec![entity(first, email.clone())],
        ..Default::default()
    };
    apply(&p, &signing_keys, &first_cfg)
        .await
        .expect("first owner");

    let duplicate_cfg = BootstrapConfig {
        entities: vec![entity(second, email.to_ascii_uppercase())],
        ..Default::default()
    };
    let err = apply(&p, &signing_keys, &duplicate_cfg)
        .await
        .expect_err("duplicate email must fail");
    assert!(err.to_string().contains("email"));
    let second_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM entities WHERE id = $1)")
            .bind(second)
            .fetch_one(&p)
            .await
            .expect("second entity lookup");
    assert!(!second_exists, "entity and email must roll back together");
}

#[tokio::test]
#[ignore]
async fn bootstrap_does_not_clobber_existing_credentials() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();

    apply(&p, &signing_keys, &credentials_config(human, service))
        .await
        .expect("first apply");

    let original_hash: String =
        sqlx::query_scalar("SELECT secret_hash FROM credentials WHERE entity_id = $1")
            .bind(human)
            .fetch_one(&p)
            .await
            .expect("password hash");

    // A second run declaring a different secret for the same entity must fail
    // closed and leave the config-managed credential unchanged.
    let mut changed = credentials_config(human, service);
    changed.entities[0].credentials = vec![BootstrapCredential::Password {
        secret: "a-totally-different-secret".to_string(),
    }];
    apply(&p, &signing_keys, &changed)
        .await
        .expect_err("credential drift must reject bootstrap");

    let after_hash: String =
        sqlx::query_scalar("SELECT secret_hash FROM credentials WHERE entity_id = $1")
            .bind(human)
            .fetch_one(&p)
            .await
            .expect("password hash after");
    assert_eq!(
        original_hash, after_hash,
        "existing password must be preserved"
    );
    assert_eq!(count_active_credentials(&p, human, "password").await, 1);
}

#[tokio::test]
#[ignore]
async fn bootstrap_rejects_one_matching_and_one_drifted_active_singleton_credential() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let human = Uuid::new_v4();
    let service = Uuid::new_v4();
    let mut base = credentials_config(human, service);
    base.entities
        .iter_mut()
        .for_each(|entity| entity.credentials.clear());
    apply(&p, &signing_keys, &base)
        .await
        .expect("create bootstrap entities");

    let drift_password_id = Uuid::new_v4();
    for (id, secret) in [
        (Uuid::new_v4(), "bootstrap-pw-123456"),
        (drift_password_id, "different-password-123"),
    ] {
        let hash = atom::identity::service::hash_secret(secret.as_bytes()).expect("hash password");
        sqlx::query(
            "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)",
        )
        .bind(id)
        .bind(human)
        .bind(hash)
        .execute(&p)
        .await
        .expect("insert password");
    }
    for (secret, description) in [
        ("bootstrap-machine-secret", Some("integration test")),
        ("different-machine-secret", Some("drift")),
    ] {
        let hash =
            atom::identity::service::hash_secret(secret.as_bytes()).expect("hash shared key");
        sqlx::query(
            r#"INSERT INTO credentials
                 (id, entity_id, kind, secret_hash, metadata)
               VALUES ($1, $2, 'shared_key', $3, $4)"#,
        )
        .bind(Uuid::new_v4())
        .bind(service)
        .bind(hash)
        .bind(json!({ "description": description }))
        .execute(&p)
        .await
        .expect("insert shared key");
    }

    let cfg = credentials_config(human, service);
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("multiple active password rows must fail");
    assert!(err.to_string().contains("password"));
    let managed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = ANY($1) AND managed_by = 'config'",
    )
    .bind(&[human, service])
    .fetch_one(&p)
    .await
    .expect("managed credential count");
    assert_eq!(managed, 0, "failed reconciliation must stamp no credential");

    sqlx::query("UPDATE credentials SET status = 'revoked' WHERE id = $1")
        .bind(drift_password_id)
        .execute(&p)
        .await
        .expect("revoke drifted password");
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("multiple active shared-key rows must fail");
    assert!(err.to_string().contains("shared key"));
    sqlx::query(
        "UPDATE credentials SET status = 'revoked' WHERE entity_id = $1 AND kind = 'shared_key' AND metadata->>'description' = 'drift'",
    )
    .bind(service)
    .execute(&p)
    .await
    .expect("revoke drifted shared key");
    apply(&p, &signing_keys, &cfg)
        .await
        .expect("revoked history must not violate active singleton cardinality");
}

#[tokio::test]
#[ignore]
async fn late_bootstrap_failure_rolls_back_earlier_sections() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let entity = Uuid::new_v4();
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("atomic-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![BootstrapEntity {
            id: entity,
            kind: EntityKind::Service,
            name: format!("atomic-service-{entity}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: Some(tenant),
            credentials: vec![BootstrapCredential::Password {
                secret: "atomic-password-123".to_string(),
            }],
        }],
        direct_policies: vec![BootstrapDirectPolicy {
            id: Uuid::new_v4(),
            tenant_id: Some(tenant),
            subject: BootstrapSubject {
                kind: SubjectKind::Entity,
                id: entity,
            },
            permission_block_id: Uuid::new_v4(),
        }],
        ..Default::default()
    };
    apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("late missing permission block must fail bootstrap");
    let rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM tenants WHERE id = $1) + (SELECT COUNT(*) FROM entities WHERE id = $2) + (SELECT COUNT(*) FROM credentials WHERE entity_id = $2)",
    )
    .bind(tenant)
    .bind(entity)
    .fetch_one(&p)
    .await
    .expect("rolled-back rows");
    assert_eq!(rows, 0);
}

/// A full tenant → entity → block → role → assignment graph, ending in a real
/// PDP-visible grant for the assigned entity.
fn rbac_config(
    tenant: Uuid,
    device: Uuid,
    block: Uuid,
    role: Uuid,
    assignment: Uuid,
) -> BootstrapConfig {
    BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec!["demo".to_string()],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![BootstrapEntity {
            id: device,
            kind: EntityKind::Device,
            name: format!("bootstrap-device-{device}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: Some(tenant),
            credentials: vec![],
        }],
        permission_blocks: vec![BootstrapPermissionBlock {
            id: block,
            scope: BootstrapScope {
                mode: ScopeMode::ObjectType,
                tenant_id: Some(tenant),
                object_kind: Some("resource".to_string()),
                object_type: Some("resource:channel".to_string()),
                object_id: None,
                group_id: None,
            },
            actions: vec!["publish".to_string(), "subscribe".to_string()],
            effect: Default::default(),
            conditions: None,
        }],
        roles: vec![BootstrapRole {
            id: role,
            name: format!("publisher-{role}"),
            tenant_id: Some(tenant),
            description: Some("can publish".to_string()),
            permission_blocks: vec![block],
        }],
        role_assignments: vec![BootstrapRoleAssignment {
            id: assignment,
            tenant_id: Some(tenant),
            subject: BootstrapSubject {
                kind: SubjectKind::Entity,
                id: device,
            },
            role_id: role,
        }],
        capabilities: vec![
            BootstrapCapability {
                name: "publish".to_string(),
                description: Some("Publish messages to a channel".to_string()),
                applicability: vec![BootstrapCapabilityApplicability {
                    object_kind: ObjectKind::Resource,
                    object_type: Some("resource:channel".to_string()),
                }],
            },
            BootstrapCapability {
                name: "subscribe".to_string(),
                description: Some("Subscribe to channel messages".to_string()),
                applicability: vec![BootstrapCapabilityApplicability {
                    object_kind: ObjectKind::Resource,
                    object_type: Some("resource:channel".to_string()),
                }],
            },
        ],
        ..Default::default()
    }
}

#[tokio::test]
#[ignore]
async fn bootstrap_provisions_full_rbac_graph() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let block = Uuid::new_v4();
    let role = Uuid::new_v4();
    let assignment = Uuid::new_v4();
    let cfg = rbac_config(tenant, device, block, role, assignment);

    // Apply twice to prove the whole graph is idempotent.
    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    apply(&p, &signing_keys, &cfg).await.expect("second apply");

    // Rows exist and are linked.
    let entity_tenant: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
            .bind(device)
            .fetch_one(&p)
            .await
            .expect("device entity");
    assert_eq!(entity_tenant, Some(tenant));

    let link_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permission_blocks WHERE role_id = $1 AND permission_block_id = $2",
    )
    .bind(role)
    .bind(block)
    .fetch_one(&p)
    .await
    .expect("role/block link");
    assert_eq!(link_count, 1, "block linked to role exactly once");

    let action_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM permission_block_actions WHERE permission_block_id = $1",
    )
    .bind(block)
    .fetch_one(&p)
    .await
    .expect("block actions");
    assert_eq!(
        action_count, 2,
        "publish + subscribe resolved to action rows"
    );

    // End-to-end: the assigned device now effectively holds `publish` via the
    // canonical grant expansion the PDP consumes.
    let publish_grants: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM subject_effective_grants($1) g
           JOIN actions a ON a.id = g.capability_id
           WHERE a.name = 'publish' AND g.effect = 'allow'"#,
    )
    .bind(device)
    .fetch_one(&p)
    .await
    .expect("effective grants");
    assert!(
        publish_grants >= 1,
        "device should effectively hold an allow-publish grant"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_supports_group_subjects_and_direct_policies() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let block = Uuid::new_v4();
    let group = Uuid::new_v4();

    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![BootstrapEntity {
            id: device,
            kind: EntityKind::Device,
            name: format!("bootstrap-device-{device}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: Some(tenant),
            credentials: vec![],
        }],
        groups: vec![BootstrapGroup {
            id: group,
            name: format!("publishers-{group}"),
            tenant_id: Some(tenant),
            description: None,
            attributes: None,
            members: vec![device],
        }],
        permission_blocks: vec![BootstrapPermissionBlock {
            id: block,
            scope: BootstrapScope {
                mode: ScopeMode::Tenant,
                tenant_id: Some(tenant),
                object_kind: None,
                object_type: None,
                object_id: None,
                group_id: None,
            },
            actions: vec!["read".to_string()],
            effect: Default::default(),
            conditions: None,
        }],
        direct_policies: vec![BootstrapDirectPolicy {
            id: Uuid::new_v4(),
            tenant_id: Some(tenant),
            subject: BootstrapSubject {
                kind: SubjectKind::Group,
                id: group,
            },
            permission_block_id: block,
        }],
        ..Default::default()
    };

    apply(&p, &signing_keys, &cfg).await.expect("apply");

    let member_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM principal_group_members WHERE group_id = $1 AND entity_id = $2",
    )
    .bind(group)
    .bind(device)
    .fetch_one(&p)
    .await
    .expect("membership");
    assert_eq!(member_count, 1);

    // The device inherits the group's direct policy: it should effectively hold
    // an allow-read grant through group membership.
    let read_grants: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM subject_effective_grants($1) g
           JOIN actions a ON a.id = g.capability_id
           WHERE a.name = 'read' AND g.effect = 'allow'"#,
    )
    .bind(device)
    .fetch_one(&p)
    .await
    .expect("effective grants");
    assert!(
        read_grants >= 1,
        "device should inherit read via group direct policy"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_provisions_resources_and_object_group_scoped_grant() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let channel = Uuid::new_v4();
    let object_group = Uuid::new_v4();
    let block = Uuid::new_v4();
    let role = Uuid::new_v4();

    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![BootstrapEntity {
            id: device,
            kind: EntityKind::Device,
            name: format!("bootstrap-device-{device}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: Some(tenant),
            credentials: vec![],
        }],
        resources: vec![BootstrapResource {
            id: channel,
            kind: "channel".to_string(),
            name: Some("temperature".to_string()),
            alias: None,
            tenant_id: Some(tenant),
            owner_id: Some(device),
            attributes: None,
        }],
        object_groups: vec![BootstrapObjectGroup {
            id: object_group,
            name: format!("channels-{object_group}"),
            tenant_id: Some(tenant),
            description: None,
            attributes: None,
            parent: None,
            entities: vec![],
            resources: vec![channel],
        }],
        permission_blocks: vec![BootstrapPermissionBlock {
            id: block,
            scope: BootstrapScope {
                mode: ScopeMode::GroupDirectObjects,
                tenant_id: Some(tenant),
                object_kind: Some("resource".to_string()),
                object_type: Some("resource:channel".to_string()),
                object_id: None,
                group_id: Some(object_group),
            },
            actions: vec!["publish".to_string()],
            effect: Default::default(),
            conditions: None,
        }],
        roles: vec![BootstrapRole {
            id: role,
            name: format!("channel-publisher-{role}"),
            tenant_id: Some(tenant),
            description: None,
            permission_blocks: vec![block],
        }],
        role_assignments: vec![BootstrapRoleAssignment {
            id: Uuid::new_v4(),
            tenant_id: Some(tenant),
            subject: BootstrapSubject {
                kind: SubjectKind::Entity,
                id: device,
            },
            role_id: role,
        }],
        // `publish` applicability on `resource:channel` is product-specific
        // and no longer seeded by the migration; declare it here so the PDP
        // can find the capability for the channel object type.
        capabilities: vec![BootstrapCapability {
            name: "publish".to_string(),
            description: Some("Publish messages to a channel".to_string()),
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Resource,
                object_type: Some("resource:channel".to_string()),
            }],
        }],
        ..Default::default()
    };

    // Apply twice for idempotency, then let the PDP prove the whole chain.
    apply(&p, &signing_keys, &cfg).await.expect("first apply");
    apply(&p, &signing_keys, &cfg).await.expect("second apply");

    // Resource + object-group membership landed.
    let membership: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_resources WHERE group_id = $1 AND resource_id = $2",
    )
    .bind(object_group)
    .bind(channel)
    .fetch_one(&p)
    .await
    .expect("membership");
    assert_eq!(membership, 1);

    // End-to-end: the device can publish on the channel because the group-scoped
    // block grants publish on resource members of the object group it belongs to.
    let req = AuthzRequest {
        subject_id: device,
        action: "publish".to_string(),
        resource_id: Some(channel),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let resp = atom::authz::engine::evaluate_with_ceiling(&p, &req, None)
        .await
        .expect("evaluate");
    assert!(
        resp.allowed,
        "device should be allowed to publish on the channel: {}",
        resp.reason
    );

    // A different channel outside the object group must NOT be allowed.
    let other_channel = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', 'other', $2)",
    )
    .bind(other_channel)
    .bind(tenant)
    .execute(&p)
    .await
    .expect("insert other channel");
    let deny_req = AuthzRequest {
        subject_id: device,
        action: "publish".to_string(),
        resource_id: Some(other_channel),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let deny = atom::authz::engine::evaluate_with_ceiling(&p, &deny_req, None)
        .await
        .expect("evaluate other");
    assert!(
        !deny.allowed,
        "a channel outside the object group must not be granted"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_rejects_capability_that_is_not_applicable_to_block_scope() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let block = Uuid::new_v4();
    let action = format!("bootstrap.inapplicable.{block}");
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        capabilities: vec![BootstrapCapability {
            name: action.clone(),
            description: None,
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Entity,
                object_type: Some("entity:device".to_string()),
            }],
        }],
        permission_blocks: vec![BootstrapPermissionBlock {
            id: block,
            scope: BootstrapScope {
                mode: ScopeMode::ObjectType,
                tenant_id: Some(tenant),
                object_kind: Some("resource".to_string()),
                object_type: Some("resource:channel".to_string()),
                object_id: None,
                group_id: None,
            },
            actions: vec![action],
            effect: Default::default(),
            conditions: None,
        }],
        ..Default::default()
    };

    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("inapplicable capability");
    assert!(err.to_string().contains("not applicable"));
    let block_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM permission_blocks WHERE id = $1)")
            .bind(block)
            .fetch_one(&p)
            .await
            .expect("block lookup");
    assert!(!block_exists, "invalid block must not be inserted");
}

#[tokio::test]
#[ignore]
async fn bootstrap_rejects_undeclared_persisted_capability_applicability() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let name = format!("bootstrap.exact-applicability.{}", Uuid::new_v4());
    let cfg = BootstrapConfig {
        capabilities: vec![BootstrapCapability {
            name: name.clone(),
            description: Some("original".to_string()),
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Resource,
                object_type: Some("resource:channel".to_string()),
            }],
        }],
        ..Default::default()
    };
    apply(&p, &signing_keys, &cfg)
        .await
        .expect("initial exact capability");
    let action_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
        .bind(&name)
        .fetch_one(&p)
        .await
        .expect("action id");
    sqlx::query(
        r#"INSERT INTO action_applicability (action_id, object_kind, object_type)
           VALUES ($1, 'entity', 'entity:device')"#,
    )
    .bind(action_id)
    .execute(&p)
    .await
    .expect("insert API applicability drift");

    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("undeclared applicability must fail");
    assert!(err.to_string().contains("not declared in config"));
    let description: Option<String> =
        sqlx::query_scalar("SELECT description FROM actions WHERE id = $1")
            .bind(action_id)
            .fetch_one(&p)
            .await
            .expect("rolled-back action description");
    assert_eq!(description.as_deref(), Some("original"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_role_assignment_obeys_assignment_guardrails() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let block = Uuid::new_v4();
    let role = Uuid::new_v4();
    let assignment = Uuid::new_v4();
    let action = format!("bootstrap.denied.{assignment}");
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![BootstrapEntity {
            id: device,
            kind: EntityKind::Device,
            name: format!("bootstrap-device-{device}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: Some(tenant),
            credentials: vec![],
        }],
        capabilities: vec![BootstrapCapability {
            name: action.clone(),
            description: None,
            applicability: vec![BootstrapCapabilityApplicability {
                object_kind: ObjectKind::Resource,
                object_type: Some("resource:channel".to_string()),
            }],
        }],
        action_assignment_rules: vec![BootstrapActionAssignmentRule {
            tenant_id: None,
            entity_kind: EntityKind::Device,
            action_name: action.clone(),
            object_kind: ObjectKind::Resource,
            object_type: Some("resource:channel".to_string()),
            decision: ActionAssignmentDecision::Deny,
            is_absolute: true,
        }],
        permission_blocks: vec![BootstrapPermissionBlock {
            id: block,
            scope: BootstrapScope {
                mode: ScopeMode::ObjectType,
                tenant_id: Some(tenant),
                object_kind: Some("resource".to_string()),
                object_type: Some("resource:channel".to_string()),
                object_id: None,
                group_id: None,
            },
            actions: vec![action],
            effect: Default::default(),
            conditions: None,
        }],
        roles: vec![BootstrapRole {
            id: role,
            name: format!("bootstrap-denied-role-{role}"),
            tenant_id: Some(tenant),
            description: None,
            permission_blocks: vec![block],
        }],
        role_assignments: vec![BootstrapRoleAssignment {
            id: assignment,
            tenant_id: Some(tenant),
            subject: BootstrapSubject {
                kind: SubjectKind::Entity,
                id: device,
            },
            role_id: role,
        }],
        ..Default::default()
    };

    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("guardrail must reject assignment");
    assert!(err.to_string().contains("guardrail rejected"));
    let assignment_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM role_assignments WHERE id = $1)")
            .bind(assignment)
            .fetch_one(&p)
            .await
            .expect("assignment lookup");
    assert!(
        !assignment_exists,
        "rejected assignment must not be persisted"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_rejects_invalid_and_drifted_assignment_rules() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let action = format!("bootstrap.rule.{tenant}");
    let capability = BootstrapCapability {
        name: action.clone(),
        description: None,
        applicability: vec![BootstrapCapabilityApplicability {
            object_kind: ObjectKind::Resource,
            object_type: Some("resource:channel".to_string()),
        }],
    };
    let invalid = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        capabilities: vec![capability.clone()],
        action_assignment_rules: vec![BootstrapActionAssignmentRule {
            tenant_id: Some(tenant),
            entity_kind: EntityKind::Device,
            action_name: action.clone(),
            object_kind: ObjectKind::Resource,
            object_type: Some("resource:channel".to_string()),
            decision: ActionAssignmentDecision::Allow,
            is_absolute: false,
        }],
        ..Default::default()
    };
    let err = apply(&p, &signing_keys, &invalid)
        .await
        .expect_err("tenant allow rule is invalid in v1");
    assert!(err.to_string().contains("can only deny"));

    let mut first = invalid;
    first.action_assignment_rules[0].tenant_id = None;
    apply(&p, &signing_keys, &first)
        .await
        .expect("valid platform allow rule");
    let mut drifted = first;
    drifted.action_assignment_rules[0].decision = ActionAssignmentDecision::Deny;
    let err = apply(&p, &signing_keys, &drifted)
        .await
        .expect_err("opposite decision drift");
    assert!(err.to_string().contains("conflicts with an existing rule"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_access_token_same_id_with_changed_secret_fails_closed() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let entity_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();
    let token =
        |secret_byte: &str| format!("atom_{}_{}", credential_id.simple(), secret_byte.repeat(64));
    let config = |token: String| BootstrapConfig {
        entities: vec![BootstrapEntity {
            id: entity_id,
            kind: EntityKind::Service,
            name: format!("bootstrap-service-{entity_id}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: None,
            credentials: vec![BootstrapCredential::AccessToken {
                token,
                name: "stable-token".to_string(),
                description: Some("bootstrap test".to_string()),
            }],
        }],
        ..Default::default()
    };
    apply(&p, &signing_keys, &config(token("1")))
        .await
        .expect("first token apply");
    let err = apply(&p, &signing_keys, &config(token("2")))
        .await
        .expect_err("same id with changed secret");
    assert!(err.to_string().contains("different owner, kind, status"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_object_group_child_before_parent_works_with_one_connection() {
    let p = single_connection_pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let child = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let object_group = |id, parent| BootstrapObjectGroup {
        id,
        name: format!("bootstrap-object-group-{id}"),
        tenant_id: Some(tenant),
        description: None,
        attributes: None,
        parent,
        entities: vec![],
        resources: vec![],
    };
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        // The child deliberately precedes its parent. Row creation must finish
        // before links are applied, without borrowing another pool connection.
        object_groups: vec![
            object_group(child, Some(parent)),
            object_group(parent, None),
        ],
        ..Default::default()
    };

    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        apply(&p, &signing_keys, &cfg),
    )
    .await
    .expect("single-connection bootstrap must not deadlock")
    .expect("child-before-parent bootstrap");

    let linked: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1 FROM object_group_hierarchy
               WHERE child_id = $1 AND parent_id = $2
           )"#,
    )
    .bind(child)
    .bind(parent)
    .fetch_one(&p)
    .await
    .expect("child-parent link");
    assert!(linked);
}

#[tokio::test]
#[ignore]
async fn bootstrap_object_group_rejects_cross_tenant_entity_membership() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let entity_tenant = Uuid::new_v4();
    let group_tenant = Uuid::new_v4();
    let entity = Uuid::new_v4();
    let group = Uuid::new_v4();
    let tenant = |id| BootstrapTenant {
        id,
        name: format!("bootstrap-tenant-{id}"),
        alias: None,
        tags: vec![],
        attributes: None,
        status: TenantStatus::Active,
    };
    let cfg = BootstrapConfig {
        tenants: vec![tenant(entity_tenant), tenant(group_tenant)],
        entities: vec![BootstrapEntity {
            id: entity,
            kind: EntityKind::Device,
            name: format!("bootstrap-device-{entity}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: Some(entity_tenant),
            credentials: vec![],
        }],
        object_groups: vec![BootstrapObjectGroup {
            id: group,
            name: format!("bootstrap-object-group-{group}"),
            tenant_id: Some(group_tenant),
            description: None,
            attributes: None,
            parent: None,
            entities: vec![entity],
            resources: vec![],
        }],
        ..Default::default()
    };
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("cross-tenant membership");
    assert!(err.to_string().contains("same tenant"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_object_group_late_failure_rolls_back_the_whole_batch() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let tenant_entity = Uuid::new_v4();
    let platform_entity = Uuid::new_v4();
    let valid_group = Uuid::new_v4();
    let invalid_group = Uuid::new_v4();
    let entity = |id, tenant_id| BootstrapEntity {
        id,
        kind: EntityKind::Device,
        name: format!("bootstrap-device-{id}"),
        alias: None,
        status: EntityStatus::Active,
        attributes: None,
        tenant_id,
        credentials: vec![],
    };
    let object_group = |id, entity_id| BootstrapObjectGroup {
        id,
        name: format!("bootstrap-object-group-{id}"),
        tenant_id: Some(tenant),
        description: None,
        attributes: None,
        parent: None,
        entities: vec![entity_id],
        resources: vec![],
    };
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![
            entity(tenant_entity, Some(tenant)),
            entity(platform_entity, None),
        ],
        object_groups: vec![
            object_group(valid_group, tenant_entity),
            object_group(invalid_group, platform_entity),
        ],
        ..Default::default()
    };

    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("second object group has an invalid member");
    assert!(err.to_string().contains("platform entity"));

    let group_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM object_groups WHERE id = ANY($1::uuid[])")
            .bind(vec![valid_group, invalid_group])
            .fetch_one(&p)
            .await
            .expect("count rolled-back object groups");
    assert_eq!(group_count, 0, "all object-group rows must roll back");
    let membership_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_entities WHERE group_id = ANY($1::uuid[])",
    )
    .bind(vec![valid_group, invalid_group])
    .fetch_one(&p)
    .await
    .expect("count rolled-back object-group memberships");
    assert_eq!(
        membership_count, 0,
        "earlier links in the batch must roll back"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_object_group_rejects_platform_entity_membership() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let entity = Uuid::new_v4();
    let group = Uuid::new_v4();
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        entities: vec![BootstrapEntity {
            id: entity,
            kind: EntityKind::Device,
            name: format!("bootstrap-device-{entity}"),
            alias: None,
            status: EntityStatus::Active,
            attributes: None,
            tenant_id: None,
            credentials: vec![],
        }],
        object_groups: vec![BootstrapObjectGroup {
            id: group,
            name: format!("bootstrap-object-group-{group}"),
            tenant_id: Some(tenant),
            description: None,
            attributes: None,
            parent: None,
            entities: vec![entity],
            resources: vec![],
        }],
        ..Default::default()
    };
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("platform membership");
    assert!(err.to_string().contains("platform entity"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_object_group_rejects_deleted_resource_membership() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let resource = Uuid::new_v4();
    let group = Uuid::new_v4();
    let base = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        resources: vec![BootstrapResource {
            id: resource,
            kind: "channel".to_string(),
            name: Some(format!("bootstrap-resource-{resource}")),
            alias: None,
            tenant_id: Some(tenant),
            owner_id: None,
            attributes: None,
        }],
        ..Default::default()
    };
    apply(&p, &signing_keys, &base).await.expect("base apply");
    sqlx::query("UPDATE resources SET deleted_at = now() WHERE id = $1")
        .bind(resource)
        .execute(&p)
        .await
        .expect("delete resource");
    let cfg = BootstrapConfig {
        object_groups: vec![BootstrapObjectGroup {
            id: group,
            name: format!("bootstrap-object-group-{group}"),
            tenant_id: Some(tenant),
            description: None,
            attributes: None,
            parent: None,
            entities: vec![],
            resources: vec![resource],
        }],
        ..Default::default()
    };
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("deleted resource membership");
    assert!(err.to_string().contains("reference is invalid"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_object_group_hierarchy_rejects_cycle() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let object_group = |id, parent| BootstrapObjectGroup {
        id,
        name: format!("bootstrap-object-group-{id}"),
        tenant_id: Some(tenant),
        description: None,
        attributes: None,
        parent: Some(parent),
        entities: vec![],
        resources: vec![],
    };
    let cfg = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        object_groups: vec![object_group(first, second), object_group(second, first)],
        ..Default::default()
    };
    let err = apply(&p, &signing_keys, &cfg)
        .await
        .expect_err("hierarchy cycle");
    assert!(err.to_string().contains("cycle"));

    let group_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM object_groups WHERE id = ANY($1::uuid[])")
            .bind(vec![first, second])
            .fetch_one(&p)
            .await
            .expect("count cycle object groups");
    assert_eq!(group_count, 0, "cycle must roll back inserted groups");
    let hierarchy_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_hierarchy WHERE child_id = ANY($1::uuid[])",
    )
    .bind(vec![first, second])
    .fetch_one(&p)
    .await
    .expect("count cycle hierarchy rows");
    assert_eq!(
        hierarchy_count, 0,
        "cycle must roll back the first parent link"
    );
}

#[tokio::test]
#[ignore]
async fn bootstrap_id_reuse_rejects_grant_semantic_drift() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let block = Uuid::new_v4();
    let role = Uuid::new_v4();
    let assignment = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let mut base = rbac_config(tenant, device, block, role, assignment);
    base.direct_policies = vec![BootstrapDirectPolicy {
        id: policy,
        tenant_id: Some(tenant),
        subject: BootstrapSubject {
            kind: SubjectKind::Entity,
            id: device,
        },
        permission_block_id: block,
    }];
    apply(&p, &signing_keys, &base).await.expect("base graph");

    let mut drifted_block = base.clone();
    drifted_block.permission_blocks[0].conditions = Some(json!({ "context.site": "other" }));
    let err = apply(&p, &signing_keys, &drifted_block)
        .await
        .expect_err("permission block drift");
    assert!(err.to_string().contains("permission block"));
    assert!(err.to_string().contains("different semantics"));

    let mut drifted_role = base.clone();
    drifted_role.roles[0].name = format!("different-role-{role}");
    let err = apply(&p, &signing_keys, &drifted_role)
        .await
        .expect_err("role drift");
    assert!(err.to_string().contains("role"));
    assert!(err.to_string().contains("different semantics"));

    let other = BootstrapEntity {
        id: other_device,
        kind: EntityKind::Device,
        name: format!("bootstrap-device-{other_device}"),
        alias: None,
        status: EntityStatus::Active,
        attributes: None,
        tenant_id: Some(tenant),
        credentials: vec![],
    };
    let mut drifted_assignment = base.clone();
    drifted_assignment.entities.push(other.clone());
    drifted_assignment.role_assignments[0].subject.id = other_device;
    let err = apply(&p, &signing_keys, &drifted_assignment)
        .await
        .expect_err("role assignment drift");
    assert!(err.to_string().contains("role assignment"));
    assert!(err.to_string().contains("different semantics"));

    let mut drifted_policy = base;
    drifted_policy.entities.push(other);
    drifted_policy.direct_policies[0].subject.id = other_device;
    let err = apply(&p, &signing_keys, &drifted_policy)
        .await
        .expect_err("direct policy drift");
    assert!(err.to_string().contains("direct policy"));
    assert!(err.to_string().contains("different semantics"));
}

#[tokio::test]
#[ignore]
async fn bootstrap_existing_object_group_parent_must_match_declaration() {
    let p = pool().await;
    let signing_keys = Config::for_tests().signing_keys;
    let tenant = Uuid::new_v4();
    let child = Uuid::new_v4();
    let first_parent = Uuid::new_v4();
    let second_parent = Uuid::new_v4();
    let object_group = |id, parent| BootstrapObjectGroup {
        id,
        name: format!("bootstrap-object-group-{id}"),
        tenant_id: Some(tenant),
        description: None,
        attributes: None,
        parent,
        entities: vec![],
        resources: vec![],
    };
    let base = BootstrapConfig {
        tenants: vec![BootstrapTenant {
            id: tenant,
            name: format!("bootstrap-tenant-{tenant}"),
            alias: None,
            tags: vec![],
            attributes: None,
            status: TenantStatus::Active,
        }],
        object_groups: vec![
            object_group(first_parent, None),
            object_group(child, Some(first_parent)),
        ],
        ..Default::default()
    };
    apply(&p, &signing_keys, &base)
        .await
        .expect("base hierarchy");

    let mut removed = base.clone();
    removed.object_groups[1].parent = None;
    let err = apply(&p, &signing_keys, &removed)
        .await
        .expect_err("Some to None parent drift");
    assert!(err.to_string().contains("parent declaration differs"));

    let mut changed = base;
    changed
        .object_groups
        .push(object_group(second_parent, None));
    changed.object_groups[1].parent = Some(second_parent);
    let err = apply(&p, &signing_keys, &changed)
        .await
        .expect_err("parent A to B drift");
    assert!(err.to_string().contains("parent declaration differs"));
}
