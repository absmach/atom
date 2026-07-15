//! Config-file bootstrap integration tests (issue #27).
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m25_config_bootstrap -- --ignored
//! ```

mod common;

use atom::bootstrap::{
    apply, BootstrapConfig, BootstrapCredential, BootstrapDirectPolicy, BootstrapEntity,
    BootstrapGroup, BootstrapObjectGroup, BootstrapPermissionBlock, BootstrapResource,
    BootstrapRole, BootstrapRoleAssignment, BootstrapScope, BootstrapSubject, BootstrapTenant,
    ScopeMode,
};
use atom::config::Config;
use atom::models::enums::{EntityKind, EntityStatus, SubjectKind, TenantStatus};
use atom::models::policy::AuthzRequest;
use common::pool;
use serde_json::json;
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

    // A second run declaring a different secret for the same entity must not
    // rotate the existing credential — bootstrap only fills in what is missing.
    let mut changed = credentials_config(human, service);
    changed.entities[0].credentials = vec![BootstrapCredential::Password {
        secret: "a-totally-different-secret".to_string(),
    }];
    apply(&p, &signing_keys, &changed)
        .await
        .expect("second apply");

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
