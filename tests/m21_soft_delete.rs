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
    identity::service,
    models::{
        entity::{ListEntities, UpdateEntity},
        enums::DeletedFilter,
        group::{CreateGroup, ListGroups, UpdateGroup},
        resource::{ListResources, UpdateResource},
        role::{ListRoles, UpdateRole},
        session::PasswordResetConfirmRequest,
        tenant::{CreateTenantInvitation, ListTenants},
        token::CreateApiKey,
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
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, status) VALUES ($1, $2, 'access_token', $3, 'active')")
        .bind(cred_id)
        .bind(id)
        .bind(format!("key-{cred_id}"))
        .execute(&pool)
        .await
        .expect("insert credential");
    let cert_id = Uuid::new_v4();
    let serial = format!("{:032x}", cert_id.as_u128());
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, identifier, status)
         VALUES ($1, $2, 'certificate', $3, 'active')",
    )
    .bind(cert_id)
    .bind(id)
    .bind(&serial)
    .execute(&pool)
    .await
    .expect("insert certificate credential");
    let issuer = format!("sd-issuer-{cert_id}");
    sqlx::query(
        "INSERT INTO certificate_crl_state (issuer_fingerprint_sha256, dirty)
         VALUES ($1, FALSE)",
    )
    .bind(&issuer)
    .execute(&pool)
    .await
    .expect("insert crl state");
    let session_id = atom::identity::repo::create_session(&pool, id, 3600)
        .await
        .expect("create session")
        .id;

    atom::identity::repo::delete_entity(&pool, id, None)
        .await
        .expect("soft delete entity");

    // Hidden from reads.
    assert!(atom::identity::repo::get_entity(&pool, id).await.is_err());

    // Tombstone set; credential revoked; session revoked — all immediately.
    let (status, deleted_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deleted_at FROM entities WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("entity row still present");
    assert_eq!(status, "inactive", "deleted entities must be disabled");
    assert!(deleted_at.is_some(), "entity should carry a tombstone");

    let cred_status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&pool)
        .await
        .expect("credential");
    assert_eq!(cred_status, "revoked");
    let (cert_status, cert_metadata): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, metadata FROM credentials WHERE id = $1")
            .bind(cert_id)
            .fetch_one(&pool)
            .await
            .expect("certificate credential");
    assert_eq!(cert_status, "revoked");
    assert_eq!(
        cert_metadata
            .get("revocation_reason")
            .and_then(serde_json::Value::as_str),
        Some("entity_deleted")
    );
    assert!(
        cert_metadata.get("revoked_at").is_some(),
        "certificate revocation time should be recorded"
    );
    let crl_dirty: bool = sqlx::query_scalar(
        "SELECT dirty FROM certificate_crl_state WHERE issuer_fingerprint_sha256 = $1",
    )
    .bind(&issuer)
    .fetch_one(&pool)
    .await
    .expect("crl state");
    assert!(crl_dirty, "entity certificate revocation should dirty CRLs");

    let revoked: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .expect("session");
    assert!(revoked.is_some(), "session should be revoked");

    assert!(
        atom::identity::repo::create_session(&pool, id, 3600)
            .await
            .is_err(),
        "deleted entity must not receive a new session"
    );
    assert!(
        service::create_password(&pool, id, "replacement-secret")
            .await
            .is_err(),
        "deleted entity must not receive a new password"
    );
    assert!(
        service::create_api_key(
            &pool,
            id,
            CreateApiKey {
                expires_at: None,
                description: None,
            },
        )
        .await
        .is_err(),
        "deleted entity must not receive a new API key"
    );
    assert!(
        atom::certs::repo::entity_tenant_id(&pool, id)
            .await
            .is_err(),
        "deleted entity must not be eligible for certificate authentication"
    );
}

#[tokio::test]
#[ignore]
async fn deleted_entity_cannot_consume_existing_password_reset_token() {
    let pool = common::pool().await;
    let id = make_entity(&pool, &format!("sd-reset-{}", Uuid::new_v4()), None).await;
    let email_id = Uuid::new_v4();
    sqlx::query("INSERT INTO entity_emails (id, entity_id, email) VALUES ($1, $2, $3)")
        .bind(email_id)
        .bind(id)
        .bind(format!("{id}@example.com"))
        .execute(&pool)
        .await
        .expect("insert email");

    let token_id = Uuid::new_v4();
    let token_secret = "ab".repeat(32);
    let token = format!(
        "atomr_{}_{}",
        hex::encode(token_id.as_bytes()),
        token_secret
    );
    let token_hash = service::hash_secret(token_secret.as_bytes()).expect("hash token");
    sqlx::query(
        r#"INSERT INTO password_reset_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, now() + interval '1 hour')"#,
    )
    .bind(token_id)
    .bind(id)
    .bind(email_id)
    .bind(token_hash)
    .execute(&pool)
    .await
    .expect("insert reset token");

    atom::identity::repo::delete_entity(&pool, id, None)
        .await
        .expect("soft delete entity");

    assert!(
        service::reset_password(
            &pool,
            PasswordResetConfirmRequest {
                token,
                password: "replacement-password".to_string(),
                confirm_password: Some("replacement-password".to_string()),
            },
        )
        .await
        .is_err(),
        "deleted entity must not reset its password"
    );

    let consumed_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT consumed_at FROM password_reset_tokens WHERE id = $1")
            .bind(token_id)
            .fetch_one(&pool)
            .await
            .expect("reset token");
    assert!(
        consumed_at.is_none(),
        "rejected reset token must remain unconsumed"
    );
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
async fn email_is_reusable_after_soft_delete() {
    let pool = common::pool().await;
    let email = format!("sd-reuse-{}@example.com", Uuid::new_v4());

    let first = make_entity(&pool, &format!("sd-email-{}", Uuid::new_v4()), None).await;
    sqlx::query("INSERT INTO entity_emails (id, entity_id, email) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(first)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("insert first email");

    atom::identity::repo::delete_entity(&pool, first, None)
        .await
        .expect("soft delete first");

    // The email row is tombstoned alongside the entity.
    let deleted_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM entity_emails WHERE entity_id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .expect("first email row");
    assert!(
        deleted_at.is_some(),
        "soft delete must tombstone the entity's email"
    );

    // The OAuth lookup (which filters deleted rows) no longer resolves the address
    // to the tombstoned entity, so a returning user re-onboards as a new entity.
    let resolved: Option<Uuid> = sqlx::query_scalar(
        "SELECT entity_id FROM entity_emails WHERE email = $1 AND deleted_at IS NULL",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .expect("oauth lookup");
    assert_eq!(resolved, None, "tombstoned email must not resolve");

    // Re-registering the same address on a fresh entity must succeed now that the
    // unique index is partial on deleted_at IS NULL.
    let second = make_entity(&pool, &format!("sd-email-{}", Uuid::new_v4()), None).await;
    sqlx::query("INSERT INTO entity_emails (id, entity_id, email) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(second)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("re-register email on a fresh entity");
    assert_ne!(first, second);
}

#[tokio::test]
#[ignore]
async fn invitation_by_email_does_not_resolve_to_soft_deleted_user() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-inv-email-ten-{}", Uuid::new_v4())).await;
    let inviter = make_entity(&pool, &format!("sd-inv-email-by-{}", Uuid::new_v4()), None).await;

    let email = format!("sd-inv-{}@example.com", Uuid::new_v4());
    let stale = make_entity(&pool, &format!("sd-inv-stale-{}", Uuid::new_v4()), None).await;
    sqlx::query("INSERT INTO entity_emails (id, entity_id, email) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(stale)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("insert stale email");
    atom::identity::repo::delete_entity(&pool, stale, None)
        .await
        .expect("soft delete stale user");

    // Inviting that address must create a pending email invitation, not bind the
    // invite to the tombstoned entity.
    let created = atom::tenants::repo::create_invitation(
        &pool,
        tenant_id,
        inviter,
        CreateTenantInvitation {
            invitee_user_id: None,
            invitee_email: Some(email),
            role_id: None,
            resend: false,
            redirect_url: None,
        },
        3600,
    )
    .await
    .expect("create invitation");
    assert_eq!(
        created.invitation.invitee_user_id, None,
        "invitation must not resolve to a soft-deleted user"
    );
}

#[tokio::test]
#[ignore]
async fn create_group_requires_explicit_group_type() {
    let pool = common::pool().await;
    let id = Uuid::new_v4();

    let err = atom::identity::repo::create_group(
        &pool,
        CreateGroup {
            id: Some(id),
            name: format!("sd-grp-requires-type-{id}"),
            tenant_id: None,
            group_type: None,
            description: None,
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect_err("missing group type should fail");
    assert!(
        err.to_string().contains("groupType is required"),
        "unexpected error: {err}"
    );

    let principal_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM principal_groups WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("principal group count");
    let object_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM object_groups WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("object group count");
    assert_eq!(principal_count, 0);
    assert_eq!(object_count, 0);
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
async fn soft_deleted_objects_are_read_only() {
    let pool = common::pool().await;

    let entity_id = make_entity(
        &pool,
        &format!("sd-readonly-entity-{}", Uuid::new_v4()),
        None,
    )
    .await;
    atom::identity::repo::delete_entity(&pool, entity_id, None)
        .await
        .expect("delete entity");
    assert!(
        atom::identity::repo::update_entity(
            &pool,
            entity_id,
            UpdateEntity {
                name: Some("mutated".to_string()),
                kind: None,
                alias: None,
                tenant_id: None,
                profile_id: None,
                profile_version_id: None,
                status: None,
                attributes: None,
            },
        )
        .await
        .is_err(),
        "deleted entity must reject updates"
    );

    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO object_groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(format!("sd-readonly-group-{group_id}"))
        .execute(&pool)
        .await
        .expect("insert group");
    atom::identity::repo::delete_group(&pool, group_id, None)
        .await
        .expect("delete group");
    assert!(
        atom::identity::repo::update_group(
            &pool,
            group_id,
            UpdateGroup {
                name: Some("mutated".to_string()),
                description: None,
                status: None,
                attributes: None,
            },
        )
        .await
        .is_err(),
        "deleted group must reject updates"
    );

    let resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(resource_id)
        .bind(format!("sd-readonly-resource-{resource_id}"))
        .execute(&pool)
        .await
        .expect("insert resource");
    atom::authz::repo::delete_resource(&pool, resource_id, None)
        .await
        .expect("delete resource");
    assert!(
        atom::authz::repo::update_resource(
            &pool,
            resource_id,
            UpdateResource {
                name: Some("mutated".to_string()),
                alias: None,
                attributes: None,
            },
        )
        .await
        .is_err(),
        "deleted resource must reject updates"
    );

    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(role_id)
        .bind(format!("sd-readonly-role-{role_id}"))
        .execute(&pool)
        .await
        .expect("insert role");
    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");
    assert!(
        atom::authz::repo::update_role(
            &pool,
            role_id,
            UpdateRole {
                name: Some("mutated".to_string()),
                description: None,
            },
        )
        .await
        .is_err(),
        "deleted role must reject updates"
    );
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
            attributes_contains: None,
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
            attributes_contains: None,
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
    let mut old_exists = true;
    for _ in 0..20 {
        atom::purge::purge_expired(&pool, cfg).await.expect("purge");
        old_exists = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM entities WHERE id = $1)")
            .bind(old)
            .fetch_one(&pool)
            .await
            .expect("check old");
        if !old_exists {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
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
async fn purge_limits_each_table_to_one_configured_batch_per_run() {
    let pool = common::pool().await;
    let cfg = PurgeConfig {
        enabled: true,
        retention_days: 90,
        interval_secs: 1,
        batch_size: 1,
    };
    let mut surviving_pair = None;

    // Other purge tests in this integration binary run in parallel and share
    // the same advisory lock. Retry with a fresh pair if another test's purge
    // consumes both rows, and wait if this invocation loses the lock.
    'pairs: for _ in 0..10 {
        let first = make_entity(&pool, &format!("sd-batch-a-{}", Uuid::new_v4()), None).await;
        let second = make_entity(&pool, &format!("sd-batch-b-{}", Uuid::new_v4()), None).await;
        let ids = vec![first, second];
        sqlx::query(
            r#"UPDATE entities
               SET deleted_at = CASE
                   WHEN id = $1 THEN now() - interval '1001 days'
                   ELSE now() - interval '1000 days'
               END
               WHERE id = ANY($2)"#,
        )
        .bind(first)
        .bind(&ids)
        .execute(&pool)
        .await
        .expect("age tombstones");

        for _ in 0..20 {
            atom::purge::purge_expired(&pool, cfg)
                .await
                .expect("first purge");
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM entities WHERE id = ANY($1)")
                    .bind(&ids)
                    .fetch_one(&pool)
                    .await
                    .expect("count after first purge");
            match remaining {
                1 => {
                    surviving_pair = Some(ids);
                    break 'pairs;
                }
                2 => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                0 => continue 'pairs,
                other => panic!("unexpected remaining entity count {other}"),
            }
        }
    }

    let ids = surviving_pair.expect("a purge run should observe one bounded entity batch");
    for _ in 0..20 {
        atom::purge::purge_expired(&pool, cfg)
            .await
            .expect("second purge");
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entities WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_one(&pool)
            .await
            .expect("count after second purge");
        if remaining == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the next bounded purge run should remove the surviving row");
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

    let before = atom::authz::engine::evaluate(&pool, &req, None)
        .await
        .expect("evaluate before");
    assert!(before.allowed, "role should grant read before deletion");

    atom::authz::repo::delete_role(&pool, role_id, None)
        .await
        .expect("delete role");

    let after = atom::authz::engine::evaluate(&pool, &req, None)
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
async fn composite_role_helpers_reject_deleted_child_roles() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-comp-ten-{}", Uuid::new_v4())).await;
    let parent_role = Uuid::new_v4();
    let child_role = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3), ($4, $5, $3)")
        .bind(parent_role)
        .bind(format!("sd-comp-parent-{parent_role}"))
        .bind(tenant_id)
        .bind(child_role)
        .bind(format!("sd-comp-child-{child_role}"))
        .execute(&pool)
        .await
        .expect("roles");
    atom::authz::repo::delete_role(&pool, child_role, None)
        .await
        .expect("delete child role");

    assert!(
        atom::authz::repo::add_composite_role_child(&pool, parent_role, child_role)
            .await
            .is_err(),
        "deleted child roles must not be copied into live parents"
    );
    assert!(
        atom::authz::repo::replace_composite_role_children(&pool, parent_role, &[child_role])
            .await
            .is_err(),
        "deleted replacement children must not be copied into live parents"
    );
    let copied_blocks: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM role_permission_blocks WHERE role_id = $1")
            .bind(parent_role)
            .fetch_one(&pool)
            .await
            .expect("parent block count");
    assert_eq!(copied_blocks, 0);
}

#[tokio::test]
#[ignore]
async fn set_group_parent_rejects_deleted_parent_or_child() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-grp-parent-ten-{}", Uuid::new_v4())).await;
    let live_parent = Uuid::new_v4();
    let deleted_parent = Uuid::new_v4();
    let live_child = Uuid::new_v4();
    let deleted_child = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO object_groups (id, name, tenant_id)
         VALUES ($1, $2, $5), ($3, $4, $5), ($6, $7, $5), ($8, $9, $5)",
    )
    .bind(live_parent)
    .bind(format!("sd-live-parent-{live_parent}"))
    .bind(deleted_parent)
    .bind(format!("sd-deleted-parent-{deleted_parent}"))
    .bind(tenant_id)
    .bind(live_child)
    .bind(format!("sd-live-child-{live_child}"))
    .bind(deleted_child)
    .bind(format!("sd-deleted-child-{deleted_child}"))
    .execute(&pool)
    .await
    .expect("groups");
    atom::identity::repo::delete_group(&pool, deleted_parent, None)
        .await
        .expect("delete parent");
    atom::identity::repo::delete_group(&pool, deleted_child, None)
        .await
        .expect("delete child");

    assert!(
        atom::identity::repo::set_group_parent(&pool, live_child, deleted_parent)
            .await
            .is_err(),
        "live group must not be moved under a deleted parent"
    );
    assert!(
        atom::identity::repo::set_group_parent(&pool, deleted_child, live_parent)
            .await
            .is_err(),
        "deleted group must not be moved under a live parent"
    );
    let hierarchy_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_hierarchy
         WHERE child_id = $1 OR child_id = $2 OR parent_id = $3",
    )
    .bind(live_child)
    .bind(deleted_child)
    .bind(deleted_parent)
    .fetch_one(&pool)
    .await
    .expect("hierarchy count");
    assert_eq!(hierarchy_rows, 0);
}

#[tokio::test]
#[ignore]
async fn set_resource_parent_group_rejects_deleted_resource_or_group() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, &format!("sd-res-parent-ten-{}", Uuid::new_v4())).await;
    let live_resource = Uuid::new_v4();
    let deleted_resource = Uuid::new_v4();
    let live_group = Uuid::new_v4();
    let deleted_group = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO resources (id, kind, name, tenant_id)
         VALUES ($1, 'channel', $2, $5), ($3, 'channel', $4, $5)",
    )
    .bind(live_resource)
    .bind(format!("sd-live-resource-{live_resource}"))
    .bind(deleted_resource)
    .bind(format!("sd-deleted-resource-{deleted_resource}"))
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("resources");
    sqlx::query(
        "INSERT INTO object_groups (id, name, tenant_id)
         VALUES ($1, $2, $5), ($3, $4, $5)",
    )
    .bind(live_group)
    .bind(format!("sd-live-res-group-{live_group}"))
    .bind(deleted_group)
    .bind(format!("sd-deleted-res-group-{deleted_group}"))
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("groups");
    atom::authz::repo::delete_resource(&pool, deleted_resource, None)
        .await
        .expect("delete resource");
    atom::identity::repo::delete_group(&pool, deleted_group, None)
        .await
        .expect("delete group");

    assert!(
        atom::authz::repo::set_resource_parent_group(&pool, live_resource, deleted_group)
            .await
            .is_err(),
        "live resource must not be attached to a deleted object group"
    );
    assert!(
        atom::authz::repo::set_resource_parent_group(&pool, deleted_resource, live_group)
            .await
            .is_err(),
        "deleted resource must not be attached to a live object group"
    );
    let edges: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_resources
         WHERE resource_id = $1 OR resource_id = $2 OR group_id = $3",
    )
    .bind(live_resource)
    .bind(deleted_resource)
    .bind(deleted_group)
    .fetch_one(&pool)
    .await
    .expect("resource group edge count");
    assert_eq!(edges, 0);
}

#[tokio::test]
#[ignore]
async fn soft_delete_tenant_marks_and_revokes_child_credentials_and_sessions() {
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
    let api_key_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, identifier, status)
         VALUES ($1, $2, 'access_token', $3, 'active')",
    )
    .bind(api_key_id)
    .bind(entity_id)
    .bind(format!("sd-api-{api_key_id}"))
    .execute(&pool)
    .await
    .expect("insert api credential");
    let cert_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, identifier, status)
         VALUES ($1, $2, 'certificate', $3, 'active')",
    )
    .bind(cert_id)
    .bind(entity_id)
    .bind(format!("{:032x}", cert_id.as_u128()))
    .execute(&pool)
    .await
    .expect("insert certificate credential");
    let issuer = format!("sd-tenant-issuer-{cert_id}");
    sqlx::query(
        "INSERT INTO certificate_crl_state (issuer_fingerprint_sha256, dirty)
         VALUES ($1, FALSE)",
    )
    .bind(&issuer)
    .execute(&pool)
    .await
    .expect("insert crl state");

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
    let api_status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(api_key_id)
        .fetch_one(&pool)
        .await
        .expect("api credential");
    assert_eq!(api_status, "revoked");
    let (cert_status, cert_metadata): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, metadata FROM credentials WHERE id = $1")
            .bind(cert_id)
            .fetch_one(&pool)
            .await
            .expect("certificate credential");
    assert_eq!(cert_status, "revoked");
    assert_eq!(
        cert_metadata
            .get("revocation_reason")
            .and_then(serde_json::Value::as_str),
        Some("tenant_deleted")
    );
    assert!(
        cert_metadata.get("revoked_at").is_some(),
        "certificate revocation time should be recorded"
    );
    let crl_dirty: bool = sqlx::query_scalar(
        "SELECT dirty FROM certificate_crl_state WHERE issuer_fingerprint_sha256 = $1",
    )
    .bind(&issuer)
    .fetch_one(&pool)
    .await
    .expect("crl state");
    assert!(crl_dirty, "tenant certificate revocation should dirty CRLs");

    // Tenant is hidden from reads.
    assert!(atom::tenants::repo::get_tenant(&pool, tenant_id)
        .await
        .is_err());
}

#[tokio::test]
#[ignore]
async fn invitation_acceptance_rejects_deleted_tenant_subject_and_role_atomically() {
    async fn invitation_state(
        pool: &sqlx::PgPool,
        invitation_id: Uuid,
        tenant_id: Uuid,
        invitee_id: Uuid,
    ) -> (Option<chrono::DateTime<chrono::Utc>>, i64, i64) {
        let accepted_at =
            sqlx::query_scalar("SELECT accepted_at FROM tenant_invitations WHERE id = $1")
                .bind(invitation_id)
                .fetch_one(pool)
                .await
                .expect("invitation accepted_at");
        let memberships = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id = $1 AND entity_id = $2",
        )
        .bind(tenant_id)
        .bind(invitee_id)
        .fetch_one(pool)
        .await
        .expect("membership count");
        let assignments = sqlx::query_scalar(
            "SELECT COUNT(*) FROM role_assignments WHERE tenant_id = $1 AND subject_id = $2",
        )
        .bind(tenant_id)
        .bind(invitee_id)
        .fetch_one(pool)
        .await
        .expect("assignment count");
        (accepted_at, memberships, assignments)
    }

    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("sd-inviter-{}", Uuid::new_v4()), None).await;

    let deleted_tenant = make_tenant(&pool, &format!("sd-inv-del-ten-{}", Uuid::new_v4())).await;
    let tenant_invitee = make_entity(&pool, &format!("sd-inv-user-{}", Uuid::new_v4()), None).await;
    let deleted_tenant_invitation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenant_invitations
           (id, tenant_id, invitee_user_id, invited_by, expires_at)
         VALUES ($1, $2, $3, $4, now() + interval '1 hour')",
    )
    .bind(deleted_tenant_invitation)
    .bind(deleted_tenant)
    .bind(tenant_invitee)
    .bind(inviter)
    .execute(&pool)
    .await
    .expect("deleted tenant invitation");
    atom::tenants::repo::soft_delete_tenant(&pool, deleted_tenant, None)
        .await
        .expect("delete tenant");
    assert!(
        atom::tenants::repo::accept_invitation(&pool, deleted_tenant, tenant_invitee)
            .await
            .is_err(),
        "deleted tenant invitation must not be accepted"
    );
    assert_eq!(
        invitation_state(
            &pool,
            deleted_tenant_invitation,
            deleted_tenant,
            tenant_invitee
        )
        .await,
        (None, 0, 0)
    );

    let deleted_subject_tenant =
        make_tenant(&pool, &format!("sd-inv-del-sub-ten-{}", Uuid::new_v4())).await;
    let deleted_subject = make_entity(
        &pool,
        &format!("sd-inv-deleted-user-{}", Uuid::new_v4()),
        None,
    )
    .await;
    let deleted_subject_invitation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenant_invitations
           (id, tenant_id, invitee_user_id, invited_by, expires_at)
         VALUES ($1, $2, $3, $4, now() + interval '1 hour')",
    )
    .bind(deleted_subject_invitation)
    .bind(deleted_subject_tenant)
    .bind(deleted_subject)
    .bind(inviter)
    .execute(&pool)
    .await
    .expect("deleted subject invitation");
    atom::identity::repo::delete_entity(&pool, deleted_subject, None)
        .await
        .expect("delete subject");
    assert!(
        atom::tenants::repo::accept_invitation(&pool, deleted_subject_tenant, deleted_subject)
            .await
            .is_err(),
        "deleted invitee must not be accepted"
    );
    assert_eq!(
        invitation_state(
            &pool,
            deleted_subject_invitation,
            deleted_subject_tenant,
            deleted_subject
        )
        .await,
        (None, 0, 0)
    );

    let deleted_role_tenant =
        make_tenant(&pool, &format!("sd-inv-del-role-ten-{}", Uuid::new_v4())).await;
    let role_invitee =
        make_entity(&pool, &format!("sd-inv-role-user-{}", Uuid::new_v4()), None).await;
    let deleted_role = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(deleted_role)
        .bind(format!("sd-inv-role-{deleted_role}"))
        .bind(deleted_role_tenant)
        .execute(&pool)
        .await
        .expect("role");
    let deleted_role_invitation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenant_invitations
           (id, tenant_id, invitee_user_id, invited_by, role_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + interval '1 hour')",
    )
    .bind(deleted_role_invitation)
    .bind(deleted_role_tenant)
    .bind(role_invitee)
    .bind(inviter)
    .bind(deleted_role)
    .execute(&pool)
    .await
    .expect("deleted role invitation");
    atom::authz::repo::delete_role(&pool, deleted_role, None)
        .await
        .expect("delete role");
    assert!(
        atom::tenants::repo::accept_invitation(&pool, deleted_role_tenant, role_invitee)
            .await
            .is_err(),
        "deleted role invitation must not be accepted"
    );
    assert_eq!(
        invitation_state(
            &pool,
            deleted_role_invitation,
            deleted_role_tenant,
            role_invitee
        )
        .await,
        (None, 0, 0)
    );
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
                attributes_contains: None,
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
                attributes_contains: None,
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
        None,
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
