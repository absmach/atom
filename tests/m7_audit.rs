//! M7 integration tests — audit tenanting and hot-path persistence policy.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m7_audit -- --ignored
//! ```

mod common;

use atom::{
    audit,
    config::AuditPolicyConfig,
    models::{
        access::AuditQuery,
        enums::{AuditOutcome, Effect, GrantKind, ScopeKind, SubjectKind},
        policy::CreatePolicyBinding,
        tenant::CreateTenant,
    },
};
use chrono::Utc;
use common::pool;
use serde_json::json;
use uuid::Uuid;

async fn tenant(pool: &sqlx::PgPool) -> Uuid {
    atom::tenants::repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: format!("m7-{}", Uuid::new_v4()),
            alias: None,
            tags: vec![],
            attributes: serde_json::Value::Null,
        },
        None,
    )
    .await
    .expect("create tenant")
    .id
}

async fn human(pool: &sqlx::PgPool, tenant_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'human', $2, $3, 'active')")
        .bind(id)
        .bind(format!("m7-human-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert human");
    id
}

async fn capability_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("capability")
}

#[tokio::test]
#[ignore]
async fn audit_write_persists_tenant_id() {
    let p = pool().await;
    let t = tenant(&p).await;
    let e = human(&p, Some(t)).await;

    audit::write(
        &p,
        false,
        audit::AuditEvent {
            actor_entity_id: Some(e),
            tenant_id: Some(t),
            target_kind: Some("entity"),
            target_id: Some(e),
            event: "m7.test",
            outcome: AuditOutcome::Allow,
            details: json!({"ok": true}),
        },
    )
    .await;

    let stored: Uuid = sqlx::query_scalar(
        "SELECT tenant_id FROM audit_logs WHERE target_kind = 'entity' AND target_id = $1 AND event = 'm7.test' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(e)
    .fetch_one(&p)
    .await
    .expect("audit tenant id");
    assert_eq!(stored, t);
}

#[tokio::test]
#[ignore]
async fn tenant_audit_filter_returns_only_allowed_tenant_rows() {
    let p = pool().await;
    let t1 = tenant(&p).await;
    let t2 = tenant(&p).await;
    let auditor = human(&p, None).await;

    atom::authz::repo::create_policy(
        &p,
        CreatePolicyBinding {
            tenant_id: Some(t1),
            subject_kind: SubjectKind::Entity,
            subject_id: auditor,
            grant_kind: GrantKind::Capability,
            grant_id: capability_id(&p, "read").await,
            scope_kind: ScopeKind::ObjectKind,
            scope_ref: Some("audit_log".to_string()),
            effect: Effect::Allow,
            conditions: json!({}),
        },
    )
    .await
    .expect("audit log read policy");

    audit::write(
        &p,
        false,
        audit::AuditEvent {
            actor_entity_id: Some(auditor),
            tenant_id: Some(t1),
            target_kind: Some("entity"),
            target_id: Some(auditor),
            event: "m7.visible",
            outcome: AuditOutcome::Allow,
            details: json!({}),
        },
    )
    .await;
    audit::write(
        &p,
        false,
        audit::AuditEvent {
            actor_entity_id: Some(auditor),
            tenant_id: Some(t2),
            target_kind: Some("entity"),
            target_id: Some(auditor),
            event: "m7.hidden",
            outcome: AuditOutcome::Allow,
            details: json!({}),
        },
    )
    .await;

    let allowed =
        atom::authz::repo::tenant_ids_for_action_on_object_kind(&p, auditor, "read", "audit_log")
            .await
            .expect("tenant filter");
    let logs = atom::authz::repo::audit_logs(
        &p,
        AuditQuery {
            actor_entity_id: Some(auditor),
            tenant_id: None,
            target_kind: None,
            target_id: None,
            event: None,
            outcome: None,
            from: Some(Utc::now() - chrono::Duration::minutes(5)),
            to: None,
            limit: 20,
            offset: 0,
        },
        Some(allowed),
    )
    .await
    .expect("audit logs");

    assert!(logs.items.iter().any(|item| item.event == "m7.visible"));
    assert!(!logs.items.iter().any(|item| item.event == "m7.hidden"));
    assert!(logs.items.iter().all(|item| item.tenant_id == Some(t1)));
}

#[tokio::test]
#[ignore]
async fn hot_path_allow_skips_db_audit_by_default() {
    let p = pool().await;
    let entity_id = human(&p, None).await;

    audit::write_hot_path(
        &p,
        AuditPolicyConfig::default(),
        false,
        audit::HotPathAuditKind::AuthLogin,
        audit::AuditEvent {
            actor_entity_id: Some(entity_id),
            tenant_id: None,
            target_kind: Some("entity"),
            target_id: Some(entity_id),
            event: "auth.login",
            outcome: AuditOutcome::Allow,
            details: json!({"identifier": format!("m7-human-{entity_id}")}),
        },
    )
    .await;

    let details: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE actor_entity_id = $1 AND target_kind = 'entity' AND target_id = $1 AND event = 'auth.login' AND outcome = 'allow' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity_id)
    .fetch_optional(&p)
    .await
    .expect("login audit lookup");
    assert!(details.is_none());
}

#[tokio::test]
#[ignore]
async fn hot_path_deny_keeps_db_audit_by_default() {
    let p = pool().await;
    let entity_id = human(&p, None).await;

    audit::write_hot_path(
        &p,
        AuditPolicyConfig::default(),
        false,
        audit::HotPathAuditKind::AuthzCheck,
        audit::AuditEvent {
            actor_entity_id: Some(entity_id),
            tenant_id: None,
            target_kind: Some("resource"),
            target_id: None,
            event: "authz.check",
            outcome: AuditOutcome::Deny,
            details: json!({"action": "publish", "reason": "no matching allow policy"}),
        },
    )
    .await;

    let details: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE actor_entity_id = $1 AND target_kind = 'resource' AND event = 'authz.check' AND outcome = 'deny' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity_id)
    .fetch_one(&p)
    .await
    .expect("deny audit");
    assert_eq!(details["reason"], json!("no matching allow policy"));
}

#[tokio::test]
#[ignore]
async fn hot_path_allow_db_audit_can_be_enabled() {
    let p = pool().await;
    let entity_id = human(&p, None).await;

    audit::write_hot_path(
        &p,
        AuditPolicyConfig {
            hot_path_allow_db_enabled: true,
        },
        false,
        audit::HotPathAuditKind::AuthLogin,
        audit::AuditEvent {
            actor_entity_id: Some(entity_id),
            tenant_id: None,
            target_kind: Some("entity"),
            target_id: Some(entity_id),
            event: "auth.login",
            outcome: AuditOutcome::Allow,
            details: json!({"identifier": format!("m7-human-{entity_id}")}),
        },
    )
    .await;

    let details: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE actor_entity_id = $1 AND target_kind = 'entity' AND target_id = $1 AND event = 'auth.login' AND outcome = 'allow' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity_id)
    .fetch_one(&p)
    .await
    .expect("login audit");
    assert_eq!(
        details["identifier"],
        json!(format!("m7-human-{entity_id}"))
    );
}

/// Create a role carrying one tenant-scoped block (the given effect) for `read`,
/// assigned to `subject`. Returns the role id.
async fn read_role(pool: &sqlx::PgPool, tenant_id: Uuid, subject: Uuid, effect: &str) -> Uuid {
    let read = capability_id(pool, "read").await;
    let role = atom::authz::repo::create_role(
        pool,
        atom::models::role::CreateRole {
            name: format!("m7-role-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, effect) VALUES ('tenant', $1, $2) RETURNING id",
    )
    .bind(tenant_id)
    .bind(effect)
    .fetch_one(pool)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(read)
    .execute(pool)
    .await
    .expect("block action");
    atom::authz::repo::replace_role_permission_block_links(pool, role.id, &[block])
        .await
        .expect("link");
    atom::authz::repo::create_role_assignment(
        pool,
        atom::models::policy::CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: subject,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");
    role.id
}

/// The audit-log tenant filter must honour role-block effect: a role whose only
/// read block is a *deny* must not grant the tenant's audit logs (the legacy
/// query treated any role with a read block as an unconditional allow).
#[tokio::test]
#[ignore]
async fn audit_tenant_filter_honours_role_deny() {
    let p = pool().await;
    let t = tenant(&p).await;
    let denied_subject = human(&p, Some(t)).await;
    let allowed_subject = human(&p, Some(t)).await;

    read_role(&p, t, denied_subject, "deny").await;
    let tenants = atom::authz::repo::tenant_ids_for_action_on_object_kind(
        &p,
        denied_subject,
        "read",
        "audit_log",
    )
    .await
    .expect("tenant ids");
    assert!(
        !tenants.contains(&t),
        "a role whose only read block is a deny must not grant audit access, got: {tenants:?}"
    );

    // Control: a separate subject with an allow role does get the tenant.
    read_role(&p, t, allowed_subject, "allow").await;
    let tenants = atom::authz::repo::tenant_ids_for_action_on_object_kind(
        &p,
        allowed_subject,
        "read",
        "audit_log",
    )
    .await
    .expect("tenant ids");
    assert!(
        tenants.contains(&t),
        "a role with an allow read block must grant audit access"
    );
}
