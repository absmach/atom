//! Regression tests for the authorization-filtered tenant listing
//! (`list_tenants_for_entity`).
//!
//! The listing used synthetic role-allow edges plus action containment and only
//! direct group membership, so a role-linked *deny* on a tenant was ignored
//! (the tenant stayed visible) and a role reaching the caller through a *parent*
//! group was missed (the tenant was hidden). It now reads the canonical grant
//! model: real block effect/conditions, recursive groups, the assignment tenant
//! boundary, and deny-override.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m19_tenant_listing -- --ignored
//! ```

mod common;

use atom::models::enums::{DeletedFilter, Effect, GrantKind, ScopeKind, SubjectKind};
use atom::models::policy::{CreatePolicyBinding, CreateRoleAssignment};
use atom::models::role::CreateRole;
use atom::models::tenant::ListTenants;
use common::pool;
use serde_json::json;
use uuid::Uuid;

fn actx(id: Uuid) -> atom::auth::AuthContext {
    atom::auth::AuthContext {
        entity_id: id,
        ..Default::default()
    }
}

async fn make_tenant(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("m19-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_human(pool: &sqlx::PgPool, tenant_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'human', $2, $3, 'active')")
        .bind(id)
        .bind(format!("m19-ent-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn make_channel(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', $2, $3)")
        .bind(id)
        .bind(format!("m19-channel-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert channel");
    id
}

async fn read_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read cap")
}

async fn make_principal_group(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    atom::identity::repo::create_group(
        pool,
        atom::models::group::CreateGroup {
            id: None,
            name: format!("m19-grp-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            group_type: Some("principal".to_string()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create group")
    .id
}

/// Link a single tenant-scoped block (the given effect) for `read` to a fresh
/// role and return the role id.
async fn read_role(pool: &sqlx::PgPool, tenant_id: Uuid, effect: &str) -> Uuid {
    let read = read_id(pool).await;
    let role = atom::authz::repo::create_role(
        pool,
        CreateRole {
            name: format!("m19-role-{}", Uuid::new_v4()),
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
    role.id
}

async fn visible_tenant_ids(pool: &sqlx::PgPool, entity_id: Uuid) -> Vec<Uuid> {
    atom::tenants::repo::list_tenants_for_entity(
        pool,
        entity_id,
        None,
        ListTenants {
            q: None,
            name: None,
            alias: None,
            status: None,
            deleted: DeletedFilter::Live,
            limit: 100,
            offset: 0,
        },
    )
    .await
    .expect("list tenants")
    .items
    .into_iter()
    .map(|t| t.id)
    .collect()
}

async fn add_membership(pool: &sqlx::PgPool, tenant_id: Uuid, entity_id: Uuid, status: &str) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, entity_id) DO UPDATE SET status = EXCLUDED.status",
    )
    .bind(tenant_id)
    .bind(entity_id)
    .bind(status)
    .execute(pool)
    .await
    .expect("upsert tenant membership");
}

/// Active tenant membership alone grants the minimal right to see and read the
/// tenant object. It must not require a role/policy block because tenant
/// membership is itself the domain-entry signal used by UI callers.
#[tokio::test]
#[ignore]
async fn active_membership_lists_and_reads_tenant() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, None).await;
    let channel = make_channel(&p, target).await;

    add_membership(&p, target, caller, "active").await;

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "an active tenant membership must list the tenant"
    );
    assert!(
        atom::authz::engine::allows_any(&p, &actx(caller), caller, "tenant", target, &["read"])
            .await
            .expect("tenant read check"),
        "an active tenant membership must authorize tenant read"
    );
    assert!(
        !atom::authz::engine::allows_any(&p, &actx(caller), caller, "resource", channel, &["read"])
            .await
            .expect("resource read check"),
        "tenant membership read must not authorize reading resources inside the tenant"
    );
}

/// Only active memberships should produce the implicit tenant-read grant.
#[tokio::test]
#[ignore]
async fn inactive_membership_statuses_do_not_list_tenant() {
    let p = pool().await;
    let caller = make_human(&p, None).await;

    for status in ["invited", "suspended", "left"] {
        let target = make_tenant(&p).await;
        add_membership(&p, target, caller, status).await;

        assert!(
            !visible_tenant_ids(&p, caller).await.contains(&target),
            "a {status} tenant membership must not list the tenant"
        );
        assert!(
            !atom::authz::engine::allows_any(
                &p,
                &actx(caller),
                caller,
                "tenant",
                target,
                &["read"]
            )
            .await
            .expect("tenant read check"),
            "a {status} tenant membership must not authorize tenant read"
        );
    }
}

/// The membership-derived read grant participates in the same deny-overrides
/// model as normal grants: an explicit tenant read deny must still hide the
/// tenant from listing and deny tenant read.
#[tokio::test]
#[ignore]
async fn explicit_tenant_read_deny_overrides_membership_visibility() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, None).await;

    add_membership(&p, target, caller, "active").await;
    direct_block(
        &p,
        target,
        caller,
        "tenant",
        None,
        "deny",
        read_id(&p).await,
    )
    .await;

    assert!(
        !visible_tenant_ids(&p, caller).await.contains(&target),
        "an explicit read deny must hide a membership-visible tenant"
    );
    assert!(
        !atom::authz::engine::allows_any(&p, &actx(caller), caller, "tenant", target, &["read"])
            .await
            .expect("tenant read check"),
        "an explicit read deny must override membership tenant read"
    );
}

/// A membership-derived grant must also disappear when the tenant lifecycle no
/// longer permits reads.
#[tokio::test]
#[ignore]
async fn membership_does_not_list_non_active_tenant() {
    let p = pool().await;
    let caller = make_human(&p, None).await;

    for status in ["frozen", "inactive", "deleted"] {
        let target = make_tenant(&p).await;
        add_membership(&p, target, caller, "active").await;

        assert!(
            visible_tenant_ids(&p, caller).await.contains(&target),
            "an active tenant with active membership must be listed"
        );

        sqlx::query("UPDATE tenants SET status = $2 WHERE id = $1")
            .bind(target)
            .bind(status)
            .execute(&p)
            .await
            .expect("set tenant status");

        assert!(
            !visible_tenant_ids(&p, caller).await.contains(&target),
            "a {status} tenant must not appear through membership"
        );
        assert!(
            !atom::authz::engine::allows_any(
                &p,
                &actx(caller),
                caller,
                "tenant",
                target,
                &["read"]
            )
            .await
            .expect("tenant read check"),
            "a {status} tenant must not be readable through membership"
        );
    }
}

/// A role-linked deny on a tenant must hide it, even with a tenant-wide read
/// allow present. Before the fix the synthetic role edge dropped the deny, so
/// the allow won. A second caller with only the allow still sees the tenant,
/// isolating the deny as the cause.
#[tokio::test]
#[ignore]
async fn role_linked_tenant_deny_hides_tenant_from_listing() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let denied_caller = make_human(&p, Some(target)).await;
    let allowed_caller = make_human(&p, Some(target)).await;

    // Both callers get a tenant-scoped read allow → the tenant is visible.
    for caller in [denied_caller, allowed_caller] {
        atom::authz::repo::create_policy(
            &p,
            CreatePolicyBinding {
                tenant_id: Some(target),
                subject_kind: SubjectKind::Entity,
                subject_id: caller,
                grant_kind: GrantKind::Capability,
                grant_id: read_id(&p).await,
                scope_kind: ScopeKind::Tenant,
                scope_ref: Some(target.to_string()),
                effect: Effect::Allow,
                conditions: json!({}),
            },
        )
        .await
        .expect("tenant read allow");
    }

    // Only the first caller also holds a role with a tenant-scoped deny-read.
    let deny_role = read_role(&p, target, "deny").await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(target),
            subject_kind: SubjectKind::Entity,
            subject_id: denied_caller,
            role_id: deny_role,
        },
    )
    .await
    .expect("assign deny role");

    assert!(
        !visible_tenant_ids(&p, denied_caller)
            .await
            .contains(&target),
        "a role-linked tenant deny must hide the tenant"
    );
    assert!(
        visible_tenant_ids(&p, allowed_caller)
            .await
            .contains(&target),
        "the tenant read allow alone must keep the tenant visible"
    );
}

/// A role granting tenant read that reaches the caller only through a parent
/// principal group must make the tenant visible. Before the fix the listing
/// expanded direct membership only, so the tenant was missed.
#[tokio::test]
#[ignore]
async fn tenant_visible_via_parent_group_role() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;

    let parent = make_principal_group(&p, target).await;
    let child = make_principal_group(&p, target).await;
    atom::identity::repo::set_group_parent(&p, child, parent)
        .await
        .expect("set parent");
    atom::identity::repo::add_group_member(&p, child, caller)
        .await
        .expect("add member");

    let allow_role = read_role(&p, target, "allow").await;
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(target),
            subject_kind: SubjectKind::Group,
            subject_id: parent,
            role_id: allow_role,
        },
    )
    .await
    .expect("assign role to parent group");

    let visible_ids = visible_tenant_ids(&p, caller).await;
    assert!(
        visible_ids.contains(&target),
        "a tenant readable via a parent-group role must be listed, got: {visible_ids:?}"
    );
}

async fn manage_id(pool: &sqlx::PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("manage cap")
}

/// Insert a permission block (raw, bypassing applicability validation) and link
/// it to `caller` via a direct policy bounded to `tenant`.
async fn direct_block(
    pool: &sqlx::PgPool,
    tenant: Uuid,
    caller: Uuid,
    scope_mode: &str,
    object_kind: Option<&str>,
    effect: &str,
    action: Uuid,
) {
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, object_kind, effect) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(scope_mode)
    .bind(tenant)
    .bind(object_kind)
    .bind(effect)
    .fetch_one(pool)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(action)
    .execute(pool)
    .await
    .expect("block action");
    sqlx::query("INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id) VALUES ($1, 'entity', $2, $3)")
        .bind(tenant)
        .bind(caller)
        .bind(block)
        .execute(pool)
        .await
        .expect("direct policy");
}

/// A manage deny must not hide a tenant the caller can read: deny-override is
/// per-action. Before the fix the listing checked allow(read|manage) then
/// deny(read|manage) uncorrelated, so the manage deny removed the tenant.
#[tokio::test]
#[ignore]
async fn read_allow_not_hidden_by_manage_deny() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;

    direct_block(
        &p,
        target,
        caller,
        "tenant",
        None,
        "allow",
        read_id(&p).await,
    )
    .await;
    direct_block(
        &p,
        target,
        caller,
        "tenant",
        None,
        "deny",
        manage_id(&p).await,
    )
    .await;

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "a read allow must keep the tenant visible despite a separate manage deny"
    );
}

/// A direct object_kind='tenant' read grant must make the tenant visible — the
/// PDP matches object_kind scope against the tenant object's kind.
#[tokio::test]
#[ignore]
async fn tenant_visible_via_object_kind_grant() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;

    direct_block(
        &p,
        target,
        caller,
        "object_kind",
        Some("tenant"),
        "allow",
        read_id(&p).await,
    )
    .await;

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "an object_kind='tenant' read grant must list the tenant"
    );
}

/// A role-linked object_kind='tenant' read grant must make the tenant visible —
/// role_grants must carry object_kind scopes, not collapse them to NULL.
#[tokio::test]
#[ignore]
async fn tenant_visible_via_role_object_kind_grant() {
    let p = pool().await;
    let target = make_tenant(&p).await;
    let caller = make_human(&p, Some(target)).await;
    let read = read_id(&p).await;

    let role = atom::authz::repo::create_role(
        &p,
        CreateRole {
            name: format!("m19-ok-role-{}", Uuid::new_v4()),
            tenant_id: Some(target),
            description: None,
        },
    )
    .await
    .expect("create role");
    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, object_kind, effect) VALUES ('object_kind', $1, 'tenant', 'allow') RETURNING id",
    )
    .bind(target)
    .fetch_one(&p)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(read)
    .execute(&p)
    .await
    .expect("block action");
    atom::authz::repo::replace_role_permission_block_links(&p, role.id, &[block])
        .await
        .expect("link");
    atom::authz::repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: Some(target),
            subject_kind: SubjectKind::Entity,
            subject_id: caller,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");

    assert!(
        visible_tenant_ids(&p, caller).await.contains(&target),
        "a role-linked object_kind='tenant' read grant must list the tenant"
    );
}

/// A tenant the caller can read must disappear from the scoped listing once it
/// is no longer active, mirroring the PDP, which denies any read on an
/// inactive/frozen/deleted tenant (`engine::load_tenant`). Before the lifecycle
/// predicate the grant alone kept a frozen/inactive tenant visible to a
/// non-platform subject.
#[tokio::test]
#[ignore]
async fn non_active_tenant_hidden_from_scoped_listing() {
    let p = pool().await;
    let caller = make_human(&p, None).await;

    for status in ["frozen", "inactive", "deleted"] {
        let target = make_tenant(&p).await;
        direct_block(
            &p,
            target,
            caller,
            "tenant",
            None,
            "allow",
            read_id(&p).await,
        )
        .await;

        // Active → visible (control: the grant resolves).
        assert!(
            visible_tenant_ids(&p, caller).await.contains(&target),
            "an active tenant with a read allow must be listed"
        );

        sqlx::query("UPDATE tenants SET status = $2 WHERE id = $1")
            .bind(target)
            .bind(status)
            .execute(&p)
            .await
            .expect("set tenant status");

        assert!(
            !visible_tenant_ids(&p, caller).await.contains(&target),
            "a {status} tenant must not appear in the scoped listing"
        );
    }
}

async fn ceiling_visible_tenant_ids(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Vec<Uuid> {
    atom::tenants::repo::list_tenants_for_entity(
        pool,
        entity_id,
        Some(credential_id),
        ListTenants {
            q: None,
            name: None,
            alias: None,
            status: None,
            deleted: DeletedFilter::Live,
            limit: 100,
            offset: 0,
        },
    )
    .await
    .expect("list tenants under ceiling")
    .items
    .into_iter()
    .map(|t| t.id)
    .collect()
}

/// Tenant visibility is ceiling-aware: a scoped access token whose ceiling
/// covers one tenant sees only that tenant, while the owner's session sees all
/// tenants its memberships/grants make visible. A conditional ceiling entry
/// fails closed in the listing, like the coarse gates.
#[tokio::test]
#[ignore]
async fn tenant_visibility_is_capped_by_access_token_ceiling() {
    let p = pool().await;
    let tenant_a = make_tenant(&p).await;
    let tenant_b = make_tenant(&p).await;
    let caller = make_human(&p, None).await;
    add_membership(&p, tenant_a, caller, "active").await;
    add_membership(&p, tenant_b, caller, "active").await;

    let unscoped = visible_tenant_ids(&p, caller).await;
    assert!(unscoped.contains(&tenant_a) && unscoped.contains(&tenant_b));

    // Scoped credential whose ceiling covers only tenant_a (tenant scope mode).
    let cred_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, scoped) VALUES ($1, $2, 'access_token', true)",
    )
    .bind(cred_id)
    .bind(caller)
    .execute(&p)
    .await
    .expect("credential");
    let limit_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO credential_permission_limits (id, credential_id, scope_mode, tenant_id) VALUES ($1, $2, 'tenant', $3)",
    )
    .bind(limit_id)
    .bind(cred_id)
    .bind(tenant_a)
    .execute(&p)
    .await
    .expect("limit");
    sqlx::query(
        "INSERT INTO credential_permission_limit_actions (limit_id, action_id) SELECT $1, id FROM actions WHERE name = 'read'",
    )
    .bind(limit_id)
    .execute(&p)
    .await
    .expect("limit action");

    let capped = ceiling_visible_tenant_ids(&p, caller, cred_id).await;
    assert!(capped.contains(&tenant_a), "ceiling covers tenant_a");
    assert!(
        !capped.contains(&tenant_b),
        "tenant outside the ceiling must be hidden"
    );

    // A conditional ceiling entry cannot satisfy the listing (fail closed).
    sqlx::query("UPDATE credential_permission_limits SET conditions = '{\"context.mfa\": true}'::jsonb WHERE id = $1")
        .bind(limit_id)
        .execute(&p)
        .await
        .expect("make conditional");
    let conditional = ceiling_visible_tenant_ids(&p, caller, cred_id).await;
    assert!(
        !conditional.contains(&tenant_a),
        "conditional ceiling entry must fail closed in listings"
    );
}
