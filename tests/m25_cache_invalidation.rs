//! Cache invalidation correctness tests.
//!
//! Requires both a reachable Postgres at `DATABASE_URL` and a reachable Redis
//! at `ATOM_TEST_REDIS_URL`. Run with:
//!
//! ```bash
//! DATABASE_URL=postgres://... ATOM_TEST_REDIS_URL=redis://... cargo test --test m25_cache_invalidation -- --ignored
//! ```
//!
//! Every test here follows the same shape: warm the cache with a read, mutate
//! through the real (wired) production path — a GraphQL mutation executed
//! through the schema, exactly as a client would call it — then immediately
//! (no sleep) re-check that the mutation's effect is visible. TTL is a
//! defense-in-depth safety net in this design, never the mechanism under
//! test; a passing test here means invalidation is precise, not merely that
//! a short enough TTL happened to expire.

mod common;

use std::sync::Arc;

use async_graphql::Request;
use atom::{
    auth::{self, AuthContext},
    authz::{engine, repo as authz_repo},
    cache::CacheClient,
    config::Config,
    graphql::build_schema,
    identity::{access_tokens, repo as identity_repo},
    models::{
        enums::{Effect, SubjectKind},
        group::CreateGroup,
        policy::{AuthzRequest, CreateDirectPolicy, CreatePermissionBlock, CreateRoleAssignment},
        role::CreateRole,
        token::{AccessTokenPermission, CreateAccessToken},
    },
    state::AppState,
    tenants::repo as tenant_repo,
};
use common::{cache_client, pool};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Builds an `AppState` wired to a fresh Redis-backed cache, plus an
/// `Arc<CacheClient>` handle to the *same* instance (mirroring how
/// production shares one cache between `state.cache` and `AuthContext::
/// cache` — see `auth_from_jwt`/`auth_from_api_key`'s `cache:
/// state.cache.clone()`). Uses a real rotated EC signing key (not an empty
/// placeholder) since several tests here actually encode/verify JWTs.
async fn state_with_cache(pool: PgPool) -> (AppState, Arc<CacheClient>) {
    let cfg = Config::for_tests();
    let active_keys = atom::keys::rotate(&pool, &cfg.signing_keys)
        .await
        .expect("rotate test signing key");
    let state = AppState::new(pool, cfg, active_keys, Some(cache_client().await));
    let cache = state.cache.clone().expect("cache configured");
    (state, cache)
}

fn auth_context(entity_id: Uuid, cache: Arc<CacheClient>) -> AuthContext {
    AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        credential_id: None,
        scoped: false,
        ceiling: None,
        cache: Some(cache),
    }
}

fn authed(entity_id: Uuid, cache: Arc<CacheClient>, query: impl Into<String>) -> Request {
    Request::new(query).data(auth_context(entity_id, cache))
}

async fn active_entity(pool: &PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("cache-test-{kind}-{id}"))
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn resource(pool: &PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(kind)
        .bind(format!("cache-test-res-{id}"))
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

async fn read_action_id(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read action")
}

/// A platform-scope allow block granting `read`, ready to attach via a
/// direct policy or a role.
async fn make_read_block(pool: &PgPool) -> Uuid {
    let action_id = read_action_id(pool).await;
    authz_repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: None,
            scope_mode: "platform".into(),
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({}),
            action_ids: vec![action_id],
        },
    )
    .await
    .expect("create permission block")
    .id
}

async fn new_group(pool: &PgPool, label: &str) -> Uuid {
    identity_repo::create_group(
        pool,
        CreateGroup {
            id: None,
            name: format!("cache-test-{label}-{}", Uuid::new_v4()),
            tenant_id: None,
            group_type: Some("principal".into()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create group")
    .id
}

async fn new_group_in_tenant(
    pool: &PgPool,
    tenant_id: Uuid,
    group_type: &str,
    label: &str,
) -> Uuid {
    identity_repo::create_group(
        pool,
        CreateGroup {
            id: None,
            name: format!("cache-test-{label}-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            group_type: Some(group_type.into()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create tenant group")
    .id
}

/// A standalone Redis connection for tests that need to inspect cache state
/// directly (e.g. asserting a key was *not* touched), independent of
/// `CacheClient`'s own (private) connection pool.
async fn raw_redis_conn() -> redis::aio::MultiplexedConnection {
    let url = std::env::var("ATOM_TEST_REDIS_URL")
        .expect("ATOM_TEST_REDIS_URL must be set for cache-gated tests");
    redis::Client::open(url)
        .expect("valid redis url")
        .get_multiplexed_async_connection()
        .await
        .expect("connect to test redis")
}

async fn evaluate_read(
    pool: &PgPool,
    subject_id: Uuid,
    resource_id: Uuid,
    cache: Arc<CacheClient>,
) -> bool {
    let req = AuthzRequest {
        subject_id,
        action: "read".into(),
        resource_id: Some(resource_id),
        object_kind: None,
        object_id: None,
        context: json!({}),
    };
    let auth = auth_context(subject_id, cache);
    engine::evaluate(pool, &req, &auth)
        .await
        .expect("evaluate")
        .allowed
}

// ─── Direct policy ──────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn direct_policy_revoke_is_immediately_reflected() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let subject = active_entity(&p, "service").await;
    let res = resource(&p, "channel").await;
    let block_id = make_read_block(&p).await;

    let policy = authz_repo::create_direct_policy(
        &p,
        CreateDirectPolicy {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: subject,
            permission_block_id: block_id,
        },
    )
    .await
    .expect("create direct policy");

    assert!(
        evaluate_read(&p, subject, res, cache.clone()).await,
        "direct policy should grant read"
    );

    let schema = build_schema(state);
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteDirectPolicy(id: "{}") }}"#, policy.id),
        ))
        .await;
    assert!(resp.errors.is_empty(), "delete failed: {:?}", resp.errors);

    assert!(
        !evaluate_read(&p, subject, res, cache.clone()).await,
        "revoked direct policy must deny immediately, not after a TTL"
    );
}

#[tokio::test]
#[ignore]
async fn direct_policy_revoke_for_group_subject_is_immediately_reflected() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let member = active_entity(&p, "service").await;
    let res = resource(&p, "channel").await;
    let block_id = make_read_block(&p).await;

    let group = new_group(&p, "direct-policy-group").await;
    identity_repo::add_group_member(&p, group, member)
        .await
        .expect("add member");

    let policy = authz_repo::create_direct_policy(
        &p,
        CreateDirectPolicy {
            tenant_id: None,
            subject_kind: SubjectKind::Group,
            subject_id: group,
            permission_block_id: block_id,
        },
    )
    .await
    .expect("create group direct policy");

    assert!(evaluate_read(&p, member, res, cache.clone()).await);

    let schema = build_schema(state);
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteDirectPolicy(id: "{}") }}"#, policy.id),
        ))
        .await;
    assert!(resp.errors.is_empty(), "delete failed: {:?}", resp.errors);

    assert!(
        !evaluate_read(&p, member, res, cache.clone()).await,
        "group-subject revoke must immediately deny the group's member"
    );
}

// ─── Role assignment / role delete ─────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn role_assignment_revoke_is_immediately_reflected() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let subject = active_entity(&p, "service").await;
    let res = resource(&p, "channel").await;
    let block_id = make_read_block(&p).await;

    let role = authz_repo::create_role(
        &p,
        CreateRole {
            name: format!("cache-test-role-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
        },
    )
    .await
    .expect("create role");
    authz_repo::replace_role_permission_block_links(&p, role.id, &[block_id])
        .await
        .expect("link block");

    let assignment = authz_repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: subject,
            role_id: role.id,
        },
    )
    .await
    .expect("create role assignment");

    assert!(evaluate_read(&p, subject, res, cache.clone()).await);

    let schema = build_schema(state);
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ deleteRoleAssignment(id: "{}") }}"#,
                assignment.id
            ),
        ))
        .await;
    assert!(resp.errors.is_empty(), "delete failed: {:?}", resp.errors);

    assert!(
        !evaluate_read(&p, subject, res, cache.clone()).await,
        "revoked role assignment must deny immediately"
    );
}

/// The fan-out case: a role assigned to a group three levels of nesting away
/// from the actual member must invalidate that member's cached grants too.
#[tokio::test]
#[ignore]
async fn role_delete_invalidates_three_level_nested_group_members() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let member = active_entity(&p, "service").await;
    let res = resource(&p, "channel").await;
    let block_id = make_read_block(&p).await;

    // grandparent -> parent -> child, member belongs to `child`, role is
    // assigned to `grandparent`.
    let grandparent = new_group(&p, "gp").await;
    let parent = new_group(&p, "parent").await;
    let child = new_group(&p, "child").await;

    identity_repo::set_group_parent(&p, parent, grandparent)
        .await
        .expect("parent under grandparent");
    identity_repo::set_group_parent(&p, child, parent)
        .await
        .expect("child under parent");
    identity_repo::add_group_member(&p, child, member)
        .await
        .expect("add member to child");

    let role = authz_repo::create_role(
        &p,
        CreateRole {
            name: format!("cache-test-nested-role-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
        },
    )
    .await
    .expect("create role");
    authz_repo::replace_role_permission_block_links(&p, role.id, &[block_id])
        .await
        .expect("link block");
    authz_repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: None,
            subject_kind: SubjectKind::Group,
            subject_id: grandparent,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role to grandparent");

    assert!(
        evaluate_read(&p, member, res, cache.clone()).await,
        "member three levels deep should inherit the grandparent's role grant"
    );

    let schema = build_schema(state);
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteRole(id: "{}") }}"#, role.id),
        ))
        .await;
    assert!(resp.errors.is_empty(), "delete failed: {:?}", resp.errors);

    assert!(
        !evaluate_read(&p, member, res, cache.clone()).await,
        "deleting the role must immediately deny the deeply-nested member, not after a TTL"
    );
}

#[tokio::test]
#[ignore]
async fn group_membership_removal_is_immediately_reflected() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let member = active_entity(&p, "service").await;
    let res = resource(&p, "channel").await;
    let block_id = make_read_block(&p).await;

    let group = new_group(&p, "membership-remove").await;
    identity_repo::add_group_member(&p, group, member)
        .await
        .expect("add member");
    let role = authz_repo::create_role(
        &p,
        CreateRole {
            name: format!("cache-test-membership-role-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
        },
    )
    .await
    .expect("create role");
    authz_repo::replace_role_permission_block_links(&p, role.id, &[block_id])
        .await
        .expect("link block");
    authz_repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: None,
            subject_kind: SubjectKind::Group,
            subject_id: group,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role to group");

    assert!(evaluate_read(&p, member, res, cache.clone()).await);

    let schema = build_schema(state);
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ removeGroupMember(groupId: "{group}", entityId: "{member}") }}"#
            ),
        ))
        .await;
    assert!(resp.errors.is_empty(), "remove failed: {:?}", resp.errors);

    assert!(
        !evaluate_read(&p, member, res, cache.clone()).await,
        "removing group membership must immediately deny the role grant it carried"
    );
}

// ─── Session / JWT ──────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn session_revoke_immediately_rejects_the_next_authentication() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        None,
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    // Warm the session/entity-status cache.
    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");

    // `logout` reads `auth.session_id` from the request context — unlike
    // `authed()`'s default (`session_id: None`, fine for every other test
    // here since they don't exercise session-bearing mutations), this must
    // carry the real session_id or there is nothing for `logout` to revoke.
    let logout_auth = AuthContext {
        session_id: Some(session_id),
        ..auth_context(entity_id, cache.clone())
    };
    let schema = build_schema(state.clone());
    let resp = schema
        .execute(Request::new("mutation { logout }").data(logout_auth))
        .await;
    assert!(resp.errors.is_empty(), "logout failed: {:?}", resp.errors);

    let result = auth::authenticate_token(&state, &token).await;
    assert!(
        result.is_err(),
        "revoked session must be rejected on the very next authentication, not after a TTL"
    );
}

/// Regression test for a review finding: `logout` used to clear the session's
/// cache barrier (`cache.end`) before `audit::commit_with_audit`'s internal
/// `tx.commit()` actually landed the revoke. In that window a concurrent
/// authentication would see a clean (non-dirty) barrier and a Postgres row
/// that (via MVCC, on a separate connection) still read as not revoked, and
/// would repopulate the cache with a "still valid" entry that then survived
/// for the full session TTL — defeating immediate revocation for exactly the
/// operation most likely to be relied on for it.
///
/// A black-box race against real `authenticate_token` calls turned out not to
/// reliably land in the gap — it's sub-millisecond, and a full auth call has
/// too much of its own latency to consistently hit it. Instead this polls the
/// barrier's raw `dirty` flag and a direct `revoked_at` read, on a real OS
/// thread running in parallel with `logout` (`flavor = "multi_thread"`, not
/// cooperative async interleaving), so it observes the transition rather than
/// racing to beat it. The invariant: once `dirty` is observed set for this
/// key, it must never be observed clear again while `revoked_at` is still
/// null — that combination is only reachable if the barrier was released
/// before the commit landed. Confirmed this fails against the pre-fix
/// ordering (reverted locally) and passes against the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn logout_cannot_leave_a_stale_valid_session_cached_during_the_revoke() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        None,
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    // Warm the session/entity-status cache.
    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");

    let logout_auth = AuthContext {
        session_id: Some(session_id),
        ..auth_context(entity_id, cache.clone())
    };
    let schema = build_schema(state.clone());
    let session_key = atom::cache::keys::session(session_id);

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let p_poll = p.clone();
    let key_poll = cache.redis_key(&session_key);
    let poller = tokio::spawn(async move {
        let mut conn = raw_redis_conn().await;
        let mut saw_dirty = false;
        loop {
            let dirty: Option<String> = redis::cmd("HGET")
                .arg(&key_poll)
                .arg("dirty")
                .query_async(&mut conn)
                .await
                .unwrap_or(None);
            let is_dirty = dirty.as_deref() == Some("1");
            if is_dirty {
                saw_dirty = true;
            }
            if saw_dirty && !is_dirty {
                let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
                    sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
                        .bind(session_id)
                        .fetch_one(&p_poll)
                        .await
                        .expect("read revoked_at");
                // Barrier just went clean; if the row isn't committed as
                // revoked yet, that's the bug. If it's already revoked, the
                // ordering was correct — nothing more to catch.
                return revoked_at.is_none();
            }
            if stop2.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
        }
    });

    let logout_result = schema
        .execute(Request::new("mutation { logout }").data(logout_auth))
        .await;
    assert!(
        logout_result.errors.is_empty(),
        "logout failed: {:?}",
        logout_result.errors
    );

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let violation = poller.await.expect("join poller");
    assert!(
        !violation,
        "observed the session cache barrier clear (dirty -> clean) while the session row still \
         read as un-revoked — a concurrent reader landing at that exact moment would repopulate \
         the cache with a stale \"still valid\" entry, exactly the bug this regresses"
    );

    let result = auth::authenticate_token(&state, &token).await;
    assert!(
        result.is_err(),
        "revoked session must be rejected on the very next authentication, not after a TTL"
    );
}

#[tokio::test]
#[ignore]
async fn entity_deactivation_immediately_rejects_an_existing_valid_session() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        None,
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    // Warm the session/entity-status cache for this session.
    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");

    // Deactivate through the real, wired GraphQL path.
    let schema = build_schema(state.clone());
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteEntity(id: "{entity_id}") }}"#),
        ))
        .await;
    assert!(resp.errors.is_empty(), "delete failed: {:?}", resp.errors);

    let result = auth::authenticate_token(&state, &token).await;
    assert!(
        result.is_err(),
        "deactivating the entity must immediately reject its existing session, not after a TTL"
    );
}

// ─── Credential ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn credential_revoke_immediately_rejects_the_next_authentication() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;

    let minted = access_tokens::create_access_token(
        &p,
        &state.config.signing_keys,
        entity_id,
        CreateAccessToken {
            name: "cache-test-token".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .expect("create access token");

    // Warm the credential cache with a successful authentication.
    auth::authenticate_token(&state, &minted.token)
        .await
        .expect("initial authentication should succeed");

    let schema = build_schema(state.clone());
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ revokeAccessToken(credentialId: "{}") }}"#,
                minted.credential_id
            ),
        ))
        .await;
    assert!(resp.errors.is_empty(), "revoke failed: {:?}", resp.errors);

    let result = auth::authenticate_token(&state, &minted.token).await;
    assert!(
        result.is_err(),
        "revoked credential must be rejected on the very next authentication, not after a TTL"
    );
}

#[tokio::test]
#[ignore]
async fn replacing_access_token_permissions_invalidates_the_cached_ceiling() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;
    let read_action_id = read_action_id(&p).await;
    let manage_action_id: Uuid =
        sqlx::query_scalar("SELECT id FROM actions WHERE name = 'manage' LIMIT 1")
            .fetch_one(&p)
            .await
            .expect("manage action");

    let minted = access_tokens::create_access_token(
        &p,
        &state.config.signing_keys,
        entity_id,
        CreateAccessToken {
            name: "cache-test-ceiling".into(),
            description: None,
            expires_at: None,
            permissions: vec![AccessTokenPermission {
                actions: vec!["read".into()],
                scope_mode: "object_kind".into(),
                tenant_id: None,
                object_kind: Some("entity".into()),
                object_type: None,
                object_id: None,
                conditions: None,
            }],
        },
        true,
    )
    .await
    .expect("create scoped access token");

    let before = auth::authenticate_token(&state, &minted.token)
        .await
        .expect("warm credential and ceiling caches");
    let before = before.ceiling.expect("scoped token ceiling");
    assert!(before
        .entries
        .iter()
        .any(|entry| entry.capability_id == read_action_id));
    assert!(!before
        .entries
        .iter()
        .any(|entry| entry.capability_id == manage_action_id));

    let schema = build_schema(state.clone());
    let replaced = schema
        .execute(authed(
            common::admin_id(),
            cache,
            format!(
                r#"mutation {{ replaceAccessTokenPermissions(credentialId: "{}", permissions: [{{ actions: ["manage"], scopeMode: "object_kind", objectKind: "entity" }}]) }}"#,
                minted.credential_id
            ),
        ))
        .await;
    assert!(
        replaced.errors.is_empty(),
        "replace failed: {:?}",
        replaced.errors
    );

    let after = auth::authenticate_token(&state, &minted.token)
        .await
        .expect("authenticate after ceiling replacement");
    let after = after.ceiling.expect("scoped token ceiling");
    assert!(
        after
            .entries
            .iter()
            .any(|entry| entry.capability_id == manage_action_id),
        "the next authentication must load the replacement ceiling"
    );
    assert!(
        !after
            .entries
            .iter()
            .any(|entry| entry.capability_id == read_action_id),
        "the cached read-only ceiling must not survive replacement"
    );
}

// ─── Tenant delete / restore ────────────────────────────────────────────────

async fn tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("cache-test-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn active_entity_in_tenant(pool: &PgPool, tenant_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("cache-test-{kind}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

/// Regression test for a review finding: `soft_delete_tenant` (behind
/// `deleteTenant`) is a separate function from `change_tenant_status` and
/// was found to be completely unwired — a stale `tenant_status` cache entry
/// let an existing JWT session for a member of the deleted tenant keep
/// authenticating. Both the session cache *and* the tenant_status cache are
/// warmed stale-valid here before the delete, so this only passes if
/// `tenant_status` is genuinely invalidated (a stale-but-unrevoked session
/// cache entry alone would otherwise still let auth through).
#[tokio::test]
#[ignore]
async fn tenant_delete_immediately_rejects_an_existing_session_of_a_member() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let tenant_id = tenant(&p).await;
    let entity_id = active_entity_in_tenant(&p, tenant_id, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        Some(tenant_id),
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    // Warm the session/entity-status/tenant_status caches, all showing valid.
    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");

    let schema = build_schema(state.clone());
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteTenant(id: "{tenant_id}") }}"#),
        ))
        .await;
    assert!(resp.errors.is_empty(), "delete failed: {:?}", resp.errors);

    let result = auth::authenticate_token(&state, &token).await;
    assert!(
        result.is_err(),
        "deleting the tenant must immediately reject an existing member session, not after a TTL \
         (this only fails if tenant_status wasn't actually invalidated, since the session cache \
         entry alone is stale-valid and would otherwise let auth through)"
    );
}

/// Regression test for a review finding: `change_tenant_status`'s
/// `disableTenant`/`freezeTenant` mutations bulk-revoke the tenant's
/// members' sessions in the same transaction as the status flip, but the
/// resolver only ever established a cache barrier on `tenant_status` — never
/// on the sessions it was about to revoke.
///
/// As with `tenant_restore_clears_reactivated_credential_cache_entries`
/// below, an end-to-end auth-behavior test can't actually isolate this: the
/// `tenant_status` barrier's own `end` always clears that entry's payload
/// too, so the very next authentication after `disableTenant` (or after a
/// subsequent `enableTenant`) is forced through a fresh-Postgres-reload path
/// regardless of whether the session was ever separately invalidated — that
/// fresh reload sees the correctly-revoked row and denies either way, and
/// self-heals the session cache entry in the process, masking the bug on
/// every subsequent check too. Confirmed by trying exactly that shape of
/// test and finding it passed even with the session invalidation reverted.
/// So this checks the one thing that actually isolates it: that
/// `disableTenant` clears the session's own cache entry directly, verified
/// against Redis, independent of what any later auth attempt would do.
#[tokio::test]
#[ignore]
async fn disabling_a_tenant_invalidates_its_members_session_cache_entries() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let tenant_id = tenant(&p).await;
    let entity_id = active_entity_in_tenant(&p, tenant_id, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        Some(tenant_id),
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    // Warm the session cache as a valid, stale-able hit.
    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");
    let session_key = atom::cache::keys::session(session_id);
    let (_, _, payload_before) = hmget_raw(&session_key).await;
    assert!(
        payload_before.is_some(),
        "session cache should be warm before disabling the tenant"
    );

    let schema = build_schema(state.clone());
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ disableTenant(id: "{tenant_id}") {{ id }} }}"#),
        ))
        .await;
    assert!(resp.errors.is_empty(), "disable failed: {:?}", resp.errors);

    // `end`'s barrier always clears the payload of whatever it covers (see
    // `src/cache/mod.rs`), so a lingering payload here means this session's
    // key was never part of the barrier at all -- the exact gap the review
    // found.
    let (_, _, payload_after) = hmget_raw(&session_key).await;
    assert!(
        payload_after.is_none(),
        "disabling a tenant must invalidate its members' session cache entries, not just \
         tenant_status -- a lingering \"still valid\" session cache entry here would keep \
         serving hits (masked only by tenant_status denying auth while the tenant stays \
         disabled) and would resurface the instant the tenant is re-enabled"
    );
}

/// Regression test for a review finding: `restore_tenant` reactivates
/// credentials but the resolver originally only invalidated `tenant_status`,
/// not the credential entries it reactivates.
///
/// Important nuance found while developing this test: an *end-to-end*
/// authentication test for this can't actually distinguish "the credential
/// invalidation ran" from "it didn't", because `restore_tenant`'s own (also
/// necessary) `tenant_status` invalidation forces `auth_from_api_key` through
/// its fresh-Postgres-reload branch regardless — that branch bypasses
/// whatever is in the credential cache entirely, masking the credential fix
/// either way. Both an "authenticate while deleted" attempt (to naturally
/// populate a stale entry) and a full auth-behavior assertion after restore
/// were tried and found to pass even with the credential invalidation
/// stripped out, for exactly this reason — confirmed by reverting the fix
/// and rerunning. So this test checks the one thing that actually isolates
/// it: that `restoreTenant` clears the credential's cache entry directly,
/// verified against Redis, independent of which auth code path would
/// subsequently be taken.
///
/// The fix is kept as a matter of defensive correctness even though the
/// review's literal "cache captures revoked, stays stuck after restore"
/// scenario isn't reachable via the normal auth flow today (the tenant's own
/// `deleted_at` join filter means nothing can populate a credential's cache
/// entry while its tenant is genuinely deleted, so there is no live window
/// in which the entry could be wrong when restore runs) — relying on that
/// incidental protection instead of an explicit invalidation would be
/// fragile against future changes to either the join or the fast-path
/// gating in `auth_from_api_key`.
#[tokio::test]
#[ignore]
async fn tenant_restore_clears_reactivated_credential_cache_entries() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let tenant_id = tenant(&p).await;
    let entity_id = active_entity_in_tenant(&p, tenant_id, "service").await;

    let minted = access_tokens::create_access_token(
        &p,
        &state.config.signing_keys,
        entity_id,
        CreateAccessToken {
            name: "cache-test-tenant-restore-token".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .expect("create access token");

    let schema = build_schema(state.clone());
    let del = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteTenant(id: "{tenant_id}") }}"#),
        ))
        .await;
    assert!(del.errors.is_empty(), "delete failed: {:?}", del.errors);

    let cred_key = atom::cache::keys::credential(minted.credential_id);
    seed_hit(
        &cred_key,
        &atom::cache::entries::CredentialCacheEntry {
            entity_id,
            status: atom::models::enums::CredentialStatus::Revoked,
            secret_hash: None,
            secret_lookup_hash: Some(vec![0u8; 32]),
            expires_at: None,
            scoped: false,
        },
    )
    .await;
    let before = hmget_raw(&cred_key).await;
    assert!(
        before.2.is_some(),
        "seeded entry should have a payload before restore: {before:?}"
    );

    let restore = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ restoreTenant(id: "{tenant_id}") {{ id }} }}"#),
        ))
        .await;
    assert!(
        restore.errors.is_empty(),
        "restore failed: {:?}",
        restore.errors
    );

    let after = hmget_raw(&cred_key).await;
    assert!(
        after.2.is_none(),
        "restoreTenant must clear the reactivated credential's cache payload \
         (begin() deletes it, end() never restores it) — got {after:?}, expected the \
         payload field to be absent"
    );
    assert_ne!(
        after.0, before.0,
        "the credential key's version must have been bumped by restoreTenant's barrier"
    );
}

/// Regression test for a review finding: `soft_delete_tenant` revokes
/// members' sessions in Postgres, but the delete resolver only invalidated
/// `tenant_status`, never the sessions themselves. During the deleted window
/// this is harmless — the `tenant_status` miss forces a fresh Postgres check,
/// which denies correctly — but once `restoreTenant` repopulates
/// `tenant_status` as active again, a session cached as valid *before* the
/// delete would resurface as a full cache hit and authenticate despite being
/// revoked, since `restoreTenant` deliberately never reinstates sessions.
///
/// The first authentication attempt after restore always denies correctly
/// regardless of this fix, because restore's own `tenant_status` invalidation
/// forces that one request through a fresh Postgres reload (which, as a side
/// effect, also repopulates `tenant_status` as a hit). It's the *second*
/// attempt — once `tenant_status` is a hit again — that actually distinguishes
/// "the session was invalidated at delete time" from "it wasn't"; confirmed
/// by temporarily reverting the fix and rerunning.
#[tokio::test]
#[ignore]
async fn tenant_delete_then_restore_immediately_rejects_a_pre_existing_session() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let tenant_id = tenant(&p).await;
    let entity_id = active_entity_in_tenant(&p, tenant_id, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        Some(tenant_id),
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    // Warm the session/entity-status/tenant_status caches, all showing valid.
    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");

    let schema = build_schema(state.clone());
    let del = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteTenant(id: "{tenant_id}") }}"#),
        ))
        .await;
    assert!(del.errors.is_empty(), "delete failed: {:?}", del.errors);

    let restore = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ restoreTenant(id: "{tenant_id}") {{ id }} }}"#),
        ))
        .await;
    assert!(
        restore.errors.is_empty(),
        "restore failed: {:?}",
        restore.errors
    );

    assert!(
        auth::authenticate_token(&state, &token).await.is_err(),
        "a session revoked by tenant delete must stay rejected immediately after restore"
    );
    assert!(
        auth::authenticate_token(&state, &token).await.is_err(),
        "a session revoked by tenant delete must stay rejected even once tenant_status is a \
         cache hit again post-restore — this only fails if the session cache entry wasn't \
         invalidated at delete time and survived as a stale 'valid' hit"
    );
}

/// Regression test for a review finding: `delete_entity` revokes the
/// entity's sessions in Postgres, but the delete resolver only invalidated
/// `entity_status`. Same masking shape as the tenant case above: the first
/// post-restore attempt always denies correctly (entity_status's own
/// invalidation forces a fresh reload), and it's the second attempt that
/// actually proves the session cache entry itself was invalidated at delete
/// time, not left as a stale 'valid' hit for `restoreEntity` to unmask.
#[tokio::test]
#[ignore]
async fn entity_delete_then_restore_immediately_rejects_a_pre_existing_session() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(&p)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    let token = auth::encode_jwt(
        entity_id,
        session_id,
        None,
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt");

    auth::authenticate_token(&state, &token)
        .await
        .expect("initial authentication should succeed");

    let schema = build_schema(state.clone());
    let del = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteEntity(id: "{entity_id}") }}"#),
        ))
        .await;
    assert!(del.errors.is_empty(), "delete failed: {:?}", del.errors);

    let restore = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ restoreEntity(id: "{entity_id}") }}"#),
        ))
        .await;
    assert!(
        restore.errors.is_empty(),
        "restore failed: {:?}",
        restore.errors
    );

    assert!(
        auth::authenticate_token(&state, &token).await.is_err(),
        "a session revoked by entity delete must stay rejected immediately after restore"
    );
    assert!(
        auth::authenticate_token(&state, &token).await.is_err(),
        "a session revoked by entity delete must stay rejected even once entity_status is a \
         cache hit again post-restore — this only fails if the session cache entry wasn't \
         invalidated at delete time and survived as a stale 'valid' hit"
    );
}

/// Same shape as the session test above, for the credential side: `delete_entity`
/// also revokes the entity's access-token credentials in Postgres, and
/// `restoreEntity` intentionally never reinstates them. Requires two
/// post-restore authentication attempts for the same reason as the session
/// test — the first always denies via a forced fresh reload; the second is
/// the one that actually proves the credential cache entry itself was
/// invalidated at delete time.
#[tokio::test]
#[ignore]
async fn entity_delete_then_restore_immediately_rejects_a_pre_existing_access_token() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let entity_id = active_entity(&p, "service").await;

    let minted = access_tokens::create_access_token(
        &p,
        &state.config.signing_keys,
        entity_id,
        CreateAccessToken {
            name: "cache-test-entity-restore-token".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .expect("create access token");

    auth::authenticate_token(&state, &minted.token)
        .await
        .expect("initial authentication should succeed");

    let schema = build_schema(state.clone());
    let del = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ deleteEntity(id: "{entity_id}") }}"#),
        ))
        .await;
    assert!(del.errors.is_empty(), "delete failed: {:?}", del.errors);

    let restore = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ restoreEntity(id: "{entity_id}") }}"#),
        ))
        .await;
    assert!(
        restore.errors.is_empty(),
        "restore failed: {:?}",
        restore.errors
    );

    assert!(
        auth::authenticate_token(&state, &minted.token)
            .await
            .is_err(),
        "an access token revoked by entity delete must stay rejected immediately after restore"
    );
    assert!(
        auth::authenticate_token(&state, &minted.token)
            .await
            .is_err(),
        "an access token revoked by entity delete must stay rejected even once entity_status is \
         a cache hit again post-restore — this only fails if the credential cache entry wasn't \
         invalidated at delete time and survived as a stale 'active' hit"
    );
}

// ─── Enumerate-before-lock race (session/credential bulk invalidation) ─────

/// Regression test for a review finding: `deleteEntity`'s session/access-token
/// cache-key enumeration used to run via a plain pool query *before* any
/// transaction or lock was taken. A session or access-token credential
/// created for the entity concurrently — after that enumeration but before
/// the delete's own revoke ran — was never included in the cache barrier and
/// could keep serving as a valid cache hit indefinitely (past the delete, and
/// even across a later `restoreEntity`), despite being revoked in Postgres.
/// This is the identical race shape already closed for group-membership
/// invalidation (see `concurrent_group_membership_change_serializes_against_
/// the_group_subject_lock` below), just previously unfixed for
/// sessions/credentials.
///
/// Fixed by moving the enumeration inside the same transaction as the lock
/// (`identity::repo::lock_entity_and_collect_revocation_ids_in_tx`), which
/// takes an exclusive lock on the entity row — the same lock
/// `create_session`/`create_access_token` take (via `lock_active_entity`)
/// before inserting. As with the group-membership fix, an end-to-end test
/// racing a real `create_session` against a real `deleteEntity` mutation
/// can't actually distinguish fixed from unfixed (a post-hoc read is always a
/// fresh cold-cache load reflecting final Postgres state); this test instead
/// calls the new function directly and proves there is no window in which a
/// concurrent `create_session` can slip past it uncounted: either it's
/// blocked until the transaction commits, or (once committed) it correctly
/// fails against the now-deactivated entity — there is no third outcome
/// where it silently succeeds outside the transaction's lock.
#[tokio::test]
#[ignore]
async fn concurrent_session_creation_cannot_evade_the_entity_delete_enumeration() {
    let p = pool().await;
    let entity = active_entity(&p, "service").await;

    let mut tx = p.begin().await.expect("begin tx");
    let (session_ids, credential_ids) =
        identity_repo::lock_entity_and_collect_revocation_ids_in_tx(&mut tx, entity)
            .await
            .expect("lock and enumerate");
    assert!(
        session_ids.is_empty() && credential_ids.is_empty(),
        "no sessions/credentials exist yet for this fresh entity"
    );

    // `create_session` takes the same entity-row lock before inserting, so it
    // must block until the transaction above commits — not race ahead of the
    // still-open delete transaction and create a session the enumeration has
    // already missed.
    let p2 = p.clone();
    let handle =
        tokio::spawn(async move { identity_repo::create_session(&p2, entity, 3600).await });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "create_session must block on the same entity-row lock the delete's enumeration holds, \
         not commit a session the enumeration has already missed"
    );

    // Mirrors the production call site's order: the status-flip runs after
    // the lock-and-enumerate step (which the barrier, in production, is
    // established between), still inside the same transaction as the lock.
    identity_repo::deactivate_and_finish_entity_deletion_in_tx(&mut tx, false, None, None, entity)
        .await
        .expect("deactivate and finish");
    tx.commit().await.expect("commit lock-holding tx");

    // Once committed, the entity is deactivated (the same effect
    // `deleteEntity`'s cache-aware path has by this point). The
    // previously-blocked `create_session` must now correctly fail rather than
    // slip through and create a session outside of any cache barrier the
    // delete established.
    let outcome = handle.await.expect("join create_session task");
    assert!(
        outcome.is_err(),
        "create_session must fail once the entity has been deactivated by the transaction it \
         was blocked on — succeeding here would mean a session was created in a window the \
         delete's enumeration could never see, exactly the race this fix closes"
    );
}

/// Tenant-level counterpart to the test above: `deleteTenant`'s session
/// cache-key enumeration used to run via a plain pool query before any
/// transaction/lock was taken, so a session created for a member entity in
/// the window between enumeration and the tenant's own bulk revoke was never
/// included in the cache barrier. Fixed by moving the enumeration inside the
/// same transaction as the lock
/// (`tenants::repo::lock_tenant_and_collect_session_ids_in_tx`), which takes
/// an exclusive lock on the tenant row — the same lock `lock_active_entity`
/// takes (via `lock_optional_active_tenant`) before any session/credential
/// can be created for *any* entity in the tenant.
#[tokio::test]
#[ignore]
async fn concurrent_session_creation_cannot_evade_the_tenant_delete_enumeration() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let entity = active_entity_in_tenant(&p, tenant_id, "service").await;

    let mut tx = p.begin().await.expect("begin tx");
    let session_ids = tenant_repo::lock_tenant_and_collect_session_ids_in_tx(&mut tx, tenant_id)
        .await
        .expect("lock and enumerate");
    assert!(
        session_ids.is_empty(),
        "no sessions exist yet for this fresh tenant's member"
    );

    let p2 = p.clone();
    let handle =
        tokio::spawn(async move { identity_repo::create_session(&p2, entity, 3600).await });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "create_session for an entity in this tenant must block on the tenant-row lock the \
         delete's enumeration holds, not commit a session the enumeration has already missed"
    );

    // Mirrors the production call site's order: the status-flip runs after
    // the lock-and-enumerate step (which the barrier, in production, is
    // established between), still inside the same transaction as the lock.
    tenant_repo::deactivate_and_finish_tenant_soft_delete_in_tx(
        &mut tx, false, None, None, tenant_id,
    )
    .await
    .expect("deactivate and finish");
    tx.commit().await.expect("commit lock-holding tx");

    // Once committed, the tenant is deleted (so `lock_active_entity`'s own
    // `lock_optional_active_tenant` check fails) — the previously-blocked
    // `create_session` must now correctly fail rather than slip through.
    let outcome = handle.await.expect("join create_session task");
    assert!(
        outcome.is_err(),
        "create_session must fail once the tenant has been deactivated by the transaction it \
         was blocked on — succeeding here would mean a session was created in a window the \
         delete's enumeration could never see, exactly the race this fix closes"
    );
}

// ─── API-key tenant context after an entity moves tenants ──────────────────

/// Regression test for a review finding: the API-key fast path derived
/// `AuthContext.tenant_id` from the credential cache entry's own duplicated
/// `tenant_id` field, which only got invalidated when the credential itself
/// changed — not when the owning entity moved to a different tenant (only
/// `entity_status` is invalidated on that mutation). The fix removed the
/// duplicated field entirely and derives tenant context from the entity's
/// own (correctly invalidated) cache entry.
///
/// As with the delete/restore tests above, the first authentication attempt
/// after the move always reflects the new tenant correctly regardless of the
/// fix, because the move's `entity_status` invalidation forces that one
/// request through a fresh Postgres reload. It's the *second* attempt — once
/// `entity_status` is a hit again — that actually distinguishes "tenant
/// context comes from the fresh entity entry" from "it comes from the stale
/// credential copy"; confirmed by temporarily reverting the fix and
/// rerunning.
#[tokio::test]
#[ignore]
async fn api_key_auth_reflects_the_current_tenant_after_an_entity_moves_tenants() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let old_tenant = tenant(&p).await;
    let new_tenant = tenant(&p).await;
    let entity_id = active_entity_in_tenant(&p, old_tenant, "service").await;

    let minted = access_tokens::create_access_token(
        &p,
        &state.config.signing_keys,
        entity_id,
        CreateAccessToken {
            name: "cache-test-tenant-move-token".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .expect("create access token");

    let ctx = auth::authenticate_token(&state, &minted.token)
        .await
        .expect("initial authentication should succeed");
    assert_eq!(ctx.tenant_id, Some(old_tenant));

    let schema = build_schema(state.clone());
    let mv = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ updateEntity(id: "{entity_id}", input: {{ tenantId: "{new_tenant}" }}) {{ id }} }}"#
            ),
        ))
        .await;
    assert!(mv.errors.is_empty(), "tenant move failed: {:?}", mv.errors);

    let ctx = auth::authenticate_token(&state, &minted.token)
        .await
        .expect("authentication right after the move should still succeed");
    assert_eq!(
        ctx.tenant_id,
        Some(new_tenant),
        "not the interesting assertion by itself"
    );

    let ctx = auth::authenticate_token(&state, &minted.token)
        .await
        .expect("authentication should still succeed once entity_status is a hit again");
    assert_eq!(
        ctx.tenant_id,
        Some(new_tenant),
        "AuthContext.tenant_id must reflect the entity's current tenant, not a stale copy that \
         would have been cached in the credential entry from before the move"
    );
}

/// Mints a real session row plus a signed JWT carrying `tenant_id` as its
/// `tid` claim, so tests can exercise `auth_from_jwt` end to end.
async fn session_jwt(
    state: &AppState,
    pool: &PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> String {
    let session_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (id, entity_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(entity_id)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("insert session");

    let primary = state.keys.read().await.primary.clone();
    auth::encode_jwt(
        entity_id,
        session_id,
        tenant_id,
        &primary,
        state.config.jwt_expiry_secs,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )
    .expect("encode jwt")
}

/// JWT counterpart to
/// `api_key_auth_reflects_the_current_tenant_after_an_entity_moves_tenants`,
/// and a regression test for a review finding the API-key path did not have:
/// `auth_from_jwt` built the `tenant_status` cache key from the token's `tid`
/// claim but populated it with the payload of the *entity's current* tenant,
/// because the miss loader joins tenants through `entities.tenant_id`. Once a
/// token outlives a tenant move the two differ, so authenticating with the
/// stale token wrote the new tenant's status under the old tenant's key — and
/// since the populate ran *before* `check_session_entity_tenant`, even the
/// request that got rejected for the tid mismatch poisoned it on the way out.
/// A frozen tenant then read back as active for every one of its members
/// until the TTL elapsed.
#[tokio::test]
#[ignore]
async fn a_stale_jwt_from_before_a_tenant_move_cannot_poison_the_old_tenants_status() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let old_tenant = tenant(&p).await;
    let new_tenant = tenant(&p).await;
    // `mover` leaves `old_tenant` for `new_tenant`; `stayer` remains behind
    // and is the one a poisoned `tenant_status:{old_tenant}` would wrongly
    // let through.
    let mover = active_entity_in_tenant(&p, old_tenant, "service").await;
    let stayer = active_entity_in_tenant(&p, old_tenant, "service").await;

    let mover_token = session_jwt(&state, &p, mover, Some(old_tenant)).await;
    let stayer_token = session_jwt(&state, &p, stayer, Some(old_tenant)).await;

    // Warm `stayer`'s session and entity_status entries while everything is
    // still valid. Freezing the tenant below invalidates `tenant_status` and
    // nothing else, so those two stay hits — which is what makes a poisoned
    // `tenant_status` entry decisive rather than academic: with all three
    // keys hitting, `auth_from_jwt` never consults Postgres at all.
    auth::authenticate_token(&state, &stayer_token)
        .await
        .expect("initial authentication should succeed");

    let schema = build_schema(state.clone());
    let mv = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ updateEntity(id: "{mover}", input: {{ tenantId: "{new_tenant}" }}) {{ id }} }}"#
            ),
        ))
        .await;
    assert!(mv.errors.is_empty(), "tenant move failed: {:?}", mv.errors);

    let sv = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ freezeTenant(id: "{old_tenant}") {{ id }} }}"#),
        ))
        .await;
    assert!(
        sv.errors.is_empty(),
        "tenant freeze failed: {:?}",
        sv.errors
    );

    // `mover`'s token still claims `old_tenant` while the entity now lives in
    // `new_tenant`, so this must be rejected on the tid mismatch.
    let result = auth::authenticate_token(&state, &mover_token).await;
    assert!(
        result.is_err(),
        "a JWT whose tid no longer matches the entity's tenant must be rejected"
    );

    // The interesting assertion: that rejected authentication must not have
    // left `new_tenant`'s active status cached under `old_tenant`'s key.
    let result = auth::authenticate_token(&state, &stayer_token).await;
    assert!(
        result.is_err(),
        "a member of the frozen tenant must still be rejected — the rejected \
         authentication above must not have populated tenant_status for the \
         frozen tenant with the moved entity's new tenant's status"
    );
}

/// A platform-scope allow block granting `create`, so a non-admin subject can
/// be given exactly the capability `createTenant`'s gate requires.
async fn make_platform_create_block(pool: &PgPool) -> Uuid {
    let action_id: Uuid =
        sqlx::query_scalar("SELECT id FROM actions WHERE name = 'create' LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("create action");
    authz_repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: None,
            scope_mode: "platform".into(),
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({}),
            action_ids: vec![action_id],
        },
    )
    .await
    .expect("create permission block")
    .id
}

/// Regression test for a review finding: `createTenant` bootstraps a
/// tenant-admin role, role assignment and membership for the creator in the
/// same transaction — growing the creator's own grant set — but ran with no
/// `grants` invalidation. The capability gate immediately above it warms that
/// exact key, so a creator without platform-wide `manage` could not administer
/// the tenant they had just created until the grants TTL lapsed.
#[tokio::test]
#[ignore]
async fn tenant_creation_immediately_grants_the_creator_tenant_admin() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    // Deliberately *not* a platform admin: with platform-wide `manage` the
    // creator would pass the post-creation check no matter what the cache
    // held, and the test would prove nothing.
    let creator = active_entity(&p, "service").await;
    let block_id = make_platform_create_block(&p).await;
    authz_repo::create_direct_policy(
        &p,
        CreateDirectPolicy {
            tenant_id: None,
            subject_kind: SubjectKind::Entity,
            subject_id: creator,
            permission_block_id: block_id,
        },
    )
    .await
    .expect("create direct policy");

    let schema = build_schema(state.clone());
    let resp = schema
        .execute(authed(
            creator,
            cache.clone(),
            r#"mutation { createTenant(input: { name: "cache-test-bootstrap" }) { id } }"#,
        ))
        .await;
    assert!(
        resp.errors.is_empty(),
        "createTenant failed: {:?}",
        resp.errors
    );
    let tenant_id: Uuid = resp
        .data
        .into_json()
        .expect("response is json")
        .pointer("/createTenant/id")
        .and_then(|id| id.as_str())
        .expect("createTenant returned an id")
        .parse()
        .expect("parse created tenant id");

    // The creator's grants were warmed by `createTenant`'s own capability
    // gate, moments before the bootstrap added the tenant-admin assignment.
    let req = AuthzRequest {
        subject_id: creator,
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("tenant".into()),
        object_id: Some(tenant_id),
        context: json!({}),
    };
    let auth = auth_context(creator, cache.clone());
    let decision = engine::evaluate(&p, &req, &auth).await.expect("evaluate");
    assert!(
        decision.allowed,
        "the creator must be able to manage the tenant they just created on the very next \
         request, not after the grants TTL expires"
    );
}

// ─── Group-subject mutation vs. concurrent membership change ───────────────

/// A real hierarchy mutation used to acquire the global hierarchy advisory
/// lock before reaching for its owning tenant. A concurrent group-subject
/// policy mutation takes those resources in the opposite order, so the pair
/// could deadlock. Hold the tenant, start the real uncached mutation, and prove
/// the advisory lock is still free while that mutation waits.
#[tokio::test]
#[ignore]
async fn group_hierarchy_mutation_locks_tenant_before_advisory() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let parent = new_group_in_tenant(&p, tenant_id, "principal", "lock-order-parent").await;
    let child = new_group_in_tenant(&p, tenant_id, "principal", "lock-order-child").await;

    let mut tenant_tx = p.begin().await.expect("begin tenant-locking tx");
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(tenant_id)
        .fetch_one(&mut *tenant_tx)
        .await
        .expect("lock tenant");

    let p2 = p.clone();
    let handle =
        tokio::spawn(async move { identity_repo::set_group_parent(&p2, child, parent).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "hierarchy mutation must wait for the tenant lock"
    );

    let advisory_available: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtextextended('atom:group-hierarchy', 0))",
    )
    .fetch_one(&mut *tenant_tx)
    .await
    .expect("try hierarchy advisory lock");
    assert!(
        advisory_available,
        "a hierarchy mutation waiting on its tenant must not already hold the hierarchy advisory lock"
    );

    tenant_tx
        .commit()
        .await
        .expect("release tenant and advisory locks");
    handle
        .await
        .expect("join hierarchy mutation")
        .expect("hierarchy mutation completes after release");
}

/// The generic closure preparation is shared by cached group mutations and
/// bootstrap object-group linking. Object roots do not produce a
/// `principal_groups` row lock, so this specifically proves the tenant barrier
/// happens before the advisory lock even for that otherwise-empty closure.
#[tokio::test]
#[ignore]
async fn object_group_closure_preparation_locks_tenant_before_advisory() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let object_group = new_group_in_tenant(&p, tenant_id, "object", "object-lock-order").await;

    let mut tenant_tx = p.begin().await.expect("begin tenant-locking tx");
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(tenant_id)
        .fetch_one(&mut *tenant_tx)
        .await
        .expect("lock tenant");

    let p2 = p.clone();
    let handle = tokio::spawn(async move {
        let mut mutation_tx = p2.begin().await.expect("begin closure-preparation tx");
        authz_repo::lock_group_closures_and_collect_member_ids(&mut mutation_tx, &[object_group])
            .await
            .expect("prepare object-group closure");
        // Mirrors the old mutation/bootstrap body which reached for the tenant
        // only after preparation had already acquired the advisory lock.
        sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_one(&mut *mutation_tx)
            .await
            .expect("re-lock tenant in mutation body");
        mutation_tx.commit().await.expect("commit preparation tx");
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "object-group preparation must wait for the tenant lock"
    );

    let advisory_available: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtextextended('atom:group-hierarchy', 0))",
    )
    .fetch_one(&mut *tenant_tx)
    .await
    .expect("try hierarchy advisory lock");
    assert!(
        advisory_available,
        "object-group preparation waiting on its tenant must not hold the hierarchy advisory lock"
    );

    tenant_tx
        .commit()
        .await
        .expect("release tenant and advisory locks");
    handle.await.expect("join object-group preparation");
}

/// A closure can contain both object and principal groups. Group mutations lock
/// all object rows before principal rows, so closure preparation must use that
/// same cross-table order or the two paths can deadlock.
#[tokio::test]
#[ignore]
async fn group_closure_preparation_locks_object_rows_before_principal_rows() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let object_group_id =
        new_group_in_tenant(&p, tenant_id, "object", "object-physical-lock").await;
    let principal_group_id =
        new_group_in_tenant(&p, tenant_id, "principal", "principal-physical-lock").await;

    let mut object_tx = p.begin().await.expect("begin object-locking tx");
    sqlx::query("SELECT id FROM object_groups WHERE id = $1 FOR UPDATE")
        .bind(object_group_id)
        .fetch_one(&mut *object_tx)
        .await
        .expect("lock object-group row");

    let p2 = p.clone();
    let handle = tokio::spawn(async move {
        let mut closure_tx = p2.begin().await.expect("begin closure tx");
        authz_repo::lock_group_closures_and_collect_member_ids(
            &mut closure_tx,
            &[principal_group_id, object_group_id],
        )
        .await
        .expect("prepare mixed-kind group closure");
        closure_tx.commit().await.expect("commit closure tx");
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "closure preparation must wait for the object-group row before reaching the principal row"
    );

    tokio::time::timeout(
        std::time::Duration::from_millis(500),
        sqlx::query("SELECT id FROM principal_groups WHERE id = $1 FOR UPDATE")
            .bind(principal_group_id)
            .fetch_one(&mut *object_tx),
    )
    .await
    .expect("principal row must remain unlocked while closure preparation waits for the object row")
    .expect("lock principal-group row");

    object_tx
        .commit()
        .await
        .expect("release physical group rows");
    handle.await.expect("join closure preparation");
}

/// Regression test for a review finding: resolving a group-subject
/// mutation's affected `grants` keys from "current members" alone has a
/// race against a concurrent `add_group_member` for the same group — a
/// member added in between the enumeration and the mutation's own commit
/// would never be in the enumerated set, so their `grants` key would never
/// be invalidated, letting a stale cached grant (or a stale cached lack of
/// one) survive until the grants TTL.
///
/// Fixed by locking the group's row — the same lock
/// `identity::repo::add_group_member`/`remove_group_member` already take —
/// via `authz::repo::lock_group_closures_and_collect_member_ids`, for the
/// caller's entire transaction (enumeration through commit). This test
/// proves the lock actually serializes against a concurrent membership
/// change, mirroring `m8_guardrails.rs`'s
/// `concurrent_block_link_and_role_assignment_serialize` for the analogous
/// role-lock case.
#[tokio::test]
#[ignore]
async fn concurrent_group_membership_change_serializes_against_the_group_subject_lock() {
    let p = pool().await;
    let group = new_group(&p, "concurrent-lock").await;
    let existing_member = active_entity(&p, "service").await;
    identity_repo::add_group_member(&p, group, existing_member)
        .await
        .expect("seed existing member");

    // Hold the lock a group-subject mutation resolver would (e.g.
    // `deleteDirectPolicy`'s) — the exact enumeration step, kept open (not
    // yet committed).
    let mut tx = p.begin().await.expect("begin tx");
    let member_ids = authz_repo::lock_group_closures_and_collect_member_ids(&mut tx, &[group])
        .await
        .expect("lock and enumerate");
    assert_eq!(
        member_ids,
        vec![existing_member],
        "enumeration should see only the pre-existing member while the lock is held"
    );

    // `add_group_member` locks the same group row, so it must block until
    // the transaction above commits — not silently add a member our
    // (already-captured) enumeration has already missed.
    let p2 = p.clone();
    let new_member = active_entity(&p, "service").await;
    let handle =
        tokio::spawn(async move { identity_repo::add_group_member(&p2, group, new_member).await });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "add_group_member must block on the same group-row lock the enumeration holds, not \
         commit a membership change the enumeration has already missed"
    );

    tx.commit().await.expect("commit lock-holding tx");
    handle
        .await
        .expect("join add_group_member task")
        .expect("add_group_member should succeed once unblocked");
}

/// Tenant-scoped role mutations and role-assignment creation must acquire the
/// same resources in the same order. Assignment preparation locks the tenant
/// before the role. The cached role-mutation preparation used to lock the role
/// first, while its mutation body later reached for the tenant through
/// `lock_role`; a concurrent assignment holding the tenant and waiting for the
/// role completed the tenant <-> role cycle.
///
/// Hold the tenant, start the exact cached preparation helper, then try to lock
/// the role from the tenant-owning transaction. With the canonical tenant ->
/// role order the helper is still queued on the tenant and the role is
/// immediately available. With the old order the helper already owns the role.
#[tokio::test]
#[ignore]
async fn cached_role_mutation_locks_tenant_before_role() {
    let p = pool().await;
    let tenant_id = tenant(&p).await;
    let role = authz_repo::create_role(
        &p,
        CreateRole {
            name: format!("m25-tenant-role-lock-order-{}", Uuid::new_v4()),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create tenant role");

    let mut tx = p.begin().await.expect("begin tenant-locking tx");
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock tenant");

    let role_id = role.id;
    let p2 = p.clone();
    let (prepared_sender, mut prepared_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut mutation_tx = p2.begin().await.expect("begin cached-preparation tx");
        authz_repo::lock_role_and_collect_grants_keys(&mut mutation_tx, role_id)
            .await
            .expect("prepare cached role mutation");
        prepared_sender.send(()).expect("report preparation");
        let _ = release_receiver.await;
        mutation_tx.commit().await.expect("commit preparation tx");
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        matches!(
            prepared_receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "cached role preparation must wait for the owning tenant before locking the role"
    );

    tokio::time::timeout(
        std::time::Duration::from_millis(500),
        sqlx::query("SELECT id FROM roles WHERE id = $1 FOR UPDATE")
            .bind(role_id)
            .fetch_one(&mut *tx),
    )
    .await
    .expect(
        "role must remain unlocked while the cached mutation waits for its tenant; a timeout \
         proves the old role -> tenant inversion is still present",
    )
    .expect("lock role");

    tx.commit().await.expect("release tenant and role locks");
    prepared_receiver
        .await
        .expect("preparation completes after tenant release");
    release_sender.send(()).expect("release preparation tx");
    handle.await.expect("join cached role preparation");
}

/// Regression test for a review finding: `createRoleAssignment`'s
/// group-subject path locked the subject group's closure first and only
/// reached the role lock afterward (inside `create_role_assignment_in_tx`'s
/// own `lock_role` call) — the reverse of every role mutation
/// (`replaceRolePermissionBlocks`/`deleteRole`/`restoreRole`, via
/// `lock_role_and_collect_grants_keys`), which always locks the tenant and
/// role before any assigned groups' closures. If role R is already assigned to an
/// ancestor group and a concurrent pair of requests ran — assign R to a
/// descendant group; mutate R's blocks — they could hold the descendant
/// group's row and the role row in opposite order: a genuine wait-for cycle,
/// which Postgres detects and resolves by aborting one side with a
/// "deadlock detected" error.
///
/// Fixed by having `createRoleAssignment`'s group-subject path lock the role
/// *before* the group closure too, via the canonical
/// `authz::repo::prepare_role_assignment_in_tx` helper.
///
/// A first version of this test held only the role lock and asserted
/// `createRoleAssignment` blocked on it — but that passes under *either*
/// lock order (the old order still reaches the role lock eventually, via
/// `create_role_assignment_in_tx`'s own `lock_role` call, just later), so it
/// couldn't actually distinguish fixed from unfixed (confirmed: it passed
/// even with the fix reverted). This version instead reconstructs the
/// actual two-resource cycle: hold the role lock, let the spawned
/// `createRoleAssignment` block on it, then — *while it's still blocked* —
/// try to lock the descendant group ourselves. With the fix, the spawned
/// task hasn't touched the group yet (it's queued for the role first), so
/// our lock attempt succeeds immediately. With the old order, the spawned
/// task would already be holding the group (locked before it ever reached
/// for the role), so our attempt would itself block — the two sides
/// waiting on each other — which is exactly the cycle this fix closes.
#[tokio::test]
#[ignore]
async fn create_role_assignment_for_group_subject_locks_the_role_before_the_group() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let ancestor = new_group(&p, "lock-order-ancestor").await;
    let descendant = new_group(&p, "lock-order-descendant").await;
    identity_repo::set_group_parent(&p, descendant, ancestor)
        .await
        .expect("set parent");
    let role = authz_repo::create_role(
        &p,
        CreateRole {
            name: format!("m25-lock-order-role-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
        },
    )
    .await
    .expect("create role");
    // Assigning R to the ancestor puts `descendant` in R's assigned-group
    // closure — exactly what `lock_role_and_collect_grants_keys` would lock
    // for a mutation on R.
    authz_repo::create_role_assignment(
        &p,
        CreateRoleAssignment {
            tenant_id: None,
            subject_kind: SubjectKind::Group,
            subject_id: ancestor,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role to ancestor");

    // Hold only the role lock — exactly what a role mutation
    // (`lock_role_and_collect_grants_keys`) holds at the point it's already
    // past its own first step, before it reaches for the assigned groups'
    // closures.
    let mut tx = p.begin().await.expect("begin tx");
    sqlx::query("SELECT id FROM roles WHERE id = $1 FOR UPDATE")
        .bind(role.id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock role");

    // Concurrently: assign R to the descendant group, through the real,
    // wired GraphQL path.
    let schema = build_schema(state.clone());
    let cache2 = cache.clone();
    let role_id = role.id;
    let handle = tokio::spawn(async move {
        schema
            .execute(authed(
                common::admin_id(),
                cache2,
                format!(
                    r#"mutation {{
                        createRoleAssignment(input: {{
                            subjectKind: group,
                            subjectId: "{descendant}",
                            roleId: "{role_id}"
                        }}) {{ id }}
                    }}"#
                ),
            ))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !handle.is_finished(),
        "createRoleAssignment must block on the role lock"
    );

    // The decisive check: while the spawned task is blocked waiting for the
    // role lock, we must still be able to lock the descendant group
    // immediately — proving the spawned task has not already acquired it
    // (which the old, reversed order would have done before ever touching
    // the role).
    tokio::time::timeout(
        std::time::Duration::from_millis(500),
        sqlx::query("SELECT id FROM principal_groups WHERE id = $1 FOR UPDATE")
            .bind(descendant)
            .fetch_one(&mut *tx),
    )
    .await
    .expect(
        "locking the descendant group must not block while createRoleAssignment is blocked on \
         the role lock — a block here means it's holding the group while waiting on the role, \
         i.e. the exact deadlock cycle this fix closes",
    )
    .expect("lock descendant group");

    tx.commit().await.expect("commit tx");
    let resp = handle.await.expect("join createRoleAssignment task");
    assert!(
        resp.errors.is_empty(),
        "createRoleAssignment failed: {:?}",
        resp.errors
    );
}

// An end-to-end complement to the test above — racing a real
// `add_group_member` against the real `deleteDirectPolicy` mutation, then
// asserting the new member's grants are correctly denied — was tried and
// dropped. It passed even with the group-row lock reverted (confirmed by
// reverting and rerunning, 5/5), because it only calls `evaluate_read` once,
// *after* both operations have fully committed: that read is always a fresh
// cold-cache load reflecting final Postgres state, so it can never observe
// the stale intermediate value the race would have produced. Reproducing the
// actual staleness would require a read to land in the narrow window between
// the add's commit and the delete's commit — not achievable through ordinary
// concurrent scheduling without injecting a hook into the read path. The
// mechanism test above (proving the lock itself blocks a concurrent
// `add_group_member`) is the one that actually distinguishes fixed from
// unfixed here, the same lesson as the credential-restore investigation
// documented on `tenant_restore_clears_reactivated_credential_cache_entries`.

async fn hmget_raw(key: &str) -> (Option<i64>, Option<String>, Option<Vec<u8>>) {
    let mut conn = raw_redis_conn().await;
    redis::cmd("HMGET")
        .arg(format!("integration-tests:{key}"))
        .arg("v")
        .arg("dirty")
        .arg("p")
        .query_async(&mut conn)
        .await
        .expect("hmget")
}

/// Directly writes a clean (non-dirty, version 1), already-populated cache
/// entry — bypassing `try_populate`'s version check entirely, since this is
/// for hand-seeding test fixtures, not exercising the barrier itself.
async fn seed_hit<T: serde::Serialize>(key: &str, value: &T) {
    let payload = rmp_serde::to_vec(value).expect("serialize seed value");
    let mut conn = raw_redis_conn().await;
    let incarnation: String = redis::cmd("GET")
        .arg("integration-tests:atom:v1:incarnation")
        .query_async(&mut conn)
        .await
        .expect("test cache namespace incarnation");
    let _: () = redis::cmd("HSET")
        .arg(format!("integration-tests:{key}"))
        .arg("i")
        .arg(incarnation)
        .arg("v")
        .arg(1)
        .arg("dirty")
        .arg("0")
        .arg("p")
        .arg(payload)
        .query_async(&mut conn)
        .await
        .expect("seed cache entry");
}

// ─── Negative control ───────────────────────────────────────────────────────

/// Proves the "tenant status short-circuits before grants" design decision is
/// actually followed, not just accidentally correct: a tenant status change
/// must invalidate `tenant_status`, but must NOT touch the `grants` key.
#[tokio::test]
#[ignore]
async fn tenant_status_change_does_not_touch_the_grants_cache_key() {
    let p = pool().await;
    let (state, cache) = state_with_cache(p.clone()).await;
    let member = active_entity(&p, "service").await;

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("cache-test-tenant-{tenant_id}"))
        .execute(&p)
        .await
        .expect("insert tenant");

    // Warm the member's grants cache (an empty grant set is still a cached
    // entry — what matters is whether the key gets touched, not its value).
    let req = AuthzRequest {
        subject_id: member,
        action: "read".into(),
        resource_id: None,
        object_kind: Some("tenant".into()),
        object_id: Some(tenant_id),
        context: json!({}),
    };
    let auth = auth_context(member, cache.clone());
    let _ = engine::evaluate(&p, &req, &auth).await.expect("evaluate");

    let grants_key = cache.redis_key(&atom::cache::keys::grants(member));
    let mut conn = raw_redis_conn().await;
    let before_exists: bool = redis::cmd("EXISTS")
        .arg(&grants_key)
        .query_async(&mut conn)
        .await
        .expect("exists check");

    let schema = build_schema(state);
    let resp = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(r#"mutation {{ disableTenant(id: "{tenant_id}") {{ id }} }}"#),
        ))
        .await;
    assert!(resp.errors.is_empty(), "disable failed: {:?}", resp.errors);

    let after_exists: bool = redis::cmd("EXISTS")
        .arg(&grants_key)
        .query_async(&mut conn)
        .await
        .expect("exists check");

    assert_eq!(
        before_exists, after_exists,
        "tenant status change must not invalidate the grants cache key — the PDP's \
         tenant-lifecycle deny check runs before grant matching, so grants invalidation \
         is unnecessary here by design (see authz::engine::load_decision_context)"
    );
}
