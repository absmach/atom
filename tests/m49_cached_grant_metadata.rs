//! Cache invalidation for metadata embedded in `EffectiveGrant` payloads.
//!
//! Requires Postgres plus Redis:
//! ```bash
//! DATABASE_URL=postgres://... ATOM_TEST_REDIS_URL=redis://... \
//!   cargo test --test m49_cached_grant_metadata -- --ignored
//! ```

mod common;

use std::sync::Arc;

use async_graphql::Request;
use atom::{
    auth::AuthContext,
    authz::{engine, repo as authz_repo},
    cache::CacheClient,
    config::Config,
    graphql::build_schema,
    identity::repo as identity_repo,
    models::{
        enums::{Effect, SubjectKind},
        group::CreateGroup,
        policy::{AuthzRequest, CreatePermissionBlock, CreateRoleAssignment},
        role::CreateRole,
    },
    state::AppState,
};
use common::{cache_client, pool};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn state_with_cache(pool: PgPool) -> (AppState, Arc<CacheClient>) {
    let config = Config::for_tests();
    let active_keys = atom::keys::rotate(&pool, &config.signing_keys)
        .await
        .expect("rotate test signing key");
    let state = AppState::new(pool, config, active_keys, Some(cache_client().await));
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

async fn active_entity(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')",
    )
    .bind(id)
    .bind(format!("m49-entity-{id}"))
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn channel(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name) VALUES ($1, 'channel', $2)")
        .bind(id)
        .bind(format!("m49-channel-{id}"))
        .execute(pool)
        .await
        .expect("insert channel");
    id
}

async fn read_block(pool: &PgPool) -> Uuid {
    let action_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read action");
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
    .expect("create read block")
    .id
}

async fn explain_read(
    pool: &PgPool,
    cache: Arc<CacheClient>,
    subject_id: Uuid,
    resource_id: Uuid,
) -> atom::models::access::EvaluatedBinding {
    let response = engine::explain(
        pool,
        &AuthzRequest {
            subject_id,
            action: "read".into(),
            resource_id: Some(resource_id),
            object_kind: None,
            object_id: None,
            context: json!({}),
        },
        &auth_context(subject_id, cache),
    )
    .await
    .expect("explain read");
    assert!(response.allowed, "{}", response.reason);
    response.matched_binding.expect("matched role binding")
}

#[tokio::test]
#[ignore]
async fn role_and_group_renames_refresh_cached_effective_grant_metadata() {
    let pool = pool().await;
    let (state, cache) = state_with_cache(pool.clone()).await;
    let member_id = active_entity(&pool).await;
    let channel_id = channel(&pool).await;

    let old_group_name = format!("m49-old-group-{}", Uuid::new_v4());
    let group = identity_repo::create_group(
        &pool,
        CreateGroup {
            id: None,
            name: old_group_name.clone(),
            tenant_id: None,
            group_type: Some("principal".into()),
            description: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create principal group");
    identity_repo::add_group_member(&pool, group.id, member_id)
        .await
        .expect("add group member");

    let old_role_name = format!("m49-old-role-{}", Uuid::new_v4());
    let role = authz_repo::create_role(
        &pool,
        CreateRole {
            name: old_role_name.clone(),
            tenant_id: None,
            description: None,
        },
    )
    .await
    .expect("create role");
    let block_id = read_block(&pool).await;
    authz_repo::replace_role_permission_block_links(&pool, role.id, &[block_id])
        .await
        .expect("link role block");
    authz_repo::create_role_assignment(
        &pool,
        CreateRoleAssignment {
            tenant_id: None,
            subject_kind: SubjectKind::Group,
            subject_id: group.id,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role to group");

    let warmed = explain_read(&pool, cache.clone(), member_id, channel_id).await;
    assert_eq!(warmed.role_name.as_deref(), Some(old_role_name.as_str()));
    assert!(
        warmed.via.contains(&old_group_name),
        "expected old group path in {:?}",
        warmed.via
    );

    let schema = build_schema(state);
    let new_role_name = format!("m49-new-role-{}", Uuid::new_v4());
    let response = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ updateRole(id: "{}", input: {{ name: "{}" }}) {{ id name }} }}"#,
                role.id, new_role_name
            ),
        ))
        .await;
    assert!(
        response.errors.is_empty(),
        "role rename failed: {:?}",
        response.errors
    );

    let after_role = explain_read(&pool, cache.clone(), member_id, channel_id).await;
    assert_eq!(
        after_role.role_name.as_deref(),
        Some(new_role_name.as_str()),
        "role rename must invalidate the member's cached EffectiveGrant"
    );

    let new_group_name = format!("m49-new-group-{}", Uuid::new_v4());
    let response = schema
        .execute(authed(
            common::admin_id(),
            cache.clone(),
            format!(
                r#"mutation {{ updateGroup(id: "{}", input: {{ name: "{}" }}) {{ id name }} }}"#,
                group.id, new_group_name
            ),
        ))
        .await;
    assert!(
        response.errors.is_empty(),
        "group rename failed: {:?}",
        response.errors
    );

    let after_group = explain_read(&pool, cache, member_id, channel_id).await;
    assert!(
        after_group.via.contains(&new_group_name),
        "group rename must refresh the cached grant path: {:?}",
        after_group.via
    );
    assert!(
        !after_group.via.contains(&old_group_name),
        "cached grant path must not retain the old group name: {:?}",
        after_group.via
    );
}
