//! Authorization regression tests for the frozen entity mutation API.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m50_entity_mutation_authorization -- --ignored
//! ```

mod common;

use async_graphql::{Request, Response};
use atom::{
    auth::AuthContext,
    authz::repo::CredentialCeiling,
    config::Config,
    error::AppError,
    graphql::build_schema,
    identity,
    keys::{ActiveKeys, LoadedKey},
    models::entity::UpdateEntity,
    state::AppState,
};
use serde_json::Value;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use uuid::Uuid;

fn state(pool: PgPool) -> AppState {
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        Config::for_tests(),
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

fn authed_scoped(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        credential_id: Some(Uuid::new_v4()),
        scoped: true,
        ceiling: Some(std::sync::Arc::new(CredentialCeiling { entries: vec![] })),
        cache: None,
    })
}

fn assert_forbidden(response: &Response, context: &str) {
    assert_eq!(
        response.errors.len(),
        1,
        "{context}: expected one authorization error, got {:?}",
        response.errors
    );
    assert_eq!(response.errors[0].message, "forbidden", "{context}");
}

async fn tenant(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(id)
        .bind(format!("entity-auth-tenant-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn entity(pool: &PgPool, tenant_id: Option<Uuid>, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("entity-auth-{kind}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn add_tenant_member(pool: &PgPool, tenant_id: Uuid, entity_id: Uuid) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, entity_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(pool)
    .await
    .expect("insert tenant membership");
}

async fn race_pool(application_name: &str) -> PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let connect_options: PgConnectOptions = database_url
        .parse()
        .expect("parse DATABASE_URL for race pool");
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options.application_name(application_name))
        .await
        .expect("connect race pool")
}

async fn wait_for_application_lock(pool: &PgPool, application_name: &str) -> bool {
    for _ in 0..200 {
        let waiting = sqlx::query_scalar(
            "SELECT EXISTS(\
                 SELECT 1 FROM pg_stat_activity \
                 WHERE application_name = $1 AND wait_event_type = 'Lock'\
             )",
        )
        .bind(application_name)
        .fetch_one(pool)
        .await
        .expect("inspect mutation wait state");
        if waiting {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    false
}

async fn allow_tenant_action(pool: &PgPool, subject_id: Uuid, tenant_id: Uuid, action: &str) {
    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, tenant_id, scope_mode, effect) \
         VALUES ($1, $2, 'tenant', 'allow')",
    )
    .bind(block_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert tenant permission block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) \
         SELECT $1, id FROM actions WHERE name = $2",
    )
    .bind(block_id)
    .bind(action)
    .execute(pool)
    .await
    .expect("link tenant action");
    sqlx::query(
        "INSERT INTO direct_policies \
         (tenant_id, subject_kind, subject_id, permission_block_id) \
         VALUES ($1, 'entity', $2, $3)",
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("assign tenant policy");
}

async fn allow_object_action(pool: &PgPool, subject_id: Uuid, object_id: Uuid, action: &str) {
    let tenant_id: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
            .bind(object_id)
            .fetch_one(pool)
            .await
            .expect("object tenant");
    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks \
         (id, tenant_id, scope_mode, object_id, effect) \
         VALUES ($1, $2, 'object', $3, 'allow')",
    )
    .bind(block_id)
    .bind(tenant_id)
    .bind(object_id)
    .execute(pool)
    .await
    .expect("insert object permission block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) \
         SELECT $1, id FROM actions WHERE name = $2",
    )
    .bind(block_id)
    .bind(action)
    .execute(pool)
    .await
    .expect("link object action");
    sqlx::query(
        "INSERT INTO direct_policies \
         (tenant_id, subject_kind, subject_id, permission_block_id) \
         VALUES ($1, 'entity', $2, $3)",
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("assign object policy");
}

async fn entity_profile(pool: &PgPool, kind: &str, json_schema: Value) -> (Uuid, Uuid) {
    let profile_id = Uuid::new_v4();
    let profile_version_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO profiles \
         (id, object_kind, kind, key, display_name, status) \
         VALUES ($1, 'entity', $2, $3, $4, 'active')",
    )
    .bind(profile_id)
    .bind(kind)
    .bind(format!("entity-auth-{kind}-{profile_id}"))
    .bind(format!("Entity auth {kind} {profile_id}"))
    .execute(pool)
    .await
    .expect("insert profile");
    sqlx::query(
        "INSERT INTO profile_versions \
         (id, profile_id, version, json_schema, ui_schema, status) \
         VALUES ($1, $2, 1, $3, '{}', 'active')",
    )
    .bind(profile_version_id)
    .bind(profile_id)
    .bind(json_schema)
    .execute(pool)
    .await
    .expect("insert profile version");
    (profile_id, profile_version_id)
}

#[tokio::test]
#[ignore]
async fn self_update_and_delete_require_real_grants() {
    let pool = common::pool().await;
    let caller = entity(&pool, None, "human").await;
    let schema = build_schema(state(pool.clone()));

    let update = schema
        .execute(authed_as(
            caller,
            format!(
                r#"mutation {{ updateEntity(id: "{caller}", input: {{ name: "grant-free-self-update" }}) {{ id }} }}"#
            ),
        ))
        .await;
    assert_forbidden(
        &update,
        "self-targeting must not bypass update authorization",
    );
    let name: String = sqlx::query_scalar("SELECT name FROM entities WHERE id = $1")
        .bind(caller)
        .fetch_one(&pool)
        .await
        .expect("entity name");
    assert_ne!(name, "grant-free-self-update");

    let delete = schema
        .execute(authed_as(
            caller,
            format!(r#"mutation {{ deleteEntity(id: "{caller}") }}"#),
        ))
        .await;
    assert_forbidden(
        &delete,
        "self-targeting must not bypass delete authorization",
    );
    let (status, deleted_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deleted_at FROM entities WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .expect("entity lifecycle");
    assert_eq!(status, "active");
    assert!(deleted_at.is_none());
}

#[tokio::test]
#[ignore]
async fn entity_move_requires_source_and_destination_authority() {
    let pool = common::pool().await;
    let source_tenant = tenant(&pool).await;
    let destination_tenant = tenant(&pool).await;
    let caller = entity(&pool, None, "human").await;
    let destination_only_caller = entity(&pool, None, "human").await;
    let target = entity(&pool, Some(source_tenant), "device").await;
    let schema = build_schema(state(pool.clone()));

    for member in [caller, destination_only_caller] {
        add_tenant_member(&pool, source_tenant, member).await;
        add_tenant_member(&pool, destination_tenant, member).await;
    }
    allow_tenant_action(&pool, caller, source_tenant, "write").await;
    allow_tenant_action(&pool, destination_only_caller, destination_tenant, "write").await;
    let move_query = format!(
        r#"mutation {{ updateEntity(id: "{target}", input: {{ tenantId: "{destination_tenant}" }}) {{ id tenantId }} }}"#
    );

    let destination_only = schema
        .execute(authed_as(destination_only_caller, move_query.clone()))
        .await;
    assert_forbidden(
        &destination_only,
        "destination authority alone must not authorize a tenant move",
    );

    let source_only = schema.execute(authed_as(caller, move_query.clone())).await;
    assert_forbidden(
        &source_only,
        "source authority alone must not authorize a tenant move",
    );
    let persisted_tenant: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("target tenant after denied move");
    assert_eq!(persisted_tenant, Some(source_tenant));

    allow_tenant_action(&pool, caller, destination_tenant, "write").await;
    let authorized = schema.execute(authed_as(caller, move_query)).await;
    assert!(authorized.errors.is_empty(), "{:?}", authorized.errors);
    assert_eq!(
        authorized.data.into_json().expect("json")["updateEntity"]["tenantId"],
        destination_tenant.to_string()
    );
    let persisted_tenant: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("target tenant after authorized move");
    assert_eq!(persisted_tenant, Some(destination_tenant));
}

#[tokio::test]
#[ignore]
async fn concurrent_tenant_move_invalidates_the_authorized_snapshot() {
    let pool = common::pool().await;
    let source_tenant = tenant(&pool).await;
    let requested_destination = tenant(&pool).await;
    let concurrent_destination = tenant(&pool).await;
    let caller = entity(&pool, None, "human").await;
    let target = entity(&pool, Some(source_tenant), "device").await;
    add_tenant_member(&pool, source_tenant, caller).await;
    add_tenant_member(&pool, requested_destination, caller).await;
    allow_tenant_action(&pool, caller, source_tenant, "write").await;
    allow_tenant_action(&pool, caller, requested_destination, "write").await;

    let application_name = format!("atom-entity-auth-race-{}", target.simple());
    let race_pool = race_pool(&application_name).await;

    // Hold every tenant lock the two moves need. The authorized mutation can
    // complete its source/destination checks and read the old ownership, but
    // it must then wait before taking the entity lock. This gives the competing
    // transaction a deterministic serialization point instead of relying on a
    // timing-only sleep.
    let mut competing = pool.begin().await.expect("begin competing move");
    let mut tenant_ids = [source_tenant, requested_destination, concurrent_destination];
    tenant_ids.sort_unstable();
    for tenant_id in tenant_ids {
        sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_one(&mut *competing)
            .await
            .expect("lock tenant for competing move");
    }

    let mutation_pool = race_pool.clone();
    let mutation = tokio::spawn(async move {
        identity::service::update_entity_authorized(
            &mutation_pool,
            None,
            false,
            &AuthContext {
                entity_id: caller,
                ..Default::default()
            },
            target,
            UpdateEntity {
                name: Some("must-not-commit-after-race".into()),
                kind: None,
                alias: None,
                external_id: None,
                tenant_id: Some(requested_destination),
                profile_id: None,
                profile_version_id: None,
                status: None,
                attributes: None,
            },
            serde_json::json!({}),
        )
        .await
    });

    let waiting_on_tenant_lock = wait_for_application_lock(&pool, &application_name).await;
    assert!(
        waiting_on_tenant_lock,
        "authorized mutation never reached the tenant-lock serialization point"
    );

    sqlx::query("UPDATE entities SET tenant_id = $2 WHERE id = $1")
        .bind(target)
        .bind(concurrent_destination)
        .execute(&mut *competing)
        .await
        .expect("commit competing tenant move");
    competing.commit().await.expect("commit competing move");

    let error = tokio::time::timeout(std::time::Duration::from_secs(5), mutation)
        .await
        .expect("authorized mutation completed after lock release")
        .expect("authorized mutation task")
        .expect_err("stale authorization snapshot must fail");
    assert!(
        matches!(error, AppError::Conflict(ref message) if message.contains("changed after authorization")),
        "unexpected stale-snapshot error: {error}"
    );
    let (tenant_id, name): (Option<Uuid>, String) =
        sqlx::query_as("SELECT tenant_id, name FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("entity after racing moves");
    assert_eq!(tenant_id, Some(concurrent_destination));
    assert_ne!(name, "must-not-commit-after-race");
}

#[tokio::test]
#[ignore]
async fn concurrent_tenant_freeze_blocks_authorized_delete() {
    let pool = common::pool().await;
    let tenant_id = tenant(&pool).await;
    let caller = entity(&pool, None, "human").await;
    let target = entity(&pool, Some(tenant_id), "device").await;
    add_tenant_member(&pool, tenant_id, caller).await;
    allow_object_action(&pool, caller, target, "manage").await;

    let application_name = format!("atom-entity-delete-race-{}", target.simple());
    let race_pool = race_pool(&application_name).await;
    let mut freezing = pool.begin().await.expect("begin concurrent freeze");
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE")
        .bind(tenant_id)
        .fetch_one(&mut *freezing)
        .await
        .expect("lock tenant for freeze");

    let mutation_pool = race_pool.clone();
    let deletion = tokio::spawn(async move {
        identity::service::delete_entity_authorized(
            &mutation_pool,
            None,
            false,
            &AuthContext {
                entity_id: caller,
                ..Default::default()
            },
            target,
        )
        .await
    });

    assert!(
        wait_for_application_lock(&pool, &application_name).await,
        "authorized delete never reached the tenant-lock serialization point"
    );
    sqlx::query("UPDATE tenants SET status = 'frozen' WHERE id = $1")
        .bind(tenant_id)
        .execute(&mut *freezing)
        .await
        .expect("freeze tenant");
    freezing.commit().await.expect("commit concurrent freeze");

    let error = tokio::time::timeout(std::time::Duration::from_secs(5), deletion)
        .await
        .expect("authorized delete completed after lock release")
        .expect("authorized delete task")
        .expect_err("tenant freeze must prevent the entity delete");
    assert!(
        matches!(error, AppError::NotFound(ref message) if message.contains("active tenant")),
        "unexpected frozen-tenant error: {error}"
    );
    let (status, deleted_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deleted_at FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("entity after concurrent tenant freeze");
    assert_eq!(status, "active");
    assert!(deleted_at.is_none());
}

#[tokio::test]
#[ignore]
async fn entity_mutations_enforce_token_ceiling_and_preserve_existing_fields() {
    let pool = common::pool().await;
    let caller = entity(&pool, None, "human").await;
    let target = entity(&pool, None, "human").await;
    let (old_profile_id, old_profile_version_id) = entity_profile(
        &pool,
        "human",
        serde_json::json!({
            "type": "object",
            "required": ["legacy"],
            "properties": { "legacy": { "type": "boolean" } }
        }),
    )
    .await;
    sqlx::query(
        "UPDATE entities \
         SET profile_id = $2, profile_version_id = $3, attributes = $4 \
         WHERE id = $1",
    )
    .bind(target)
    .bind(old_profile_id)
    .bind(old_profile_version_id)
    .bind(serde_json::json!({ "legacy": true }))
    .execute(&pool)
    .await
    .expect("bind old profile");
    allow_object_action(&pool, caller, target, "manage").await;
    let schema = build_schema(state(pool.clone()));

    let denied_update = schema
        .execute(authed_scoped(
            caller,
            format!(
                r#"mutation {{ updateEntity(id: "{target}", input: {{ name: "outside-token-ceiling" }}) {{ id }} }}"#
            ),
        ))
        .await;
    assert_forbidden(
        &denied_update,
        "the owner's live grant must not exceed an empty token ceiling",
    );
    let name_after_denied_update: String =
        sqlx::query_scalar("SELECT name FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("entity name after ceiling denial");
    assert_ne!(name_after_denied_update, "outside-token-ceiling");
    let denied_delete = schema
        .execute(authed_scoped(
            caller,
            format!(r#"mutation {{ deleteEntity(id: "{target}") }}"#),
        ))
        .await;
    assert_forbidden(
        &denied_delete,
        "delete must also honor the scoped-token ceiling",
    );
    let deleted_at_after_denied_delete: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("entity tombstone after ceiling denial");
    assert!(deleted_at_after_denied_delete.is_none());

    let (profile_id, profile_version_id) = entity_profile(
        &pool,
        "service",
        serde_json::json!({
            "type": "object",
            "required": ["marker"],
            "properties": { "marker": { "const": "authorized" } }
        }),
    )
    .await;

    let name = format!("authorized-update-{target}");
    let alias = format!("authorized-{}", target.simple());
    let external_id = format!("external-{target}");
    let authorized_update = schema
        .execute(authed_as(
            caller,
            format!(
                r#"mutation {{
                    updateEntity(id: "{target}", input: {{
                        name: "{name}"
                        kind: service
                        alias: "{alias}"
                        externalId: "{external_id}"
                        profileId: "{profile_id}"
                        status: suspended
                        attributes: {{ marker: "authorized" }}
                    }}) {{
                        id name kind alias externalId profileId profileVersionId status attributes
                    }}
                }}"#
            ),
        ))
        .await;
    assert!(
        authorized_update.errors.is_empty(),
        "{:?}",
        authorized_update.errors
    );
    let updated = &authorized_update.data.into_json().expect("json")["updateEntity"];
    assert_eq!(updated["name"], name);
    assert_eq!(updated["kind"], "service");
    assert_eq!(updated["alias"], alias);
    assert_eq!(updated["externalId"], external_id);
    assert_eq!(updated["profileId"], profile_id.to_string());
    assert_eq!(updated["profileVersionId"], profile_version_id.to_string());
    assert_eq!(updated["status"], "suspended");
    assert_eq!(updated["attributes"]["marker"], "authorized");

    let persisted: (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        String,
        Value,
    ) = sqlx::query_as(
        "SELECT name, kind, alias, external_id, profile_id, profile_version_id, status, attributes \
         FROM entities WHERE id = $1",
    )
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("updated entity");
    assert_eq!(persisted.0, name);
    assert_eq!(persisted.1, "service");
    assert_eq!(persisted.2.as_deref(), Some(alias.as_str()));
    assert_eq!(persisted.3.as_deref(), Some(external_id.as_str()));
    assert_eq!(persisted.4, Some(profile_id));
    assert_eq!(persisted.5, Some(profile_version_id));
    assert_eq!(persisted.6, "suspended");
    assert_eq!(persisted.7["marker"], "authorized");

    let authorized_delete = schema
        .execute(authed_as(
            caller,
            format!(r#"mutation {{ deleteEntity(id: "{target}") }}"#),
        ))
        .await;
    assert!(
        authorized_delete.errors.is_empty(),
        "{:?}",
        authorized_delete.errors
    );
    let (status, deleted_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deleted_at FROM entities WHERE id = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .expect("deleted entity");
    assert_eq!(status, "inactive");
    assert!(deleted_at.is_some());
}
