//! DB-gated tests for the gRPC credential authentication path.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m23_authenticate_credential -- --ignored
//! ```

mod common;

use atom::{
    auth::encode_jwt,
    config::Config,
    grpc::{
        self,
        proto::{auth_service_client::AuthServiceClient, AuthenticateCredentialRequest},
    },
    identity::{repo as identity_repo, service as identity_service},
    keys::{self, ActiveKeys},
    models::{entity::CreateEntity, enums::EntityKind, tenant::CreateTenant},
    state::AppState,
    tenants::repo as tenant_repo,
};
use serde_json::json;
use sqlx::PgPool;
use tokio::time::{sleep, Duration};
use tonic::{metadata::MetadataValue, transport::Channel, Code, Request};
use uuid::Uuid;

const DEVICE_SECRET: &str = "dev1_key";

fn slug(prefix: &str) -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..12])
}

async fn active_keys(pool: &PgPool) -> ActiveKeys {
    keys::rotate(pool, &Config::for_tests().signing_keys)
        .await
        .expect("rotate signing key")
}

async fn token_for(pool: &PgPool, keys: &ActiveKeys, entity_id: Uuid) -> String {
    let cfg = Config::for_tests();
    let session = identity_repo::create_session(pool, entity_id, 3600)
        .await
        .expect("create session");
    encode_jwt(
        entity_id,
        session.id,
        None,
        &keys.primary,
        3600,
        &cfg.jwt_issuer,
        &cfg.jwt_audience,
    )
    .expect("encode jwt")
}

async fn make_tenant(pool: &PgPool) -> (Uuid, String) {
    let alias = slug("dom");
    let tenant = tenant_repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: slug("tenant"),
            alias: Some(alias.clone()),
            tags: vec![],
            attributes: json!({}),
        },
        None,
    )
    .await
    .expect("create tenant");
    (tenant.id, alias)
}

async fn make_device(pool: &PgPool, tenant_id: Uuid) -> (Uuid, String, String, Uuid) {
    let name = slug("dev");
    let alias = slug("meter");
    let device = identity_repo::create_entity(
        pool,
        CreateEntity {
            id: None,
            kind: Some(EntityKind::Device),
            profile_id: None,
            profile_version_id: None,
            name: name.clone(),
            alias: Some(alias.clone()),
            tenant_id: Some(tenant_id),
            attributes: json!({}),
        },
    )
    .await
    .expect("create device");
    identity_service::create_password(pool, device.id, DEVICE_SECRET)
        .await
        .expect("create password");
    let credential_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM credentials WHERE entity_id = $1 AND kind = 'password' LIMIT 1",
    )
    .bind(device.id)
    .fetch_one(pool)
    .await
    .expect("password credential");
    (device.id, name, alias, credential_id)
}

async fn make_service(pool: &PgPool) -> Uuid {
    identity_repo::create_entity(
        pool,
        CreateEntity {
            id: None,
            kind: Some(EntityKind::Service),
            profile_id: None,
            profile_version_id: None,
            name: slug("svc"),
            alias: None,
            tenant_id: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create service")
    .id
}

#[tokio::test]
#[ignore]
async fn credential_authenticates_uuid_name_and_alias_without_session() {
    let pool = common::pool().await;
    let cfg = Config::for_tests();
    let (tenant_id, _) = make_tenant(&pool).await;
    let (entity_id, name, alias, credential_id) = make_device(&pool, tenant_id).await;

    for identifier in [entity_id.to_string(), name, alias] {
        let authenticated = identity_service::authenticate_password_credential_in_tenant(
            &pool,
            &cfg,
            &identifier,
            DEVICE_SECRET,
            Some(tenant_id),
        )
        .await
        .expect("authenticate credential");
        assert_eq!(authenticated.entity_id, entity_id);
        assert_eq!(authenticated.tenant_id, Some(tenant_id));
        assert_eq!(authenticated.credential_id, credential_id);
    }

    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE entity_id = $1")
        .bind(entity_id)
        .fetch_one(&pool)
        .await
        .expect("session count");
    assert_eq!(sessions, 0, "credential auth must not create sessions");
}

#[tokio::test]
#[ignore]
async fn credential_authentication_rejects_wrong_secret_revoked_credential_and_bad_selector() {
    let pool = common::pool().await;
    let cfg = Config::for_tests();
    let (tenant_id, tenant_alias) = make_tenant(&pool).await;
    let (entity_id, name, _, _) = make_device(&pool, tenant_id).await;

    let wrong = identity_service::authenticate_password_credential_in_tenant(
        &pool,
        &cfg,
        &name,
        "wrong-secret",
        Some(tenant_id),
    )
    .await
    .expect_err("wrong secret must be rejected");
    assert!(wrong.to_string().contains("invalid credentials"));

    sqlx::query("UPDATE credentials SET status = 'revoked' WHERE entity_id = $1")
        .bind(entity_id)
        .execute(&pool)
        .await
        .expect("revoke credential");
    let revoked = identity_service::authenticate_password_credential_in_tenant(
        &pool,
        &cfg,
        &name,
        DEVICE_SECRET,
        Some(tenant_id),
    )
    .await
    .expect_err("revoked credential must be rejected");
    assert!(revoked.to_string().contains("invalid credentials"));

    let bad_selector = identity_service::resolve_credential_auth_tenant(
        &pool,
        Some(tenant_id),
        Some(&tenant_alias),
    )
    .await
    .expect_err("tenant id and alias cannot both be set");
    assert!(bad_selector
        .to_string()
        .contains("provide either tenant_id or tenant_alias"));
}

#[tokio::test]
#[ignore]
async fn credential_authentication_rejects_inactive_or_deleted_principals() {
    let pool = common::pool().await;
    let cfg = Config::for_tests();

    let (inactive_tenant_id, _) = make_tenant(&pool).await;
    let (_, inactive_name, _, _) = make_device(&pool, inactive_tenant_id).await;
    sqlx::query("UPDATE entities SET status = 'inactive' WHERE name = $1 AND tenant_id = $2")
        .bind(&inactive_name)
        .bind(inactive_tenant_id)
        .execute(&pool)
        .await
        .expect("deactivate entity");
    let inactive = identity_service::authenticate_password_credential_in_tenant(
        &pool,
        &cfg,
        &inactive_name,
        DEVICE_SECRET,
        Some(inactive_tenant_id),
    )
    .await
    .expect_err("inactive entity must be rejected");
    assert!(inactive.to_string().contains("entity is not active"));

    let (deleted_entity_tenant_id, _) = make_tenant(&pool).await;
    let (_, deleted_entity_name, _, _) = make_device(&pool, deleted_entity_tenant_id).await;
    sqlx::query("UPDATE entities SET deleted_at = now() WHERE name = $1 AND tenant_id = $2")
        .bind(&deleted_entity_name)
        .bind(deleted_entity_tenant_id)
        .execute(&pool)
        .await
        .expect("soft delete entity");
    let deleted_entity = identity_service::authenticate_password_credential_in_tenant(
        &pool,
        &cfg,
        &deleted_entity_name,
        DEVICE_SECRET,
        Some(deleted_entity_tenant_id),
    )
    .await
    .expect_err("deleted entity must be rejected");
    assert!(deleted_entity.to_string().contains("invalid credentials"));

    let (inactive_scope_id, _) = make_tenant(&pool).await;
    sqlx::query("UPDATE tenants SET status = 'inactive' WHERE id = $1")
        .bind(inactive_scope_id)
        .execute(&pool)
        .await
        .expect("deactivate tenant");
    let inactive_tenant =
        identity_service::resolve_credential_auth_tenant(&pool, Some(inactive_scope_id), None)
            .await
            .expect_err("inactive tenant must be rejected");
    assert!(inactive_tenant.to_string().contains("tenant is not active"));

    let (deleted_scope_id, _) = make_tenant(&pool).await;
    sqlx::query("UPDATE tenants SET status = 'deleted', deleted_at = now() WHERE id = $1")
        .bind(deleted_scope_id)
        .execute(&pool)
        .await
        .expect("soft delete tenant");
    let deleted_tenant =
        identity_service::resolve_credential_auth_tenant(&pool, Some(deleted_scope_id), None)
            .await
            .expect_err("deleted tenant must be rejected");
    assert!(deleted_tenant.to_string().contains("invalid credentials"));
}

#[tokio::test]
#[ignore]
async fn grpc_authenticate_credential_requires_service_auth_and_returns_identity() {
    let pool = common::pool().await;
    let keys = active_keys(&pool).await;
    let state = AppState::new(pool.clone(), Config::for_tests(), keys.clone(), None);
    let listener = grpc::bind_listener("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("bind grpc");
    let addr = listener.local_addr().expect("local addr");
    let grpc_state = state.clone();
    tokio::spawn(async move {
        let _ = grpc::serve(listener, grpc_state).await;
    });

    let (tenant_id, tenant_alias) = make_tenant(&pool).await;
    let (entity_id, _, alias, credential_id) = make_device(&pool, tenant_id).await;
    let admin_token = token_for(&pool, &keys, common::admin_id()).await;
    let service_id = make_service(&pool).await;
    let service_token = token_for(&pool, &keys, service_id).await;

    let mut client = auth_client(addr).await;
    let missing = client
        .authenticate_credential(AuthenticateCredentialRequest {
            identifier: alias.clone(),
            secret: DEVICE_SECRET.into(),
            kind: "password".into(),
            tenant_id: String::new(),
            tenant_alias: tenant_alias.clone(),
        })
        .await
        .expect_err("missing caller metadata");
    assert_eq!(missing.code(), Code::Unauthenticated);

    let denied = client
        .authenticate_credential(authed_request(
            &service_token,
            AuthenticateCredentialRequest {
                identifier: alias.clone(),
                secret: DEVICE_SECRET.into(),
                kind: "password".into(),
                tenant_id: String::new(),
                tenant_alias: tenant_alias.clone(),
            },
        ))
        .await
        .expect_err("caller without authz.check must be denied");
    assert_eq!(denied.code(), Code::PermissionDenied);

    let response = client
        .authenticate_credential(authed_request(
            &admin_token,
            AuthenticateCredentialRequest {
                identifier: alias,
                secret: DEVICE_SECRET.into(),
                kind: String::new(),
                tenant_id: String::new(),
                tenant_alias,
            },
        ))
        .await
        .expect("authenticate credential")
        .into_inner();
    assert_eq!(response.entity_id, entity_id.to_string());
    assert_eq!(response.tenant_id, tenant_id.to_string());
    assert_eq!(response.credential_id, credential_id.to_string());

    let unsupported = client
        .authenticate_credential(authed_request(
            &admin_token,
            AuthenticateCredentialRequest {
                identifier: entity_id.to_string(),
                secret: DEVICE_SECRET.into(),
                kind: "api_key".into(),
                tenant_id: tenant_id.to_string(),
                tenant_alias: String::new(),
            },
        ))
        .await
        .expect_err("unsupported kind");
    assert_eq!(unsupported.code(), Code::InvalidArgument);
}

fn authed_request<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    let value = format!("Bearer {token}")
        .parse::<MetadataValue<_>>()
        .expect("metadata value");
    request.metadata_mut().insert("authorization", value);
    request
}

async fn auth_client(addr: std::net::SocketAddr) -> AuthServiceClient<Channel> {
    let endpoint = format!("http://{addr}");
    for _ in 0..20 {
        if let Ok(channel) = Channel::from_shared(endpoint.clone())
            .expect("grpc endpoint")
            .connect()
            .await
        {
            return AuthServiceClient::new(channel);
        }
        sleep(Duration::from_millis(25)).await;
    }
    let channel = Channel::from_shared(endpoint)
        .expect("grpc endpoint")
        .connect()
        .await
        .expect("connect grpc client");
    AuthServiceClient::new(channel)
}
