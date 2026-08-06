//! DB-gated tests for the broker auth callout — Atom serving FluxMQ's
//! `fluxmq.auth.v1.AuthService` directly, with no adapter service in between.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m29_broker_auth_callout -- --ignored
//! ```

mod common;

use atom::{
    authz::repo as authz_repo,
    broker_auth::service::proto::{
        auth_service_client::AuthServiceClient, Action, AuthnReq, AuthzReq,
    },
    config::{BrokerAuthConfig, BrokerTopicRef, Config},
    grpc,
    identity::{repo as identity_repo, service as identity_service},
    keys::{self, ActiveKeys},
    models::{
        entity::CreateEntity,
        enums::{EntityKind, SubjectKind},
        resource::CreateResource,
        tenant::CreateTenant,
    },
    state::AppState,
    tenants::repo as tenant_repo,
};
use serde_json::json;
use sqlx::PgPool;
use tokio::time::{sleep, Duration};
use tonic::{transport::Channel, Request};
use uuid::Uuid;

const DEVICE_SECRET: &str = "broker-device-secret";

fn slug(prefix: &str) -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..12])
}

fn broker_config(template: &str, topic_ref: BrokerTopicRef) -> Config {
    Config {
        broker_auth: BrokerAuthConfig {
            enabled: true,
            topic_templates: atom::broker_auth::TopicTemplateSet::parse_list(&[
                template.to_string()
            ])
            .expect("template parses"),
            topic_ref,
            ..BrokerAuthConfig::default()
        },
        ..Config::for_tests()
    }
}

async fn active_keys(pool: &PgPool) -> ActiveKeys {
    keys::rotate(pool, &Config::for_tests().signing_keys)
        .await
        .expect("rotate signing key")
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

/// A device with a password credential, standing in for an MQTT client.
async fn make_device(pool: &PgPool, tenant_id: Option<Uuid>) -> (Uuid, String) {
    let name = slug("dev");
    let device = identity_repo::create_entity(
        pool,
        CreateEntity {
            id: None,
            kind: Some(EntityKind::Device),
            profile_id: None,
            profile_version_id: None,
            name: name.clone(),
            alias: Some(slug("meter")),
            tenant_id,
            attributes: json!({}),
        },
    )
    .await
    .expect("create device");
    identity_service::create_password(pool, device.id, DEVICE_SECRET)
        .await
        .expect("create password");
    (device.id, name)
}

/// A resource with an alias, standing in for an MQTT channel.
async fn make_channel(pool: &PgPool, tenant_id: Option<Uuid>) -> (Uuid, String) {
    let alias = slug("chan");
    let resource = authz_repo::create_resource(
        pool,
        CreateResource {
            id: None,
            kind: "channel".to_string(),
            name: Some(slug("channel")),
            alias: Some(alias.clone()),
            tenant_id,
            owner_id: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create resource");
    (resource.id, alias)
}

/// Grant `action` on exactly one object, via a role assignment.
async fn grant(pool: &PgPool, subject: Uuid, tenant_id: Option<Uuid>, object: Uuid, action: &str) {
    let role = authz_repo::create_role(
        pool,
        atom::models::role::CreateRole {
            name: slug("broker-role"),
            tenant_id,
            description: None,
        },
    )
    .await
    .expect("create role");

    let action_id: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("seeded action");

    let block: Uuid = sqlx::query_scalar(
        "INSERT INTO permission_blocks (scope_mode, tenant_id, object_id, effect)
         VALUES ('object', $1, $2, 'allow') RETURNING id",
    )
    .bind(tenant_id)
    .bind(object)
    .fetch_one(pool)
    .await
    .expect("permission block");

    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block)
    .bind(action_id)
    .execute(pool)
    .await
    .expect("block action");

    authz_repo::replace_role_permission_block_links(pool, role.id, &[block])
        .await
        .expect("link block");
    authz_repo::create_role_assignment(
        pool,
        atom::models::policy::CreateRoleAssignment {
            tenant_id,
            subject_kind: SubjectKind::Entity,
            subject_id: subject,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");
}

async fn serve(pool: &PgPool, cfg: Config) -> AuthServiceClient<Channel> {
    let keys = active_keys(pool).await;
    let state = AppState::new(pool.clone(), cfg, keys, None);
    let listener = grpc::bind_listener("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("bind grpc");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = grpc::serve(listener, state, None).await;
    });

    let endpoint = format!("http://{addr}");
    for _ in 0..40 {
        if let Ok(channel) = Channel::from_shared(endpoint.clone())
            .expect("endpoint")
            .connect()
            .await
        {
            return AuthServiceClient::new(channel);
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("gRPC server did not come up");
}

fn authn(username: &str, password: &str) -> Request<AuthnReq> {
    Request::new(AuthnReq {
        client_id: slug("mqtt"),
        username: username.to_string(),
        password: password.to_string(),
        protocol: 0,
    })
}

fn authz(external_id: &str, topic: &str, action: Action) -> Request<AuthzReq> {
    Request::new(AuthzReq {
        external_id: external_id.to_string(),
        topic: topic.to_string(),
        action: action as i32,
    })
}

/// The zero-configuration path end to end: a device connects with its name and
/// password, and publishes to a topic whose first segment is a channel alias.
/// No tenant appears anywhere in the broker's requests — Atom derives it from
/// the authenticated subject.
#[tokio::test]
#[ignore]
async fn device_authenticates_and_publishes_with_no_tenant_in_the_topic() {
    let pool = common::pool().await;
    let (tenant_id, _) = make_tenant(&pool).await;
    let (device_id, device_name) = make_device(&pool, Some(tenant_id)).await;
    let (channel_id, channel_alias) = make_channel(&pool, Some(tenant_id)).await;
    grant(&pool, device_id, Some(tenant_id), channel_id, "publish").await;

    let mut client = serve(&pool, broker_config("{resource}/#", BrokerTopicRef::Alias)).await;

    let authenticated = client
        .authenticate(authn(&device_name, DEVICE_SECRET))
        .await
        .expect("authenticate rpc")
        .into_inner();
    assert!(authenticated.authenticated);
    assert_eq!(authenticated.id, device_id.to_string());

    let allowed = client
        .authorize(authz(
            &authenticated.id,
            &format!("{channel_alias}/eu/temp"),
            Action::Publish,
        ))
        .await
        .expect("authorize rpc")
        .into_inner();
    assert!(
        allowed.authorized,
        "publish should be allowed: {}",
        allowed.reason
    );

    // Only `publish` was granted.
    let denied = client
        .authorize(authz(&authenticated.id, &channel_alias, Action::Subscribe))
        .await
        .expect("authorize rpc")
        .into_inner();
    assert!(!denied.authorized);
}

/// A `{tenant}` segment scopes alias resolution, so a topic can address a
/// channel without Atom consulting the subject's own tenant.
#[tokio::test]
#[ignore]
async fn tenant_segment_scopes_alias_resolution() {
    let pool = common::pool().await;
    let (tenant_id, tenant_alias) = make_tenant(&pool).await;
    let (device_id, _) = make_device(&pool, Some(tenant_id)).await;
    let (channel_id, channel_alias) = make_channel(&pool, Some(tenant_id)).await;
    grant(&pool, device_id, Some(tenant_id), channel_id, "publish").await;

    let mut client = serve(
        &pool,
        broker_config("m/{tenant}/c/{resource}/#", BrokerTopicRef::Alias),
    )
    .await;

    let allowed = client
        .authorize(authz(
            &device_id.to_string(),
            &format!("m/{tenant_alias}/c/{channel_alias}/eu"),
            Action::Publish,
        ))
        .await
        .expect("authorize rpc")
        .into_inner();
    assert!(allowed.authorized, "{}", allowed.reason);
}

/// UUID topics skip alias resolution entirely.
#[tokio::test]
#[ignore]
async fn uuid_topic_ref_addresses_the_object_directly() {
    let pool = common::pool().await;
    let (tenant_id, _) = make_tenant(&pool).await;
    let (device_id, _) = make_device(&pool, Some(tenant_id)).await;
    let (channel_id, _) = make_channel(&pool, Some(tenant_id)).await;
    grant(&pool, device_id, Some(tenant_id), channel_id, "subscribe").await;

    let mut client = serve(&pool, broker_config("{resource}/#", BrokerTopicRef::Uuid)).await;

    let allowed = client
        .authorize(authz(
            &device_id.to_string(),
            &format!("{channel_id}/eu/temp"),
            Action::Subscribe,
        ))
        .await
        .expect("authorize rpc")
        .into_inner();
    assert!(allowed.authorized, "{}", allowed.reason);
}

/// Every rejection must arrive as a successful RPC carrying a false verdict.
/// A gRPC error would trip the broker's circuit breaker, which rejects *all*
/// client connections — one bad device must not be able to cause that.
#[tokio::test]
#[ignore]
async fn every_rejection_is_a_verdict_not_an_rpc_error() {
    let pool = common::pool().await;
    let (tenant_id, _) = make_tenant(&pool).await;
    let (device_id, device_name) = make_device(&pool, Some(tenant_id)).await;
    let (channel_id, channel_alias) = make_channel(&pool, Some(tenant_id)).await;
    grant(&pool, device_id, Some(tenant_id), channel_id, "publish").await;

    let mut client = serve(&pool, broker_config("{resource}/#", BrokerTopicRef::Alias)).await;

    let wrong_password = client
        .authenticate(authn(&device_name, "not-the-secret"))
        .await
        .expect("wrong password must not be an rpc error")
        .into_inner();
    assert!(!wrong_password.authenticated);
    assert!(wrong_password.id.is_empty());

    let unknown_user = client
        .authenticate(authn(&slug("ghost"), DEVICE_SECRET))
        .await
        .expect("unknown identity must not be an rpc error")
        .into_inner();
    assert!(!unknown_user.authenticated);

    let empty = client
        .authenticate(authn("", ""))
        .await
        .expect("empty credentials must not be an rpc error")
        .into_inner();
    assert!(!empty.authenticated);

    for (topic, why) in [
        (format!("{channel_alias}/x"), "granted, for contrast"),
        (slug("nosuchchannel"), "unknown object"),
        ("+/temp".to_string(), "wildcard on the object segment"),
        ("#".to_string(), "wildcard spanning everything"),
    ] {
        let response = client
            .authorize(authz(&device_id.to_string(), &topic, Action::Publish))
            .await
            .unwrap_or_else(|err| panic!("{why} must not be an rpc error: {err}"))
            .into_inner();
        if why == "granted, for contrast" {
            assert!(response.authorized, "{why}: {}", response.reason);
        } else {
            assert!(!response.authorized, "{why} should be denied");
        }
    }

    // A client the broker never authenticated arrives with a protocol-level id.
    let unauthenticated = client
        .authorize(authz("mqtt-client-7", &channel_alias, Action::Publish))
        .await
        .expect("non-UUID subject must not be an rpc error")
        .into_inner();
    assert!(!unauthenticated.authorized);

    // `Action::None` is the proto's unset value.
    let no_action = client
        .authorize(authz(&device_id.to_string(), &channel_alias, Action::None))
        .await
        .expect("unset action must not be an rpc error")
        .into_inner();
    assert!(!no_action.authorized);
}

/// Operational topics address no object, so no policy could describe them and
/// every request for one would otherwise be denied. The allow list is the only
/// path in the callout that skips the PDP, so its edges matter: it must admit
/// exactly the configured shape and nothing broader.
#[tokio::test]
#[ignore]
async fn the_allow_list_admits_operational_topics_and_nothing_wider() {
    let pool = common::pool().await;
    let (tenant_id, _) = make_tenant(&pool).await;
    let (device_id, _) = make_device(&pool, Some(tenant_id)).await;
    let (_, channel_alias) = make_channel(&pool, Some(tenant_id)).await;

    let mut cfg = broker_config("{resource}/#", BrokerTopicRef::Alias);
    cfg.broker_auth.topic_allow =
        atom::broker_auth::TopicAllowList::parse_list(&["hc/+".to_string()])
            .expect("allow list parses");
    let mut client = serve(&pool, cfg).await;

    let health = client
        .authorize(authz(&device_id.to_string(), "hc/acme", Action::Publish))
        .await
        .expect("authorize rpc")
        .into_inner();
    assert!(health.authorized, "health topic should be admitted");

    // The device holds no grant on this channel; the allow list must not have
    // turned into a general bypass.
    let ungranted = client
        .authorize(authz(
            &device_id.to_string(),
            &channel_alias,
            Action::Publish,
        ))
        .await
        .expect("authorize rpc")
        .into_inner();
    assert!(
        !ungranted.authorized,
        "allow list leaked into ordinary topics"
    );

    for (topic, why) in [
        ("hc/acme/extra", "deeper than the single-segment pattern"),
        ("hc", "shorter than the pattern"),
        ("hc/#", "spans the whole subtree, wider than `hc/+`"),
    ] {
        let response = client
            .authorize(authz(&device_id.to_string(), topic, Action::Publish))
            .await
            .expect("authorize rpc")
            .into_inner();
        assert!(!response.authorized, "{topic} admitted, but it is {why}");
    }
}

/// The callout is off unless explicitly enabled, because it authenticates its
/// caller at the transport rather than with a bearer token.
#[tokio::test]
#[ignore]
async fn callout_is_not_mounted_unless_enabled() {
    let pool = common::pool().await;
    let mut client = serve(&pool, Config::for_tests()).await;

    let status = client
        .authenticate(authn("someone", "something"))
        .await
        .expect_err("service must not be mounted when disabled");
    assert_eq!(status.code(), tonic::Code::Unimplemented);
}
