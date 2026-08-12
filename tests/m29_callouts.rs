//! Callout integration tests.
//!
//! These tests spin up in-process mock HTTP and gRPC policy services and
//! drive the [`atom::callout::CalloutService`] runner end-to-end. They do
//! not require the DB, so they run under plain `cargo test`.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use atom::callout::{
    config::{
        CalloutsFile, EndpointConfig, EndpointId, GrpcTransportConfig, HttpMethod,
        HttpTransportConfig, OnError, OperationConfig, SurfaceKind, TransportConfig,
    },
    envelope::Actor,
    CalloutOutcome, CalloutService, CalloutsConfig, Surface,
};
use axum::{extract::State, routing::post, Json, Router};
use tokio::{net::TcpListener, sync::oneshot};

// ─── HTTP mock ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct HttpMockState {
    recorded: Arc<Mutex<Vec<serde_json::Value>>>,
    behaviour: Behaviour,
}

#[derive(Clone)]
enum Behaviour {
    Allow,
    Deny(String),
    /// Sleep for the given duration before responding — used to force a
    /// timeout on the client side.
    Delay(Duration),
    /// Return HTTP 500 with a body.
    Error(String),
}

async fn http_handler(
    State(state): State<HttpMockState>,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, (axum::http::StatusCode, String)> {
    state.recorded.lock().unwrap().push(body);
    match &state.behaviour {
        Behaviour::Allow => Ok(Json(serde_json::json!({"decision": "allow"})).into_response()),
        Behaviour::Deny(reason) => Ok(Json(serde_json::json!({
            "decision": "deny",
            "reason": reason,
        }))
        .into_response()),
        Behaviour::Delay(d) => {
            tokio::time::sleep(*d).await;
            Ok(Json(serde_json::json!({"decision": "allow"})).into_response())
        }
        Behaviour::Error(msg) => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg.clone())),
    }
}

fn axum_response_into<T: axum::response::IntoResponse>() {}

use axum::response::IntoResponse;

async fn spawn_http_mock(behaviour: Behaviour) -> (String, HttpMockState, oneshot::Sender<()>) {
    let state = HttpMockState {
        recorded: Arc::new(Mutex::new(Vec::new())),
        behaviour,
    };
    let app = Router::new()
        .route("/authz", post(http_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    let _: fn() = axum_response_into::<axum::response::Response>;
    (format!("http://{addr}/authz"), state, tx)
}

// ─── gRPC mock ────────────────────────────────────────────────────────────

mod callout_proto {
    tonic::include_proto!("atom.v1");
}

use callout_proto::{
    callout_service_check_response::Decision as ProtoDecision,
    callout_service_server::CalloutServiceServer, CalloutServiceCheckResponse,
};

struct GrpcMock {
    recorded: Arc<Mutex<Vec<callout_proto::CalloutServiceCheckRequest>>>,
    behaviour: Behaviour,
}

#[tonic::async_trait]
impl callout_proto::callout_service_server::CalloutService for GrpcMock {
    async fn check(
        &self,
        request: tonic::Request<callout_proto::CalloutServiceCheckRequest>,
    ) -> Result<tonic::Response<CalloutServiceCheckResponse>, tonic::Status> {
        self.recorded.lock().unwrap().push(request.into_inner());
        match &self.behaviour {
            Behaviour::Allow => Ok(tonic::Response::new(CalloutServiceCheckResponse {
                decision: ProtoDecision::Allow as i32,
                reason: String::new(),
            })),
            Behaviour::Deny(reason) => Ok(tonic::Response::new(CalloutServiceCheckResponse {
                decision: ProtoDecision::Deny as i32,
                reason: reason.clone(),
            })),
            Behaviour::Delay(d) => {
                tokio::time::sleep(*d).await;
                Ok(tonic::Response::new(CalloutServiceCheckResponse {
                    decision: ProtoDecision::Allow as i32,
                    reason: String::new(),
                }))
            }
            Behaviour::Error(msg) => Err(tonic::Status::internal(msg.clone())),
        }
    }
}

async fn spawn_grpc_mock(
    behaviour: Behaviour,
) -> (
    String,
    Arc<Mutex<Vec<callout_proto::CalloutServiceCheckRequest>>>,
    oneshot::Sender<()>,
) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let svc = GrpcMock {
        recorded: recorded.clone(),
        behaviour,
    };
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    let incoming = tonic::transport::server::TcpIncoming::from_listener(
        listener,
        true,
        Some(Duration::from_secs(1)),
    )
    .unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CalloutServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (format!("http://{bound}"), recorded, tx)
}

// ─── config helpers ───────────────────────────────────────────────────────

fn http_endpoint(id: &str, url: &str, on_error: OnError, timeout_ms: u64) -> EndpointConfig {
    EndpointConfig {
        id: EndpointId(id.to_string()),
        transport: TransportConfig::Http(HttpTransportConfig {
            url: url.to_string(),
            method: HttpMethod::Post,
            headers: Default::default(),
        }),
        timeout_ms,
        tls: None,
        on_error,
    }
}

fn grpc_endpoint(id: &str, address: &str, on_error: OnError, timeout_ms: u64) -> EndpointConfig {
    EndpointConfig {
        id: EndpointId(id.to_string()),
        transport: TransportConfig::Grpc(GrpcTransportConfig {
            address: address.to_string(),
        }),
        timeout_ms,
        tls: None,
        on_error,
    }
}

fn op(name: &str, endpoints: &[&str], include: &[&str]) -> OperationConfig {
    OperationConfig {
        name: name.to_string(),
        surface: SurfaceKind::Graphql,
        endpoints: endpoints
            .iter()
            .map(|e| EndpointId(e.to_string()))
            .collect(),
        include: include.iter().map(|s| s.to_string()).collect(),
        extra: Default::default(),
    }
}

fn build_service(endpoints: Vec<EndpointConfig>, ops: Vec<OperationConfig>) -> CalloutsFile {
    CalloutsFile {
        callouts: atom::callout::config::CalloutsSection {
            endpoints,
            operations: ops,
        },
    }
}

fn dummy_actor() -> Actor {
    Actor {
        entity_id: "00000000-0000-0000-0000-000000000001".into(),
        tenant_id: "22222222-2222-2222-2222-222222222222".into(),
        scope: "session".into(),
        ..Default::default()
    }
}

// ─── tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn http_allow_lets_call_through_and_forwards_payload() {
    let (url, mock, shutdown) = spawn_http_mock(Behaviour::Allow).await;
    let cfg = CalloutsConfig::build(build_service(
        vec![http_endpoint("policy", &url, OnError::Deny, 2000)],
        vec![op(
            "createEntity",
            &["policy"],
            &["actor.entity_id", "args.input.name"],
        )],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({"input": {"name": "gadget", "kind": "device"}}),
        )
        .await;
    assert!(matches!(outcome, CalloutOutcome::Allow));

    let recorded = mock.recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0]["operation"], "createEntity");
    assert_eq!(
        recorded[0]["actor"]["entity_id"],
        "00000000-0000-0000-0000-000000000001"
    );
    // Only whitelisted args made it through.
    assert_eq!(recorded[0]["args"]["input"]["name"], "gadget");
    assert!(recorded[0]["args"]["input"].get("kind").is_none());

    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_deny_short_circuits_with_reason_and_endpoint() {
    let (url, _mock, shutdown) =
        spawn_http_mock(Behaviour::Deny("policy blocks new entities".into())).await;
    let cfg = CalloutsConfig::build(build_service(
        vec![http_endpoint("policy", &url, OnError::Deny, 2000)],
        vec![op("createEntity", &["policy"], &[])],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    match outcome {
        CalloutOutcome::Deny {
            reason,
            endpoint_id,
        } => {
            assert_eq!(endpoint_id, "policy");
            assert!(reason.contains("policy blocks new entities"));
        }
        other => panic!("expected deny, got {other:?}"),
    }
    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_timeout_denies_when_on_error_deny() {
    let (url, _mock, shutdown) =
        spawn_http_mock(Behaviour::Delay(Duration::from_millis(500))).await;
    let cfg = CalloutsConfig::build(build_service(
        vec![http_endpoint("policy", &url, OnError::Deny, 50)],
        vec![op("createEntity", &["policy"], &[])],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    assert!(
        matches!(outcome, CalloutOutcome::Deny { .. }),
        "expected deny, got {outcome:?}"
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn http_transport_error_allows_when_on_error_allow() {
    let (url, _mock, shutdown) = spawn_http_mock(Behaviour::Error("upstream broken".into())).await;
    let cfg = CalloutsConfig::build(build_service(
        vec![http_endpoint("policy", &url, OnError::Allow, 2000)],
        vec![op("createEntity", &["policy"], &[])],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    assert!(
        matches!(outcome, CalloutOutcome::Allow),
        "expected allow-on-error, got {outcome:?}"
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn multi_endpoint_chain_all_must_allow_and_fails_fast() {
    let (allow_url, allow_mock, allow_shutdown) = spawn_http_mock(Behaviour::Allow).await;
    let (deny_url, _deny_mock, deny_shutdown) =
        spawn_http_mock(Behaviour::Deny("second stage denied".into())).await;
    let (never_url, never_mock, never_shutdown) = spawn_http_mock(Behaviour::Allow).await;

    let cfg = CalloutsConfig::build(build_service(
        vec![
            http_endpoint("stage1", &allow_url, OnError::Deny, 2000),
            http_endpoint("stage2", &deny_url, OnError::Deny, 2000),
            http_endpoint("stage3", &never_url, OnError::Deny, 2000),
        ],
        vec![op("createEntity", &["stage1", "stage2", "stage3"], &[])],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    match outcome {
        CalloutOutcome::Deny { endpoint_id, .. } => assert_eq!(endpoint_id, "stage2"),
        other => panic!("expected deny at stage2, got {other:?}"),
    }
    // stage1 was called, stage3 was not.
    assert_eq!(allow_mock.recorded.lock().unwrap().len(), 1);
    assert_eq!(never_mock.recorded.lock().unwrap().len(), 0);

    let _ = allow_shutdown.send(());
    let _ = deny_shutdown.send(());
    let _ = never_shutdown.send(());
}

#[tokio::test]
async fn grpc_allow_and_deny_end_to_end() {
    let (address, recorded, shutdown) = spawn_grpc_mock(Behaviour::Allow).await;
    // Give the server a beat to be ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let cfg = CalloutsConfig::build(build_service(
        vec![grpc_endpoint("policy", &address, OnError::Deny, 3000)],
        vec![op(
            "authzCheck",
            &["policy"],
            &["actor.entity_id", "args.action"],
        )],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "authzCheck",
            dummy_actor(),
            serde_json::json!({"action": "publish"}),
        )
        .await;
    assert!(matches!(outcome, CalloutOutcome::Allow), "{outcome:?}");
    let entries = recorded.lock().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].operation, "authzCheck");
    assert_eq!(
        entries[0].actor.as_ref().unwrap().entity_id,
        "00000000-0000-0000-0000-000000000001"
    );
    drop(entries);
    let _ = shutdown.send(());
}

#[tokio::test]
async fn grpc_deny_short_circuits() {
    let (address, _recorded, shutdown) =
        spawn_grpc_mock(Behaviour::Deny("grpc says no".into())).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let cfg = CalloutsConfig::build(build_service(
        vec![grpc_endpoint("policy", &address, OnError::Deny, 3000)],
        vec![op("createEntity", &["policy"], &[])],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    match outcome {
        CalloutOutcome::Deny { reason, .. } => assert!(reason.contains("grpc says no")),
        other => panic!("expected deny, got {other:?}"),
    }
    let _ = shutdown.send(());
}

#[tokio::test]
async fn unconfigured_operation_short_circuits_to_not_configured() {
    let cfg = CalloutsConfig::build(build_service(vec![], vec![])).unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "somethingElse",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    assert!(matches!(outcome, CalloutOutcome::NotConfigured));
}

#[tokio::test]
async fn mixed_http_and_grpc_chain_stops_at_first_deny() {
    let (grpc_addr, _grpc_recorded, grpc_shutdown) =
        spawn_grpc_mock(Behaviour::Deny("grpc block".into())).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (http_url, http_state, http_shutdown) = spawn_http_mock(Behaviour::Allow).await;

    let cfg = CalloutsConfig::build(build_service(
        vec![
            http_endpoint("http-stage", &http_url, OnError::Deny, 2000),
            grpc_endpoint("grpc-stage", &grpc_addr, OnError::Deny, 3000),
        ],
        vec![op("createEntity", &["http-stage", "grpc-stage"], &[])],
    ))
    .unwrap();
    let svc = CalloutService::build(cfg).await.unwrap();

    let outcome = svc
        .check(
            Surface::GraphQL,
            "createEntity",
            dummy_actor(),
            serde_json::json!({}),
        )
        .await;
    match outcome {
        CalloutOutcome::Deny { endpoint_id, .. } => assert_eq!(endpoint_id, "grpc-stage"),
        other => panic!("expected deny at grpc-stage, got {other:?}"),
    }
    // http stage recorded one call before grpc denied.
    assert_eq!(http_state.recorded.lock().unwrap().len(), 1);
    let _ = grpc_shutdown.send(());
    let _ = http_shutdown.send(());
}
