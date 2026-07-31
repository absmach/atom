//! Live end-to-end proof against FluxMQ's "Internal AMQP Local Principals"
//! contract (`docs/deployment/internal-amqp-local-principals.md` in the
//! FluxMQ repo): a dedicated mTLS listener, SASL username/secret plus a
//! client-certificate URI SAN, and publish access restricted to exactly one
//! `(default exchange, fixed routing key)` target — no exchange/queue
//! declaration permitted. This is the sanctioned integration contract for
//! Atom's event publishing, distinct from `tests/m27_live_amqp_delivery.rs`
//! (which proves the same `AmqpPublisher` works against a plain broker with
//! no TLS at all).
//!
//! Requires a running FluxMQ instance configured with the local listener
//! and matching PKI. To set this up locally:
//!
//! 1. Build FluxMQ from a local checkout: `make build`.
//! 2. Generate a throwaway CA + server cert + client cert (ECDSA P256,
//!    PKCS8 keys, client cert URI SAN of your choosing) — see this
//!    session's `/tmp/.../scratchpad/gen-pki/main.go` for a minimal
//!    generator mirroring FluxMQ's own `tests/smoke/local_principal_test.go`.
//! 3. Write a FluxMQ config with every listener disabled except
//!    `server.amqp091.local` (cert/key/ca_file pointing at the generated
//!    PKI, `client_auth: "require"`), one `auth.local_principals` entry
//!    (`certificate_uri_san` matching the client cert, `role: "publisher"`,
//!    `current_secret_file`
//!    a 32+ byte random secret, `permissions.publish` granting exactly
//!    `exchange: ""` / the routing key used below), and a matching
//!    pre-provisioned `queues:` entry (`type: "stream"`, `reserved: true`).
//!    `cluster.enabled` must be `false`.
//! 4. Run the binary against that config.
//!
//! Then:
//!
//! ```bash
//! TEST_FLUXMQ_MTLS_HOST=127.0.0.1:15683 \
//! TEST_FLUXMQ_MTLS_USERNAME=atom-audit-publisher \
//! TEST_FLUXMQ_MTLS_SECRET_FILE=/path/to/audit-secret-current \
//! TEST_FLUXMQ_MTLS_CLIENT_CERT=/path/to/client.crt \
//! TEST_FLUXMQ_MTLS_CLIENT_KEY=/path/to/client.key \
//! TEST_FLUXMQ_MTLS_CA=/path/to/ca.crt \
//! TEST_FLUXMQ_MTLS_ADMIN_API=http://127.0.0.1:18092 \
//!   cargo test --test m28_amqp_mtls_local_principal -- --ignored --test-threads=1
//! ```

use atom::config::EventsConfig;
use atom::events::publisher::{AmqpPublisher, EventPublisher};
use atom::events::DomainEventPayload;
use serde_json::Value;
use uuid::Uuid;

const ATOM_EVENTS_ROUTING_KEY: &str = "atom.events";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set to run this live test"))
}

fn read_secret_trimmed(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read secret file {path}: {e}"))
        .trim_end_matches(['\r', '\n'])
        .to_string()
}

fn test_config(routing_key: &str) -> EventsConfig {
    let host = env("TEST_FLUXMQ_MTLS_HOST");
    let username = env("TEST_FLUXMQ_MTLS_USERNAME");
    let secret = read_secret_trimmed(&env("TEST_FLUXMQ_MTLS_SECRET_FILE"));
    let url = format!("amqps://{username}:{secret}@{host}/%2f");

    EventsConfig {
        amqp_url: Some(url),
        amqp_exchange: String::new(),
        amqp_routing_key: routing_key.to_string(),
        amqp_tls_client_cert_path: Some(env("TEST_FLUXMQ_MTLS_CLIENT_CERT")),
        amqp_tls_client_key_path: Some(env("TEST_FLUXMQ_MTLS_CLIENT_KEY")),
        amqp_tls_ca_path: Some(env("TEST_FLUXMQ_MTLS_CA")),
        ..EventsConfig::default()
    }
}

fn sample_payload() -> DomainEventPayload {
    DomainEventPayload {
        schema_version: 1,
        event_id: Uuid::new_v4(),
        event: "resource.create".to_string(),
        occurred_at: chrono::Utc::now(),
        source: "atom".to_string(),
        actor_entity_id: None,
        tenant_id: None,
        target_kind: Some("resource".to_string()),
        target_id: Some(Uuid::new_v4()),
        outcome: "allow".to_string(),
        details: serde_json::json!({"kind": "channel"}),
        request_id: None,
    }
}

/// Queries FluxMQ's admin API (`GET /api/v1/stats`) via `curl`, rather than
/// adding an HTTP client dependency just for this one test.
fn fetch_stats() -> Value {
    let admin_api = env("TEST_FLUXMQ_MTLS_ADMIN_API");
    let output = std::process::Command::new("curl")
        .args(["-s", "-f", &format!("{admin_api}/api/v1/stats")])
        .output()
        .expect("run curl");
    assert!(
        output.status.success(),
        "GET {admin_api}/api/v1/stats failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse stats JSON")
}

fn amqp_local_principal_stats(stats: &Value) -> &Value {
    &stats["by_protocol"]["amqp"]["local_principals"]
}

#[tokio::test]
#[ignore]
async fn publishing_to_atom_events_is_confirmed_without_topology_mutation() {
    assert_eq!(
        EventsConfig::default().amqp_routing_key,
        ATOM_EVENTS_ROUTING_KEY,
        "the live FluxMQ contract must exercise Atom's configured default"
    );
    let before = fetch_stats();
    let auth_success_before = amqp_local_principal_stats(&before)["authentication"]["success"]
        .as_i64()
        .unwrap_or(0);
    let messages_received_before = before["messages"]["received"].as_i64().unwrap_or(0);
    let operation_denied_before = amqp_local_principal_stats(&before)["authorization"]
        ["operation_denied"]
        .as_i64()
        .unwrap_or(0);
    let publish_rejections_before = amqp_local_principal_stats(&before)["publish_rejections"]
        .as_i64()
        .unwrap_or(0);
    let publish_timeouts_before = amqp_local_principal_stats(&before)["publish_timeouts"]
        .as_i64()
        .unwrap_or(0);

    let cfg = test_config(ATOM_EVENTS_ROUTING_KEY);
    let publisher = AmqpPublisher::connect(&cfg)
        .await
        .expect("connect via mTLS + SASL to FluxMQ's local listener");

    let res = publisher
        .publish(&[sample_payload()])
        .await
        .expect("publish to the exactly-granted (default exchange, routing key) target");
    assert!(res[0].is_ok(), "event publish should succeed");

    let after = fetch_stats();
    let auth_success_after = amqp_local_principal_stats(&after)["authentication"]["success"]
        .as_i64()
        .unwrap_or(0);
    let messages_received_after = after["messages"]["received"].as_i64().unwrap_or(0);
    let operation_denied_after = amqp_local_principal_stats(&after)["authorization"]
        ["operation_denied"]
        .as_i64()
        .unwrap_or(0);
    let publish_rejections = amqp_local_principal_stats(&after)["publish_rejections"]
        .as_i64()
        .unwrap_or(-1);
    let publish_timeouts = amqp_local_principal_stats(&after)["publish_timeouts"]
        .as_i64()
        .unwrap_or(-1);

    assert!(
        auth_success_after > auth_success_before,
        "mTLS+SASL authentication must have succeeded (before={auth_success_before}, after={auth_success_after})"
    );
    assert!(
        messages_received_after > messages_received_before,
        "the broker must have received the publish (before={messages_received_before}, after={messages_received_after})"
    );
    assert_eq!(
        publish_rejections, publish_rejections_before,
        "the confirmed Atom publish must not add a local-principal storage rejection"
    );
    assert_eq!(
        publish_timeouts, publish_timeouts_before,
        "the confirmed Atom publish must not add a local-principal timeout"
    );
    assert_eq!(
        operation_denied_after, operation_denied_before,
        "Atom must publish without attempting a forbidden topology mutation"
    );
}

/// Proves the ACL is real and exact: publishing to any routing key other
/// than the one granted must be refused, not silently accepted.
#[tokio::test]
#[ignore]
async fn publishing_to_a_different_routing_key_is_denied() {
    let cfg = test_config("atom.events.other");
    let publisher = AmqpPublisher::connect(&cfg)
        .await
        .expect("the connection itself should still succeed (auth is per-connection)");

    let result = publisher.publish(&[sample_payload()]).await;
    let is_denied = match result {
        Err(_) => true,
        Ok(vec) => vec.iter().any(|r| r.is_err()),
    };
    assert!(
        is_denied,
        "publishing to an ungranted routing key must be denied, not silently accepted"
    );
}
