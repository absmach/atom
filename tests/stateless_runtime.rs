//! Standalone process replacement against PostgreSQL.
//! Use an empty, disposable DATABASE_URL; CI creates one per test binary.
#![cfg(unix)]

use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::Client;
use serde_json::{json, Value};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    process::{Child, Command},
    time::{sleep, timeout},
};
use uuid::Uuid;

struct Process {
    child: Child,
    directory: PathBuf,
    base: String,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Process {
    async fn start(database_url: &str, client: &Client) -> Self {
        // Reserving ephemeral ports avoids clashes with the developer's Atom.
        // Release just before spawning; readiness also detects a failed bind.
        let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let grpc = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http.local_addr().unwrap();
        let grpc_addr = grpc.local_addr().unwrap();
        let directory = std::env::temp_dir().join(format!("atom-stateless-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        drop((http, grpc));
        let child = Command::new(env!("CARGO_BIN_EXE_atom"))
            .env_clear()
            .env("DATABASE_URL", database_url)
            .env("LISTEN_ADDR", http_addr.to_string())
            .env("GRPC_ADDR", grpc_addr.to_string())
            .env("ADMIN_SECRET", "Stateless-Test-Password-42!")
            .env("ATOM_KEY_ENCRYPTION_KEY", STANDARD.encode([42_u8; 32]))
            .env("ATOM_KEY_ENCRYPTION_KEY_ID", "stateless-test:v1")
            .env("ATOM_LOG_LEVEL", "error")
            .env("ATOM_METRICS_ENABLED", "false")
            .env("ATOM_HTTP_SHUTDOWN_DRAIN_TIMEOUT_SECS", "5")
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("launch standalone Atom");
        let mut process = Self {
            child,
            directory,
            base: format!("http://{http_addr}"),
        };
        timeout(Duration::from_secs(30), async {
            loop {
                assert!(
                    process.child.try_wait().unwrap().is_none(),
                    "Atom exited before readiness"
                );
                if let Ok(response) = client
                    .get(format!("{}/health/ready", process.base))
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        break;
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("Atom ready within startup deadline");
        process
    }

    async fn graceful_stop(&mut self) {
        let status = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(self.child.id().unwrap().to_string())
            .status()
            .await
            .unwrap();
        assert!(status.success());
        let exit = timeout(Duration::from_secs(8), self.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(exit.success(), "coordinated shutdown must succeed: {exit}");
    }
}

async fn graph(client: &Client, process: &Process, token: &str, query: String) -> Value {
    let response: Value = client
        .post(format!("{}/graphql", process.base))
        .bearer_auth(token)
        .json(&json!({"query": query}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        response.get("errors").is_none(),
        "GraphQL errors: {:?}",
        response["errors"]
    );
    response["data"].clone()
}

async fn assert_recovered(
    client: &Client,
    process: &Process,
    token: &str,
    session_id: &Value,
    tenant_id: &Value,
    name: &str,
    jwks: &Value,
) {
    let session: Value = client
        .get(format!("{}/auth/session", process.base))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(&session["session"]["sessionId"], session_id);
    let keys: Value = client
        .get(format!("{}/.well-known/jwks.json", process.base))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(&keys, jwks, "replacement must load the same signing keys");
    let data = graph(
        client,
        process,
        token,
        format!("{{ tenants(name: \"{name}\") {{ items {{ id name }} total }} }}"),
    )
    .await;
    assert_eq!(&data["tenants"]["items"][0]["id"], tenant_id);
    // Atom needs no writable application state in its working directory.
    assert_eq!(std::fs::read_dir(&process.directory).unwrap().count(), 0);
}

async fn coordination_snapshot(database_url: &str, id: Uuid) -> Value {
    let pool = sqlx::PgPool::connect(database_url).await.unwrap();
    let value = sqlx::query_scalar::<_, Value>(
        "SELECT jsonb_build_object('resource', to_jsonb(r), 'leases', (SELECT jsonb_agg(l) FROM object_leases l WHERE object_id=$1), 'replays', (SELECT jsonb_agg(q ORDER BY request_id) FROM object_change_requests q)) FROM resources r WHERE r.id=$1"
    ).bind(id).fetch_one(&pool).await.unwrap();
    pool.close().await;
    value
}

#[tokio::test]
#[ignore = "requires an empty disposable PostgreSQL database via DATABASE_URL"]
async fn committed_state_survives_graceful_and_forced_process_replacement() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut first = Process::start(&database_url, &client).await;
    let login: Value = client
        .post(format!("{}/auth/login", first.base))
        .json(&json!({"identifier": atom::config::ADMIN_ENTITY_ID, "secret": "Stateless-Test-Password-42!"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = login["token"].as_str().expect("login token");
    let jwks: Value = client
        .get(format!("{}/.well-known/jwks.json", first.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let name = format!("stateless-{}", Uuid::new_v4());
    let data = graph(
        &client,
        &first,
        token,
        format!("mutation {{ createTenant(input: {{ name: \"{name}\" }}) {{ id }} }}"),
    )
    .await;
    let tenant_id = &data["createTenant"]["id"];
    assert!(tenant_id.is_string());
    let object = Uuid::new_v4();
    let request = Uuid::new_v4();
    let replay_query = format!("mutation {{ commitObjectChanges(requestId: \"{request}\", changes: [{{objectKind: \"resource\", operation: \"create\", id: \"{object}\", kind: \"restart_test\", name: \"restart\", attributes: {{value: 1}}}}]) }}");
    let replay = graph(&client, &first, token, replay_query.clone()).await;
    let lease = graph(&client, &first, token, format!("mutation {{ acquireObjectLease(input: {{objectKind: \"resource\", objectId: \"{object}\", holderId: \"{}\", operation: \"replacement-test\", ttlSeconds: 300}}) }}", Uuid::new_v4())).await;
    assert_eq!(lease["acquireObjectLease"]["fence"], 1);
    let snapshot = coordination_snapshot(&database_url, object).await;
    assert_eq!(snapshot["resource"]["revision"], 1);
    assert_eq!(snapshot["leases"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["replays"].as_array().unwrap().len(), 1);
    first.graceful_stop().await;
    drop(first);

    let mut second = Process::start(&database_url, &client).await;
    assert_recovered(
        &client,
        &second,
        token,
        &login["session_id"],
        tenant_id,
        &name,
        &jwks,
    )
    .await;
    assert_eq!(coordination_snapshot(&database_url, object).await, snapshot);
    assert_eq!(
        graph(&client, &second, token, replay_query.clone()).await,
        replay
    );
    second.child.kill().await.unwrap(); // SIGKILL: no graceful-shutdown code runs.
    drop(second);

    let mut third = Process::start(&database_url, &client).await;
    assert_recovered(
        &client,
        &third,
        token,
        &login["session_id"],
        tenant_id,
        &name,
        &jwks,
    )
    .await;
    assert_eq!(coordination_snapshot(&database_url, object).await, snapshot);
    assert_eq!(graph(&client, &third, token, replay_query).await, replay);
    third.graceful_stop().await;
}
