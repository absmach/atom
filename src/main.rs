use anyhow::Context;
use atom::{
    audit, bootstrap, cache, callout, certs, config, db, events, grpc, http_server, identity, keys,
    metrics, purge, routes,
    state::{self, GrpcRuntimeStatus},
};
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

// Lapin logs the complete BasicReturnMessage with Debug formatting, which
// renders its JSON payload as a byte array. AmqpPublisher emits the same
// unroutable-message warning with a decoded payload and broker metadata.
const LAPIN_RETURNED_MESSAGE_FILTER: &str = "lapin::returned_messages=error";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = config::Config::from_env()?;
    init_tracing(&cfg.logging)?;
    tracing::info!(
        version = atom::build_info::VERSION,
        revision = atom::build_info::REVISION,
        "starting atom"
    );

    metrics::init(cfg.metrics.enabled);
    let pool = db::create_pool(&cfg.database_url, &cfg.db_pool).await?;
    let bootstrap_cfg = match cfg.bootstrap_file.as_deref() {
        Some(path) => Some(bootstrap::load(std::path::Path::new(path)).await?),
        None => None,
    };

    bootstrap::preflight_product_applicability(&pool, bootstrap_cfg.as_ref()).await?;
    bootstrap::preflight_legacy_email_uniqueness(&pool).await?;
    atom::protected_objects::preflight_global_protected_object_ids(&pool).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    certs::authority::key_provider::validate_startup(&pool, &cfg.pki_ca_keys).await?;

    if let Some(ref path) = cfg.pki_root_cert_path {
        bootstrap_pki_root(&pool, path).await?;
    }

    match (
        cfg.pki_platform_intermediate_cert_path.as_deref(),
        cfg.pki_platform_intermediate_key_path.as_deref(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            bootstrap_platform_intermediate(&pool, &cfg.pki_ca_keys, cert_path, key_path).await?;
        }
        (Some(_), None) | (None, Some(_)) => {
            tracing::warn!(
                "ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH and \
                 ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH must be set together; \
                 skipping platform intermediate bootstrap"
            );
        }
        (None, None) => {}
    }

    if let Some(ref secret) = cfg.admin_secret {
        bootstrap_admin_credentials(&pool, cfg.admin_entity_id, secret).await?;
    }
    if let Some(ref secret) = cfg.service_secret {
        bootstrap_password_credentials(&pool, cfg.service_entity_id, secret, "service").await?;
    }

    let cache = init_cache(&cfg.cache).await?;

    if let (Some(path), Some(bootstrap_cfg)) =
        (cfg.bootstrap_file.as_deref(), bootstrap_cfg.as_ref())
    {
        bootstrap::apply_with_cache(&pool, &cfg.signing_keys, bootstrap_cfg, cache.as_ref())
            .await?;
        tracing::info!("bootstrap file applied: {path}");
    }

    keys::bootstrap_if_needed(&pool, &cfg.signing_keys).await?;
    let active_keys = keys::load_active_keys(&pool, &cfg.signing_keys).await?;

    let grpc_addr = cfg.grpc_addr.parse()?;
    let grpc_listener = grpc::bind_listener(grpc_addr)
        .await
        .with_context(|| format!("failed to bind gRPC listener on {}", cfg.grpc_addr))?;
    let grpc_bound_addr = grpc_listener.local_addr()?;
    // Validate gRPC TLS material before serving anything, so a bad cert aborts
    // startup instead of leaving HTTP up with a permanently failing gRPC task.
    let grpc_tls = grpc::load_tls_config(&cfg).await?;

    let callouts_config = callout::CalloutsConfig::load_from_env().await?;
    let callout_service = callout::CalloutService::build(callouts_config).await?;
    let mut state =
        state::AppState::new(pool, cfg.clone(), active_keys, cache).with_callouts(callout_service);
    if cfg.events.enabled() {
        let publisher = events::publisher::AmqpPublisher::connect(&cfg.events)
            .await
            .with_context(|| {
                "failed to connect to the configured AMQP broker for event publishing"
            })?;
        state = state.with_event_publisher(std::sync::Arc::new(publisher));
        tracing::info!(
            "event publishing enabled (AMQP exchange {:?}, routing key {})",
            cfg.events.amqp_exchange,
            cfg.events.amqp_routing_key
        );
    } else {
        tracing::info!("event publishing disabled (ATOM_EVENTS_AMQP_URL not set)");
    }
    state
        .set_grpc_status(GrpcRuntimeStatus::starting(grpc_bound_addr.to_string()))
        .await;
    audit::spawn_retention_cleanup(state.clone());
    purge::spawn_purge_cleanup(state.clone());
    events::spawn_event_publisher(state.clone());
    certs::lifecycle::spawn(state.clone());

    // Enrollment is a separate public TLS surface. Prepare it before spawning
    // any server so bad TLS material or a bad bind address fails startup.
    let enrollment_server = certs::enrollment::tls::prepare(&state).await?;

    // Spawn gRPC server on a separate port; runs concurrently with HTTP. It
    // installs its own shutdown listener and drains on SIGINT/SIGTERM.
    let grpc_state = state.clone();
    let mut grpc_handle = tokio::spawn(async move {
        if let Err(e) = grpc::serve(grpc_listener, grpc_state, grpc_tls).await {
            tracing::error!("grpc server exited: {e}");
        }
    });

    let enrollment_handle = enrollment_server.map(|server| {
        let enrollment_state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = certs::enrollment::tls::serve(server, enrollment_state).await {
                tracing::error!(%error, "PKI enrollment server exited");
            }
        })
    });

    let app = routes::create_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr).await?;
    tracing::info!("atom listening on {}", cfg.listen_addr);

    let shutdown_drain_timeout = Duration::from_secs(cfg.http_server.shutdown_drain_timeout_secs);
    http_server::serve(
        listener,
        app,
        cfg.http_server,
        cfg.rate_limits.ipv6_prefix_len,
    )
    .await?;

    // HTTP has drained; wait for the gRPC task to finish draining too so the
    // process does not exit out from under in-flight gRPC requests.
    tracing::info!("http server stopped; waiting for grpc to drain");
    match tokio::time::timeout(shutdown_drain_timeout, &mut grpc_handle).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(%error, "grpc task join error"),
        Err(_) => {
            tracing::warn!(
                timeout_secs = shutdown_drain_timeout.as_secs(),
                "grpc drain timed out; aborting remaining requests"
            );
            grpc_handle.abort();
            let _ = grpc_handle.await;
        }
    }
    if let Some(handle) = enrollment_handle {
        if let Err(error) = handle.await {
            tracing::error!(%error, "PKI enrollment task join error");
        }
    }

    Ok(())
}

/// Builds the Redis-backed cache in prepare or enabled mode.
///
/// `None` means "caching is not configured", and every mutation guard becomes
/// a pure pass-through on that basis. So a configured cache that merely can't
/// reach Redis right now must never degrade to `None`: this process would go
/// on mutating grants, sessions, and credentials without invalidating entries
/// that other replicas are still serving, and a revoke here would stay
/// authorized there. Unreachable Redis is a runtime condition, not a
/// configuration one — the client is retained either way, and its own
/// behavior covers the outage: reads fall through to Postgres as misses,
/// while `begin` fails and so refuses security-sensitive mutations until
/// Redis returns (see `src/cache/mod.rs` and `src/cache/invalidate.rs`).
///
/// A *build* failure is fatal regardless: an unparseable URL cannot recover.
/// `ATOM_CACHE_FAIL_FAST_ON_STARTUP` then decides whether an unreachable
/// Redis should also abort startup, rather than boot into the refusing state.
async fn init_cache(cfg: &config::CacheConfig) -> anyhow::Result<Option<cache::CacheClient>> {
    if !cfg.mode.configured() {
        return Ok(None);
    }
    let client = cache::CacheClient::build(cfg).context("cache configuration is invalid")?;
    match client.probe(cfg.connect_timeout_ms).await {
        Ok(()) => tracing::info!(
            mode = ?cfg.mode,
            namespace = %cfg.namespace,
            "cache configured; connected to Redis"
        ),
        Err(err) if cfg.fail_fast_on_startup => {
            return Err(
                err.context("cache connect failed and ATOM_CACHE_FAIL_FAST_ON_STARTUP=true")
            );
        }
        Err(err) => tracing::error!(
            "cache configured but not ready: {err}. Reads fall through to Postgres; \
             security-sensitive mutations are refused until the cache is safely initialized or \
             the process is restarted, as the reported condition requires."
        ),
    }
    Ok(Some(client))
}

fn tracing_filter(level: &str) -> anyhow::Result<EnvFilter> {
    let filter = EnvFilter::try_new(level)
        .context("ATOM_LOG_LEVEL/RUST_LOG must be a valid tracing filter")?
        .add_directive(
            LAPIN_RETURNED_MESSAGE_FILTER
                .parse()
                .context("the static lapin tracing filter must be valid")?,
        );
    Ok(filter)
}

fn init_tracing(logging: &config::LoggingConfig) -> anyhow::Result<()> {
    let filter = tracing_filter(&logging.level)?;

    match logging.format {
        config::LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
        config::LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }

    Ok(())
}

#[cfg(test)]
mod tracing_tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture buffer lock").write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tracing_suppresses_lapin_returned_message_byte_dump() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer_output = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_env_filter(tracing_filter("warn").expect("valid tracing filter"))
            .with_writer(move || SharedWriter(Arc::clone(&writer_output)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "lapin::returned_messages",
                data = ?[123_u8, 34, 101, 118, 101, 110, 116],
                "Server returned us a message"
            );
            tracing::warn!(
                target: "atom::events::publisher",
                payload = %r#"{"event":"resource.create"}"#,
                "AMQP broker returned an unroutable event"
            );
        });

        let output = String::from_utf8(output.lock().expect("capture buffer lock").clone())
            .expect("tracing output is UTF-8");
        assert!(!output.contains("Server returned us a message"));
        assert!(!output.contains("[123, 34, 101"));
        assert!(output.contains("AMQP broker returned an unroutable event"));
        assert!(output.contains(r#"{"event":"resource.create"}"#));
    }
}

async fn bootstrap_pki_root(pool: &sqlx::PgPool, path: &str) -> anyhow::Result<()> {
    let pem = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read ATOM_PKI_ROOT_CERT_PATH ({path})"))?;
    let mut tx = pool
        .begin()
        .await
        .context("failed to open PKI root bootstrap transaction")?;
    let outcome = certs::authority::provisioning::import_root_mutation_in_tx(&mut tx, &pem)
        .await
        .with_context(|| format!("importing PKI root from {path}"))?;
    tx.commit()
        .await
        .context("failed to commit PKI root bootstrap")?;
    let authority = &outcome.value;
    if outcome.changed {
        tracing::info!(
            path = %path,
            authority_id = %authority.id,
            subject = %authority.subject,
            fingerprint = authority.fingerprint_sha256.as_deref().unwrap_or(""),
            "PKI root certificate imported at bootstrap"
        );
    } else {
        tracing::info!(
            path = %path,
            authority_id = %authority.id,
            "PKI root certificate already present; bootstrap is a no-op"
        );
    }
    Ok(())
}

async fn bootstrap_platform_intermediate(
    pool: &sqlx::PgPool,
    ca_keys: &config::PkiCaKeyConfig,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<()> {
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .with_context(|| {
            format!("failed to read ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH ({cert_path})")
        })?;
    let key_pem = tokio::fs::read_to_string(key_path).await.with_context(|| {
        format!("failed to read ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH ({key_path})")
    })?;
    let mut tx = pool
        .begin()
        .await
        .context("failed to open PKI platform intermediate bootstrap transaction")?;
    let mut outcome = certs::authority::provisioning::import_platform_intermediate_mutation_in_tx(
        &mut tx, ca_keys, &cert_pem, &key_pem,
    )
    .await
    .with_context(|| format!("importing platform intermediate from {cert_path}"))?;
    tx.commit()
        .await
        .context("failed to commit PKI platform intermediate bootstrap")?;
    let authority = outcome.value.clone();
    if outcome.changed {
        tracing::info!(
            cert_path = %cert_path,
            authority_id = %authority.id,
            subject = %authority.subject,
            fingerprint = authority.fingerprint_sha256.as_deref().unwrap_or(""),
            "PKI platform intermediate imported at bootstrap"
        );
    } else {
        tracing::info!(
            cert_path = %cert_path,
            authority_id = %authority.id,
            "PKI platform intermediate already present; bootstrap is a no-op"
        );
    }
    outcome.commit_generated_key();
    Ok(())
}

async fn bootstrap_admin_credentials(
    pool: &sqlx::PgPool,
    admin_entity_id: Uuid,
    secret: &str,
) -> anyhow::Result<()> {
    bootstrap_password_credentials(pool, admin_entity_id, secret, "admin").await
}

async fn bootstrap_password_credentials(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    secret: &str,
    label: &str,
) -> anyhow::Result<()> {
    identity::service::validate_password_strength(secret).map_err(|e| anyhow::anyhow!("{e}"))?;
    let hash =
        identity::service::hash_secret(secret.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut tx = pool
        .begin()
        .await
        .with_context(|| format!("failed to begin {label} password bootstrap transaction"))?;
    if identity::repo::lock_active_entity(&mut tx, entity_id)
        .await
        .map_err(|e| anyhow::anyhow!("{label} password bootstrap: {e}"))?
        .is_none()
    {
        anyhow::bail!("active {label} entity {entity_id} not found");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active'",
    )
    .bind(entity_id)
    .fetch_one(&mut *tx)
    .await?;

    let mut created = false;
    if count == 0 {
        sqlx::query(
            "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(entity_id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
        created = true;
    }
    tx.commit()
        .await
        .with_context(|| format!("failed to commit {label} password bootstrap"))?;
    if created {
        tracing::info!("{label} password bootstrapped");
    }

    Ok(())
}
