use anyhow::Context;
use atom::{
    audit, bootstrap, cache, callout, certs, config, db, events, grpc, http_server, identity, keys,
    metrics, purge, routes,
    state::{self, GrpcRuntimeStatus},
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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

    if let Some(ref path) = cfg.bootstrap_file {
        let bootstrap_cfg = bootstrap::load(std::path::Path::new(path))?;
        bootstrap::apply(&pool, &cfg.signing_keys, &bootstrap_cfg).await?;
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
    let cache = init_cache(&cfg.cache).await?;

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
    let grpc_handle = tokio::spawn(async move {
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
    if let Err(e) = grpc_handle.await {
        tracing::error!("grpc task join error: {e}");
    }
    if let Some(handle) = enrollment_handle {
        if let Err(error) = handle.await {
            tracing::error!(%error, "PKI enrollment task join error");
        }
    }

    Ok(())
}

/// Builds the Redis-backed cache when enabled.
///
/// `None` means "caching is not configured", and every mutation guard becomes
/// a pure pass-through on that basis. So an *enabled* cache that merely can't
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
    if !cfg.enabled {
        return Ok(None);
    }
    let client = cache::CacheClient::build(cfg).context("cache configuration is invalid")?;
    match client.probe(cfg.connect_timeout_ms).await {
        Ok(()) => tracing::info!("cache enabled; connected to Redis"),
        Err(err) if cfg.fail_fast_on_startup => {
            return Err(
                err.context("cache connect failed and ATOM_CACHE_FAIL_FAST_ON_STARTUP=true")
            );
        }
        Err(err) => tracing::error!(
            "cache enabled but Redis is unreachable: {err}. Reads fall through to Postgres; \
             security-sensitive mutations are refused until Redis recovers."
        ),
    }
    Ok(Some(client))
}

fn init_tracing(logging: &config::LoggingConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&logging.level)
        .context("ATOM_LOG_LEVEL/RUST_LOG must be a valid tracing filter")?;

    match logging.format {
        config::LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
        config::LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }

    Ok(())
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
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active'",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await?;

    if count == 0 {
        identity::service::validate_password_strength(secret)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = identity::service::hash_secret(secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        sqlx::query(
            "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(entity_id)
        .bind(hash)
        .execute(pool)
        .await?;
        tracing::info!("{label} password bootstrapped");
    }

    Ok(())
}
