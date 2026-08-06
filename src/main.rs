use anyhow::Context;
use atom::{
    audit, certs, config, db, events, grpc, identity, keys, metrics, purge, routes,
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

    if let Some(ref secret) = cfg.admin_secret {
        bootstrap_admin_credentials(&pool, cfg.admin_entity_id, secret).await?;
    }
    if let Some(ref secret) = cfg.service_secret {
        bootstrap_password_credentials(&pool, cfg.service_entity_id, secret, "service").await?;
    }

    keys::bootstrap_if_needed(&pool, &cfg.signing_keys).await?;
    let certificate_issuer = certs::service::load_file_issuer_if_enabled(&cfg)?;
    let active_keys = keys::load_active_keys(&pool, &cfg.signing_keys).await?;

    let grpc_addr = cfg.grpc_addr.parse()?;
    let grpc_listener = grpc::bind_listener(grpc_addr)
        .await
        .with_context(|| format!("failed to bind gRPC listener on {}", cfg.grpc_addr))?;
    let grpc_bound_addr = grpc_listener.local_addr()?;
    // Validate gRPC TLS material before serving anything, so a bad cert aborts
    // startup instead of leaving HTTP up with a permanently failing gRPC task.
    let grpc_tls = grpc::load_tls_config(&cfg).await?;

    let mut state = state::AppState::new(pool, cfg.clone(), active_keys, certificate_issuer);
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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(atom::shutdown::shutdown_signal())
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
