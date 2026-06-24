use anyhow::Context;
use atom::{
    audit, certs, config, db, grpc, identity, keys, purge, routes,
    state::{self, GrpcRuntimeStatus},
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = config::Config::from_env()?;
    let pool = db::create_pool(&cfg.database_url, &cfg.db_pool).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

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

    let state = state::AppState::new(pool, cfg.clone(), active_keys, certificate_issuer);
    state
        .set_grpc_status(GrpcRuntimeStatus::starting(grpc_bound_addr.to_string()))
        .await;
    audit::spawn_retention_cleanup(state.clone());
    purge::spawn_purge_cleanup(state.clone());

    // Spawn gRPC server on a separate port; runs concurrently with HTTP. It
    // installs its own shutdown listener and drains on SIGINT/SIGTERM.
    let grpc_state = state.clone();
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = grpc::serve(grpc_listener, grpc_state).await {
            tracing::error!("grpc server exited: {e}");
        }
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
