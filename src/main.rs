mod audit;
mod auth;
mod authz;
mod config;
mod db;
mod error;
mod grpc;
mod identity;
mod keys;
mod models;
mod routes;
mod state;

use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = config::Config::from_env()?;
    let pool = db::create_pool(&cfg.database_url).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    if let Some(ref secret) = cfg.admin_secret {
        bootstrap_admin_credentials(&pool, cfg.admin_entity_id, secret).await?;
    }

    keys::bootstrap_if_needed(&pool).await?;
    let active_keys = keys::load_active_keys(&pool).await?;

    let state = state::AppState::new(pool, cfg.clone(), active_keys);

    // Spawn gRPC server on a separate port; runs concurrently with HTTP.
    let grpc_addr = cfg.grpc_addr.parse()?;
    let grpc_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = grpc::serve(grpc_addr, grpc_state).await {
            tracing::error!("grpc server exited: {e}");
        }
    });

    let app = routes::create_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr).await?;
    tracing::info!("atom listening on {}", cfg.listen_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn bootstrap_admin_credentials(
    pool: &sqlx::PgPool,
    admin_entity_id: Uuid,
    secret: &str,
) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active'",
    )
    .bind(admin_entity_id)
    .fetch_one(pool)
    .await?;

    if count == 0 {
        let hash = identity::service::hash_secret(secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        sqlx::query(
            "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(admin_entity_id)
        .bind(hash)
        .execute(pool)
        .await?;
        tracing::info!("admin password bootstrapped");
    }

    Ok(())
}
