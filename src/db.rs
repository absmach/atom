use std::time::Duration;

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};

use crate::config::DbPoolConfig;

pub fn pool_options(cfg: &DbPoolConfig) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .max_lifetime(Duration::from_secs(cfg.max_lifetime_secs))
}

pub async fn create_pool(url: &str, cfg: &DbPoolConfig) -> anyhow::Result<PgPool> {
    let connect_options: PgConnectOptions = url.parse::<PgConnectOptions>()?;
    let pool = tokio::time::timeout(
        Duration::from_secs(cfg.connect_timeout_secs),
        pool_options(cfg).connect_with(connect_options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("database connect timed out"))??;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_options_accept_configured_values() {
        let cfg = DbPoolConfig {
            max_connections: 12,
            min_connections: 2,
            acquire_timeout_secs: 3,
            connect_timeout_secs: 4,
            idle_timeout_secs: 5,
            max_lifetime_secs: 6,
        };

        let pool = pool_options(&cfg)
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("lazy pool");

        assert_eq!(pool.options().get_max_connections(), 12);
        assert_eq!(pool.options().get_min_connections(), 2);
    }
}
