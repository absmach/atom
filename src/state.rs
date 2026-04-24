use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{config::Config, keys::ActiveKeys};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub keys: Arc<RwLock<ActiveKeys>>,
}

impl AppState {
    pub fn new(pool: sqlx::PgPool, config: Config, keys: ActiveKeys) -> Self {
        AppState {
            pool,
            config,
            keys: Arc::new(RwLock::new(keys)),
        }
    }
}
