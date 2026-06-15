use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    certs::service::CertificateIssuer, config::Config, keys::ActiveKeys, rate_limit::RateLimiter,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub keys: Arc<RwLock<ActiveKeys>>,
    pub certificate_issuer: Option<Arc<CertificateIssuer>>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(
        pool: sqlx::PgPool,
        config: Config,
        keys: ActiveKeys,
        certificate_issuer: Option<CertificateIssuer>,
    ) -> Self {
        AppState {
            pool,
            config,
            keys: Arc::new(RwLock::new(keys)),
            certificate_issuer: certificate_issuer.map(Arc::new),
            rate_limiter: Arc::new(RateLimiter::default()),
        }
    }
}
