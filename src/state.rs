use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{certs::service::CertificateIssuer, config::Config, keys::ActiveKeys};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub keys: Arc<RwLock<ActiveKeys>>,
    pub certificate_issuer: Option<Arc<CertificateIssuer>>,
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
        }
    }
}
