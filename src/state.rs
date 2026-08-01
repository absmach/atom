use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    certs::service::CertificateIssuer, config::Config, events::publisher::EventPublisher,
    keys::ActiveKeys, rate_limit::RateLimiter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcRuntimeState {
    Starting,
    Serving,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcRuntimeStatus {
    pub state: GrpcRuntimeState,
    pub address: String,
    pub message: String,
}

impl GrpcRuntimeStatus {
    pub fn starting(address: impl Into<String>) -> Self {
        let address = address.into();
        Self {
            state: GrpcRuntimeState::Starting,
            message: format!("starting on {address}"),
            address,
        }
    }

    pub fn serving(address: impl Into<String>) -> Self {
        let address = address.into();
        Self {
            state: GrpcRuntimeState::Serving,
            message: format!("serving on {address}"),
            address,
        }
    }

    pub fn error(address: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            state: GrpcRuntimeState::Error,
            address: address.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: Config,
    pub keys: Arc<RwLock<ActiveKeys>>,
    pub certificate_issuer: Option<Arc<CertificateIssuer>>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Delivers domain events out of the outbox (see `src/events/mod.rs`).
    /// `None` (the default) means no broker is configured: event publishing
    /// is a complete no-op — no outbox rows are written, no poller runs.
    /// Set via [`AppState::with_event_publisher`], since connecting to a
    /// broker is an async operation `AppState::new` (sync) can't perform.
    pub event_publisher: Option<Arc<dyn EventPublisher>>,
    grpc_status: Arc<RwLock<GrpcRuntimeStatus>>,
}

impl AppState {
    pub fn new(
        pool: sqlx::PgPool,
        config: Config,
        keys: ActiveKeys,
        certificate_issuer: Option<CertificateIssuer>,
    ) -> Self {
        let grpc_status = GrpcRuntimeStatus::starting(config.grpc_addr.clone());
        AppState {
            pool,
            config,
            keys: Arc::new(RwLock::new(keys)),
            certificate_issuer: certificate_issuer.map(Arc::new),
            rate_limiter: Arc::new(RateLimiter::default()),
            event_publisher: None,
            grpc_status: Arc::new(RwLock::new(grpc_status)),
        }
    }

    /// Installs an event publisher (e.g. the AMQP-backed one, once connected
    /// in `main.rs`, or a test-only mock that records calls). Does not
    /// affect any other field.
    pub fn with_event_publisher(mut self, publisher: Arc<dyn EventPublisher>) -> Self {
        self.event_publisher = Some(publisher);
        self
    }

    pub async fn grpc_status(&self) -> GrpcRuntimeStatus {
        self.grpc_status.read().await.clone()
    }

    pub async fn set_grpc_status(&self, status: GrpcRuntimeStatus) {
        *self.grpc_status.write().await = status;
    }
}
