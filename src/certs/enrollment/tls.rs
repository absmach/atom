//! In-process TLS termination for the public enrollment listener.

use std::{io::Cursor, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::{certs::authority::provisioning, config::EnrollmentTlsConfig, state::AppState};

use super::http;

#[derive(Debug, Clone)]
pub struct VerifiedPeerCertificate(Arc<[u8]>);

impl VerifiedPeerCertificate {
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

pub struct PreparedEnrollmentServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    max_connections: usize,
}

impl PreparedEnrollmentServer {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("read enrollment listener address")
    }
}

/// Loads all TLS material and binds the dedicated port before any HTTP surface
/// starts. A bad certificate, key, trust bundle, or address therefore fails
/// startup rather than leaving a partially healthy process.
pub async fn prepare(state: &AppState) -> Result<Option<PreparedEnrollmentServer>> {
    if !state.config.enrollment.enabled {
        return Ok(None);
    }
    let tls = state
        .config
        .enrollment
        .tls
        .as_ref()
        .context("enrollment enabled without TLS configuration")?;
    let server_config = load_server_config(state, tls).await?;
    let listener = TcpListener::bind(&state.config.enrollment.listen_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind enrollment listener on {}",
                state.config.enrollment.listen_addr
            )
        })?;
    Ok(Some(PreparedEnrollmentServer {
        listener,
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        max_connections: state.config.enrollment.max_connections,
    }))
}

pub async fn serve(prepared: PreparedEnrollmentServer, state: AppState) -> Result<()> {
    let address = prepared.local_addr()?;
    let permits = Arc::new(Semaphore::new(prepared.max_connections));
    let refresh_secs = state.config.enrollment.trust_bundle_refresh_secs;
    let refresh_state = state.clone();
    let router = http::create_router(state);
    let mut acceptor = prepared.acceptor;
    let mut trust_refresh = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
    trust_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    trust_refresh.tick().await;
    tracing::info!(%address, "PKI enrollment listener ready (in-process optional mTLS)");

    loop {
        let accepted = tokio::select! {
            accepted = prepared.listener.accept() => accepted,
            _ = trust_refresh.tick() => {
                // CA provisioning and rotation are live operations. Refresh the
                // verifier without dropping existing connections; on a
                // transient read/DB error the last known-good trust stays live.
                let tls = refresh_state.config.enrollment.tls.as_ref()
                    .expect("enabled enrollment has TLS configuration");
                match load_server_config(&refresh_state, tls).await {
                    Ok(config) => {
                        acceptor = TlsAcceptor::from(Arc::new(config));
                        tracing::info!("refreshed PKI enrollment trust bundle");
                    }
                    Err(error) => tracing::warn!(%error, "failed to refresh PKI enrollment trust bundle; retaining last known-good verifier"),
                }
                continue;
            },
            _ = crate::shutdown::shutdown_signal() => break,
        };
        let (stream, remote_addr) = match accepted {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "enrollment listener accept failed");
                continue;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(%remote_addr, "enrollment connection limit reached");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%remote_addr, %error, "enrollment TLS handshake rejected");
                    return;
                }
            };
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .map(|certificate| {
                    VerifiedPeerCertificate(Arc::from(certificate.as_ref().to_vec()))
                });
            let connection_router = match peer {
                Some(peer) => router.layer(axum::Extension(peer)),
                None => router,
            };
            let service = TowerToHyperService::new(connection_router);
            let builder = Builder::new(TokioExecutor::new());
            if let Err(error) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%remote_addr, %error, "enrollment connection closed with error");
            }
        });
    }
    tracing::info!(%address, "PKI enrollment listener stopped");
    Ok(())
}

async fn load_server_config(state: &AppState, tls: &EnrollmentTlsConfig) -> Result<ServerConfig> {
    let certificate_pem = tokio::fs::read(&tls.cert_path)
        .await
        .with_context(|| format!("read enrollment TLS certificate {}", tls.cert_path))?;
    let key_pem = tokio::fs::read(&tls.key_path)
        .await
        .with_context(|| format!("read enrollment TLS private key {}", tls.key_path))?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate_pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse enrollment TLS certificate chain")?;
    if certificates.is_empty() {
        anyhow::bail!("enrollment TLS certificate chain is empty");
    }
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
        .context("parse enrollment TLS private key")?
        .context("enrollment TLS private key is missing")?;

    let bundle = provisioning::trust_bundle(&state.pool)
        .await
        .map_err(|error| anyhow::anyhow!("load Atom enrollment trust bundle: {error}"))?;
    let trust_certificates = rustls_pemfile::certs(&mut Cursor::new(bundle.pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse Atom enrollment trust bundle")?;
    if trust_certificates.is_empty() {
        anyhow::bail!("Atom enrollment trust bundle contains no certificates");
    }
    let mut roots = RootCertStore::empty();
    for certificate in trust_certificates {
        roots
            .add(certificate)
            .context("add certificate to enrollment client trust store")?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .context("build enrollment client-certificate verifier")?;
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("select safe enrollment TLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .context("build enrollment TLS server configuration")
}
