//! In-process TLS termination for the public enrollment listener.

use std::{
    collections::HashMap,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use axum::extract::ConnectInfo;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
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
    max_connections_per_ip: usize,
    tls_handshake_timeout: Duration,
    http_header_timeout: Duration,
    connection_timeout: Duration,
    shutdown_drain_timeout: Duration,
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
        max_connections_per_ip: state.config.enrollment.max_connections_per_ip,
        tls_handshake_timeout: Duration::from_secs(
            state.config.enrollment.tls_handshake_timeout_secs,
        ),
        http_header_timeout: Duration::from_secs(state.config.enrollment.http_header_timeout_secs),
        connection_timeout: Duration::from_secs(state.config.enrollment.connection_timeout_secs),
        shutdown_drain_timeout: Duration::from_secs(
            state.config.enrollment.shutdown_drain_timeout_secs,
        ),
    }))
}

pub async fn serve(prepared: PreparedEnrollmentServer, state: AppState) -> Result<()> {
    let address = prepared.local_addr()?;
    let permits = Arc::new(Semaphore::new(prepared.max_connections));
    let ip_connections = PerIpConnectionLimiter::new(prepared.max_connections_per_ip);
    let handshake_timeout = prepared.tls_handshake_timeout;
    let http_header_timeout = prepared.http_header_timeout;
    let connection_timeout = prepared.connection_timeout;
    let shutdown_drain_timeout = prepared.shutdown_drain_timeout;
    let refresh_secs = state.config.enrollment.trust_bundle_refresh_secs;
    let refresh_state = state.clone();
    let router = http::create_router(state);
    let mut acceptor = prepared.acceptor;
    let mut trust_refresh = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
    let mut connections = JoinSet::new();
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
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(%error, "enrollment connection task failed");
                }
                continue;
            },
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
        let ip_connection = match ip_connections.try_acquire(remote_addr.ip()) {
            Some(permit) => permit,
            None => {
                tracing::warn!(%remote_addr, "enrollment per-IP connection limit reached");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        connections.spawn(async move {
            let _permit = permit;
            let _ip_connection = ip_connection;
            let stream = match timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::warn!(%remote_addr, %error, "enrollment TLS handshake rejected");
                    return;
                }
                Err(_) => {
                    tracing::warn!(%remote_addr, "enrollment TLS handshake timed out");
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
            let connection_router = router.layer(axum::Extension(ConnectInfo(remote_addr)));
            let connection_router = match peer {
                Some(peer) => connection_router.layer(axum::Extension(peer)),
                None => connection_router,
            };
            let service = TowerToHyperService::new(connection_router);
            // Do not let the auto builder sniff an HTTP/2 preface: that read
            // has no HTTP/1 header timer, and HTTP/2 would bypass the
            // single-request/disabled-keep-alive limits below.
            let mut builder = Builder::new(TokioExecutor::new()).http1_only();
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(http_header_timeout)
                .keep_alive(false);
            match timeout(
                connection_timeout,
                builder.serve_connection(TokioIo::new(stream), service),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%remote_addr, %error, "enrollment connection closed with error");
                }
                Err(_) => {
                    tracing::warn!(%remote_addr, "enrollment connection deadline reached");
                }
            }
        });
    }

    if timeout(shutdown_drain_timeout, async {
        while let Some(joined) = connections.join_next().await {
            if let Err(error) = joined {
                tracing::warn!(%error, "enrollment connection task failed during shutdown");
            }
        }
    })
    .await
    .is_err()
    {
        let remaining = connections.len();
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        tracing::warn!(
            remaining,
            "aborted enrollment connections after shutdown drain deadline"
        );
    }
    tracing::info!(%address, "PKI enrollment listener stopped");
    Ok(())
}

#[derive(Clone)]
struct PerIpConnectionLimiter {
    max_connections_per_ip: usize,
    active: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl PerIpConnectionLimiter {
    fn new(max_connections_per_ip: usize) -> Self {
        Self {
            max_connections_per_ip,
            active: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<PerIpConnectionPermit> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(ip).or_default();
        if *count >= self.max_connections_per_ip {
            return None;
        }
        *count += 1;
        Some(PerIpConnectionPermit {
            limiter: self.clone(),
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match active.get_mut(&ip) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                active.remove(&ip);
            }
            None => tracing::error!(%ip, "enrollment per-IP connection permit released twice"),
        }
    }
}

struct PerIpConnectionPermit {
    limiter: PerIpConnectionLimiter,
    ip: IpAddr,
}

impl Drop for PerIpConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
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
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("select safe enrollment TLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .context("build enrollment TLS server configuration")?;
    // Enrollment serves HTTP/1.1 only. This advertises the same contract to
    // TLS clients that the connection builder enforces after the handshake.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_connection_cap_releases_when_a_connection_finishes() {
        let limiter = PerIpConnectionLimiter::new(1);
        let ip = "203.0.113.8".parse().expect("IP address");

        let permit = limiter.try_acquire(ip).expect("first connection allowed");
        assert!(
            limiter.try_acquire(ip).is_none(),
            "second connection denied"
        );

        drop(permit);
        assert!(limiter.try_acquire(ip).is_some(), "slot released on drop");
    }
}
