//! Bounded transport for Atom's primary HTTP API listener.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{extract::ConnectInfo, Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::{
    net::TcpListener,
    sync::{watch, Semaphore},
    task::JoinSet,
    time::timeout,
};

use crate::{
    config::HttpServerConfig, connection_limit::PerIpConnectionLimiter, shutdown::shutdown_signal,
};

pub async fn serve(
    listener: TcpListener,
    router: Router,
    config: HttpServerConfig,
    ipv6_prefix_len: u8,
) -> Result<()> {
    let address = listener.local_addr()?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let ip_connections =
        PerIpConnectionLimiter::new(config.max_connections_per_ip, ipv6_prefix_len);
    let header_timeout = Duration::from_secs(config.http_header_timeout_secs);
    let connection_timeout = Duration::from_secs(config.connection_timeout_secs);
    let drain_timeout = Duration::from_secs(config.shutdown_drain_timeout_secs);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let (connection_shutdown, _) = watch::channel(false);
    let mut connections = JoinSet::new();

    tracing::info!(%address, "HTTP listener ready");
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = &mut shutdown => break,
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(%error, "HTTP connection task failed");
                }
                continue;
            },
        };
        let (stream, remote_addr) = match accepted {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "HTTP listener accept failed");
                continue;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::debug!(%remote_addr, "HTTP global connection limit reached");
                continue;
            }
        };
        let ip_connection = match ip_connections.try_acquire(remote_addr.ip()) {
            Some(permit) => permit,
            None => {
                tracing::debug!(%remote_addr, "HTTP per-source connection limit reached");
                continue;
            }
        };
        let connection_router = router
            .clone()
            .layer(Extension(ConnectInfo::<SocketAddr>(remote_addr)));
        let mut connection_shutdown = connection_shutdown.subscribe();
        connections.spawn(async move {
            let _permit = permit;
            let _ip_connection = ip_connection;
            let service = TowerToHyperService::new(connection_router);
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
            tokio::pin!(connection);
            match timeout(connection_timeout, async {
                tokio::select! {
                    result = &mut connection => result,
                    changed = connection_shutdown.changed() => {
                        if changed.is_ok() {
                            connection.as_mut().graceful_shutdown();
                        }
                        connection.await
                    }
                }
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%remote_addr, %error, "HTTP connection closed with error");
                }
                Err(_) => {
                    tracing::debug!(%remote_addr, "HTTP connection lifetime reached");
                }
            }
        });
    }

    connection_shutdown.send_replace(true);
    if timeout(drain_timeout, async {
        while let Some(joined) = connections.join_next().await {
            if let Err(error) = joined {
                tracing::warn!(%error, "HTTP connection task failed during shutdown");
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
            "aborted HTTP connections after shutdown drain deadline"
        );
    }
    tracing::info!(%address, "HTTP listener stopped");
    Ok(())
}
