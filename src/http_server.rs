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

use crate::{config::HttpServerConfig, connection_limit::PerIpConnectionLimiter};

pub async fn serve(
    listener: TcpListener,
    router: Router,
    config: HttpServerConfig,
    ipv6_prefix_len: u8,
) -> Result<()> {
    serve_with_shutdown(
        listener,
        router,
        config,
        ipv6_prefix_len,
        crate::shutdown::shutdown_signal(),
    )
    .await
}

pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    router: Router,
    config: HttpServerConfig,
    ipv6_prefix_len: u8,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send,
{
    let address = listener.local_addr()?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let ip_connections =
        PerIpConnectionLimiter::new(config.max_connections_per_ip, ipv6_prefix_len);
    let header_timeout = Duration::from_secs(config.http_header_timeout_secs);
    let connection_timeout = Duration::from_secs(config.connection_timeout_secs);
    let drain_timeout = Duration::from_secs(config.shutdown_drain_timeout_secs);
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
            // HTTP/2 does not expose an equivalent to the HTTP/1 header read
            // timeout below. Restrict this listener to HTTP/1 so an incomplete
            // HTTP/2 preface or HEADERS frame cannot hold a connection permit
            // until the overall connection deadline.
            let mut builder = Builder::new(TokioExecutor::new()).http1_only();
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
        anyhow::bail!("active requests exceeded the drain deadline; graceful shutdown failed");
    }
    tracing::info!(%address, "HTTP listener stopped");
    Ok(())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use axum::routing::get;
    use std::sync::Mutex;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn injected_shutdown_reports_forced_request_abort_as_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started_tx, started_rx) = oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started_tx)));
        let router = Router::new().route(
            "/work",
            get(move || {
                let started = started.lock().unwrap().take().unwrap();
                async move {
                    started.send(()).unwrap();
                    std::future::pending::<&'static str>().await
                }
            }),
        );
        let stop = CancellationToken::new();
        let config = HttpServerConfig {
            shutdown_drain_timeout_secs: 0,
            ..HttpServerConfig::default()
        };
        let server =
            serve_with_shutdown(listener, router, config, 64, stop.clone().cancelled_owned());
        tokio::pin!(server);
        let request = tokio::spawn(async move {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("http://{address}/work"))
                .send()
                .await
        });
        tokio::select! {
            result = &mut server => panic!("server exited before request entered: {result:?}"),
            started = tokio::time::timeout(Duration::from_secs(2), started_rx) => started.unwrap().unwrap(),
        }
        stop.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap();
        assert!(
            result.is_err(),
            "forced request abort cannot acknowledge graceful shutdown"
        );
        request.abort();
        let _ = request.await;
    }

    #[tokio::test]
    async fn injected_shutdown_drains_an_active_request_without_an_os_signal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started_tx)));
        let release = Arc::new(Mutex::new(Some(release_rx)));
        let router = Router::new().route(
            "/work",
            get(move || {
                let started = started.lock().unwrap().take().unwrap();
                let release = release.lock().unwrap().take().unwrap();
                async move {
                    started.send(()).unwrap();
                    release.await.unwrap();
                    "completed"
                }
            }),
        );
        let stop = CancellationToken::new();
        let server = serve_with_shutdown(
            listener,
            router,
            HttpServerConfig::default(),
            64,
            stop.clone().cancelled_owned(),
        );
        tokio::pin!(server);
        let request = tokio::spawn(async move {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("http://{address}/work"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        tokio::select! {
            result = &mut server => panic!("server exited before request entered: {result:?}"),
            started = tokio::time::timeout(Duration::from_secs(2), started_rx) => started.unwrap().unwrap(),
        }
        stop.cancel();
        tokio::select! {
            biased;
            result = &mut server => panic!("active request was not drained: {result:?}"),
            _ = std::future::ready(()) => {}
        }
        release_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap(),
            "completed"
        );
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
