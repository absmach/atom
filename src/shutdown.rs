//! Process shutdown signaling shared by the HTTP and gRPC servers.

/// Resolves when the process receives SIGINT (Ctrl-C) or, on Unix, SIGTERM.
///
/// The standalone entry point listens once and cancels the shared runtime token
/// so HTTP, gRPC, enrollment and background jobs drain together. On non-Unix
/// platforms only Ctrl-C is awaited.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!("failed to install Ctrl-C handler: {err}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => tracing::error!("failed to install SIGTERM handler: {err}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    tracing::info!("shutdown signal received");
}
