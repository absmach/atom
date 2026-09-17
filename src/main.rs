use anyhow::Context;
use atom::{config, runtime, shutdown};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

// Suppress Lapin's raw payload dump; our publisher logs the decoded event.
const LAPIN_RETURNED_MESSAGE_FILTER: &str = "lapin::returned_messages=error";

fn main() -> anyhow::Result<()> {
    let executor = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = executor.block_on(run());
    // Native HSM calls may outlive their request timeout. Do not hang forever
    // while Tokio waits for its blocking pool after the drain deadline expires.
    executor.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn run() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let cfg = config::Config::from_env()?;
    init_tracing(&cfg.logging)?;
    tracing::info!(
        version = atom::build_info::VERSION,
        revision = atom::build_info::REVISION,
        "starting atom"
    );
    let drain_timeout = Duration::from_secs(cfg.http_server.shutdown_drain_timeout_secs);
    let stop = CancellationToken::new();
    let serving = runtime::run(cfg, stop.clone(), drain_timeout);
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => result,
        _ = shutdown::shutdown_signal() => {
            stop.cancel();
            // This outer deadline also covers a signal received during startup.
            tokio::time::timeout(drain_timeout, serving)
                .await
                .context("Atom shutdown deadline exceeded")?
        }
    }
}

fn tracing_filter(level: &str) -> anyhow::Result<EnvFilter> {
    let filter = EnvFilter::try_new(level)
        .context("ATOM_LOG_LEVEL/RUST_LOG must be a valid tracing filter")?
        .add_directive(
            LAPIN_RETURNED_MESSAGE_FILTER
                .parse()
                .context("the static lapin tracing filter must be valid")?,
        );
    Ok(filter)
}

fn init_tracing(logging: &config::LoggingConfig) -> anyhow::Result<()> {
    let filter = tracing_filter(&logging.level)?;

    match logging.format {
        config::LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
        config::LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }

    Ok(())
}

#[cfg(test)]
mod tracing_tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture buffer lock").write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tracing_suppresses_lapin_returned_message_byte_dump() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer_output = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_env_filter(tracing_filter("warn").expect("valid tracing filter"))
            .with_writer(move || SharedWriter(Arc::clone(&writer_output)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "lapin::returned_messages",
                data = ?[123_u8, 34, 101, 118, 101, 110, 116],
                "Server returned us a message"
            );
            tracing::warn!(
                target: "atom::events::publisher",
                payload = %r#"{"event":"resource.create"}"#,
                "AMQP broker returned an unroutable event"
            );
        });

        let output = String::from_utf8(output.lock().expect("capture buffer lock").clone())
            .expect("tracing output is UTF-8");
        assert!(!output.contains("Server returned us a message"));
        assert!(!output.contains("[123, 34, 101"));
        assert!(output.contains("AMQP broker returned an unroutable event"));
        assert!(output.contains(r#"{"event":"resource.create"}"#));
    }
}
