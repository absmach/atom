//! Standalone Atom startup and coordinated shutdown.
//!
//! PostgreSQL owns durable application state. Each process recreates its pools,
//! keys and clients from the database and externally supplied configuration.

use anyhow::Context;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    audit, bootstrap, cache, callout, certs, config, db, events, grpc, http_server, identity, keys,
    metrics, purge, routes,
    state::{self, AppState, GrpcRuntimeStatus},
};

/// Initializes persisted state; callers own logging and the process runtime.
pub async fn initialize(cfg: config::Config) -> anyhow::Result<AppState> {
    metrics::init(cfg.metrics.enabled);
    let pool = db::create_pool(&cfg.database_url, &cfg.db_pool).await?;
    let bootstrap_cfg = match cfg.bootstrap_file.as_deref() {
        Some(path) => Some(bootstrap::load(std::path::Path::new(path)).await?),
        None => None,
    };

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    certs::authority::key_provider::validate_startup(&pool, &cfg.pki_ca_keys).await?;

    if let Some(ref path) = cfg.pki_root_cert_path {
        bootstrap_pki_root(&pool, path).await?;
    }

    match (
        cfg.pki_platform_intermediate_cert_path.as_deref(),
        cfg.pki_platform_intermediate_key_path.as_deref(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            bootstrap_platform_intermediate(&pool, &cfg.pki_ca_keys, cert_path, key_path).await?;
        }
        (Some(_), None) | (None, Some(_)) => {
            tracing::warn!(
                "ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH and \
                 ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH must be set together; \
                 skipping platform intermediate bootstrap"
            );
        }
        (None, None) => {}
    }

    if let Some(ref secret) = cfg.admin_secret {
        bootstrap_admin_credentials(&pool, cfg.admin_entity_id, secret).await?;
    }
    if let Some(ref secret) = cfg.service_secret {
        bootstrap_password_credentials(&pool, cfg.service_entity_id, secret, "service").await?;
    }

    let cache = init_cache(&cfg.cache).await?;

    if let (Some(path), Some(bootstrap_cfg)) =
        (cfg.bootstrap_file.as_deref(), bootstrap_cfg.as_ref())
    {
        bootstrap::apply_with_cache(&pool, &cfg.signing_keys, bootstrap_cfg, cache.as_ref())
            .await?;
        tracing::info!("bootstrap file applied: {path}");
    }

    keys::bootstrap_if_needed(&pool, &cfg.signing_keys).await?;
    let active_keys = keys::load_active_keys(&pool, &cfg.signing_keys).await?;

    let callouts_config = callout::CalloutsConfig::load_from_env().await?;
    let callout_service = callout::CalloutService::build(callouts_config).await?;
    let mut state =
        state::AppState::new(pool, cfg.clone(), active_keys, cache).with_callouts(callout_service);
    if cfg.events.enabled() {
        let publisher = events::publisher::AmqpPublisher::connect(&cfg.events)
            .await
            .with_context(|| {
                "failed to connect to the configured AMQP broker for event publishing"
            })?;
        state = state.with_event_publisher(std::sync::Arc::new(publisher));
        tracing::info!(
            "event publishing enabled (AMQP exchange {:?}, routing key {})",
            cfg.events.amqp_exchange,
            cfg.events.amqp_routing_key
        );
    } else {
        tracing::info!("event publishing disabled (ATOM_EVENTS_AMQP_URL not set)");
    }
    Ok(state)
}

/// Runs all enabled Atom surfaces and drains their database work on shutdown.
/// A drain timeout is an error, never a successful graceful shutdown.
pub async fn run(
    cfg: config::Config,
    shutdown: CancellationToken,
    drain_timeout: Duration,
) -> anyhow::Result<()> {
    if drain_timeout.is_zero() {
        anyhow::bail!("Atom drain timeout must be positive");
    }
    let state = initialize(cfg).await?;
    serve(state, shutdown, drain_timeout).await
}

pub async fn serve(
    state: AppState,
    shutdown: CancellationToken,
    drain_timeout: Duration,
) -> anyhow::Result<()> {
    serve_inner(state, shutdown, drain_timeout, None).await
}

async fn serve_inner(
    state: AppState,
    shutdown: CancellationToken,
    drain_timeout: Duration,
    ready: Option<CancellationToken>,
) -> anyhow::Result<()> {
    if drain_timeout.is_zero() {
        anyhow::bail!("Atom drain timeout must be positive");
    }
    let cfg = state.config.clone();
    let grpc_addr = cfg.grpc_addr.parse()?;
    let grpc_listener = grpc::bind_listener(grpc_addr).await?;
    let grpc_bound_addr = grpc_listener.local_addr()?;
    let grpc_tls = grpc::load_tls_config(&cfg).await?;
    let enrollment = certs::enrollment::tls::prepare(&state).await?;
    let http_listener = tokio::net::TcpListener::bind(&cfg.listen_addr).await?;
    state
        .set_grpc_status(GrpcRuntimeStatus::starting(grpc_bound_addr.to_string()))
        .await;

    let api_stop = shutdown.child_token();
    let jobs_stop = CancellationToken::new();
    let mut workers = JoinSet::new();
    for (name, handle) in [
        (
            "audit",
            audit::spawn_retention_cleanup_with_shutdown(state.clone(), jobs_stop.clone()),
        ),
        (
            "purge",
            purge::spawn_purge_cleanup_with_shutdown(state.clone(), jobs_stop.clone()),
        ),
        (
            "refresh_tokens",
            purge::spawn_refresh_token_cleanup_with_shutdown(state.clone(), jobs_stop.clone()),
        ),
        (
            "events",
            events::spawn_event_publisher_with_shutdown(state.clone(), jobs_stop.clone()),
        ),
        (
            "pki",
            certs::lifecycle::spawn_with_shutdown(state.clone(), jobs_stop.clone()),
        ),
    ] {
        if let Some(handle) = handle {
            workers.spawn(async move { (name, handle.await) });
        }
    }

    let mut servers = JoinSet::new();
    let grpc_state = state.clone();
    let grpc_stop = api_stop.clone();
    servers.spawn(async move {
        (
            "grpc",
            grpc::serve_with_shutdown(
                grpc_listener,
                grpc_state,
                grpc_tls,
                grpc_stop.cancelled_owned(),
            )
            .await,
        )
    });
    if let Some(prepared) = enrollment {
        let enrollment_state = state.clone();
        let enrollment_stop = api_stop.clone();
        servers.spawn(async move {
            (
                "enrollment",
                certs::enrollment::tls::serve_with_shutdown(
                    prepared,
                    enrollment_state,
                    enrollment_stop.cancelled_owned(),
                )
                .await,
            )
        });
    }
    let app = routes::create_router(state.clone());
    let http_stop = api_stop.clone();
    servers.spawn(async move {
        (
            "http",
            http_server::serve_with_shutdown(
                http_listener,
                app,
                cfg.http_server,
                cfg.rate_limits.ipv6_prefix_len,
                http_stop.cancelled_owned(),
            )
            .await,
        )
    });

    if !shutdown.is_cancelled() {
        if let Some(ready) = ready {
            ready.cancel();
        }
    }

    let mut outcome = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(()),
        stopped = servers.join_next() => match stopped {
            Some(Ok((name, Ok(())))) => Err(anyhow::anyhow!("Atom {name} server stopped unexpectedly")),
            Some(Ok((name, Err(error)))) => Err(error.context(format!("Atom {name} server failed"))),
            Some(Err(error)) => Err(anyhow::anyhow!("Atom server task failed: {error}")),
            None => Err(anyhow::anyhow!("Atom has no serving tasks")),
        },
        stopped = workers.join_next(), if !workers.is_empty() => match stopped {
            Some(Ok((name, Ok(())))) => Err(anyhow::anyhow!("Atom {name} worker stopped unexpectedly")),
            Some(Ok((name, Err(error)))) => Err(anyhow::anyhow!("Atom {name} worker failed: {error}")),
            Some(Err(error)) => Err(anyhow::anyhow!("Atom worker supervisor failed: {error}")),
            None => Err(anyhow::anyhow!("Atom worker supervision ended unexpectedly")),
        },
    };
    api_stop.cancel();
    jobs_stop.cancel();

    let drain = async {
        while let Some(stopped) = servers.join_next().await {
            match stopped {
                Ok((_, Ok(()))) => {}
                Ok((name, Err(error))) => {
                    outcome = Err(error.context(format!("Atom {name} server failed during drain")));
                }
                Err(error) => {
                    outcome = Err(anyhow::anyhow!(
                        "Atom server task failed during drain: {error}"
                    ));
                }
            }
        }
        // API producers have stopped. Closing the tracker now cannot race a
        // new request-side callout audit spawn. Workers finish their active pass.
        state.background_tasks.close();
        state.background_tasks.wait().await;
        while let Some(stopped) = workers.join_next().await {
            match stopped {
                Ok((_, Ok(()))) => {}
                Ok((name, Err(error))) => {
                    outcome = Err(anyhow::anyhow!(
                        "Atom {name} worker failed during drain: {error}"
                    ));
                }
                Err(error) => {
                    outcome = Err(anyhow::anyhow!(
                        "Atom worker supervisor failed during drain: {error}"
                    ));
                }
            }
        }
        certs::authority::key_provider::wait_for_idle().await;
        state.pool.close().await;
    };
    if tokio::time::timeout(drain_timeout, drain).await.is_err() {
        // Never wait past the deadline. The executable also bounds Tokio
        // shutdown because a native HSM call cannot be forcibly cancelled.
        servers.abort_all();
        anyhow::bail!(
            "Atom drain deadline exceeded; background database or native HSM work may remain"
        );
    }
    outcome
}

/// Builds the Redis-backed cache in prepare or enabled mode.
///
/// `None` means "caching is not configured", and every mutation guard becomes
/// a pure pass-through on that basis. So a configured cache that merely can't
/// reach Redis right now must never degrade to `None`: this process would go
/// on mutating grants, sessions, and credentials without invalidating entries
/// that other replicas are still serving, and a revoke here would stay
/// authorized there. Unreachable Redis is a runtime condition, not a
/// configuration one — the client is retained either way, and its own
/// behavior covers the outage: reads fall through to Postgres as misses,
/// while `begin` fails and so refuses security-sensitive mutations until
/// Redis returns (see `src/cache/mod.rs` and `src/cache/invalidate.rs`).
///
/// A *build* failure is fatal regardless: an unparseable URL cannot recover.
/// `ATOM_CACHE_FAIL_FAST_ON_STARTUP` then decides whether an unreachable
/// Redis should also abort startup, rather than boot into the refusing state.
async fn init_cache(cfg: &config::CacheConfig) -> anyhow::Result<Option<cache::CacheClient>> {
    if !cfg.mode.configured() {
        return Ok(None);
    }
    let client = cache::CacheClient::build(cfg).context("cache configuration is invalid")?;
    match client.probe(cfg.connect_timeout_ms).await {
        Ok(()) => tracing::info!(
            mode = ?cfg.mode,
            namespace = %cfg.namespace,
            "cache configured; connected to Redis"
        ),
        Err(err) if cfg.fail_fast_on_startup => {
            return Err(
                err.context("cache connect failed and ATOM_CACHE_FAIL_FAST_ON_STARTUP=true")
            );
        }
        Err(err) => tracing::error!(
            "cache configured but not ready: {err}. Reads fall through to Postgres; \
             security-sensitive mutations are refused until the cache is safely initialized or \
             the process is restarted, as the reported condition requires."
        ),
    }
    Ok(Some(client))
}

async fn bootstrap_pki_root(pool: &sqlx::PgPool, path: &str) -> anyhow::Result<()> {
    let pem = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read ATOM_PKI_ROOT_CERT_PATH ({path})"))?;
    let mut tx = pool
        .begin()
        .await
        .context("failed to open PKI root bootstrap transaction")?;
    let outcome = certs::authority::provisioning::import_root_mutation_in_tx(&mut tx, &pem)
        .await
        .with_context(|| format!("importing PKI root from {path}"))?;
    tx.commit()
        .await
        .context("failed to commit PKI root bootstrap")?;
    let authority = &outcome.value;
    if outcome.changed {
        tracing::info!(
            path = %path,
            authority_id = %authority.id,
            subject = %authority.subject,
            fingerprint = authority.fingerprint_sha256.as_deref().unwrap_or(""),
            "PKI root certificate imported at bootstrap"
        );
    } else {
        tracing::info!(
            path = %path,
            authority_id = %authority.id,
            "PKI root certificate already present; bootstrap is a no-op"
        );
    }
    Ok(())
}

async fn bootstrap_platform_intermediate(
    pool: &sqlx::PgPool,
    ca_keys: &config::PkiCaKeyConfig,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<()> {
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .with_context(|| {
            format!("failed to read ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH ({cert_path})")
        })?;
    let key_pem = tokio::fs::read_to_string(key_path).await.with_context(|| {
        format!("failed to read ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH ({key_path})")
    })?;
    let mut tx = pool
        .begin()
        .await
        .context("failed to open PKI platform intermediate bootstrap transaction")?;
    let mut outcome = certs::authority::provisioning::import_platform_intermediate_mutation_in_tx(
        &mut tx, ca_keys, &cert_pem, &key_pem,
    )
    .await
    .with_context(|| format!("importing platform intermediate from {cert_path}"))?;
    tx.commit()
        .await
        .context("failed to commit PKI platform intermediate bootstrap")?;
    let authority = outcome.value.clone();
    if outcome.changed {
        tracing::info!(
            cert_path = %cert_path,
            authority_id = %authority.id,
            subject = %authority.subject,
            fingerprint = authority.fingerprint_sha256.as_deref().unwrap_or(""),
            "PKI platform intermediate imported at bootstrap"
        );
    } else {
        tracing::info!(
            cert_path = %cert_path,
            authority_id = %authority.id,
            "PKI platform intermediate already present; bootstrap is a no-op"
        );
    }
    outcome.commit_generated_key();
    Ok(())
}

async fn bootstrap_admin_credentials(
    pool: &sqlx::PgPool,
    admin_entity_id: Uuid,
    secret: &str,
) -> anyhow::Result<()> {
    bootstrap_password_credentials(pool, admin_entity_id, secret, "admin").await
}

async fn bootstrap_password_credentials(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    secret: &str,
    label: &str,
) -> anyhow::Result<()> {
    identity::service::validate_password_strength(secret).map_err(|e| anyhow::anyhow!("{e}"))?;
    let hash =
        identity::service::hash_secret(secret.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut tx = pool
        .begin()
        .await
        .with_context(|| format!("failed to begin {label} password bootstrap transaction"))?;
    if identity::repo::lock_active_entity(&mut tx, entity_id)
        .await
        .map_err(|e| anyhow::anyhow!("{label} password bootstrap: {e}"))?
        .is_none()
    {
        anyhow::bail!("active {label} entity {entity_id} not found");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active'",
    )
    .bind(entity_id)
    .fetch_one(&mut *tx)
    .await?;

    let mut created = false;
    if count == 0 {
        sqlx::query(
            "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(entity_id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
        created = true;
    }
    tx.commit()
        .await
        .with_context(|| format!("failed to commit {label} password bootstrap"))?;
    if created {
        tracing::info!("{label} password bootstrapped");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(cfg: config::Config) -> AppState {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        AppState::new(
            pool,
            cfg,
            keys::ActiveKeys {
                primary: keys::LoadedKey {
                    kid: "runtime-test".into(),
                    public_key_pem: String::new(),
                    private_key_pem: String::new(),
                    x_b64: String::new(),
                    y_b64: String::new(),
                },
                standby: None,
            },
            None,
        )
    }

    #[tokio::test]
    async fn shutdown_waits_for_tracked_work_before_closing_the_pool() {
        let mut cfg = config::Config::for_tests();
        cfg.listen_addr = "127.0.0.1:0".into();
        cfg.grpc_addr = "127.0.0.1:0".into();
        let state = test_state(cfg);
        let pool = state.pool.clone();
        let (release, released) = tokio::sync::oneshot::channel();
        state.background_tasks.spawn(async move {
            released.await.unwrap();
        });
        let stop = CancellationToken::new();
        let ready = CancellationToken::new();
        let serving = serve_inner(
            state,
            stop.clone(),
            Duration::from_secs(3),
            Some(ready.clone()),
        );
        tokio::pin!(serving);
        tokio::select! {
            result = &mut serving => panic!("exited before startup: {result:?}"),
            _ = tokio::time::timeout(Duration::from_secs(2), ready.cancelled()) => {
                assert!(ready.is_cancelled());
            }
        }
        stop.cancel();
        tokio::select! {
            biased;
            result = &mut serving => panic!("did not wait for tracked work: {result:?}"),
            _ = std::future::ready(()) => {}
        }
        assert!(!pool.is_closed());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(4), serving)
            .await
            .unwrap()
            .unwrap();
        assert!(pool.is_closed());
    }

    #[tokio::test]
    async fn unexpected_worker_failure_stops_the_runtime() {
        let mut cfg = config::Config::for_tests();
        cfg.listen_addr = "127.0.0.1:0".into();
        cfg.grpc_addr = "127.0.0.1:0".into();
        // Production config rejects zero. Inject it here to crash the worker.
        cfg.audit_retention.cleanup_interval_secs = 0;
        let state = test_state(cfg);
        let pool = state.pool.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            serve(state, CancellationToken::new(), Duration::from_secs(2)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(result.to_string().contains("audit worker failed"));
        assert!(pool.is_closed());
    }

    #[tokio::test]
    async fn occupied_listener_never_signals_runtime_readiness() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = config::Config::for_tests();
        cfg.listen_addr = occupied.local_addr().unwrap().to_string();
        cfg.grpc_addr = "127.0.0.1:0".into();
        let state = test_state(cfg);
        let ready = CancellationToken::new();
        let result = serve_inner(
            state,
            CancellationToken::new(),
            Duration::from_secs(2),
            Some(ready.clone()),
        )
        .await;
        assert!(result.is_err());
        assert!(!ready.is_cancelled());
    }
}
