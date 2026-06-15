use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{keys, rate_limit, state::AppState};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Ok,
    Disabled,
    Degraded,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentCheck {
    pub status: ComponentStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DbPoolStatus {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
    pub size: u32,
    pub idle: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRetentionStatus {
    pub enabled: bool,
    pub days: i64,
    pub cleanup_interval_secs: u64,
    pub cleanup_batch_size: i64,
    pub last_cleanup: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigningKeyStatus {
    pub configured_key_id: String,
    pub encrypted_count: i64,
    pub plaintext_count: i64,
    pub total_count: i64,
    pub plaintext_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemStatus {
    pub status: ComponentStatus,
    pub http_ready: ComponentCheck,
    pub grpc_ready: ComponentCheck,
    pub database: ComponentCheck,
    pub migrations: ComponentCheck,
    pub signing_keys: ComponentCheck,
    pub certificate_issuer: ComponentCheck,
    pub db_pool: DbPoolStatus,
    pub signing_key_state: Option<SigningKeyStatus>,
    pub audit_retention: AuditRetentionStatus,
    pub rate_limits: rate_limit::RateLimitStatus,
}

pub async fn live() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

pub async fn ready(State(state): State<AppState>) -> Response {
    readiness(&state).await.into_response()
}

pub async fn legacy_health(State(state): State<AppState>) -> Response {
    readiness(&state).await.into_response()
}

pub async fn readiness(state: &AppState) -> (StatusCode, Json<SystemStatus>) {
    let database = database_check(state).await;
    let migrations = migrations_check(state).await;
    let (signing_keys, signing_key_state) = signing_keys_check(state).await;
    let certificate_issuer = certificate_issuer_check(state);
    let ready = matches!(&database.status, ComponentStatus::Ok)
        && matches!(&migrations.status, ComponentStatus::Ok)
        && matches!(&signing_keys.status, ComponentStatus::Ok)
        && matches!(
            &certificate_issuer.status,
            ComponentStatus::Ok | ComponentStatus::Disabled
        );
    let status = if ready {
        ComponentStatus::Ok
    } else {
        ComponentStatus::Error
    };
    let http_ready = ComponentCheck {
        status: status.clone(),
        message: if ready { "ready" } else { "not ready" }.to_string(),
    };
    let grpc_ready = ComponentCheck {
        status: ComponentStatus::Ok,
        message: format!("serving on {}", state.config.grpc_addr),
    };
    let response = SystemStatus {
        status,
        http_ready,
        grpc_ready,
        database,
        migrations,
        signing_keys,
        certificate_issuer,
        db_pool: db_pool_status(state),
        signing_key_state,
        audit_retention: audit_retention_status(state).await,
        rate_limits: rate_limit::status(&state.config.rate_limits),
    };
    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status_code, Json(response))
}

async fn database_check(state: &AppState) -> ComponentCheck {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => ComponentCheck {
            status: ComponentStatus::Ok,
            message: "database reachable".to_string(),
        },
        Err(err) => ComponentCheck {
            status: ComponentStatus::Error,
            message: format!("database ping failed: {err}"),
        },
    }
}

async fn migrations_check(state: &AppState) -> ComponentCheck {
    match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE")
        .fetch_one(&state.pool)
        .await
    {
        Ok(count) if count > 0 => ComponentCheck {
            status: ComponentStatus::Ok,
            message: format!("{count} migrations applied"),
        },
        Ok(_) => ComponentCheck {
            status: ComponentStatus::Error,
            message: "no successful migrations recorded".to_string(),
        },
        Err(err) => ComponentCheck {
            status: ComponentStatus::Error,
            message: format!("migration check failed: {err}"),
        },
    }
}

async fn signing_keys_check(state: &AppState) -> (ComponentCheck, Option<SigningKeyStatus>) {
    let loaded = state.keys.read().await;
    if loaded.primary.kid.is_empty() {
        return (
            ComponentCheck {
                status: ComponentStatus::Error,
                message: "primary signing key is not loaded".to_string(),
            },
            None,
        );
    }
    drop(loaded);

    match keys::storage_summary(&state.pool).await {
        Ok(summary) => {
            let plaintext_allowed = state.config.signing_keys.allow_plaintext_signing_keys;
            let status = if summary.plaintext > 0 && !plaintext_allowed {
                ComponentStatus::Degraded
            } else {
                ComponentStatus::Ok
            };
            let message = if summary.plaintext > 0 {
                format!("{} plaintext signing keys remain", summary.plaintext)
            } else {
                "signing keys loaded".to_string()
            };
            (
                ComponentCheck { status, message },
                Some(SigningKeyStatus {
                    configured_key_id: state.config.signing_keys.key_encryption_key_id.clone(),
                    encrypted_count: summary.encrypted,
                    plaintext_count: summary.plaintext,
                    total_count: summary.total,
                    plaintext_allowed,
                }),
            )
        }
        Err(err) => (
            ComponentCheck {
                status: ComponentStatus::Error,
                message: format!("signing key status failed: {err}"),
            },
            None,
        ),
    }
}

fn certificate_issuer_check(state: &AppState) -> ComponentCheck {
    if !state.config.certs_enabled {
        return ComponentCheck {
            status: ComponentStatus::Disabled,
            message: "certificate issuer disabled".to_string(),
        };
    }
    if state.certificate_issuer.is_some() {
        ComponentCheck {
            status: ComponentStatus::Ok,
            message: format!(
                "certificate issuer loaded using {}",
                state.config.certs_ca_mode.as_str()
            ),
        }
    } else {
        ComponentCheck {
            status: ComponentStatus::Error,
            message: "certificate issuer is enabled but not loaded".to_string(),
        }
    }
}

fn db_pool_status(state: &AppState) -> DbPoolStatus {
    DbPoolStatus {
        max_connections: state.config.db_pool.max_connections,
        min_connections: state.config.db_pool.min_connections,
        acquire_timeout_secs: state.config.db_pool.acquire_timeout_secs,
        connect_timeout_secs: state.config.db_pool.connect_timeout_secs,
        idle_timeout_secs: state.config.db_pool.idle_timeout_secs,
        max_lifetime_secs: state.config.db_pool.max_lifetime_secs,
        size: state.pool.size(),
        idle: state.pool.num_idle(),
    }
}

async fn audit_retention_status(state: &AppState) -> AuditRetentionStatus {
    let cfg = state.config.audit_retention;
    let last_cleanup = sqlx::query_scalar::<_, serde_json::Value>(
        r#"SELECT details
           FROM audit_logs
           WHERE event = 'audit.retention_cleanup'
           ORDER BY created_at DESC
           LIMIT 1"#,
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    AuditRetentionStatus {
        enabled: cfg.enabled,
        days: cfg.days,
        cleanup_interval_secs: cfg.cleanup_interval_secs,
        cleanup_batch_size: cfg.cleanup_batch_size,
        last_cleanup,
    }
}
