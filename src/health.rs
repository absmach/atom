use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{
    build_info,
    certs::authority::{
        key_provider::AuthorityKeyProviderError, repo as authority_repo, AuthorityKeyBackend,
    },
    config::PkiCaKeyConfig,
    keys, rate_limit,
    state::{AppState, GrpcRuntimeState},
};

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
    // Build identity is deliberately kept out of the serialized form. The HTTP
    // readiness endpoints are unauthenticated, and the exact commit pins a
    // running instance to a line of public source. GraphQL `systemStatus`
    // reads these fields directly and is gated on platform `manage`, so
    // operators still see them.
    #[serde(skip)]
    pub version: &'static str,
    #[serde(skip)]
    pub revision: &'static str,
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
    let grpc_ready = grpc_check(state).await;
    let certificate_issuer = certificate_issuer_check(state).await;
    let ready = readiness_ok(
        &database,
        &migrations,
        &signing_keys,
        &grpc_ready,
        &certificate_issuer,
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
    let response = SystemStatus {
        version: build_info::VERSION,
        revision: build_info::REVISION,
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

fn readiness_ok(
    database: &ComponentCheck,
    migrations: &ComponentCheck,
    signing_keys: &ComponentCheck,
    grpc_ready: &ComponentCheck,
    certificate_issuer: &ComponentCheck,
) -> bool {
    matches!(&database.status, ComponentStatus::Ok)
        && matches!(&migrations.status, ComponentStatus::Ok)
        && matches!(&signing_keys.status, ComponentStatus::Ok)
        && matches!(&grpc_ready.status, ComponentStatus::Ok)
        && matches!(
            &certificate_issuer.status,
            ComponentStatus::Ok | ComponentStatus::Disabled
        )
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

/// Reports whether the providers selected by live leaf issuers are configured
/// and were validated at startup. This endpoint is unauthenticated and called
/// repeatedly by load balancers, so it must never open a PKCS#11 session or
/// affect the HSM provider's circuit breaker.
async fn certificate_issuer_check(state: &AppState) -> ComponentCheck {
    match authority_repo::leaf_issuer_authority_count(&state.pool).await {
        Ok(0) => ComponentCheck {
            status: ComponentStatus::Disabled,
            message: "no certificate issuers configured".to_string(),
        },
        Ok(_) => match authority_repo::active_leaf_issuer_backends(&state.pool).await {
            Ok(backends) if backends.is_empty() => ComponentCheck {
                status: ComponentStatus::Error,
                message:
                    "certificate issuers are configured but none are active and eligible to issue"
                        .to_string(),
            },
            Ok(backends) => certificate_issuer_config_check(
                &state.config.pki_ca_keys,
                &backends,
                state
                    .config
                    .pki_ca_keys
                    .pkcs11
                    .as_ref()
                    .is_some_and(crate::certs::authority::key_provider::pkcs11_circuit_is_open),
            ),
            Err(error) => ComponentCheck {
                status: ComponentStatus::Error,
                message: format!("certificate issuer status query failed: {error}"),
            },
        },
        Err(error) => ComponentCheck {
            status: ComponentStatus::Error,
            message: format!("certificate issuer status query failed: {error}"),
        },
    }
}

fn certificate_issuer_config_check(
    ca_keys: &PkiCaKeyConfig,
    backends: &[AuthorityKeyBackend],
    pkcs11_circuit_open: bool,
) -> ComponentCheck {
    if backends.is_empty() {
        return ComponentCheck {
            status: ComponentStatus::Disabled,
            message: "no active certificate issuers".to_string(),
        };
    }

    let uses_encrypted_database = backends.contains(&AuthorityKeyBackend::EncryptedDatabase);
    let uses_pkcs11 = backends.contains(&AuthorityKeyBackend::Pkcs11);
    let uses_kms = backends.contains(&AuthorityKeyBackend::Kms);
    let uses_public_only = backends.contains(&AuthorityKeyBackend::PublicOnly);

    if uses_kms {
        return ComponentCheck {
            status: ComponentStatus::Error,
            message: "an active certificate issuer requires an unavailable KMS provider"
                .to_string(),
        };
    }
    if uses_public_only {
        return ComponentCheck {
            status: ComponentStatus::Error,
            message: "an active certificate issuer has no signing key".to_string(),
        };
    }
    if uses_encrypted_database && ca_keys.key_encryption_key.is_none() {
        return ComponentCheck {
            status: ComponentStatus::Error,
            message: "an active certificate issuer requires the encrypted database CA key"
                .to_string(),
        };
    }
    if uses_pkcs11 && ca_keys.pkcs11.is_none() {
        return ComponentCheck {
            status: ComponentStatus::Error,
            message: format!(
                "active PKCS#11 certificate issuer provider configuration failed: {}",
                AuthorityKeyProviderError::Unconfigured
            ),
        };
    }
    if uses_pkcs11 && pkcs11_circuit_open {
        return ComponentCheck {
            status: ComponentStatus::Error,
            message: "an active PKCS#11 certificate issuer circuit is open".to_string(),
        };
    }

    let providers = [
        uses_encrypted_database.then_some("encrypted database"),
        uses_pkcs11.then_some("PKCS#11"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" and ");
    ComponentCheck {
        status: ComponentStatus::Ok,
        message: format!("{providers} certificate issuer configured and verified at startup"),
    }
}

async fn grpc_check(state: &AppState) -> ComponentCheck {
    let status = state.grpc_status().await;
    match status.state {
        GrpcRuntimeState::Starting => ComponentCheck {
            status: ComponentStatus::Degraded,
            message: status.message,
        },
        GrpcRuntimeState::Serving => ComponentCheck {
            status: ComponentStatus::Ok,
            message: status.message,
        },
        GrpcRuntimeState::Error => ComponentCheck {
            status: ComponentStatus::Error,
            message: status.message,
        },
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

#[cfg(test)]
mod tests {
    use super::{
        certificate_issuer_config_check, readiness_ok, AuditRetentionStatus, ComponentCheck,
        ComponentStatus, DbPoolStatus, SystemStatus,
    };
    use crate::{
        certs::authority::AuthorityKeyBackend,
        config::{Config, PkiPkcs11Config, SecretText},
        rate_limit::RateLimitStatus,
    };

    fn check(status: ComponentStatus) -> ComponentCheck {
        ComponentCheck {
            status,
            message: String::new(),
        }
    }

    #[test]
    fn serialized_status_omits_build_identity() {
        let status = SystemStatus {
            version: "v9.9.9",
            revision: "0badc0ffee",
            status: ComponentStatus::Ok,
            http_ready: check(ComponentStatus::Ok),
            grpc_ready: check(ComponentStatus::Ok),
            database: check(ComponentStatus::Ok),
            migrations: check(ComponentStatus::Ok),
            signing_keys: check(ComponentStatus::Ok),
            certificate_issuer: check(ComponentStatus::Ok),
            db_pool: DbPoolStatus {
                max_connections: 0,
                min_connections: 0,
                acquire_timeout_secs: 0,
                connect_timeout_secs: 0,
                idle_timeout_secs: 0,
                max_lifetime_secs: 0,
                size: 0,
                idle: 0,
            },
            signing_key_state: None,
            audit_retention: AuditRetentionStatus {
                enabled: false,
                days: 0,
                cleanup_interval_secs: 0,
                cleanup_batch_size: 0,
                last_cleanup: None,
            },
            rate_limits: RateLimitStatus {
                enabled: false,
                policies: Vec::new(),
                trusted_proxy_cidrs: Vec::new(),
            },
        };

        let body = serde_json::to_value(&status).expect("system status serializes");

        // `/health/ready` and `/health` are unauthenticated. Build identity
        // stays on the `manage`-gated GraphQL `systemStatus` field only.
        assert!(body.get("version").is_none());
        assert!(body.get("revision").is_none());
        assert!(!body.to_string().contains("0badc0ffee"));
        assert!(body.get("status").is_some());
    }

    #[test]
    fn readiness_requires_serving_grpc() {
        let database = check(ComponentStatus::Ok);
        let migrations = check(ComponentStatus::Ok);
        let signing_keys = check(ComponentStatus::Ok);
        let ca = check(ComponentStatus::Ok);

        assert!(!readiness_ok(
            &database,
            &migrations,
            &signing_keys,
            &check(ComponentStatus::Degraded),
            &ca,
        ));
        assert!(!readiness_ok(
            &database,
            &migrations,
            &signing_keys,
            &check(ComponentStatus::Error),
            &ca,
        ));
        assert!(readiness_ok(
            &database,
            &migrations,
            &signing_keys,
            &check(ComponentStatus::Ok),
            &ca,
        ));
    }

    #[test]
    fn readiness_blocks_when_certificate_issuer_is_unavailable() {
        let ok = check(ComponentStatus::Ok);
        assert!(!readiness_ok(
            &ok,
            &ok,
            &ok,
            &ok,
            &check(ComponentStatus::Error),
        ));
        // A deployment without PKI configured stays ready — the check
        // reports Disabled and does not block.
        assert!(readiness_ok(
            &ok,
            &ok,
            &ok,
            &ok,
            &check(ComponentStatus::Disabled),
        ));
    }

    #[test]
    fn readiness_uses_active_issuer_backends_without_probing_the_hsm() {
        let mut config = Config::for_tests();
        config.pki_ca_keys.pkcs11 = Some(PkiPkcs11Config {
            module_path: "/nonexistent/pkcs11-module.so".to_string(),
            token_label: "missing-token".to_string(),
            user_pin: SecretText::new("test-pin".to_string()).expect("PIN"),
            operation_timeout_ms: 1,
            mutation_hard_timeout_ms: 1,
            max_retries: 0,
            max_in_flight: 1,
            circuit_failure_threshold: 1,
            circuit_reset_secs: 1,
        });

        let status = certificate_issuer_config_check(
            &config.pki_ca_keys,
            &[AuthorityKeyBackend::Pkcs11],
            false,
        );
        assert!(matches!(status.status, ComponentStatus::Ok));
        assert!(status.message.contains("verified at startup"));
    }

    #[test]
    fn readiness_rejects_an_active_issuer_without_its_provider_configuration() {
        let config = Config::for_tests();
        let status = certificate_issuer_config_check(
            &config.pki_ca_keys,
            &[AuthorityKeyBackend::Pkcs11],
            false,
        );
        let ok = check(ComponentStatus::Ok);

        assert!(matches!(status.status, ComponentStatus::Error));
        assert!(status.message.contains("CA key provider is not configured"));
        assert!(!readiness_ok(&ok, &ok, &ok, &ok, &status));
    }

    #[test]
    fn readiness_rejects_an_active_issuer_with_an_open_pkcs11_circuit() {
        let mut config = Config::for_tests();
        config.pki_ca_keys.pkcs11 = Some(PkiPkcs11Config {
            module_path: "/nonexistent/pkcs11-module.so".to_string(),
            token_label: "missing-token".to_string(),
            user_pin: SecretText::new("test-pin".to_string()).expect("PIN"),
            operation_timeout_ms: 1,
            mutation_hard_timeout_ms: 1,
            max_retries: 0,
            max_in_flight: 1,
            circuit_failure_threshold: 1,
            circuit_reset_secs: 1,
        });

        let status = certificate_issuer_config_check(
            &config.pki_ca_keys,
            &[AuthorityKeyBackend::Pkcs11],
            true,
        );
        assert!(matches!(status.status, ComponentStatus::Error));
        assert!(status.message.contains("circuit is open"));
    }
}
