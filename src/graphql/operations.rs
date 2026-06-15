use async_graphql::{Context, Enum, Object, Result, SimpleObject};

use crate::{
    audit,
    auth::{require_capability, Scope},
    health,
    keys::{self, SigningKeyStorageMode},
    models::enums::AuditOutcome,
    state::AppState,
};

use super::auth::{gql_error, require_auth};

#[derive(Default)]
pub struct OperationsQuery;

#[derive(Default)]
pub struct OperationsMutation;

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "ComponentStatus", rename_items = "snake_case")]
pub enum GqlComponentStatus {
    Ok,
    Disabled,
    Degraded,
    Error,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "SigningKeyStorageMode", rename_items = "snake_case")]
pub enum GqlSigningKeyStorageMode {
    Encrypted,
    Plaintext,
}

#[derive(SimpleObject)]
#[graphql(name = "ComponentCheck")]
pub struct GqlComponentCheck {
    pub status: GqlComponentStatus,
    pub message: String,
}

#[derive(SimpleObject)]
#[graphql(name = "DbPoolStatus")]
pub struct GqlDbPoolStatus {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
    pub size: u32,
    pub idle: usize,
}

#[derive(SimpleObject)]
#[graphql(name = "SigningKeyState")]
pub struct GqlSigningKeyState {
    pub configured_key_id: String,
    pub encrypted_count: i64,
    pub plaintext_count: i64,
    pub total_count: i64,
    pub plaintext_allowed: bool,
}

#[derive(SimpleObject)]
#[graphql(name = "AuditRetentionStatus")]
pub struct GqlAuditRetentionStatus {
    pub enabled: bool,
    pub days: i64,
    pub cleanup_interval_secs: u64,
    pub cleanup_batch_size: i64,
    pub last_cleanup: Option<serde_json::Value>,
}

#[derive(SimpleObject)]
#[graphql(name = "RateLimitPolicyStatus")]
pub struct GqlRateLimitPolicyStatus {
    pub category: String,
    pub max_requests: u32,
    pub window_secs: u64,
}

#[derive(SimpleObject)]
#[graphql(name = "RateLimitStatus")]
pub struct GqlRateLimitStatus {
    pub enabled: bool,
    pub policies: Vec<GqlRateLimitPolicyStatus>,
}

#[derive(SimpleObject)]
#[graphql(name = "SystemStatus")]
pub struct GqlSystemStatus {
    pub status: GqlComponentStatus,
    pub http_ready: GqlComponentCheck,
    pub grpc_ready: GqlComponentCheck,
    pub database: GqlComponentCheck,
    pub migrations: GqlComponentCheck,
    pub signing_keys: GqlComponentCheck,
    pub certificate_issuer: GqlComponentCheck,
    pub db_pool: GqlDbPoolStatus,
    pub signing_key_state: Option<GqlSigningKeyState>,
    pub audit_retention: GqlAuditRetentionStatus,
    pub rate_limits: GqlRateLimitStatus,
}

#[derive(SimpleObject)]
#[graphql(name = "SigningKey")]
pub struct GqlSigningKey {
    pub kid: String,
    pub status: String,
    pub algorithm: String,
    pub created_at: String,
    pub storage_mode: GqlSigningKeyStorageMode,
    pub key_encryption_key_id: Option<String>,
}

#[Object]
impl OperationsQuery {
    async fn system_status(&self, ctx: &Context<'_>) -> Result<GqlSystemStatus> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "manage", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let (_, axum::Json(status)) = health::readiness(state).await;
        Ok(status.into())
    }

    async fn signing_keys(&self, ctx: &Context<'_>) -> Result<Vec<GqlSigningKey>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "read", Scope::Platform)
            .await
            .map_err(gql_error)?;
        keys::list_metadata(&state.pool)
            .await
            .map(|keys| keys.into_iter().map(GqlSigningKey::from).collect())
            .map_err(gql_error)
    }
}

#[Object]
impl OperationsMutation {
    async fn rotate_signing_keys(&self, ctx: &Context<'_>) -> Result<bool> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        require_capability(&state.pool, auth.entity_id, "rotate", Scope::Platform)
            .await
            .map_err(gql_error)?;
        let new_keys = keys::rotate(&state.pool, &state.config.signing_keys)
            .await
            .map_err(gql_error)?;
        *state.keys.write().await = new_keys;
        audit::write(
            &state.pool,
            Some(auth.entity_id),
            None,
            "signing_key.rotate",
            AuditOutcome::Allow,
            serde_json::json!({"transport": "graphql"}),
        )
        .await;
        Ok(true)
    }
}

impl From<health::SystemStatus> for GqlSystemStatus {
    fn from(status: health::SystemStatus) -> Self {
        Self {
            status: status.status.into(),
            http_ready: status.http_ready.into(),
            grpc_ready: status.grpc_ready.into(),
            database: status.database.into(),
            migrations: status.migrations.into(),
            signing_keys: status.signing_keys.into(),
            certificate_issuer: status.certificate_issuer.into(),
            db_pool: status.db_pool.into(),
            signing_key_state: status.signing_key_state.map(Into::into),
            audit_retention: status.audit_retention.into(),
            rate_limits: GqlRateLimitStatus {
                enabled: status.rate_limits.enabled,
                policies: status
                    .rate_limits
                    .policies
                    .into_iter()
                    .map(|policy| GqlRateLimitPolicyStatus {
                        category: policy.category.as_str().to_string(),
                        max_requests: policy.max_requests,
                        window_secs: policy.window_secs,
                    })
                    .collect(),
            },
        }
    }
}

impl From<health::ComponentStatus> for GqlComponentStatus {
    fn from(status: health::ComponentStatus) -> Self {
        match status {
            health::ComponentStatus::Ok => Self::Ok,
            health::ComponentStatus::Disabled => Self::Disabled,
            health::ComponentStatus::Degraded => Self::Degraded,
            health::ComponentStatus::Error => Self::Error,
        }
    }
}

impl From<health::ComponentCheck> for GqlComponentCheck {
    fn from(check: health::ComponentCheck) -> Self {
        Self {
            status: check.status.into(),
            message: check.message,
        }
    }
}

impl From<health::DbPoolStatus> for GqlDbPoolStatus {
    fn from(status: health::DbPoolStatus) -> Self {
        Self {
            max_connections: status.max_connections,
            min_connections: status.min_connections,
            acquire_timeout_secs: status.acquire_timeout_secs,
            connect_timeout_secs: status.connect_timeout_secs,
            idle_timeout_secs: status.idle_timeout_secs,
            max_lifetime_secs: status.max_lifetime_secs,
            size: status.size,
            idle: status.idle,
        }
    }
}

impl From<health::SigningKeyStatus> for GqlSigningKeyState {
    fn from(status: health::SigningKeyStatus) -> Self {
        Self {
            configured_key_id: status.configured_key_id,
            encrypted_count: status.encrypted_count,
            plaintext_count: status.plaintext_count,
            total_count: status.total_count,
            plaintext_allowed: status.plaintext_allowed,
        }
    }
}

impl From<health::AuditRetentionStatus> for GqlAuditRetentionStatus {
    fn from(status: health::AuditRetentionStatus) -> Self {
        Self {
            enabled: status.enabled,
            days: status.days,
            cleanup_interval_secs: status.cleanup_interval_secs,
            cleanup_batch_size: status.cleanup_batch_size,
            last_cleanup: status.last_cleanup,
        }
    }
}

impl From<keys::SigningKeyMetadata> for GqlSigningKey {
    fn from(key: keys::SigningKeyMetadata) -> Self {
        Self {
            kid: key.kid,
            status: key.status,
            algorithm: key.algorithm,
            created_at: key.created_at.to_rfc3339(),
            storage_mode: match key.storage_mode {
                SigningKeyStorageMode::Encrypted => GqlSigningKeyStorageMode::Encrypted,
                SigningKeyStorageMode::Plaintext => GqlSigningKeyStorageMode::Plaintext,
            },
            key_encryption_key_id: key.key_encryption_key_id,
        }
    }
}
