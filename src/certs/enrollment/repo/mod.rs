//! Enrollment rate-limit domain contract and policy result.
mod postgres;
mod sqlite;

use chrono::Utc;
use uuid::Uuid;

use crate::{config::RateLimitPolicyConfig, db::DbTransaction, error::AppError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    Entity,
    Tenant,
}

impl RateLimitScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Tenant => "tenant",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub retry_after_secs: u64,
}

/// Atomically consumes one fixed-window allowance. The conditional upsert is
/// the serialization point, so concurrent replicas cannot exceed the limit.
pub async fn consume_rate_limit(
    tx: &mut DbTransaction<'_>,
    scope: RateLimitScope,
    scope_id: Uuid,
    policy: RateLimitPolicyConfig,
) -> Result<RateLimitDecision, AppError> {
    let window_secs = i64::try_from(policy.window_secs)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("rate-limit window is too large")))?;
    let max_requests = i64::from(policy.max_requests);
    let count = match tx {
        DbTransaction::Postgres(conn) => {
            postgres::consume_window(conn, scope, scope_id, window_secs, max_requests).await?
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::consume_window(conn, scope, scope_id, window_secs, max_requests).await?
        }
    };

    let elapsed = Utc::now().timestamp().rem_euclid(window_secs);
    let retry_after_secs = u64::try_from(window_secs - elapsed).unwrap_or(1).max(1);
    Ok(RateLimitDecision {
        allowed: count.is_some(),
        retry_after_secs,
    })
}
