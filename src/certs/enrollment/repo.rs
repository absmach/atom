use chrono::Utc;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{config::RateLimitPolicyConfig, error::AppError};

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
    tx: &mut Transaction<'_, Postgres>,
    scope: RateLimitScope,
    scope_id: Uuid,
    policy: RateLimitPolicyConfig,
) -> Result<RateLimitDecision, AppError> {
    let window_secs = i64::try_from(policy.window_secs)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("rate-limit window is too large")))?;
    let max_requests = i64::from(policy.max_requests);
    let count: Option<i64> = sqlx::query_scalar(
        r#"
        INSERT INTO pki_enrollment_rate_windows (
            scope_kind, scope_id, window_start, request_count, updated_at
        )
        VALUES (
            $1,
            $2,
            to_timestamp(floor(extract(epoch FROM now()) / $3) * $3),
            1,
            now()
        )
        ON CONFLICT (scope_kind, scope_id, window_start) DO UPDATE
        SET request_count = pki_enrollment_rate_windows.request_count + 1,
            updated_at = now()
        WHERE pki_enrollment_rate_windows.request_count < $4
        RETURNING request_count
        "#,
    )
    .bind(scope.as_str())
    .bind(scope_id)
    .bind(window_secs)
    .bind(max_requests)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::Database)?;

    // Bound storage per subject without a global cleanup scan on this public
    // hot path. At most the current and immediately preceding window survive.
    sqlx::query(
        r#"
        DELETE FROM pki_enrollment_rate_windows
        WHERE scope_kind = $1
          AND scope_id = $2
          AND window_start < now() - ($3 * interval '2 seconds')
        "#,
    )
    .bind(scope.as_str())
    .bind(scope_id)
    .bind(window_secs)
    .execute(&mut **tx)
    .await
    .map_err(AppError::Database)?;

    let elapsed = Utc::now().timestamp().rem_euclid(window_secs);
    let retry_after_secs = u64::try_from(window_secs - elapsed).unwrap_or(1).max(1);
    Ok(RateLimitDecision {
        allowed: count.is_some(),
        retry_after_secs,
    })
}
