//! Native postgres enrollment rate-window storage.
use super::RateLimitScope;
use crate::error::AppError;
use sqlx::PgConnection as Connection;
use uuid::Uuid;

/// Consume the allowance and prune old windows on the same connection.
pub(super) async fn consume_window(
    tx: &mut Connection,
    scope: RateLimitScope,
    scope_id: Uuid,
    window_secs: i64,
    max_requests: i64,
) -> Result<Option<i64>, AppError> {
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
    .fetch_optional(&mut *tx)
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
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    Ok(count)
}
