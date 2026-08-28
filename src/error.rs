use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("forbidden")]
    Forbidden,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    #[error("{message}")]
    RateLimited {
        message: String,
        retry_after_secs: u64,
    },
    #[error("{0}")]
    ServiceUnavailable(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

#[allow(dead_code)]
impl AppError {
    /// Audit outcome for a failed operation. Authorization failures are `Deny`;
    /// everything else (validation, conflict, DB, internal) is a system `Error`.
    pub fn audit_outcome(&self) -> crate::models::enums::AuditOutcome {
        use crate::models::enums::AuditOutcome;
        match self {
            AppError::Unauthorized(_) | AppError::Forbidden => AuditOutcome::Deny,
            _ => AuditOutcome::Error,
        }
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        AppError::NotFound(what.into())
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        AppError::Unauthorized(msg.into())
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        AppError::Conflict(msg.into())
    }
    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        AppError::PayloadTooLarge(msg.into())
    }
    pub fn rate_limited(msg: impl Into<String>, retry_after_secs: u64) -> Self {
        AppError::RateLimited {
            message: msg.into(),
            retry_after_secs,
        }
    }
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        AppError::ServiceUnavailable(msg.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::PayloadTooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m.clone()),
            AppError::RateLimited {
                message,
                retry_after_secs,
            } => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({"error": message})),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
            AppError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m.clone()),
            AppError::Database(e) => {
                match database_constraint_violation(e) {
                    Some(DatabaseConstraintViolation::Unique) => {
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({"error": "already exists"})),
                        )
                            .into_response();
                    }
                    Some(DatabaseConstraintViolation::ForeignKey) => {
                        tracing::warn!("foreign-key violation: {e}");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "invalid reference"})),
                        )
                            .into_response();
                    }
                    Some(DatabaseConstraintViolation::Check) => {
                        tracing::warn!("check violation: {e}");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "invalid value"})),
                        )
                            .into_response();
                    }
                    None => {}
                }
                tracing::error!("db error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database error".to_string(),
                )
            }
            AppError::Internal(e) => {
                tracing::error!("internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(json!({"error": message}))).into_response()
    }
}

impl From<AppError> for tonic::Status {
    fn from(err: AppError) -> Self {
        match err {
            AppError::NotFound(msg) => tonic::Status::not_found(msg),
            AppError::BadRequest(msg) => tonic::Status::invalid_argument(msg),
            AppError::Unauthorized(msg) => tonic::Status::unauthenticated(msg),
            AppError::Forbidden => tonic::Status::permission_denied("forbidden"),
            AppError::Conflict(msg) => tonic::Status::already_exists(msg),
            AppError::PayloadTooLarge(msg) => tonic::Status::invalid_argument(msg),
            AppError::RateLimited { message, .. } => tonic::Status::resource_exhausted(message),
            AppError::ServiceUnavailable(msg) => tonic::Status::unavailable(msg),
            AppError::Database(e) => {
                match database_constraint_violation(&e) {
                    Some(DatabaseConstraintViolation::Unique) => {
                        return tonic::Status::already_exists("already exists");
                    }
                    Some(DatabaseConstraintViolation::ForeignKey) => {
                        tracing::warn!("foreign-key violation: {e}");
                        return tonic::Status::invalid_argument("invalid reference");
                    }
                    Some(DatabaseConstraintViolation::Check) => {
                        tracing::warn!("check violation: {e}");
                        return tonic::Status::invalid_argument("invalid value");
                    }
                    None => {}
                }
                tracing::error!("db error: {e}");
                tonic::Status::internal("database error")
            }
            AppError::Internal(e) => {
                tracing::error!("internal error: {e}");
                tonic::Status::internal("internal error")
            }
        }
    }
}

pub fn db_err(e: sqlx::Error) -> AppError {
    match e {
        sqlx::Error::RowNotFound => AppError::NotFound("not found".to_string()),
        other => AppError::Database(other),
    }
}

/// The partial unique index backing entity `external_id` uniqueness
/// (`migrations/010_entity_external_id.sql`). Postgres reports the index name as
/// the violated constraint, which is what lets a 23505 be attributed to
/// `external_id` rather than to `name` or `alias`.
const ENTITY_EXTERNAL_ID_INDEX: &str = "idx_entities_external_id";
const ENTITY_EMAIL_INDEX: &str = "idx_entity_emails_email";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseConstraintViolation {
    Unique,
    ForeignKey,
    Check,
}

fn database_constraint_violation(e: &sqlx::Error) -> Option<DatabaseConstraintViolation> {
    let sqlx::Error::Database(db) = e else {
        return None;
    };
    database_constraint_violation_code(db.code().as_deref())
}

fn database_constraint_violation_code(code: Option<&str>) -> Option<DatabaseConstraintViolation> {
    match code {
        Some("23505") => Some(DatabaseConstraintViolation::Unique),
        Some("23503") => Some(DatabaseConstraintViolation::ForeignKey),
        Some("23514") => Some(DatabaseConstraintViolation::Check),
        _ => None,
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    database_constraint_violation(e) == Some(DatabaseConstraintViolation::Unique)
}

/// The constraint a unique-violation (23505) names, if this error is one.
fn unique_violation_constraint(e: &sqlx::Error) -> Option<&str> {
    match e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => db.constraint(),
        _ => None,
    }
}

/// Maps a unique-violation (23505) raised while clearing a tombstone back into a
/// caller-facing conflict: a soft-deleted name/alias/email/external_id was
/// re-taken by a live row while the record sat in the retention window, so it can
/// no longer be restored under its old identifier. Other errors pass through
/// `db_err`.
pub fn restore_conflict(e: sqlx::Error) -> AppError {
    // The `external_id` index deliberately excludes soft-deleted rows, so
    // deleting an entity frees its identifier for a replacement device. That is
    // the wanted behaviour, but it means a restore can lose the race — name the
    // field so the operator knows which one to free.
    if unique_violation_constraint(&e) == Some(ENTITY_EXTERNAL_ID_INDEX) {
        return AppError::conflict(
            "another live entity in this tenant took this entity's externalId while it was \
             deleted; clear or change that entity's externalId before restoring",
        );
    }
    if unique_violation_constraint(&e) == Some(ENTITY_EMAIL_INDEX) {
        return AppError::conflict(
            "another live entity took this entity's email while it was deleted; clear or change \
             that entity's email before restoring",
        );
    }
    if is_unique_violation(&e) {
        return AppError::conflict(
            "a live record already uses this name; rename the conflicting record before restoring",
        );
    }
    db_err(e)
}

/// Maps the entity `external_id` unique-violation (23505 on
/// `idx_entities_external_id`) into an actionable conflict naming the field.
/// Without this the generic 23505 handling reports a bare "already exists",
/// which a caller writing several unique fields at once cannot act on. Every
/// other error — including a 23505 on `name` or `alias` — passes through
/// `db_err` unchanged.
pub fn entity_write_conflict(e: sqlx::Error) -> AppError {
    if unique_violation_constraint(&e) == Some(ENTITY_EXTERNAL_ID_INDEX) {
        return AppError::conflict("externalId is already used by another entity in this tenant");
    }
    if unique_violation_constraint(&e) == Some(ENTITY_EMAIL_INDEX) {
        return AppError::conflict("Email address already taken");
    }
    db_err(e)
}

#[cfg(test)]
mod tests {
    use super::{database_constraint_violation_code, DatabaseConstraintViolation};

    #[test]
    fn frozen_database_constraint_codes_are_classified_once_for_http_and_grpc() {
        assert_eq!(
            database_constraint_violation_code(Some("23505")),
            Some(DatabaseConstraintViolation::Unique)
        );
        assert_eq!(
            database_constraint_violation_code(Some("23503")),
            Some(DatabaseConstraintViolation::ForeignKey)
        );
        assert_eq!(
            database_constraint_violation_code(Some("23514")),
            Some(DatabaseConstraintViolation::Check)
        );
        assert_eq!(database_constraint_violation_code(Some("40001")), None);
        assert_eq!(database_constraint_violation_code(None), None);
    }
}
