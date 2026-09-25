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
                match classify_database_error(e) {
                    DatabaseErrorKind::Unique => {
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({"error": "already exists"})),
                        )
                            .into_response();
                    }
                    DatabaseErrorKind::ForeignKey => {
                        tracing::warn!("foreign-key violation: {e}");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "invalid reference"})),
                        )
                            .into_response();
                    }
                    DatabaseErrorKind::Check => {
                        tracing::warn!("check violation: {e}");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "invalid value"})),
                        )
                            .into_response();
                    }
                    DatabaseErrorKind::NotFound
                    | DatabaseErrorKind::Busy
                    | DatabaseErrorKind::Internal => {}
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
                match classify_database_error(&e) {
                    DatabaseErrorKind::Unique => {
                        return tonic::Status::already_exists("already exists");
                    }
                    DatabaseErrorKind::ForeignKey => {
                        tracing::warn!("foreign-key violation: {e}");
                        return tonic::Status::invalid_argument("invalid reference");
                    }
                    DatabaseErrorKind::Check => {
                        tracing::warn!("check violation: {e}");
                        return tonic::Status::invalid_argument("invalid value");
                    }
                    DatabaseErrorKind::NotFound
                    | DatabaseErrorKind::Busy
                    | DatabaseErrorKind::Internal => {}
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
    match classify_database_error(&e) {
        DatabaseErrorKind::NotFound => AppError::NotFound("not found".to_string()),
        DatabaseErrorKind::Busy => {
            tracing::warn!("database busy: {e}");
            AppError::ServiceUnavailable("database is busy; retry shortly".to_string())
        }
        DatabaseErrorKind::Unique
        | DatabaseErrorKind::ForeignKey
        | DatabaseErrorKind::Check
        | DatabaseErrorKind::Internal => AppError::Database(e),
    }
}

/// Backend-neutral classification of a database failure, computed once ahead
/// of transport mapping. Only the kinds Postgres actually produces today are
/// represented — a busy/unavailable kind belongs to whichever backend phase
/// first needs it (see `product-docs/development/database-backends/`), not
/// here as a currently-unreachable placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseErrorKind {
    NotFound,
    Unique,
    ForeignKey,
    Check,
    /// SQLite could not take its write lock within the busy timeout; the
    /// request fails closed as "service unavailable" instead of hanging.
    Busy,
    Internal,
}

pub fn classify_database_error(e: &sqlx::Error) -> DatabaseErrorKind {
    match e {
        sqlx::Error::RowNotFound => DatabaseErrorKind::NotFound,
        _ => match database_constraint_violation(e) {
            Some(DatabaseConstraintViolation::Unique) => DatabaseErrorKind::Unique,
            Some(DatabaseConstraintViolation::ForeignKey) => DatabaseErrorKind::ForeignKey,
            Some(DatabaseConstraintViolation::Check) => DatabaseErrorKind::Check,
            None if is_busy(e) => DatabaseErrorKind::Busy,
            None => DatabaseErrorKind::Internal,
        },
    }
}

/// The partial unique index backing entity `external_id` uniqueness
/// (`migrations/001_initial.sql`). Postgres reports the index name as
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
    // SQLite reports an `ON DELETE RESTRICT` foreign-key failure with the
    // trigger code (1811) rather than 787; the message tells them apart.
    if db.code().as_deref() == Some("1811") && db.message().starts_with("FOREIGN KEY constraint") {
        return Some(DatabaseConstraintViolation::ForeignKey);
    }
    database_constraint_violation_code(db.code().as_deref())
}

fn database_constraint_violation_code(code: Option<&str>) -> Option<DatabaseConstraintViolation> {
    match code {
        // PostgreSQL SQLSTATEs.
        Some("23505") => Some(DatabaseConstraintViolation::Unique),
        Some("23503") => Some(DatabaseConstraintViolation::ForeignKey),
        Some("23514") => Some(DatabaseConstraintViolation::Check),
        // SQLite extended result codes: UNIQUE (2067) and PRIMARY KEY (1555),
        // FOREIGN KEY (787), CHECK (275) and trigger `RAISE(ABORT)` (1811), which
        // is how the schema's invariant triggers report a violation.
        Some("2067") | Some("1555") => Some(DatabaseConstraintViolation::Unique),
        Some("787") => Some(DatabaseConstraintViolation::ForeignKey),
        Some("275") | Some("1811") => Some(DatabaseConstraintViolation::Check),
        _ => None,
    }
}

/// SQLite `SQLITE_BUSY` / `SQLITE_LOCKED` (primary codes 5 and 6, and their
/// extended variants).
fn is_busy(e: &sqlx::Error) -> bool {
    let sqlx::Error::Database(db) = e else {
        return false;
    };
    db.code()
        .and_then(|code| code.parse::<i32>().ok())
        .is_some_and(|code| matches!(code & 0xff, 5 | 6))
}

/// True for a uniqueness (or primary-key) violation on either backend.
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    database_constraint_violation(e) == Some(DatabaseConstraintViolation::Unique)
}

/// True for a foreign-key violation on either backend.
pub fn is_foreign_key_violation(e: &sqlx::Error) -> bool {
    database_constraint_violation(e) == Some(DatabaseConstraintViolation::ForeignKey)
}

/// True for a `CHECK` violation on either backend, including the schema's
/// invariant triggers (PostgreSQL raises them as `check_violation`, SQLite as a
/// trigger abort).
pub fn is_check_violation(e: &sqlx::Error) -> bool {
    database_constraint_violation(e) == Some(DatabaseConstraintViolation::Check)
}

/// The constraint a unique violation names, if this error is one. PostgreSQL
/// reports the constraint or index; SQLite reports `index '<name>'` in the
/// message for expression indexes, which is what the entity identifiers use.
pub fn unique_violation_constraint(e: &sqlx::Error) -> Option<&str> {
    let sqlx::Error::Database(db) = e else {
        return None;
    };
    match db.code().as_deref() {
        Some("23505") => db.constraint(),
        Some("2067") | Some("1555") => {
            let message = db.message();
            if let Some(rest) = message.split("index '").nth(1) {
                return rest.split('\'').next();
            }
            // Column-list violations name `table.column`; the registry's primary
            // key is the one whose PostgreSQL constraint name callers match on.
            message
                .contains("protected_object_ids.id")
                .then_some("protected_object_ids_pkey")
        }
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
    use super::{
        classify_database_error, database_constraint_violation_code, db_err,
        DatabaseConstraintViolation, DatabaseErrorKind,
    };
    use crate::error::AppError;

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

    #[test]
    fn row_not_found_classifies_as_not_found_and_db_err_converts_it() {
        assert_eq!(
            classify_database_error(&sqlx::Error::RowNotFound),
            DatabaseErrorKind::NotFound
        );
        assert!(matches!(
            db_err(sqlx::Error::RowNotFound),
            AppError::NotFound(_)
        ));
    }

    #[test]
    fn an_unclassified_error_stays_internal_and_db_err_preserves_it_as_database() {
        let e = sqlx::Error::PoolClosed;
        assert_eq!(classify_database_error(&e), DatabaseErrorKind::Internal);
        assert!(matches!(
            db_err(sqlx::Error::PoolClosed),
            AppError::Database(sqlx::Error::PoolClosed)
        ));
    }
}
