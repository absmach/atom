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
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

#[allow(dead_code)]
impl AppError {
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
            AppError::Database(e) => {
                if let sqlx::Error::Database(db) = e {
                    match db.code().as_deref() {
                        // Unique violation
                        Some("23505") => {
                            return (
                                StatusCode::CONFLICT,
                                Json(json!({"error": "already exists"})),
                            )
                                .into_response();
                        }
                        // Foreign-key violation — most commonly an unknown tenant_id
                        Some("23503") => {
                            tracing::warn!("foreign-key violation: {}", db.message());
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error": "invalid reference"})),
                            )
                                .into_response();
                        }
                        // Check violation
                        Some("23514") => {
                            tracing::warn!("check violation: {}", db.message());
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error": "invalid value"})),
                            )
                                .into_response();
                        }
                        _ => {}
                    }
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
            AppError::Database(e) => {
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
