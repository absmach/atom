use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
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
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::Database(e) => {
                // Postgres unique violation
                if let sqlx::Error::Database(db) = e {
                    if db.code().as_deref() == Some("23505") {
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({"error": "already exists"})),
                        )
                            .into_response();
                    }
                }
                tracing::error!("db error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string())
            }
            AppError::Internal(e) => {
                tracing::error!("internal error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
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
