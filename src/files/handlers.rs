//! REST endpoints for files. Bytes do not go through GraphQL: uploads stream
//! into the store and downloads stream out of it, never whole in memory.
//!
//! Mounted only when storage is configured.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{sniff, Access, FileObject, NewUpload};
use crate::{
    auth::AuthContext,
    error::AppError,
    models::resource::Resource,
    state::AppState,
    storage::{BlobError, ByteStream},
};

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub size_bytes: i64,
    pub content_type: String,
    pub sha256: String,
    pub public: bool,
    pub url: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl FileResponse {
    fn new(state: &AppState, resource: Resource, file: FileObject) -> Self {
        Self {
            id: resource.id,
            tenant_id: resource.tenant_id,
            owner_id: resource.owner_id,
            name: resource.name,
            alias: resource.alias,
            size_bytes: file.size_bytes,
            content_type: file.content_type,
            sha256: file.sha256,
            public: file.public,
            url: super::file_url(state, resource.id),
            created_at: file.created_at,
            updated_at: file.updated_at,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct UploadQuery {
    pub tenant_id: Option<Uuid>,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub public: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct DownloadQuery {
    pub expires: Option<i64>,
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignedUrlRequest {
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct SignedUrlResponse {
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// Refuses a body that announces itself as too large before reading any of
/// it. Bodies without a length are counted as they stream.
fn check_length(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let max = state.config.storage.max_file_bytes;
    let length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    match length {
        Some(length) if length > max => Err(AppError::payload_too_large(format!(
            "files are limited to {max} bytes"
        ))),
        _ => Ok(()),
    }
}

fn declared_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
}

fn body_stream(body: Body) -> ByteStream {
    body.into_data_stream()
        .map(|chunk| chunk.map_err(|err| BlobError::Body(err.to_string())))
        .boxed()
}

async fn upload(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<impl IntoResponse, AppError> {
    check_length(&state, &headers)?;
    let req = NewUpload {
        tenant_id: query.tenant_id.or(auth.tenant_id),
        name: query.name,
        alias: query.alias,
        owner_id: query.owner_id,
        public: query.public,
    };
    let (resource, file) = super::upload(
        &state,
        &auth,
        req,
        declared_type(&headers),
        body_stream(body),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(FileResponse::new(&state, resource, file)),
    ))
}

async fn replace(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<FileResponse>, AppError> {
    check_length(&state, &headers)?;
    let (resource, file) = super::replace(
        &state,
        &auth,
        id,
        declared_type(&headers),
        body_stream(body),
    )
    .await?;
    Ok(Json(FileResponse::new(&state, resource, file)))
}

async fn delete(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    super::delete(&state, &auth, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn signed_url(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<SignedUrlRequest>,
) -> Result<Json<SignedUrlResponse>, AppError> {
    let (url, expires_at) = super::signed_url(&state, &auth, id, req.expires_in).await?;
    Ok(Json(SignedUrlResponse { url, expires_at }))
}

/// What a `Range` header asks of a file of `size` bytes.
#[derive(Debug, PartialEq, Eq)]
enum RangeRequest {
    Whole,
    Part(std::ops::Range<u64>),
    Unsatisfiable,
}

/// Single byte ranges only (`bytes=a-b`, `bytes=a-`, `bytes=-n`); anything
/// else, multiple ranges included, is answered with the whole file.
fn parse_range(value: Option<&str>, size: u64) -> RangeRequest {
    let Some(spec) = value.and_then(|value| value.trim().strip_prefix("bytes=")) else {
        return RangeRequest::Whole;
    };
    if spec.contains(',') {
        return RangeRequest::Whole;
    }
    let Some((start, end)) = spec.split_once('-') else {
        return RangeRequest::Whole;
    };
    let (start, end) = (start.trim(), end.trim());
    let range = match (start.parse::<u64>(), end.parse::<u64>()) {
        (Ok(start), Ok(end)) if start <= end => start..end.saturating_add(1).min(size),
        (Ok(start), Err(_)) if end.is_empty() => start..size,
        (Err(_), Ok(suffix)) if start.is_empty() => size.saturating_sub(suffix)..size,
        _ => return RangeRequest::Whole,
    };
    if range.start >= size || range.is_empty() {
        RangeRequest::Unsatisfiable
    } else {
        RangeRequest::Part(range)
    }
}

/// `filename*` in RFC 5987 form, so any name is safe in the header.
fn content_disposition(inline: bool, name: Option<&str>) -> String {
    let kind = if inline { "inline" } else { "attachment" };
    match name.filter(|name| !name.is_empty()) {
        Some(name) => {
            let encoded: String = name
                .bytes()
                .map(|byte| match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => {
                        (byte as char).to_string()
                    }
                    _ => format!("%{byte:02X}"),
                })
                .collect();
            format!("{kind}; filename*=UTF-8''{encoded}")
        }
        None => kind.to_string(),
    }
}

fn header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
}

async fn download(
    State(state): State<AppState>,
    auth: Option<AuthContext>,
    Path(id): Path<Uuid>,
    Query(query): Query<DownloadQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let signed = matches!((&query.expires, &query.signature), (Some(_), Some(_)));
    let access = match (&auth, query.expires, query.signature.as_deref()) {
        (_, Some(expires), Some(signature)) => Access::Signed { expires, signature },
        (Some(auth), _, _) => Access::Session(auth),
        (None, _, _) => Access::Anonymous,
    };
    let (resource, file) = super::authorize_read(&state, id, access).await?;

    let etag = format!("\"{}\"", file.sha256);
    let cache_control = if file.public && !signed {
        // Revalidated often: a replacement keeps the URL and changes the ETag.
        "public, max-age=300"
    } else {
        "private, no-store"
    };
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, header_value(&etag));
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|tag| tag.trim() == etag || tag.trim() == "*")
        });
    if not_modified {
        return Ok((StatusCode::NOT_MODIFIED, response_headers).into_response());
    }

    let size = u64::try_from(file.size_bytes).unwrap_or_default();
    let range = match parse_range(
        headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok()),
        size,
    ) {
        RangeRequest::Whole => None,
        RangeRequest::Part(range) => Some(range),
        RangeRequest::Unsatisfiable => {
            response_headers.insert(
                header::CONTENT_RANGE,
                header_value(&format!("bytes */{size}")),
            );
            return Ok((StatusCode::RANGE_NOT_SATISFIABLE, response_headers).into_response());
        }
    };

    let inline = sniff::inline(&file.content_type);
    response_headers.insert(header::CONTENT_TYPE, header_value(&file.content_type));
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        header_value(&content_disposition(inline, resource.name.as_deref())),
    );
    if !inline {
        // Anything that is not a verified image or PDF gets no script and no
        // same-origin access, even if a browser were to render it.
        response_headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("sandbox"),
        );
    }

    let download = super::open(&state, resource, file, range).await?;
    let status = match &download.range {
        Some(range) => {
            response_headers.insert(
                header::CONTENT_RANGE,
                header_value(&format!("bytes {}-{}/{size}", range.start, range.end - 1)),
            );
            response_headers.insert(
                header::CONTENT_LENGTH,
                header_value(&(range.end - range.start).to_string()),
            );
            StatusCode::PARTIAL_CONTENT
        }
        None => {
            response_headers.insert(header::CONTENT_LENGTH, header_value(&size.to_string()));
            StatusCode::OK
        }
    };
    Ok((status, response_headers, Body::from_stream(download.body)).into_response())
}

/// The file routes. Kept last in the file: `tests/api_contract.rs` reads the
/// routes from this source to check them against `apidocs/openapi.yaml`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/files", post(upload))
        .route("/files/:id", get(download).put(replace).delete(delete))
        .route("/files/:id/signed-url", post(signed_url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 10), RangeRequest::Whole);
        assert_eq!(parse_range(Some("bytes=0-3"), 10), RangeRequest::Part(0..4));
        assert_eq!(parse_range(Some("bytes=4-"), 10), RangeRequest::Part(4..10));
        assert_eq!(parse_range(Some("bytes=-3"), 10), RangeRequest::Part(7..10));
        assert_eq!(
            parse_range(Some("bytes=5-99"), 10),
            RangeRequest::Part(5..10)
        );
        assert_eq!(
            parse_range(Some("bytes=10-"), 10),
            RangeRequest::Unsatisfiable
        );
        assert_eq!(parse_range(Some("bytes=0-1,4-5"), 10), RangeRequest::Whole);
        assert_eq!(parse_range(Some("items=0-1"), 10), RangeRequest::Whole);
        assert_eq!(parse_range(Some("bytes=5-2"), 10), RangeRequest::Whole);
    }

    #[test]
    fn disposition_encodes_the_name() {
        assert_eq!(content_disposition(true, None), "inline");
        assert_eq!(
            content_disposition(false, Some("a \"b\".svg")),
            "attachment; filename*=UTF-8''a%20%22b%22.svg"
        );
    }
}
