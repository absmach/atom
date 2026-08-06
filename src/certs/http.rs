use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use uuid::Uuid;

use crate::{certs::service, error::AppError, state::AppState};

pub async fn ca_chain(State(state): State<AppState>) -> Result<Response, AppError> {
    let pem = service::ca_chain(&state.config, state.certificate_issuer.as_deref())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    Ok((StatusCode::OK, headers, pem).into_response())
}

pub async fn crl(State(state): State<AppState>) -> Result<Response, AppError> {
    let der = service::generate_crl(
        &state.pool,
        &state.config,
        state.certificate_issuer.as_deref(),
    )
    .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    Ok((StatusCode::OK, headers, der).into_response())
}

pub async fn issuer_crl(
    Path(issuer_id): Path<Uuid>,
    State(state): State<AppState>,
    request_headers: HeaderMap,
) -> Result<Response, AppError> {
    let artifact = service::issuer_crl(&state.pool, &state.config, issuer_id).await?;
    let etag = format!("\"{}\"", artifact.sha256);
    let max_age = (artifact.next_update - Utc::now())
        .num_seconds()
        .clamp(0, 24 * 60 * 60);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|error| {
            AppError::Internal(anyhow::anyhow!("invalid cached CRL identifier: {error}"))
        })?,
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={max_age}, must-revalidate")).map_err(
            |error| AppError::Internal(anyhow::anyhow!("invalid CRL cache lifetime: {error}")),
        )?,
    );
    let not_modified = request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value == "*" || value.split(',').any(|candidate| candidate.trim() == etag)
        });
    if not_modified {
        return Ok((StatusCode::NOT_MODIFIED, headers).into_response());
    }
    Ok((StatusCode::OK, headers, artifact.der).into_response())
}

pub async fn ocsp(State(state): State<AppState>, body: Bytes) -> Result<Response, AppError> {
    let der = match service::ocsp_response(
        &state.pool,
        &state.config,
        state.certificate_issuer.as_deref(),
        &body,
    )
    .await
    {
        Ok(der) => der,
        Err(AppError::BadRequest(_)) => {
            service::unsuccessful_ocsp(ocsp::response::OcspRespStatus::MalformedReq)?
        }
        Err(err) => {
            tracing::error!("OCSP response generation failed: {err}");
            service::unsuccessful_ocsp(ocsp::response::OcspRespStatus::InternalError)?
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/ocsp-response"),
    );
    Ok((StatusCode::OK, headers, der).into_response())
}
