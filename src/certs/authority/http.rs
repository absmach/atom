use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{error::AppError, state::AppState};

use super::provisioning;

const TRUST_BUNDLE_CACHE_CONTROL: &str = "public, max-age=60, stale-while-revalidate=300";

pub async fn trust_bundle(
    State(state): State<AppState>,
    request_headers: HeaderMap,
) -> Result<Response, AppError> {
    let bundle = provisioning::trust_bundle(&state.pool).await?;
    let etag = format!("\"{}\"", bundle.version);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(TRUST_BUNDLE_CACHE_CONTROL),
    );
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid trust bundle version")))?,
    );

    if request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| etag_matches(value, &etag))
    {
        return Ok((StatusCode::NOT_MODIFIED, response_headers).into_response());
    }

    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    Ok((StatusCode::OK, response_headers, bundle.pem).into_response())
}

pub(crate) fn etag_matches(if_none_match: &str, current: &str) -> bool {
    if_none_match.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate == current || candidate.strip_prefix("W/") == Some(current)
    })
}

#[cfg(test)]
mod tests {
    use super::etag_matches;

    #[test]
    fn etag_revalidation_handles_lists_weak_tags_and_wildcards() {
        assert!(etag_matches("\"old\", \"current\"", "\"current\""));
        assert!(etag_matches("W/\"current\"", "\"current\""));
        assert!(etag_matches("*", "\"current\""));
        assert!(!etag_matches("\"other\"", "\"current\""));
    }
}
