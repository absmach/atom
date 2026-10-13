//! Request-correlation ID (issue #101): one ID per request, returned in the
//! `X-Request-ID` response header and echoed into `extensions.requestId` on
//! every GraphQL error in that response — see `graphql::mod` and
//! `api/v1/graphql-error-contract.md`.
//!
//! Applied as the outermost HTTP layer (see `routes.rs`) so every response,
//! including ones rejected by CORS, rate limiting, or the body-size limit,
//! carries the header — not just GraphQL responses.

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;

pub const HEADER_NAME: &str = "x-request-id";

/// Generous enough for a UUID, ULID, or a load balancer's own correlation
/// ID, but bounded so a client cannot use this header to smuggle unbounded
/// data into logs or the GraphQL response.
const MAX_LEN: usize = 128;

/// The ID for the current request, stored in Axum request extensions by
/// [`middleware`] and read back out in `graphql::graphql_handler`.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A client-supplied ID is trusted only if it looks like an identifier, not
/// arbitrary text — bounded length, ASCII letters/digits plus `-`, `_`, `.`.
/// Anything else (empty, oversized, containing whitespace or control
/// characters) is treated as absent and a fresh ID is generated instead.
fn is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub async fn middleware(mut req: Request<Body>, next: Next) -> Response {
    let incoming = req
        .headers()
        .get(HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid(value))
        .map(str::to_string);
    let id = incoming.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    req.extensions_mut().insert(RequestId(id.clone()));

    let span = tracing::info_span!("http_request", request_id = %id);
    let mut response = next.run(req).instrument(span).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(HEADER_NAME), value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn handler_logs_and_response_share_the_validated_request_id() {
        use axum::{body::Body, http::Request, middleware, routing::get, Extension, Router};
        use tower::ServiceExt;
        use tracing::instrument::WithSubscriber;

        let log = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(log.clone())
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let app = Router::new()
            .route(
                "/",
                get(|Extension(id): Extension<super::RequestId>| async move {
                    tracing::error!("handler failure");
                    id.0
                }),
            )
            .layer(middleware::from_fn(super::middleware));

        for incoming in ["correlation-test", "invalid value"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/")
                        .header(super::HEADER_NAME, incoming)
                        .body(Body::empty())
                        .expect("request"),
                )
                .with_subscriber(dispatch.clone())
                .await
                .expect("response");
            let id = response.headers()[super::HEADER_NAME]
                .to_str()
                .expect("id")
                .to_owned();
            if incoming == "correlation-test" {
                assert_eq!(id, incoming);
            } else {
                assert_ne!(id, incoming);
                assert!(uuid::Uuid::parse_str(&id).is_ok());
            }
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .expect("body");
            assert_eq!(body.as_ref(), id.as_bytes());
            let output = log.0.lock().expect("log buffer");
            let text = std::str::from_utf8(&output).expect("UTF-8 logs");
            assert!(
                text.lines().any(|line| {
                    let event: serde_json::Value = serde_json::from_str(line).expect("JSON log");
                    event["fields"]["message"] == "handler failure"
                        && event["span"]["request_id"] == id
                }),
                "handler log must contain the response's request id: {text}"
            );
        }
    }

    #[test]
    fn accepts_uuid_and_ulid_shaped_ids() {
        assert!(is_valid("2cc55e48-d44f-49ce-99e2-b08f06f619a6"));
        assert!(is_valid("01HZY3K2N1P4Q5R6S7T8U9V0W1"));
        assert!(is_valid("a.b_c-d"));
    }

    #[test]
    fn rejects_empty_oversized_and_unsafe_values() {
        assert!(!is_valid(""));
        assert!(!is_valid(&"a".repeat(129)));
        assert!(!is_valid("has space"));
        assert!(!is_valid("has\ttab"));
        assert!(!is_valid("has\nnewline"));
        assert!(!is_valid("has\"quote"));
        assert!(!is_valid("has;semicolon"));
    }

    #[test]
    fn accepts_max_length_boundary() {
        assert!(is_valid(&"a".repeat(128)));
        assert!(!is_valid(&"a".repeat(129)));
    }
}
