//! RFC 7030 Enrollment over Secure Transport adapter.
//!
//! This module owns only HTTP authentication and EST wire encodings. Subject,
//! scope, profile, issuer, lifecycle, rate-limit, and audit decisions remain in
//! the enrollment and certificate services.

use std::io::Cursor;

use axum::{
    body::Bytes,
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cms::content_info::ContentInfo;
use der::{Decode, Encode};
use ring::digest;
use x509_cert::Certificate;
use x509_parser::{certification_request::X509CertificationRequest, prelude::FromDer as _};
use yasna::models::ObjectIdentifier;

use crate::{
    audit,
    auth::{self, AuthContext},
    certs::{
        authority::provisioning,
        profile::{KeyAlgorithm, KeyAlgorithmRule},
    },
    error::AppError,
    identity::service as identity_service,
    state::AppState,
};

use super::{service, tls::VerifiedPeerCertificate};

const PKCS10_MEDIA_TYPE: &str = "application/pkcs10";
const PKCS7_CERTS_ONLY_MEDIA_TYPE: &str = "application/pkcs7-mime; smime-type=certs-only";
const CSR_ATTRS_MEDIA_TYPE: &str = "application/csrattrs";
const PKCS8_MEDIA_TYPE: &str = "application/pkcs8";
const TRANSFER_ENCODING_BASE64: &str = "base64";
const SERVER_KEYGEN_BOUNDARY: &str = "atom-est-serverkeygen-boundary";
const BASIC_CHALLENGE: &str = "Basic realm=\"Atom EST\"";
const CSR_PEM_HEADER: &str = "-----BEGIN CERTIFICATE REQUEST-----\n";
const CSR_PEM_FOOTER: &str = "-----END CERTIFICATE REQUEST-----\n";

/// EST simple re-enrollment authenticates the TLS peer before accepting a
/// request body. Anonymous rejections are observed in the extractor because
/// handlers are never invoked for an extractor failure.
struct EstReenrollmentPeer(VerifiedPeerCertificate);

#[axum::async_trait]
impl FromRequestParts<AppState> for EstReenrollmentPeer {
    type Rejection = EstError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<VerifiedPeerCertificate>()
            .cloned()
            .map(Self);
        let Some(peer) = peer else {
            let error = AppError::unauthorized("a verified client certificate is required");
            super::observe_missing_peer("est", &error);
            return Err(error.into());
        };
        Ok(peer)
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/est/cacerts", get(cacerts))
        .route("/.well-known/est/simpleenroll", post(simple_enroll))
        .route("/.well-known/est/simplereenroll", post(simple_reenroll))
        .route("/.well-known/est/serverkeygen", post(server_keygen))
        .route("/.well-known/est/csrattrs", get(csr_attrs))
}

async fn cacerts(State(state): State<AppState>) -> Result<Response, EstError> {
    let bundle = provisioning::trust_bundle(&state.pool).await?;
    base64_response(
        PKCS7_CERTS_ONLY_MEDIA_TYPE,
        certs_only_der(&bundle.pem)?,
        "public, max-age=60, stale-while-revalidate=300",
    )
}

async fn simple_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EstError> {
    require_media_type(&headers, PKCS10_MEDIA_TYPE)?;
    let auth = authenticate_http(&state, &headers).await?;
    let csr_der = decode_request_body(
        maximum_der_csr_bytes(state.config.enrollment.max_csr_bytes),
        &body,
    )?;
    validate_csr(&csr_der)?;
    let result = service::enroll(
        &state,
        auth.clone(),
        service::EnrollmentInput {
            csr_pem: csr_pem(&csr_der),
            ttl_secs: None,
            idempotency_key: idempotency_key("simpleenroll", &auth, &csr_der),
        },
    )
    .await;
    if let Err(ref error) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: auth.tenant_id,
                target_kind: "credential",
                target_id: None,
                event: "certificate.enroll",
            },
            &serde_json::json!({"mode": "first", "transport": "est"}),
            error,
        )
        .await;
    }
    let response = result?;
    enrollment_response(&response)
}

async fn simple_reenroll(
    State(state): State<AppState>,
    EstReenrollmentPeer(peer): EstReenrollmentPeer,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EstError> {
    require_media_type(&headers, PKCS10_MEDIA_TYPE)?;
    let csr_der = decode_request_body(
        maximum_der_csr_bytes(state.config.enrollment.max_csr_bytes),
        &body,
    )?;
    validate_csr(&csr_der)?;
    let peer_fingerprint = digest::digest(&digest::SHA256, peer.as_der());
    let result = service::re_enroll(
        &state,
        peer,
        service::EnrollmentInput {
            csr_pem: csr_pem(&csr_der),
            ttl_secs: None,
            idempotency_key: idempotency_key_with_subject(
                "simplereenroll",
                peer_fingerprint.as_ref(),
                &csr_der,
            ),
        },
    )
    .await;
    if let Err(ref error) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &audit::AuditMeta {
                actor_entity_id: None,
                tenant_id: None,
                target_kind: "credential",
                target_id: None,
                event: "certificate.reenroll",
            },
            &serde_json::json!({
                "mode": "reenroll",
                "peer_fingerprint_sha256": hex::encode(peer_fingerprint.as_ref()),
                "transport": "est",
            }),
            error,
        )
        .await;
    }
    let response = result?;
    enrollment_response(&response)
}

async fn server_keygen(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EstError> {
    require_media_type(&headers, PKCS10_MEDIA_TYPE)?;
    let auth = authenticate_http(&state, &headers).await?;
    let csr_der = decode_request_body(
        maximum_der_csr_bytes(state.config.enrollment.max_csr_bytes),
        &body,
    )?;
    validate_csr(&csr_der)?;

    let result = service::enroll_generated(&state, auth.clone()).await;
    if let Err(ref error) = result {
        audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: auth.tenant_id,
                target_kind: "credential",
                target_id: None,
                event: "certificate.enroll",
            },
            &serde_json::json!({"mode": "serverkeygen", "transport": "est"}),
            error,
        )
        .await;
    }
    let generated = result?;
    let key_der = private_key_info_der(generated.private_key_pem.expose())?;
    let certs_der = certs_only_der(&generated.enrollment.certificate_pem)?;
    let body = format!(
        "--{SERVER_KEYGEN_BOUNDARY}\r\n\
         Content-Type: {PKCS8_MEDIA_TYPE}\r\n\
         Content-Transfer-Encoding: {TRANSFER_ENCODING_BASE64}\r\n\r\n\
         {}\r\n\
         --{SERVER_KEYGEN_BOUNDARY}\r\n\
         Content-Type: {PKCS7_CERTS_ONLY_MEDIA_TYPE}\r\n\
         Content-Transfer-Encoding: {TRANSFER_ENCODING_BASE64}\r\n\r\n\
         {}\r\n\
         --{SERVER_KEYGEN_BOUNDARY}--\r\n",
        STANDARD.encode(key_der),
        STANDARD.encode(certs_der),
    );
    response_with_headers(
        body,
        &[
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(&format!(
                    "multipart/mixed; boundary=\"{SERVER_KEYGEN_BOUNDARY}\""
                ))
                .map_err(internal_encoding_error)?,
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
}

async fn csr_attrs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, EstError> {
    let auth = authenticate_http(&state, &headers).await?;
    let requirements = service::csr_requirements(&state, &auth).await?;
    let der = encode_csr_attributes(&requirements)?;
    base64_response(CSR_ATTRS_MEDIA_TYPE, der, "private, no-store")
}

async fn authenticate_http(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::unauthorized("missing HTTP authentication"))?
        .to_str()
        .map_err(|_| AppError::unauthorized("invalid Authorization header"))?;

    let (scheme, credential) = value
        .split_once(' ')
        .filter(|(_, credential)| !credential.is_empty())
        .ok_or_else(|| AppError::unauthorized("invalid HTTP authentication"))?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return auth::authenticate_token(state, credential).await;
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(AppError::unauthorized(
            "HTTP Basic or Bearer authentication is required",
        ));
    }

    let encoded = credential;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| AppError::unauthorized("invalid HTTP Basic authentication"))?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| AppError::unauthorized("invalid HTTP Basic authentication"))?;
    let (identifier, secret) = decoded
        .split_once(':')
        .filter(|(identifier, secret)| !identifier.is_empty() && !secret.is_empty())
        .ok_or_else(|| AppError::unauthorized("invalid HTTP Basic authentication"))?;
    let authenticated = identity_service::authenticate_password_credential_in_tenant(
        &state.pool,
        &state.config,
        identifier,
        secret,
        None,
    )
    .await?;
    Ok(AuthContext {
        entity_id: authenticated.entity_id,
        tenant_id: authenticated.tenant_id,
        ..Default::default()
    })
}

fn require_media_type(headers: &HeaderMap, expected: &'static str) -> Result<(), EstError> {
    let actual = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if actual.is_some_and(|value| value.eq_ignore_ascii_case(expected)) {
        Ok(())
    } else {
        Err(EstError::unsupported_media_type(format!(
            "Content-Type must be {expected}"
        )))
    }
}

fn decode_request_body(max_der: usize, body: &[u8]) -> Result<Vec<u8>, AppError> {
    let max_base64 = max_der
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4);
    if body.len() > max_base64.saturating_add(8 * 1024) {
        return Err(AppError::payload_too_large("EST request body is too large"));
    }
    let compact = body
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.is_empty() {
        return Err(AppError::bad_request("EST request body is empty"));
    }
    if compact.len() > max_base64 {
        return Err(AppError::payload_too_large("EST request body is too large"));
    }
    let der = STANDARD
        .decode(compact)
        .map_err(|_| AppError::bad_request("EST request body is not valid base64"))?;
    if der.len() > max_der {
        return Err(AppError::payload_too_large("EST request body is too large"));
    }
    Ok(der)
}

/// Derive the largest DER request whose canonical PEM representation still
/// fits the enrollment service's representation-independent CSR limit.
pub(super) fn maximum_der_csr_bytes(max_pem_bytes: usize) -> usize {
    let mut low = 0usize;
    let mut high = max_pem_bytes;
    while low < high {
        let midpoint = low + (high - low) / 2 + 1;
        if csr_pem_encoded_len(midpoint) <= max_pem_bytes {
            low = midpoint;
        } else {
            high = midpoint - 1;
        }
    }
    low
}

fn csr_pem_encoded_len(der_len: usize) -> usize {
    let base64_len = der_len
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4);
    let line_breaks = base64_len.saturating_add(63).saturating_div(64);
    CSR_PEM_HEADER
        .len()
        .saturating_add(base64_len)
        .saturating_add(line_breaks)
        .saturating_add(CSR_PEM_FOOTER.len())
}

fn validate_csr(der: &[u8]) -> Result<(), AppError> {
    let (remaining, _) = X509CertificationRequest::from_der(der)
        .map_err(|_| AppError::bad_request("malformed certificate signing request"))?;
    if !remaining.is_empty() {
        return Err(AppError::bad_request(
            "certificate signing request contains trailing data",
        ));
    }
    Ok(())
}

fn csr_pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from(CSR_PEM_HEADER);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(CSR_PEM_FOOTER);
    pem
}

fn idempotency_key(operation: &str, auth: &AuthContext, csr_der: &[u8]) -> String {
    idempotency_key_with_subject(operation, auth.entity_id.as_bytes(), csr_der)
}

fn idempotency_key_with_subject(operation: &str, subject: &[u8], csr_der: &[u8]) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"atom:est:idempotency:v1\0");
    context.update(operation.as_bytes());
    context.update(&[0]);
    context.update(subject);
    context.update(csr_der);
    format!("est:{}", hex::encode(context.finish()))
}

fn enrollment_response(response: &service::EnrollmentResponse) -> Result<Response, EstError> {
    certs_only_response(&response.certificate_pem)
}

fn certs_only_response(certificates_pem: &str) -> Result<Response, EstError> {
    base64_response(
        PKCS7_CERTS_ONLY_MEDIA_TYPE,
        certs_only_der(certificates_pem)?,
        "no-store",
    )
}

fn certs_only_der(certificates_pem: &str) -> Result<Vec<u8>, AppError> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificates_pem.as_bytes()))
        .map(|result| {
            let der = result.map_err(|_| {
                AppError::Internal(anyhow::anyhow!("failed to parse certificate PEM"))
            })?;
            Certificate::from_der(der.as_ref()).map_err(internal_encoding_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "certificate response is empty"
        )));
    }
    ContentInfo::try_from(certificates)
        .and_then(|content| content.to_der())
        .map_err(internal_encoding_error)
}

fn private_key_info_der(private_key_pem: &str) -> Result<Vec<u8>, AppError> {
    let mut lines = private_key_pem.lines();
    if lines.next() != Some("-----BEGIN PRIVATE KEY-----") {
        return Err(AppError::Internal(anyhow::anyhow!(
            "generated key is not PKCS#8 PrivateKeyInfo"
        )));
    }
    let mut encoded = String::new();
    let mut found_end = false;
    for line in &mut lines {
        if line == "-----END PRIVATE KEY-----" {
            found_end = true;
            break;
        }
        encoded.push_str(line);
    }
    if !found_end || lines.any(|line| !line.trim().is_empty()) {
        return Err(AppError::Internal(anyhow::anyhow!(
            "generated PKCS#8 key PEM is malformed"
        )));
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("generated PKCS#8 key is malformed")))
}

fn encode_csr_attributes(requirements: &[KeyAlgorithmRule]) -> Result<Vec<u8>, AppError> {
    for requirement in requirements {
        match requirement.algorithm {
            KeyAlgorithm::Ecdsa
                if requirement
                    .sizes
                    .iter()
                    .all(|size| matches!(size, 256 | 384)) => {}
            KeyAlgorithm::Rsa if requirement.sizes.iter().all(|size| *size >= 2048) => {}
            KeyAlgorithm::Ed25519 if requirement.sizes.as_slice() == [255] => {}
            _ => {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "client certificate profile has unsupported EST key requirements"
                )))
            }
        }
    }

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            for requirement in requirements {
                match requirement.algorithm {
                    KeyAlgorithm::Ecdsa => {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&oid(&[1, 2, 840, 10045, 2, 1]));
                            writer.next().write_set(|writer| {
                                for size in &requirement.sizes {
                                    let curve = match size {
                                        256 => &[1, 2, 840, 10045, 3, 1, 7][..],
                                        384 => &[1, 3, 132, 0, 34][..],
                                        _ => unreachable!("requirements were validated"),
                                    };
                                    writer.next().write_oid(&oid(curve));
                                }
                            });
                        });
                        for size in &requirement.sizes {
                            let signature = match size {
                                256 => &[1, 2, 840, 10045, 4, 3, 2][..],
                                384 => &[1, 2, 840, 10045, 4, 3, 3][..],
                                _ => unreachable!("requirements were validated"),
                            };
                            writer.next().write_oid(&oid(signature));
                        }
                    }
                    KeyAlgorithm::Rsa => {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&oid(&[1, 2, 840, 113549, 1, 1, 1]));
                            writer.next().write_set(|writer| {
                                for size in &requirement.sizes {
                                    writer.next().write_u64(u64::from(*size));
                                }
                            });
                        });
                        writer
                            .next()
                            .write_oid(&oid(&[1, 2, 840, 113549, 1, 1, 11]));
                    }
                    KeyAlgorithm::Ed25519 => {
                        writer.next().write_oid(&oid(&[1, 3, 101, 112]));
                    }
                }
            }
        });
    }))
}

fn oid(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(arcs)
}

fn base64_response(
    media_type: &str,
    der: Vec<u8>,
    cache_control: &'static str,
) -> Result<Response, EstError> {
    response_with_headers(
        STANDARD.encode(der),
        &[
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(media_type).map_err(internal_encoding_error)?,
            ),
            (
                HeaderName::from_static("content-transfer-encoding"),
                HeaderValue::from_static(TRANSFER_ENCODING_BASE64),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(cache_control),
            ),
        ],
    )
}

fn response_with_headers(
    body: String,
    headers: &[(HeaderName, HeaderValue)],
) -> Result<Response, EstError> {
    let mut response = (StatusCode::OK, body).into_response();
    for (name, value) in headers {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    Ok(response)
}

fn internal_encoding_error(error: impl std::fmt::Display) -> AppError {
    AppError::Internal(anyhow::anyhow!("EST encoding failed: {error}"))
}

struct EstError {
    source: AppError,
    status_override: Option<StatusCode>,
}

impl EstError {
    fn unsupported_media_type(message: String) -> Self {
        Self {
            source: AppError::bad_request(message),
            status_override: Some(StatusCode::UNSUPPORTED_MEDIA_TYPE),
        }
    }
}

impl From<AppError> for EstError {
    fn from(source: AppError) -> Self {
        Self {
            source,
            status_override: None,
        }
    }
}

impl IntoResponse for EstError {
    fn into_response(self) -> Response {
        let mut response = self.source.into_response();
        if let Some(status) = self.status_override {
            *response.status_mut() = status;
        }
        if response.status() == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(BASIC_CHALLENGE),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_csr_attributes_match_the_rfc7030_shape() {
        let der = encode_csr_attributes(&[KeyAlgorithmRule {
            algorithm: KeyAlgorithm::Ecdsa,
            sizes: vec![256],
        }])
        .unwrap();
        assert_eq!(
            STANDARD.encode(der),
            "MCEwFQYHKoZIzj0CATEKBggqhkjOPQMBBwYIKoZIzj0EAwI="
        );
    }

    #[test]
    fn request_decoder_rejects_invalid_base64_before_crypto_parsing() {
        assert!(matches!(
            decode_request_body(64 * 1024, b"%%%"),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn der_limit_accounts_for_pem_envelope_and_line_wrapping() {
        let configured_limit = 1024;
        let maximum_der = maximum_der_csr_bytes(configured_limit);
        assert!(csr_pem(&vec![0; maximum_der]).len() <= configured_limit);
        assert!(csr_pem(&vec![0; maximum_der + 1]).len() > configured_limit);

        let accepted = vec![0; maximum_der];
        let accepted_body = STANDARD.encode(&accepted);
        assert_eq!(
            decode_request_body(maximum_der, accepted_body.as_bytes()).unwrap(),
            accepted
        );
        let rejected_body = STANDARD.encode(vec![0; maximum_der + 1]);
        assert!(matches!(
            decode_request_body(maximum_der, rejected_body.as_bytes()),
            Err(AppError::PayloadTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn simple_enroll_authenticates_before_decoding_the_csr() {
        let response = simple_enroll(
            State(test_state()),
            pkcs10_headers(),
            Bytes::from_static(b"%%%"),
        )
        .await
        .expect_err("missing authentication must be rejected before invalid CSR parsing")
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn server_keygen_authenticates_before_decoding_the_csr() {
        let response = server_keygen(
            State(test_state()),
            pkcs10_headers(),
            Bytes::from_static(b"%%%"),
        )
        .await
        .expect_err("missing authentication must be rejected before invalid CSR parsing")
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn pkcs10_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PKCS10_MEDIA_TYPE),
        );
        headers
    }

    fn test_state() -> AppState {
        crate::certs::test_state_without_database()
    }
}
