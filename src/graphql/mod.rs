pub mod admin;
pub mod api_endpoints;
pub mod auth;
pub mod authz;
pub mod callout_ext;
pub mod certificates;
pub mod pki_authorities {
    pub use crate::certs::authority::graphql::*;
}
pub mod credentials;
pub mod entities;
pub mod groups;
pub mod mutation;
pub mod operations;
pub mod policies;
pub mod profiles;
pub mod query;
pub mod resources;
pub mod schema;
pub mod tenants;
pub mod types;

use async_graphql::{ErrorExtensionValues, Extensions, Request, Response, ServerError, Variables};
use async_graphql_axum::GraphQLResponse;
use axum::{extract::State, http::HeaderMap, Extension, Json};
use serde::Deserialize;

use crate::{
    auth::{authenticate_token, require_trusted_origin, token_from_headers, AuthTokenSource},
    error::AppError,
    request_id::RequestId,
    state::AppState,
};

pub use schema::{build_schema, schema_sdl, AtomSchema};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphqlHttpRequest {
    query: String,
    #[serde(default)]
    operation_name: Option<String>,
    #[serde(default)]
    variables: Option<Variables>,
    #[serde(default)]
    extensions: Option<Extensions>,
}

pub async fn graphql_handler(
    Extension(schema): Extension<AtomSchema>,
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GraphqlHttpRequest>,
) -> GraphQLResponse {
    let mut req = Request::new(body.query);
    if let Some(operation_name) = body.operation_name {
        req = req.operation_name(operation_name);
    }
    if let Some(variables) = body.variables {
        req = req.variables(variables);
    }
    if let Some(extensions) = body.extensions {
        req.extensions = extensions;
    }
    match token_from_headers(&headers) {
        Ok(Some((token, source))) => {
            if source == AuthTokenSource::Cookie {
                if let Err(err) =
                    require_trusted_origin(&headers, &state.config.cors_allowed_origins)
                {
                    return graphql_error(err, &request_id);
                }
            }
            match authenticate_token(&state, token).await {
                Ok(auth) => {
                    // The access-token ceiling rides inside AuthContext and is
                    // enforced explicitly by each gate; no request wrapper needed.
                    req = req.data(auth);
                }
                Err(err) => return graphql_error(err, &request_id),
            }
        }
        Ok(None) => {}
        Err(err) => return graphql_error(err, &request_id),
    }

    attach_error_metadata(schema.execute(req).await, &request_id).into()
}

/// Builds the GraphQL error envelope for a failure that happens *before*
/// `schema.execute` ever runs (bad token, untrusted cookie origin) — so no
/// extension hook in the schema's execution chain ever sees it. Derives the
/// full public contract from `AppError::public_contract` (issue #101), the
/// same mapping `graphql::auth::gql_error` uses for in-resolver failures.
fn graphql_error(err: AppError, request_id: &RequestId) -> GraphQLResponse {
    let contract = err.public_contract();
    let mut extensions = ErrorExtensionValues::default();
    extensions.set("code", contract.code.as_str());
    extensions.set("retryable", contract.retryable);
    if let Some(retry_after_secs) = contract.retry_after_secs {
        extensions.set("retryAfterSeconds", retry_after_secs);
    }
    extensions.set("requestId", request_id.as_str());
    let error = ServerError {
        message: contract.message,
        source: None,
        locations: Vec::new(),
        path: Vec::new(),
        extensions: Some(extensions),
    };
    Response::from_errors(vec![error]).into()
}

/// Stamps `extensions.requestId` on every error in the response, and — for
/// any error that does not already carry a `code` (async-graphql's own
/// parse/validation/depth/complexity/introspection-disabled failures, which
/// never reach a resolver or `gql_error`) — a default `BAD_REQUEST`,
/// non-retryable code. Errors `gql_error` already coded (the overwhelming
/// majority — every resolver failure) are left exactly as set; this only
/// adds `requestId` to those. See `api/v1/graphql-error-contract.md`.
fn attach_error_metadata(mut response: Response, request_id: &RequestId) -> Response {
    for error in &mut response.errors {
        let extensions = error
            .extensions
            .get_or_insert_with(ErrorExtensionValues::default);
        if extensions.get("code").is_none() {
            extensions.set("code", "BAD_REQUEST");
            extensions.set("retryable", false);
        }
        extensions.set("requestId", request_id.as_str());
    }
    response
}
