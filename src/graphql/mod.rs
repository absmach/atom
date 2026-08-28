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

use async_graphql::{Extensions, Request, Response, ServerError, Variables};
use async_graphql_axum::GraphQLResponse;
use axum::{extract::State, http::HeaderMap, Extension, Json};
use serde::Deserialize;

use crate::{
    auth::{authenticate_token, require_trusted_origin, token_from_headers, AuthTokenSource},
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
                    return graphql_error(err.to_string());
                }
            }
            match authenticate_token(&state, token).await {
                Ok(auth) => {
                    // The access-token ceiling rides inside AuthContext and is
                    // enforced explicitly by each gate; no request wrapper needed.
                    req = req.data(auth);
                }
                Err(err) => return graphql_error(err.to_string()),
            }
        }
        Ok(None) => {}
        Err(err) => return graphql_error(err.to_string()),
    }

    schema.execute(req).await.into()
}

fn graphql_error(message: String) -> GraphQLResponse {
    Response::from_errors(vec![ServerError::new(message, None)]).into()
}
