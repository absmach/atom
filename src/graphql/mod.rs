pub mod admin;
pub mod api_endpoints;
pub mod auth;
pub mod authz;
pub mod certificates;
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

use async_graphql::{Response, ServerError};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{extract::State, http::HeaderMap, Extension};

use crate::{
    auth::{authenticate_token, require_trusted_origin, token_from_headers, AuthTokenSource},
    state::AppState,
};

pub use schema::{build_schema, AtomSchema};

pub async fn graphql_handler(
    Extension(schema): Extension<AtomSchema>,
    State(state): State<AppState>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();
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
