pub mod admin;
pub mod api_endpoints;
pub mod auth;
pub mod authz;
pub mod credentials;
pub mod entities;
pub mod groups;
pub mod mutation;
pub mod policies;
pub mod profiles;
pub mod query;
pub mod resources;
pub mod schema;
pub mod tenants;
pub mod types;

use async_graphql::{Response, ServerError};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::State,
    http::{header, HeaderMap},
    Extension,
};

use crate::{auth::authenticate_token, state::AppState};

pub use schema::{build_schema, AtomSchema};

pub async fn graphql_handler(
    Extension(schema): Extension<AtomSchema>,
    State(state): State<AppState>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();
    match bearer_token(&headers) {
        Ok(Some(token)) => match authenticate_token(&state, token).await {
            Ok(auth) => {
                req = req.data(auth);
            }
            Err(err) => return graphql_error(err.to_string()),
        },
        Ok(None) => {}
        Err(err) => return graphql_error(err),
    }

    schema.execute(req).await.into()
}

fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, String> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| "invalid Authorization header".to_string())?;
    value
        .strip_prefix("Bearer ")
        .map(Some)
        .ok_or_else(|| "Authorization header must use Bearer".to_string())
}

fn graphql_error(message: String) -> GraphQLResponse {
    Response::from_errors(vec![ServerError::new(message, None)]).into()
}
