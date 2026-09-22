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

use async_graphql::{
    parser::types::{DocumentOperations, OperationType, Selection},
    Extensions, Request, Response, ServerError, Variables,
};
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
    let auth = match token_from_headers(&headers) {
        Ok(Some((token, source))) => {
            if source == AuthTokenSource::Cookie {
                if let Err(err) =
                    require_trusted_origin(&headers, &state.config.cors_allowed_origins)
                {
                    return graphql_error(err.to_string());
                }
            }
            match authenticate_token(&state, token).await {
                Ok(auth) => Some(auth),
                Err(err) => {
                    // Many GraphQL clients attach a stored bearer token to every
                    // request via a global interceptor, so a client can't always
                    // omit Authorization once its access JWT has expired.
                    // Recognize only an unambiguous solo `refreshToken` request
                    // via the real parser and let it through without AuthContext;
                    // any other shape keeps today's strict behavior.
                    if is_solely_refresh_token_mutation(&body.query, body.operation_name.as_deref())
                    {
                        None
                    } else {
                        return graphql_error(err.to_string());
                    }
                }
            }
        }
        Ok(None) => None,
        Err(err) => return graphql_error(err.to_string()),
    };

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
    if let Some(auth) = auth {
        // The access-token ceiling rides inside AuthContext and is enforced
        // explicitly by each gate; no request wrapper needed.
        req = req.data(auth);
    }

    schema.execute(req).await.into()
}

/// True only for a request whose sole top-level selection is a single
/// `refreshToken` mutation field — no sibling fields, fragments, or aliasing
/// tricks. Uses the real GraphQL parser rather than string matching so a
/// crafted query can't smuggle another operation past this check.
fn is_solely_refresh_token_mutation(query: &str, operation_name: Option<&str>) -> bool {
    let Ok(doc) = async_graphql::parser::parse_query(query) else {
        return false;
    };
    let op = match &doc.operations {
        DocumentOperations::Single(op) => Some(op),
        DocumentOperations::Multiple(map) => operation_name.and_then(|name| map.get(name)),
    };
    let Some(op) = op else {
        return false;
    };
    if op.node.ty != OperationType::Mutation {
        return false;
    }
    let items = &op.node.selection_set.node.items;
    items.len() == 1
        && matches!(
            &items[0].node,
            Selection::Field(field) if field.node.name.node.as_str() == "refreshToken"
        )
}

fn graphql_error(message: String) -> GraphQLResponse {
    Response::from_errors(vec![ServerError::new(message, None)]).into()
}
