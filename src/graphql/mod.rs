pub mod admin;
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
    response::Html,
    Extension,
};
use serde_json::json;

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

pub async fn graphql_playground() -> Html<String> {
    Html(playground_html())
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

fn playground_html() -> String {
    let config = json!({
        "endpoint": "/graphql",
        "settings": {
            "editor.reuseHeaders": true,
            "request.credentials": "same-origin"
        },
        "tabs": [
            {
                "name": "Login",
                "endpoint": "/graphql",
                "query": concat!(
                    "mutation Login($input: LoginInput!) {\n",
                    "  login(input: $input) {\n",
                    "    token\n",
                    "    entityId\n",
                    "    sessionId\n",
                    "    expiresAt\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": "{\n  \"input\": {\n    \"identifier\": \"atom-admin\",\n    \"secret\": \"change-me\",\n    \"kind\": \"password\"\n  }\n}"
            },
            {
                "name": "Profiles",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "query Profiles($objectKind: String, $kind: String, $limit: Int = 20, $offset: Int = 0) {\n",
                    "  profiles(objectKind: $objectKind, kind: $kind, limit: $limit, offset: $offset) {\n",
                    "    items {\n",
                    "      id\n",
                    "      key\n",
                    "      displayName\n",
                    "      kind\n",
                    "    }\n",
                    "    total\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": "{\n  \"objectKind\": \"entity\",\n  \"kind\": \"device\",\n  \"limit\": 20,\n  \"offset\": 0\n}"
            },
            {
                "name": "Create Tenant",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "mutation CreateTenant($input: CreateTenantInput!) {\n",
                    "  createTenant(input: $input) {\n",
                    "    id\n",
                    "    name\n",
                    "    route\n",
                    "    status\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": "{\n  \"input\": {\n    \"name\": \"factory-a\",\n    \"route\": \"factory-a\"\n  }\n}"
            },
            {
                "name": "View Tenants",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "query ViewTenants($limit: Int = 20, $offset: Int = 0) {\n",
                    "  tenants(limit: $limit, offset: $offset) {\n",
                    "    items {\n",
                    "      id\n",
                    "      name\n",
                    "      route\n",
                    "      status\n",
                    "      tags\n",
                    "      attributes\n",
                    "      createdAt\n",
                    "      updatedAt\n",
                    "    }\n",
                    "    total\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": "{\n  \"limit\": 20,\n  \"offset\": 0\n}"
            },
            {
                "name": "Create Entity",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "mutation CreateEntity($input: CreateEntityInput!) {\n",
                    "  createEntity(input: $input) {\n",
                    "    id\n",
                    "    kind\n",
                    "    profileId\n",
                    "    profileVersionId\n",
                    "    name\n",
                    "    attributes\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": concat!(
                    "{\n",
                    "  \"input\": {\n",
                    "    \"profileId\": \"paste-profile-id-here\",\n",
                    "    \"name\": \"meter-001\",\n",
                    "    \"attributes\": {\n",
                    "      \"serial_no\": \"WM-001\"\n",
                    "    }\n",
                    "  }\n",
                    "}"
                )
            },
            {
                "name": "View Entities",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "query ViewEntities($kind: EntityKind, $limit: Int = 20, $offset: Int = 0) {\n",
                    "  entities(kind: $kind, limit: $limit, offset: $offset) {\n",
                    "    items {\n",
                    "      id\n",
                    "      kind\n",
                    "      profileId\n",
                    "      profileVersionId\n",
                    "      name\n",
                    "      tenantId\n",
                    "      status\n",
                    "      attributes\n",
                    "      createdAt\n",
                    "      updatedAt\n",
                    "    }\n",
                    "    total\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": "{\n  \"kind\": \"device\",\n  \"limit\": 20,\n  \"offset\": 0\n}"
            },
            {
                "name": "Create Resource",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "mutation CreateResource($input: CreateResourceInput!) {\n",
                    "  createResource(input: $input) {\n",
                    "    id\n",
                    "    kind\n",
                    "    name\n",
                    "    tenantId\n",
                    "    attributes\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": concat!(
                    "{\n",
                    "  \"input\": {\n",
                    "    \"kind\": \"channel\",\n",
                    "    \"name\": \"telemetry\",\n",
                    "    \"attributes\": {\n",
                    "      \"topic\": \"telemetry\"\n",
                    "    }\n",
                    "  }\n",
                    "}"
                )
            },
            {
                "name": "View Resources",
                "endpoint": "/graphql",
                "headers": {
                    "Authorization": "Bearer paste-jwt-or-api-key-here"
                },
                "query": concat!(
                    "query ViewResources($kind: String, $limit: Int = 20, $offset: Int = 0) {\n",
                    "  resources(kind: $kind, limit: $limit, offset: $offset) {\n",
                    "    items {\n",
                    "      id\n",
                    "      kind\n",
                    "      name\n",
                    "      tenantId\n",
                    "      ownerId\n",
                    "      attributes\n",
                    "      createdAt\n",
                    "      updatedAt\n",
                    "    }\n",
                    "    total\n",
                    "  }\n",
                    "}\n"
                ),
                "variables": "{\n  \"kind\": \"channel\",\n  \"limit\": 20,\n  \"offset\": 0\n}"
            }
        ]
    });

    let config = serde_json::to_string(&config).expect("playground config should serialize");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Atom GraphQL Playground</title>
  <link rel="stylesheet" href="//cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css" />
  <link rel="shortcut icon" href="//cdn.jsdelivr.net/npm/graphql-playground-react/build/favicon.png" />
  <script src="//cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans:300,400,600,700|Source+Code+Pro:400,700" />
</head>
<body>
  <div id="root"></div>
  <script>
    window.addEventListener('load', function () {{
      GraphQLPlayground.init(document.getElementById('root'), {config});
    }});
  </script>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::playground_html;

    #[test]
    fn playground_contains_seed_tabs() {
        let html = playground_html();
        assert!(html.contains("Login"));
        assert!(html.contains("Profiles"));
        assert!(html.contains("Create Tenant"));
        assert!(html.contains("View Tenants"));
        assert!(html.contains("Create Entity"));
        assert!(html.contains("View Entities"));
        assert!(html.contains("Create Resource"));
        assert!(html.contains("View Resources"));
        assert!(html.contains("paste-jwt-or-api-key-here"));
        assert!(!html.contains("request.globalHeaders"));
        for suffix in ["Domain", "Client", "Channel"] {
            assert!(!html.contains(&format!("create{suffix}")));
        }
    }
}
