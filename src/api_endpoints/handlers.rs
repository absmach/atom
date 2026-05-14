use std::{collections::HashMap, time::Duration};

use async_graphql::{Request as GraphqlRequest, Variables};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method},
    Extension, Json,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    api_endpoints::repo as api_endpoint_repo,
    auth::{authenticate_token, require_any_capability, scope_for_tenant, AuthContext, Scope},
    error::AppError,
    graphql::AtomSchema,
    models::api_endpoint::ApiEndpoint,
    state::AppState,
};

const MAX_CUSTOM_ENDPOINT_BODY_BYTES: usize = 1024 * 1024;
const CUSTOM_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn custom_endpoint(
    Extension(schema): Extension<AtomSchema>,
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, AppError> {
    let path = format!("/api/custom/{path}");
    let method = method.as_str().to_string();
    let endpoint = match api_endpoint_repo::find_api_endpoint(&state.pool, &method, &path).await {
        Ok(endpoint) => endpoint,
        Err(err) => {
            record_execution(
                &state,
                None,
                None,
                "denied",
                request_summary(&method, &path, json!({})),
                json!({}),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };

    let caller = match bearer_token(&headers) {
        Ok(token) => match authenticate_token(&state, token).await {
            Ok(auth) => auth,
            Err(err) => {
                record_execution(
                    &state,
                    Some(endpoint.id),
                    None,
                    "denied",
                    request_summary(&method, &path, json!({})),
                    json!({}),
                    Some(err.to_string()),
                )
                .await;
                return Err(err);
            }
        },
        Err(err) => {
            record_execution(
                &state,
                Some(endpoint.id),
                None,
                "denied",
                request_summary(&method, &path, json!({})),
                json!({}),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };

    if let Err(err) = require_any_capability(
        &state.pool,
        caller.entity_id,
        &[
            ("execute", Scope::Object(endpoint.id)),
            ("manage", Scope::Object(endpoint.id)),
            ("execute", scope_for_tenant(endpoint.tenant_id)),
            ("manage", scope_for_tenant(endpoint.tenant_id)),
        ],
    )
    .await
    {
        record_execution(
            &state,
            Some(endpoint.id),
            Some(caller.entity_id),
            "denied",
            request_summary(&method, &path, json!({})),
            json!({}),
            Some(err.to_string()),
        )
        .await;
        return Err(err);
    }

    let result = execute_endpoint(EndpointExecutionRequest {
        schema: &schema,
        state: &state,
        endpoint: &endpoint,
        caller: &caller,
        method: &method,
        path: &path,
        query: &query,
        headers: &headers,
        body,
    })
    .await;

    match result {
        Ok(value) => Ok(Json(value)),
        Err(err) => Err(err),
    }
}

struct EndpointExecutionRequest<'a> {
    schema: &'a AtomSchema,
    state: &'a AppState,
    endpoint: &'a ApiEndpoint,
    caller: &'a AuthContext,
    method: &'a str,
    path: &'a str,
    query: &'a HashMap<String, String>,
    headers: &'a HeaderMap,
    body: Bytes,
}

async fn execute_endpoint(req: EndpointExecutionRequest<'_>) -> Result<Value, AppError> {
    let EndpointExecutionRequest {
        schema,
        state,
        endpoint,
        caller,
        method,
        path,
        query,
        headers,
        body,
    } = req;
    if body.len() > MAX_CUSTOM_ENDPOINT_BODY_BYTES {
        let err = AppError::payload_too_large("custom endpoint request body is too large");
        record_execution(
            state,
            Some(endpoint.id),
            Some(caller.entity_id),
            "error",
            request_summary(method, path, json!({ "bodyBytes": body.len() })),
            json!({}),
            Some(err.to_string()),
        )
        .await;
        return Err(err);
    }

    let body_json = match parse_body(&body) {
        Ok(value) => value,
        Err(err) => {
            let err =
                AppError::bad_request(format!("custom endpoint request body must be JSON: {err}"));
            record_execution(
                state,
                Some(endpoint.id),
                Some(caller.entity_id),
                "error",
                request_summary(method, path, json!({ "bodyBytes": body.len() })),
                json!({}),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };

    if let Err(err) = validate_request_schema(&endpoint.request_schema, &body_json) {
        record_execution(
            state,
            Some(endpoint.id),
            Some(caller.entity_id),
            "error",
            request_summary(method, path, redact_value(&body_json)),
            json!({}),
            Some(err.to_string()),
        )
        .await;
        return Err(err);
    }

    if contains_introspection(&endpoint.graphql) {
        let err = AppError::bad_request("custom endpoints cannot execute introspection GraphQL");
        record_execution(
            state,
            Some(endpoint.id),
            Some(caller.entity_id),
            "error",
            request_summary(method, path, redact_value(&body_json)),
            json!({}),
            Some(err.to_string()),
        )
        .await;
        return Err(err);
    }

    let variables = match build_variables(
        &endpoint.variables_mapping,
        &body_json,
        query,
        headers,
        caller,
        path,
    ) {
        Ok(variables) => variables,
        Err(err) => {
            record_execution(
                state,
                Some(endpoint.id),
                Some(caller.entity_id),
                "error",
                request_summary(method, path, redact_value(&body_json)),
                json!({}),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };
    let execution_auth = match execution_auth_context(state, endpoint, caller).await {
        Ok(auth) => auth,
        Err(err) => {
            record_execution(
                state,
                Some(endpoint.id),
                Some(caller.entity_id),
                "error",
                request_summary(method, path, redact_value(&variables)),
                json!({}),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };
    let request_summary = request_summary(method, path, redact_value(&variables));

    let request = GraphqlRequest::new(endpoint.graphql.clone())
        .variables(Variables::from_json(variables.clone()))
        .data(execution_auth);

    let response =
        match tokio::time::timeout(CUSTOM_ENDPOINT_TIMEOUT, schema.execute(request)).await {
            Ok(response) => response,
            Err(_) => {
                let err = AppError::bad_request("custom endpoint execution timed out");
                record_execution(
                    state,
                    Some(endpoint.id),
                    Some(caller.entity_id),
                    "error",
                    request_summary,
                    json!({}),
                    Some(err.to_string()),
                )
                .await;
                return Err(err);
            }
        };

    if !response.errors.is_empty() {
        let errors = serde_json::to_value(&response.errors).unwrap_or_else(|_| json!([]));
        record_execution(
            state,
            Some(endpoint.id),
            Some(caller.entity_id),
            "error",
            request_summary,
            json!({ "errors": redact_value(&errors) }),
            Some("GraphQL execution returned errors".into()),
        )
        .await;
        return Err(AppError::bad_request(
            "custom endpoint GraphQL execution failed",
        ));
    }

    let data = match response.data.into_json() {
        Ok(data) => data,
        Err(err) => {
            let err = AppError::Internal(anyhow::anyhow!("GraphQL data serialization: {err}"));
            record_execution(
                state,
                Some(endpoint.id),
                Some(caller.entity_id),
                "error",
                request_summary,
                json!({}),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };
    let mapped = match apply_response_mapping(&endpoint.response_mapping, &data) {
        Ok(mapped) => mapped,
        Err(err) => {
            record_execution(
                state,
                Some(endpoint.id),
                Some(caller.entity_id),
                "error",
                request_summary,
                redact_value(&data),
                Some(err.to_string()),
            )
            .await;
            return Err(err);
        }
    };
    record_execution(
        state,
        Some(endpoint.id),
        Some(caller.entity_id),
        "success",
        request_summary,
        redact_value(&mapped),
        None,
    )
    .await;
    Ok(mapped)
}

async fn execution_auth_context(
    state: &AppState,
    endpoint: &crate::models::api_endpoint::ApiEndpoint,
    caller: &AuthContext,
) -> Result<AuthContext, AppError> {
    match endpoint.auth_mode.as_str() {
        "caller_context" => Ok(caller.clone()),
        "service_context" => {
            let service_entity_id = endpoint.service_entity_id.ok_or_else(|| {
                AppError::bad_request("service_context endpoint has no service entity")
            })?;
            let row = sqlx::query(
                r#"SELECT e.tenant_id, e.status AS entity_status, t.status AS tenant_status
                   FROM entities e
                   LEFT JOIN tenants t ON t.id = e.tenant_id
                   WHERE e.id = $1"#,
            )
            .bind(service_entity_id)
            .fetch_one(&state.pool)
            .await
            .map_err(crate::error::db_err)?;
            use sqlx::Row;
            let entity_status: crate::models::enums::EntityStatus =
                row.try_get("entity_status").map_err(crate::error::db_err)?;
            if entity_status != crate::models::enums::EntityStatus::Active {
                return Err(AppError::Forbidden);
            }
            if let Some(tenant_status) = row
                .try_get::<Option<crate::models::enums::TenantStatus>, _>("tenant_status")
                .unwrap_or(None)
            {
                if tenant_status != crate::models::enums::TenantStatus::Active {
                    return Err(AppError::Forbidden);
                }
            }
            let tenant_id: Option<Uuid> = row.try_get("tenant_id").unwrap_or(None);
            Ok(AuthContext {
                entity_id: service_entity_id,
                tenant_id,
                session_id: None,
            })
        }
        _ => Err(AppError::bad_request("unsupported api endpoint auth mode")),
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;
    value
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("expected Bearer token"))
}

fn parse_body(body: &[u8]) -> Result<Value, serde_json::Error> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body)
    }
}

fn validate_request_schema(schema: &Value, body: &Value) -> Result<(), AppError> {
    if schema.as_object().map(Map::is_empty).unwrap_or(false) {
        return Ok(());
    }
    let compiled = jsonschema::JSONSchema::compile(schema)
        .map_err(|err| AppError::bad_request(format!("invalid requestSchema: {err}")))?;
    if let Err(errors) = compiled.validate(body) {
        let messages = errors.map(|err| err.to_string()).collect::<Vec<_>>();
        return Err(AppError::bad_request(format!(
            "request body failed requestSchema validation: {}",
            messages.join("; ")
        )));
    }
    Ok(())
}

fn build_variables(
    mapping: &Value,
    body: &Value,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    auth: &AuthContext,
    path: &str,
) -> Result<Value, AppError> {
    let Some(map) = mapping.as_object() else {
        return Err(AppError::bad_request(
            "variablesMapping must be a JSON object",
        ));
    };
    if map.is_empty() {
        return Ok(body.clone());
    }

    let mut variables = Value::Object(Map::new());
    for (target, source) in map {
        let Some(value) = resolve_mapping_source(source, body, query, headers, auth, path)? else {
            continue;
        };
        set_dotted_value(&mut variables, target, value)?;
    }
    Ok(variables)
}

fn resolve_mapping_source(
    source: &Value,
    body: &Value,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    auth: &AuthContext,
    path: &str,
) -> Result<Option<Value>, AppError> {
    let Some(source) = source.as_str() else {
        return Ok(Some(source.clone()));
    };
    let Some(source) = source.strip_prefix('$') else {
        return Ok(Some(Value::String(source.to_string())));
    };
    if source == "path" || source == "path.path" {
        return Ok(Some(Value::String(path.to_string())));
    }
    if let Some(rest) = source.strip_prefix("body.") {
        return Ok(select_value(body, rest).cloned());
    }
    if source == "body" {
        return Ok(Some(body.clone()));
    }
    if let Some(rest) = source.strip_prefix("query.") {
        return Ok(query.get(rest).cloned().map(Value::String));
    }
    if let Some(rest) = source.strip_prefix("headers.") {
        return Ok(headers
            .get(rest)
            .and_then(|value| value.to_str().ok())
            .map(|value| Value::String(value.to_string())));
    }
    if let Some(rest) = source.strip_prefix("auth.") {
        return match rest {
            "entityId" | "entity_id" => Ok(Some(Value::String(auth.entity_id.to_string()))),
            "tenantId" | "tenant_id" => Ok(auth.tenant_id.map(|id| Value::String(id.to_string()))),
            "sessionId" | "session_id" => {
                Ok(auth.session_id.map(|id| Value::String(id.to_string())))
            }
            _ => Ok(None),
        };
    }
    Err(AppError::bad_request(format!(
        "unsupported variablesMapping source ${source}"
    )))
}

fn select_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |current, part| {
        if let Ok(index) = part.parse::<usize>() {
            current.as_array()?.get(index)
        } else {
            current.as_object()?.get(part)
        }
    })
}

fn set_dotted_value(target: &mut Value, path: &str, value: Value) -> Result<(), AppError> {
    if path.is_empty() {
        return Err(AppError::bad_request(
            "variablesMapping target cannot be empty",
        ));
    }
    let mut current = target;
    let parts = path.split('.').collect::<Vec<_>>();
    for part in &parts[..parts.len() - 1] {
        let object = current.as_object_mut().ok_or_else(|| {
            AppError::bad_request("variablesMapping target path must be an object")
        })?;
        current = object
            .entry((*part).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    let object = current
        .as_object_mut()
        .ok_or_else(|| AppError::bad_request("variablesMapping target path must be an object"))?;
    object.insert(parts[parts.len() - 1].to_string(), value);
    Ok(())
}

fn apply_response_mapping(mapping: &Value, data: &Value) -> Result<Value, AppError> {
    let Some(map) = mapping.as_object() else {
        return Err(AppError::bad_request(
            "responseMapping must be a JSON object",
        ));
    };
    if map.is_empty() {
        return Ok(data.clone());
    }

    let mut response = Map::new();
    for (target, selector) in map {
        let value =
            if let Some(selector) = selector.as_str().and_then(|value| value.strip_prefix("$.")) {
                select_value(data, selector).cloned().unwrap_or(Value::Null)
            } else {
                selector.clone()
            };
        response.insert(target.clone(), value);
    }
    Ok(Value::Object(response))
}

fn request_summary(method: &str, path: &str, variables_or_body: Value) -> Value {
    json!({
        "method": method,
        "path": path,
        "variablesOrBody": variables_or_body
    })
}

fn redact_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(key) {
                        Value::String("<redacted>".into())
                    } else {
                        redact_value(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("password")
        || key.contains("secret")
        || key.contains("token")
        || key.contains("authorization")
        || key.contains("apikey")
        || key.contains("api_key")
        || key.contains("api-key")
}

fn contains_introspection(graphql: &str) -> bool {
    let lower = graphql.to_ascii_lowercase();
    lower.contains("__schema") || lower.contains("__type") || lower.contains("introspectionquery")
}

async fn record_execution(
    state: &AppState,
    endpoint_id: Option<Uuid>,
    caller_entity_id: Option<Uuid>,
    status: &str,
    request_summary: Value,
    response_summary: Value,
    error: Option<String>,
) {
    if let Err(err) = api_endpoint_repo::record_api_endpoint_execution(
        &state.pool,
        endpoint_id,
        caller_entity_id,
        status,
        request_summary,
        response_summary,
        error,
    )
    .await
    {
        tracing::warn!("failed to record api endpoint execution: {err}");
    }
}
