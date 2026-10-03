//! MCP (Model Context Protocol) server over Streamable HTTP at `POST /mcp`.
//!
//! Stateless: each request carries one JSON-RPC message and gets a plain
//! `application/json` reply — no sessions and no SSE stream (`GET` answers 405,
//! which the spec permits). Bearer-only: cookie auth is ambient, so it is
//! refused here rather than letting a browser drive tool calls.
//!
//! Each tool is a fixed GraphQL document executed against the live schema with
//! the caller's `AuthContext`, so control-plane gates, PDP decisions, the
//! access-token ceiling, and the audit/event paths are the resolvers' own. This
//! module adds no authorization of its own — do not add a tool that bypasses
//! the schema without bringing those along.

use async_graphql::{Request, Variables};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::{
    auth::{
        authenticate_token, require_trusted_origin, token_from_headers, AuthContext,
        AuthTokenSource,
    },
    build_info,
    error::AppError,
    graphql::AtomSchema,
    state::AppState,
};

const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

pub async fn mcp_handler(
    Extension(schema): Extension<AtomSchema>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // DNS-rebinding guard required by the transport spec: a browser-originated
    // request must come from a configured origin. Native clients send no Origin.
    if headers.contains_key(header::ORIGIN) {
        if let Err(err) = require_trusted_origin(&headers, &state.config.cors_allowed_origins) {
            return err.into_response();
        }
    }
    let auth = match authenticate(&state, &headers).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };

    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_error(Value::Null, PARSE_ERROR, "invalid JSON");
    };
    if !message.is_object() {
        return rpc_error(
            Value::Null,
            INVALID_REQUEST,
            "expected a single JSON-RPC message",
        );
    }
    // A message without an id is a notification (`notifications/initialized`,
    // `notifications/cancelled`, ...) and gets no JSON-RPC reply.
    let Some(id) = message.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return rpc_error(id, INVALID_REQUEST, "missing method");
    };
    let params = message.get("params").unwrap_or(&Value::Null);

    match method {
        "initialize" => rpc_result(id, initialize(params)),
        "ping" => rpc_result(id, json!({})),
        "tools/list" => rpc_result(
            id,
            json!({ "tools": TOOLS.iter().map(Tool::descriptor).collect::<Vec<_>>() }),
        ),
        "tools/call" => match call_tool(&schema, auth, params).await {
            Ok(result) => rpc_result(id, result),
            Err(message) => rpc_error(id, INVALID_PARAMS, &message),
        },
        _ => rpc_error(id, METHOD_NOT_FOUND, "method not found"),
    }
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, Response> {
    let token = match token_from_headers(headers) {
        Ok(Some((token, AuthTokenSource::Authorization))) => token,
        Ok(Some((_, AuthTokenSource::Cookie)) | None) => {
            return Err(unauthorized(AppError::unauthorized(
                "MCP requires an Authorization: Bearer token",
            )))
        }
        Err(err) => return Err(unauthorized(err)),
    };
    authenticate_token(state, token).await.map_err(unauthorized)
}

/// MCP clients start their auth flow from `WWW-Authenticate` on a 401.
fn unauthorized(err: AppError) -> Response {
    let mut response = err.into_response();
    if response.status() == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

fn initialize(params: &Value) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|requested| SUPPORTED_PROTOCOL_VERSIONS.contains(requested))
        .unwrap_or(LATEST_PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "atom", "version": build_info::VERSION },
    })
}

async fn call_tool(
    schema: &AtomSchema,
    auth: AuthContext,
    params: &Value,
) -> Result<Value, String> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing tool name".to_string())?;
    let tool = TOOLS
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| format!("unknown tool: {name}"))?;
    let args = match params.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(args @ Value::Object(_)) => args.clone(),
        Some(_) => return Err("arguments must be an object".to_string()),
    };
    let variables = if tool.wrap_input {
        json!({ "input": args })
    } else {
        args
    };

    let request = Request::new(tool.query)
        .variables(Variables::from_json(variables))
        .data(auth);
    let response = schema.execute(request).await;

    // GraphQL errors (denied, not found, bad argument) are tool execution
    // errors: the model sees them and can correct itself.
    if !response.errors.is_empty() {
        let message = response
            .errors
            .iter()
            .map(|err| err.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Ok(json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true,
        }));
    }
    let data = response.data.into_json().map_err(|err| err.to_string())?;
    let value = data.get(tool.field).cloned().unwrap_or(Value::Null);
    Ok(json!({
        "content": [{ "type": "text", "text": value.to_string() }],
        "structuredContent": value,
        "isError": false,
    }))
}

fn rpc_result(id: Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn rpc_error(id: Value, code: i64, message: &str) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    }))
    .into_response()
}

struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input_schema: fn() -> Value,
    read_only: bool,
    /// GraphQL document run on the caller's behalf; tool arguments are its variables.
    query: &'static str,
    /// Top-level response field returned as the tool result.
    field: &'static str,
    /// Pass the arguments as `{ "input": arguments }` (input-object operations).
    wrap_input: bool,
}

impl Tool {
    fn descriptor(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": (self.input_schema)(),
            "annotations": { "readOnlyHint": self.read_only },
        })
    }
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "authz_check",
        title: "Check access",
        description: "Ask Atom's policy decision point whether a subject may perform an \
                      action on a resource or object. Returns allowed plus a reason.",
        input_schema: authz_input_schema,
        read_only: true,
        query: "mutation McpAuthzCheck($input: AuthzCheckInput!) { \
                authzCheck(input: $input) { allowed reason details } }",
        field: "authzCheck",
        wrap_input: true,
    },
    Tool {
        name: "authz_explain",
        title: "Explain access decision",
        description: "Like authz_check, but also returns every grant that was evaluated \
                      and the one that decided the outcome. Use it to find out why \
                      access is allowed or denied.",
        input_schema: authz_input_schema,
        read_only: true,
        query: "mutation McpAuthzExplain($input: AuthzCheckInput!) { \
                authzExplain(input: $input) { allowed reason subject resource \
                capability matchedBinding evaluatedBindings } }",
        field: "authzExplain",
        wrap_input: true,
    },
    Tool {
        name: "list_entities",
        title: "List entities",
        description: "List identities (humans, devices, services, workloads, applications) \
                      visible to the caller, with optional search and filters. Paginate \
                      with limit/offset; the result includes the total match count.",
        input_schema: list_entities_input_schema,
        read_only: true,
        query: "query McpListEntities($q: String, $kind: EntityKind, $tenantId: ID, \
                $status: EntityStatus, $limit: Int, $offset: Int) { \
                entities(q: $q, kind: $kind, tenantId: $tenantId, status: $status, \
                limit: $limit, offset: $offset) { total items { id kind name alias \
                externalId tenantId status attributes createdAt } } }",
        field: "entities",
        wrap_input: false,
    },
];

fn authz_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "subjectId": {
                "type": "string",
                "format": "uuid",
                "description": "Entity whose access is being checked.",
            },
            "action": {
                "type": "string",
                "description": "Action name, e.g. `read`, `manage`, `revoke`.",
            },
            "resourceId": {
                "type": "string",
                "format": "uuid",
                "description": "Resource to check against.",
            },
            "objectKind": {
                "type": "string",
                "description": "Kind of a non-resource object (e.g. `entity`, `group`, \
                                `tenant`); use together with objectId.",
            },
            "objectId": { "type": "string", "format": "uuid" },
            "context": {
                "type": "object",
                "description": "Request context visible to ABAC conditions as `context.*`.",
            },
        },
        "required": ["subjectId", "action"],
        "additionalProperties": false,
    })
}

fn list_entities_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "q": { "type": "string", "description": "Free-text search." },
            "kind": {
                "type": "string",
                "enum": ["human", "device", "service", "workload", "application"],
            },
            "tenantId": { "type": "string", "format": "uuid" },
            "status": { "type": "string", "enum": ["active", "inactive", "suspended"] },
            "limit": { "type": "integer", "minimum": 1, "description": "Defaults to 20." },
            "offset": { "type": "integer", "minimum": 0 },
        },
        "additionalProperties": false,
    })
}

#[cfg(test)]
mod tests {
    use async_graphql::{EmptySubscription, Schema};

    use super::*;
    use crate::graphql::{mutation::mutation_root, query::QueryRoot};

    #[test]
    fn initialize_echoes_a_supported_version_and_falls_back_otherwise() {
        let reply = initialize(&json!({ "protocolVersion": "2025-03-26" }));
        assert_eq!(reply["protocolVersion"], "2025-03-26");

        let reply = initialize(&json!({ "protocolVersion": "1999-01-01" }));
        assert_eq!(reply["protocolVersion"], LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn tool_names_are_unique() {
        let mut names = TOOLS.iter().map(|tool| tool.name).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TOOLS.len());
    }

    /// Pins every tool document to the real schema: a renamed field or argument
    /// fails validation (an error without a path) instead of failing at runtime.
    /// With no `AuthContext`, a valid document reaches its resolver and stops at
    /// the auth gate, which reports an error *with* a path.
    #[tokio::test]
    async fn tool_documents_validate_against_the_schema() {
        let schema =
            Schema::build(QueryRoot::default(), mutation_root(), EmptySubscription).finish();
        let sample = json!({
            "subjectId": "00000000-0000-0000-0000-000000000001",
            "action": "read",
        });
        for tool in TOOLS {
            let variables = if tool.wrap_input {
                json!({ "input": sample })
            } else {
                json!({})
            };
            let response = schema
                .execute(Request::new(tool.query).variables(Variables::from_json(variables)))
                .await;
            assert!(
                response.errors.iter().all(|err| !err.path.is_empty()),
                "{} failed validation: {:?}",
                tool.name,
                response.errors
            );
        }
    }
}
