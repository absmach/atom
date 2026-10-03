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

/// What a tool does to state, surfaced to clients as MCP tool annotations so
/// they can auto-approve reads and confirm writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    /// Adds state; repeating it is harmless or rejected as a conflict.
    Write,
    /// Removes access or data.
    Destructive,
}

struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input_schema: fn() -> Value,
    access: Access,
    /// GraphQL document run on the caller's behalf; tool arguments are its variables.
    query: &'static str,
    /// Top-level response field returned as the tool result.
    field: &'static str,
    /// Pass the arguments as `{ "input": arguments }` (input-object operations).
    wrap_input: bool,
}

impl Tool {
    fn descriptor(&self) -> Value {
        let annotations = match self.access {
            Access::Read => json!({ "readOnlyHint": true }),
            Access::Write => json!({ "readOnlyHint": false, "destructiveHint": false }),
            Access::Destructive => json!({ "readOnlyHint": false, "destructiveHint": true }),
        };
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": (self.input_schema)(),
            "annotations": annotations,
        })
    }
}

const TOOLS: &[Tool] = &[
    // --- Authorization -----------------------------------------------------
    Tool {
        name: "authz_check",
        title: "Check access",
        description: "Ask Atom's policy decision point whether a subject may perform an \
                      action on a resource or object. Returns allowed plus a reason.",
        input_schema: authz_input_schema,
        access: Access::Read,
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
        access: Access::Read,
        query: "mutation McpAuthzExplain($input: AuthzCheckInput!) { \
                authzExplain(input: $input) { allowed reason subject resource \
                capability matchedBinding evaluatedBindings } }",
        field: "authzExplain",
        wrap_input: true,
    },
    // --- Entities ----------------------------------------------------------
    Tool {
        name: "list_entities",
        title: "List entities",
        description: "List identities (humans, devices, services, workloads, applications) \
                      visible to the caller, with optional search and filters. Paginate \
                      with limit/offset; the result includes the total match count.",
        input_schema: list_entities_input_schema,
        access: Access::Read,
        query: "query McpListEntities($q: String, $kind: EntityKind, $tenantId: ID, \
                $status: EntityStatus, $limit: Int, $offset: Int) { \
                entities(q: $q, kind: $kind, tenantId: $tenantId, status: $status, \
                limit: $limit, offset: $offset) { total items { id kind name alias \
                externalId tenantId status attributes createdAt } } }",
        field: "entities",
        wrap_input: false,
    },
    Tool {
        name: "get_entity",
        title: "Get entity",
        description: "Fetch one identity by id, including its attributes and the object \
                      groups it belongs to.",
        input_schema: id_input_schema,
        access: Access::Read,
        query: "query McpGetEntity($id: ID!) { entity(id: $id) { id kind name alias \
                externalId tenantId profileId objectGroupIds status attributes \
                createdAt updatedAt managedBy } }",
        field: "entity",
        wrap_input: false,
    },
    // --- Resources ---------------------------------------------------------
    Tool {
        name: "list_resources",
        title: "List resources",
        description: "List protected resources visible to the caller, with optional \
                      search and filters by kind and tenant. Paginate with limit/offset.",
        input_schema: list_resources_input_schema,
        access: Access::Read,
        query: "query McpListResources($q: String, $kind: String, $tenantId: ID, \
                $limit: Int, $offset: Int) { resources(q: $q, kind: $kind, \
                tenantId: $tenantId, limit: $limit, offset: $offset) { total items { \
                id kind name alias tenantId ownerId attributes createdAt } } }",
        field: "resources",
        wrap_input: false,
    },
    Tool {
        name: "get_resource",
        title: "Get resource",
        description: "Fetch one resource by id, including its attributes, owner, and the \
                      object groups it belongs to.",
        input_schema: id_input_schema,
        access: Access::Read,
        query: "query McpGetResource($id: ID!) { resource(id: $id) { id kind name alias \
                tenantId ownerId objectGroupIds attributes createdAt updatedAt \
                managedBy } }",
        field: "resource",
        wrap_input: false,
    },
    // --- Tenants and groups ------------------------------------------------
    Tool {
        name: "list_tenants",
        title: "List tenants",
        description: "List tenants visible to the caller, with optional search and status \
                      filter. Paginate with limit/offset.",
        input_schema: list_tenants_input_schema,
        access: Access::Read,
        query: "query McpListTenants($q: String, $status: TenantStatus, $limit: Int, \
                $offset: Int) { tenants(q: $q, status: $status, limit: $limit, \
                offset: $offset) { total items { id name alias status tags attributes \
                createdAt } } }",
        field: "tenants",
        wrap_input: false,
    },
    Tool {
        name: "list_groups",
        title: "List groups",
        description: "List groups visible to the caller. Filter by tenant or by parent \
                      group to walk the hierarchy. Paginate with limit/offset.",
        input_schema: list_groups_input_schema,
        access: Access::Read,
        query: "query McpListGroups($q: String, $tenantId: ID, $parentId: ID, \
                $limit: Int, $offset: Int) { groups(q: $q, tenantId: $tenantId, \
                parentId: $parentId, limit: $limit, offset: $offset) { total items { \
                id name tenantId groupType description parentId status attributes \
                createdAt } } }",
        field: "groups",
        wrap_input: false,
    },
    Tool {
        name: "list_group_members",
        title: "List group members",
        description: "List the entities that are members of a group.",
        input_schema: group_input_schema,
        access: Access::Read,
        query: "query McpListGroupMembers($groupId: ID!) { groupMembers(groupId: $groupId) \
                { id kind name alias tenantId status } }",
        field: "groupMembers",
        wrap_input: false,
    },
    // --- Roles -------------------------------------------------------------
    Tool {
        name: "list_roles",
        title: "List roles",
        description: "List roles with their permission blocks (scope, effect, ABAC \
                      conditions, and actions). Use it to find the role id to assign.",
        input_schema: list_roles_input_schema,
        access: Access::Read,
        query: "query McpListRoles($tenantId: ID, $q: String, $limit: Int, $offset: Int) { \
                roles(tenantId: $tenantId, q: $q, limit: $limit, offset: $offset) { \
                total items { id name tenantId description permissionBlocks { id \
                scopeMode objectKind objectType objectId groupId effect conditions \
                actions { name } } } } }",
        field: "roles",
        wrap_input: false,
    },
    Tool {
        name: "list_role_assignments",
        title: "List role assignments",
        description: "List which roles are assigned to which subjects. Filter by subject \
                      to see an entity's or group's direct roles (group inheritance is \
                      not expanded — use authz_explain for effective access), or by role \
                      to see who holds it.",
        input_schema: list_role_assignments_input_schema,
        access: Access::Read,
        query: "query McpListRoleAssignments($tenantId: ID, $subjectKind: SubjectKind, \
                $subjectId: ID, $roleId: ID, $limit: Int, $offset: Int) { \
                roleAssignments(tenantId: $tenantId, subjectKind: $subjectKind, \
                subjectId: $subjectId, roleId: $roleId, limit: $limit, offset: $offset) \
                { total items { id tenantId subjectKind subjectId roleId role { name } \
                createdAt managedBy } } }",
        field: "roleAssignments",
        wrap_input: false,
    },
    Tool {
        name: "assign_role",
        title: "Assign role",
        description: "Grant a role to an entity or group, optionally within a tenant. \
                      Takes effect on the next authorization check.",
        input_schema: assign_role_input_schema,
        access: Access::Write,
        query: "mutation McpAssignRole($input: CreateRoleAssignmentInput!) { \
                createRoleAssignment(input: $input) { id tenantId subjectKind subjectId \
                roleId createdAt } }",
        field: "createRoleAssignment",
        wrap_input: true,
    },
    Tool {
        name: "remove_role_assignment",
        title: "Remove role assignment",
        description: "Revoke a role assignment by its id (from list_role_assignments). \
                      The subject loses the role's access immediately.",
        input_schema: id_input_schema,
        access: Access::Destructive,
        query: "mutation McpRemoveRoleAssignment($id: ID!) { deleteRoleAssignment(id: $id) }",
        field: "deleteRoleAssignment",
        wrap_input: false,
    },
    Tool {
        name: "add_group_member",
        title: "Add group member",
        description: "Add an entity to a group; it inherits the group's grants. Adding an \
                      existing member is a no-op.",
        input_schema: group_member_input_schema,
        access: Access::Write,
        query: "mutation McpAddGroupMember($groupId: ID!, $entityId: ID!) { \
                addGroupMember(groupId: $groupId, entityId: $entityId) }",
        field: "addGroupMember",
        wrap_input: false,
    },
    Tool {
        name: "remove_group_member",
        title: "Remove group member",
        description: "Remove an entity from a group; it loses the access it inherited \
                      through that group immediately.",
        input_schema: group_member_input_schema,
        access: Access::Destructive,
        query: "mutation McpRemoveGroupMember($groupId: ID!, $entityId: ID!) { \
                removeGroupMember(groupId: $groupId, entityId: $entityId) }",
        field: "removeGroupMember",
        wrap_input: false,
    },
    // --- Audit -------------------------------------------------------------
    Tool {
        name: "list_audit_logs",
        title: "Search audit log",
        description: "Search the compliance audit trail (logins, authz checks, credential \
                      and certificate operations, updates, deletes). Newest first. Filter \
                      by actor, target, event name, outcome, and time range.",
        input_schema: list_audit_logs_input_schema,
        access: Access::Read,
        query: "query McpListAuditLogs($actorEntityId: ID, $tenantId: ID, \
                $targetKind: String, $targetId: ID, $event: String, \
                $outcome: AuditOutcome, $from: String, $to: String, $limit: Int, \
                $offset: Int) { auditLogs(actorEntityId: $actorEntityId, \
                tenantId: $tenantId, targetKind: $targetKind, targetId: $targetId, \
                event: $event, outcome: $outcome, from: $from, to: $to, limit: $limit, \
                offset: $offset) { total items { id actorEntityId tenantId targetKind \
                targetId event outcome details createdAt } } }",
        field: "auditLogs",
        wrap_input: false,
    },
];

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn uuid(description: &str) -> Value {
    json!({ "type": "string", "format": "uuid", "description": description })
}

fn limit() -> Value {
    json!({ "type": "integer", "minimum": 1, "description": "Page size. Defaults to 20." })
}

fn offset() -> Value {
    json!({ "type": "integer", "minimum": 0 })
}

fn id_input_schema() -> Value {
    object_schema(json!({ "id": uuid("Object id.") }), &["id"])
}

fn authz_input_schema() -> Value {
    object_schema(
        json!({
            "subjectId": uuid("Entity whose access is being checked."),
            "action": {
                "type": "string",
                "description": "Action name, e.g. `read`, `manage`, `revoke`.",
            },
            "resourceId": uuid("Resource to check against."),
            "objectKind": {
                "type": "string",
                "description": "Kind of a non-resource object (e.g. `entity`, `group`, \
                                `tenant`); use together with objectId.",
            },
            "objectId": uuid("Non-resource object to check against."),
            "context": {
                "type": "object",
                "description": "Request context visible to ABAC conditions as `context.*`.",
            },
        }),
        &["subjectId", "action"],
    )
}

fn list_entities_input_schema() -> Value {
    object_schema(
        json!({
            "q": { "type": "string", "description": "Free-text search." },
            "kind": {
                "type": "string",
                "enum": ["human", "device", "service", "workload", "application"],
            },
            "tenantId": uuid("Only entities in this tenant."),
            "status": { "type": "string", "enum": ["active", "inactive", "suspended"] },
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn list_resources_input_schema() -> Value {
    object_schema(
        json!({
            "q": { "type": "string", "description": "Free-text search." },
            "kind": { "type": "string", "description": "Resource kind, e.g. `file`." },
            "tenantId": uuid("Only resources in this tenant."),
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn list_tenants_input_schema() -> Value {
    object_schema(
        json!({
            "q": { "type": "string", "description": "Free-text search." },
            "status": {
                "type": "string",
                "enum": ["active", "inactive", "frozen", "deleted"],
            },
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn list_groups_input_schema() -> Value {
    object_schema(
        json!({
            "q": { "type": "string", "description": "Free-text search." },
            "tenantId": uuid("Only groups in this tenant."),
            "parentId": uuid("Only direct children of this group."),
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn group_input_schema() -> Value {
    object_schema(json!({ "groupId": uuid("Group id.") }), &["groupId"])
}

fn group_member_input_schema() -> Value {
    object_schema(
        json!({
            "groupId": uuid("Group id."),
            "entityId": uuid("Entity to add or remove."),
        }),
        &["groupId", "entityId"],
    )
}

fn list_roles_input_schema() -> Value {
    object_schema(
        json!({
            "tenantId": uuid("Only roles in this tenant."),
            "q": { "type": "string", "description": "Free-text search." },
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn list_role_assignments_input_schema() -> Value {
    object_schema(
        json!({
            "tenantId": uuid("Only assignments in this tenant."),
            "subjectKind": { "type": "string", "enum": ["entity", "group"] },
            "subjectId": uuid("Entity or group holding the role."),
            "roleId": uuid("Only assignments of this role."),
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn assign_role_input_schema() -> Value {
    object_schema(
        json!({
            "subjectKind": { "type": "string", "enum": ["entity", "group"] },
            "subjectId": uuid("Entity or group receiving the role."),
            "roleId": uuid("Role to assign (see list_roles)."),
            "tenantId": uuid("Tenant the assignment applies in; omit for a global assignment."),
        }),
        &["subjectKind", "subjectId", "roleId"],
    )
}

fn list_audit_logs_input_schema() -> Value {
    object_schema(
        json!({
            "actorEntityId": uuid("Entity that performed the action."),
            "tenantId": uuid("Only events in this tenant."),
            "targetKind": { "type": "string", "description": "e.g. `entity`, `credential`." },
            "targetId": uuid("Object the event is about."),
            "event": { "type": "string", "description": "Event name, e.g. `auth.login`." },
            "outcome": { "type": "string", "enum": ["allow", "deny", "error"] },
            "from": { "type": "string", "format": "date-time", "description": "RFC 3339." },
            "to": { "type": "string", "format": "date-time", "description": "RFC 3339." },
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
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

    /// Every advertised argument of a variables-style tool must be a variable
    /// of its document, or the client's value is silently dropped.
    #[test]
    fn input_schema_properties_are_document_variables() {
        for tool in TOOLS.iter().filter(|tool| !tool.wrap_input) {
            let schema = (tool.input_schema)();
            for property in schema["properties"].as_object().expect("properties").keys() {
                assert!(
                    tool.query.contains(&format!("${property}:")),
                    "{}: `{property}` is not a variable of its document",
                    tool.name
                );
            }
        }
    }

    /// Minimal arguments satisfying a tool's input schema: every required
    /// property, filled with a value of its declared shape.
    fn sample_arguments(tool: &Tool) -> Value {
        let schema = (tool.input_schema)();
        let required = schema["required"].as_array().expect("required");
        let args = required
            .iter()
            .map(|name| {
                let name = name.as_str().expect("property name");
                let property = &schema["properties"][name];
                let value = if let Some(first) = property["enum"].get(0) {
                    first.clone()
                } else if property["format"] == "uuid" {
                    json!("00000000-0000-0000-0000-000000000001")
                } else {
                    json!("read")
                };
                (name.to_string(), value)
            })
            .collect::<serde_json::Map<_, _>>();
        if tool.wrap_input {
            json!({ "input": args })
        } else {
            Value::Object(args)
        }
    }

    /// Pins every tool document to the real schema: a renamed field or argument
    /// fails validation (an error without a path) instead of failing at runtime.
    /// With no `AuthContext`, a valid document reaches its resolver and stops at
    /// the auth gate, which reports an error *with* a path — so this never
    /// mutates anything.
    #[tokio::test]
    async fn tool_documents_validate_against_the_schema() {
        let schema =
            Schema::build(QueryRoot::default(), mutation_root(), EmptySubscription).finish();
        for tool in TOOLS {
            let response = schema
                .execute(
                    Request::new(tool.query)
                        .variables(Variables::from_json(sample_arguments(tool))),
                )
                .await;
            assert!(
                !response.errors.is_empty()
                    && response.errors.iter().all(|err| !err.path.is_empty()),
                "{} failed validation: {:?}",
                tool.name,
                response.errors
            );
        }
    }
}
