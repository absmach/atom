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
        "prompts/list" => rpc_result(
            id,
            json!({ "prompts": PROMPTS.iter().map(Prompt::descriptor).collect::<Vec<_>>() }),
        ),
        "prompts/get" => match get_prompt(params) {
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
        "capabilities": { "tools": {}, "prompts": {} },
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

    let entity_id = auth.entity_id;
    let request = Request::new(tool.query)
        .variables(Variables::from_json(variables))
        .data(auth);
    let response = schema.execute(request).await;
    // Resolvers write the audit/event rows, which do not say which surface
    // the call came through; this line is what ties them to an MCP tool.
    tracing::info!(
        tool = tool.name,
        entity_id = %entity_id,
        is_error = !response.errors.is_empty(),
        "mcp tool call"
    );

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
    let mut result = json!({
        "content": [{ "type": "text", "text": value.to_string() }],
        "isError": false,
    });
    // The spec types structuredContent as an object; lists and booleans are
    // carried by the text content alone.
    if value.is_object() {
        result["structuredContent"] = value;
    }
    Ok(result)
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
    Tool {
        name: "authz_bulk_check",
        title: "Check access in bulk",
        description: "Run up to 20 authz_check questions in one call, e.g. which of \
                      several subjects may perform an action, or which of several \
                      actions one subject may perform. Results are in input order.",
        input_schema: authz_bulk_input_schema,
        access: Access::Read,
        query: "mutation McpAuthzBulkCheck($checks: [AuthzCheckInput!]!) { \
                authzBulkCheck(input: $checks) { allowed reason details } }",
        field: "authzBulkCheck",
        wrap_input: false,
    },
    Tool {
        name: "authorized_object_ids",
        title: "List what a subject can access",
        description: "The reverse of authz_check: list the ids of every object of one \
                      kind (entity, resource, group, role, policy, api_endpoint) that a \
                      subject may perform an action on. Paginate with limit/offset.",
        input_schema: authorized_object_ids_input_schema,
        access: Access::Read,
        query: "query McpAuthorizedObjectIds($input: AuthorizedObjectIdsInput!) { \
                authorizedObjectIds(input: $input) { total ids } }",
        field: "authorizedObjectIds",
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
    Tool {
        name: "list_entity_groups",
        title: "List an entity's groups",
        description: "List the ids of the groups an entity is a direct member of.",
        input_schema: entity_input_schema,
        access: Access::Read,
        query: "query McpListEntityGroups($entityId: ID!) { entityGroups(entityId: $entityId) }",
        field: "entityGroups",
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
        name: "list_direct_policies",
        title: "List direct policies",
        description: "List permission blocks granted to a subject directly rather than \
                      through a role. Filter forward by subject or backward by the object \
                      a block names. Together with list_role_assignments this is \
                      everything granted to a subject directly.",
        input_schema: list_direct_policies_input_schema,
        access: Access::Read,
        query: "query McpListDirectPolicies($tenantId: ID, $subjectKind: SubjectKind, \
                $subjectId: ID, $objectId: ID, $objectKind: String, $limit: Int, \
                $offset: Int) { directPolicies(tenantId: $tenantId, \
                subjectKind: $subjectKind, subjectId: $subjectId, objectId: $objectId, \
                objectKind: $objectKind, limit: $limit, offset: $offset) { total items { \
                id tenantId subjectKind subjectId createdAt managedBy permissionBlock { \
                id scopeMode objectKind objectType objectId groupId effect conditions \
                actions { name } } } } }",
        field: "directPolicies",
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
    // --- Hygiene (platform administrators) ---------------------------------
    Tool {
        name: "expiring_credentials",
        title: "List expiring credentials",
        description: "List active credentials (access tokens, certificates, shared keys, \
                      passwords) that expire within the given number of days or have \
                      already expired, soonest first. Metadata only; secrets are never \
                      returned. Platform administrators only.",
        input_schema: expiring_credentials_input_schema,
        access: Access::Read,
        query: "query McpExpiringCredentials($days: Int, $entityId: ID, \
                $kind: CredentialKind, $limit: Int, $offset: Int) { \
                expiringCredentials(days: $days, entityId: $entityId, kind: $kind, \
                limit: $limit, offset: $offset) { id entityId kind identifier status \
                expiresAt createdAt } }",
        field: "expiringCredentials",
        wrap_input: false,
    },
    Tool {
        name: "orphan_policies",
        title: "List orphan policies",
        description: "List role assignments and direct policies whose subject, role, or \
                      permission block no longer exists (orphanReason says which). They \
                      are clutter worth cleaning up. Platform administrators only.",
        input_schema: page_input_schema,
        access: Access::Read,
        query: "query McpOrphanPolicies($limit: Int, $offset: Int) { \
                orphanPolicies(limit: $limit, offset: $offset) { id tenantId sourceKind \
                subjectKind subjectId roleId permissionBlockId orphanReason createdAt } }",
        field: "orphanPolicies",
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

/// `tenantId` for tools whose gate checks the platform scope when it is
/// omitted: a tenant-scoped token is refused without it, and a model that is
/// not told so gives up or guesses.
fn gated_tenant() -> Value {
    uuid(
        "Tenant to look in. Required unless the caller has platform-wide access: \
         a tenant-scoped token is refused (`forbidden`) without it.",
    )
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
            "tenantId": gated_tenant(),
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
            "tenantId": gated_tenant(),
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

fn entity_input_schema() -> Value {
    object_schema(json!({ "entityId": uuid("Entity id.") }), &["entityId"])
}

fn page_input_schema() -> Value {
    object_schema(json!({ "limit": limit(), "offset": offset() }), &[])
}

fn authz_bulk_input_schema() -> Value {
    object_schema(
        json!({
            "checks": {
                "type": "array",
                "items": authz_input_schema(),
                "minItems": 1,
                "maxItems": 20,
            },
        }),
        &["checks"],
    )
}

fn authorized_object_ids_input_schema() -> Value {
    object_schema(
        json!({
            "subjectId": uuid("Entity whose access is being listed."),
            "action": {
                "type": "string",
                "description": "Action name, e.g. `read`, `manage`.",
            },
            "objectKind": {
                "type": "string",
                "enum": ["entity", "resource", "group", "role", "policy", "api_endpoint"],
            },
            "objectType": {
                "type": "string",
                "description": "Narrow to one type within the kind, e.g. `device`.",
            },
            "tenantId": gated_tenant(),
            "q": { "type": "string", "description": "Free-text search." },
            "limit": limit(),
            "offset": offset(),
        }),
        &["subjectId", "action", "objectKind"],
    )
}

fn list_direct_policies_input_schema() -> Value {
    object_schema(
        json!({
            "tenantId": gated_tenant(),
            "subjectKind": { "type": "string", "enum": ["entity", "group"] },
            "subjectId": uuid("Entity or group holding the policy."),
            "objectId": uuid("Only blocks that name this object."),
            "objectKind": { "type": "string", "description": "e.g. `resource`, `entity`." },
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

fn expiring_credentials_input_schema() -> Value {
    object_schema(
        json!({
            "days": {
                "type": "integer",
                "minimum": 1,
                "description": "Look-ahead window in days. Defaults to 30.",
            },
            "entityId": uuid("Only this entity's credentials."),
            "kind": {
                "type": "string",
                "enum": ["password", "access_token", "certificate", "shared_key"],
            },
            "limit": limit(),
            "offset": offset(),
        }),
        &[],
    )
}

/// A ready-made workflow the user can pick from the client's prompt menu. It
/// only produces text for the user's own model; the tools it names still run
/// under the caller's token, one call at a time.
struct Prompt {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    arguments: &'static [PromptArgument],
    render: fn(&PromptArgs) -> String,
}

struct PromptArgument {
    name: &'static str,
    description: &'static str,
    required: bool,
}

impl Prompt {
    fn descriptor(&self) -> Value {
        let arguments = self
            .arguments
            .iter()
            .map(|arg| {
                json!({
                    "name": arg.name,
                    "description": arg.description,
                    "required": arg.required,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "arguments": arguments,
        })
    }
}

/// Arguments of a `prompts/get` call. The spec makes every value a string;
/// blank counts as absent.
struct PromptArgs<'a>(&'a serde_json::Map<String, Value>);

impl PromptArgs<'_> {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// A required argument; `get_prompt` has already checked it is present.
    fn value(&self, name: &str) -> &str {
        self.get(name).unwrap_or_default()
    }
}

fn get_prompt(params: &Value) -> Result<Value, String> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing prompt name".to_string())?;
    let prompt = PROMPTS
        .iter()
        .find(|prompt| prompt.name == name)
        .ok_or_else(|| format!("unknown prompt: {name}"))?;
    let empty = serde_json::Map::new();
    let args = match params.get("arguments") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(args)) => args,
        Some(_) => return Err("arguments must be an object".to_string()),
    };
    let args = PromptArgs(args);
    if let Some(missing) = prompt
        .arguments
        .iter()
        .find(|arg| arg.required && args.get(arg.name).is_none())
    {
        return Err(format!("missing required argument: {}", missing.name));
    }
    Ok(json!({
        "description": prompt.description,
        "messages": [{
            "role": "user",
            "content": { "type": "text", "text": (prompt.render)(&args) },
        }],
    }))
}

const PROMPTS: &[Prompt] = &[
    Prompt {
        name: "why_denied",
        title: "Explain an access decision",
        description: "Investigate why a subject is or is not allowed to perform an action \
                      on an object, and what the smallest fix would be.",
        arguments: &[
            PromptArgument {
                name: "subjectId",
                description: "Entity whose access is in question.",
                required: true,
            },
            PromptArgument {
                name: "action",
                description: "Action name, e.g. `read`.",
                required: true,
            },
            PromptArgument {
                name: "objectId",
                description: "Resource id, or the id of the object named by objectKind.",
                required: true,
            },
            PromptArgument {
                name: "objectKind",
                description: "Kind of the object when it is not a resource, e.g. `entity`, \
                              `group`, `tenant`.",
                required: false,
            },
        ],
        render: render_why_denied,
    },
    Prompt {
        name: "access_review",
        title: "Review access in a tenant",
        description: "Read-only review of roles, role assignments, and direct policies in a \
                      tenant, flagging broad or stale grants.",
        arguments: &[PromptArgument {
            name: "tenantId",
            description: "Tenant to review.",
            required: true,
        }],
        render: render_access_review,
    },
    Prompt {
        name: "credential_hygiene",
        title: "Check credential hygiene",
        description: "Find expiring and expired credentials, failing credential logins, and \
                      orphaned assignments. Needs platform administrator access.",
        arguments: &[PromptArgument {
            name: "days",
            description: "Look-ahead window in days. Defaults to 30.",
            required: false,
        }],
        render: render_credential_hygiene,
    },
    Prompt {
        name: "offboard_entity",
        title: "Offboard an entity",
        description: "Gather everything granted to an entity, present a removal plan, and \
                      carry it out only after explicit confirmation.",
        arguments: &[PromptArgument {
            name: "entityId",
            description: "Entity to offboard.",
            required: true,
        }],
        render: render_offboard_entity,
    },
];

fn render_why_denied(args: &PromptArgs) -> String {
    let subject = args.value("subjectId");
    let action = args.value("action");
    let object_id = args.value("objectId");
    let (target, object_args) = match args.get("objectKind") {
        Some(kind) => (
            format!("{kind} {object_id}"),
            format!("objectKind `{kind}` and objectId {object_id}"),
        ),
        None => (
            format!("resource {object_id}"),
            format!("resourceId {object_id}"),
        ),
    };
    format!(
        "Find out whether entity {subject} may `{action}` on {target}, and why.

1. Call authz_explain with subjectId {subject}, action `{action}` and {object_args}. \
If you are not allowed to call it, use authz_check with the same arguments and work \
from its reason in the steps below.
2. If access is allowed, name the grant that allowed it (matchedBinding) and how the \
subject holds it: a role assignment, a direct policy, or a group it belongs to.
3. If access is denied, say whether an explicit deny matched or no allow matched. Use \
list_role_assignments, list_direct_policies and list_entity_groups for the subject, and \
list_roles, to show what it does hold and the closest grant that falls short: wrong \
scope, missing action, a failing ABAC condition, or an inactive entity or tenant.
4. Suggest the smallest change that would give the expected outcome, and who would \
need to make it.

This is an investigation only: do not call any tool that changes access."
    )
}

fn render_access_review(args: &PromptArgs) -> String {
    let tenant = args.value("tenantId");
    format!(
        "Review who has access to what in tenant {tenant}. This is a read-only review: do \
not call any tool that changes access.

1. Call list_roles for the tenant, and again without tenantId for global roles. Note \
each role's permission blocks: scope, effect, actions, and conditions.
2. Call list_role_assignments and list_direct_policies for the tenant. Page through all \
results using limit, offset, and total.
3. Name the subjects with get_entity, or list_groups for groups. Use list_group_members \
for groups that hold roles.
4. If you are allowed to, call orphan_policies and include the ones in this tenant.

Report:
- A table of roles: what each allows and how many subjects hold it.
- Broad grants worth a second look: `manage` or tenant-wide scope, grants to large \
groups, and unconditional allows on sensitive actions such as `policy.manage`, \
`role.manage`, and `revoke`.
- Direct policies that duplicate or bypass a role.
- Grants held by inactive or suspended entities, and orphaned assignments.

End with a short, prioritized list of recommended changes."
    )
}

fn render_credential_hygiene(args: &PromptArgs) -> String {
    let days = args.get("days").unwrap_or("30");
    format!(
        "Check credential hygiene for the next {days} days. This is read-only: do not \
change anything.

1. Call expiring_credentials with days {days} and page through all results. Group them \
by owner (get_entity for names) and by kind. Call out credentials that have already \
expired but are still active.
2. Call list_audit_logs with event `auth.credential_authenticate` and outcome `deny` for \
the last 7 days (the `from` filter, RFC 3339) to spot credentials that keep failing.
3. Call orphan_policies to find assignments left behind by deleted subjects or roles.

Report what needs renewal, by date and owner, and what needs cleaning up."
    )
}

fn render_offboard_entity(args: &PromptArgs) -> String {
    let entity = args.value("entityId");
    format!(
        "Prepare to offboard entity {entity} by removing the access it holds.

Step 1, gather (read-only):
- get_entity for its name, kind, tenant, and status.
- list_role_assignments with subjectId {entity}.
- list_direct_policies with subjectId {entity}.
- list_entity_groups with entityId {entity}.

Step 2, present a numbered plan: each role assignment and each group membership to \
remove, with names, not just ids. List separately what these tools cannot do and an \
administrator must do in the Atom admin UI or GraphQL API: removing direct policies, \
revoking credentials and sessions, and deleting the entity (which also revokes its \
credentials and sessions).

Step 3, stop and ask for explicit confirmation. Only after the user confirms, call \
remove_role_assignment and remove_group_member for the approved items. Then repeat step \
1 and report what remains."
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

    #[test]
    fn prompt_names_are_unique() {
        let mut names = PROMPTS.iter().map(|prompt| prompt.name).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PROMPTS.len());
    }

    fn prompt_arguments(prompt: &Prompt) -> Value {
        let args = prompt
            .arguments
            .iter()
            .map(|arg| (arg.name.to_string(), json!("value")))
            .collect::<serde_json::Map<_, _>>();
        json!({ "name": prompt.name, "arguments": args })
    }

    #[test]
    fn prompts_refuse_a_missing_required_argument() {
        for prompt in PROMPTS {
            for required in prompt.arguments.iter().filter(|arg| arg.required) {
                let mut params = prompt_arguments(prompt);
                params["arguments"][required.name] = json!(" ");
                let err = get_prompt(&params).expect_err("blank required argument");
                assert!(err.contains(required.name), "{}: {err}", prompt.name);
            }
        }
    }

    /// A prompt that names a tool which does not exist sends the model after
    /// something it cannot call.
    #[test]
    fn prompts_only_name_existing_tools() {
        const TOOL_PREFIXES: &[&str] = &[
            "add_",
            "assign_",
            "authorized_",
            "authz_",
            "expiring_",
            "get_",
            "list_",
            "orphan_",
            "remove_",
        ];
        for prompt in PROMPTS {
            let reply = get_prompt(&prompt_arguments(prompt)).expect("prompt renders");
            let text = reply["messages"][0]["content"]["text"]
                .as_str()
                .expect("text content");
            for word in text
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| TOOL_PREFIXES.iter().any(|prefix| word.starts_with(prefix)))
            {
                assert!(
                    TOOLS.iter().any(|tool| tool.name == word),
                    "{} names unknown tool `{word}`",
                    prompt.name
                );
            }
        }
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

    /// A minimal value of a JSON Schema's declared shape; for an object, only
    /// its required properties.
    fn sample(schema: &Value) -> Value {
        if let Some(first) = schema["enum"].get(0) {
            return first.clone();
        }
        match schema["type"].as_str() {
            Some("object") => Value::Object(
                schema["required"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|name| {
                        let name = name.as_str().expect("property name");
                        (name.to_string(), sample(&schema["properties"][name]))
                    })
                    .collect(),
            ),
            Some("array") => json!([sample(&schema["items"])]),
            Some("integer") => json!(1),
            _ if schema["format"] == "uuid" => json!("00000000-0000-0000-0000-000000000001"),
            _ => json!("read"),
        }
    }

    fn sample_arguments(tool: &Tool) -> Value {
        let args = sample(&(tool.input_schema)());
        if tool.wrap_input {
            json!({ "input": args })
        } else {
            args
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
