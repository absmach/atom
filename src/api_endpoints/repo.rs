use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::api_endpoint::{
        ApiEndpoint, ApiEndpointExecution, ApiEndpointExecutionList, ApiEndpointList,
        CreateApiEndpoint, ListApiEndpointExecutions, ListApiEndpoints, UpdateApiEndpoint,
    },
};

const API_ENDPOINT_COLS: &str = "id, tenant_id, key, name, description, method, path, operation_kind, graphql, auth_mode, service_entity_id, variables_mapping, request_schema, response_mapping, status, created_by, updated_by, created_at, updated_at";
const API_ENDPOINT_EXECUTION_COLS: &str = "id, endpoint_id, caller_entity_id, status, request_summary, response_summary, error, created_at";

pub async fn create_api_endpoint(
    pool: &PgPool,
    req: CreateApiEndpoint,
    created_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    let method = normalize_method(&req.method)?;
    validate_path(&req.path)?;
    validate_operation_kind(&req.operation_kind)?;
    validate_graphql_endpoint(&req.graphql)?;
    let auth_mode = req.auth_mode.unwrap_or_else(|| "caller_context".into());
    validate_auth_mode(&auth_mode, req.service_entity_id)?;
    let status = req.status.unwrap_or_else(|| "draft".into());
    validate_status(&status)?;
    validate_json_object("variables_mapping", &req.variables_mapping)?;
    validate_json_object("request_schema", &req.request_schema)?;
    validate_json_object("response_mapping", &req.response_mapping)?;

    let id = Uuid::new_v4();
    sqlx::query_as::<_, ApiEndpoint>(&format!(
        r#"INSERT INTO api_endpoints
           (id, tenant_id, key, name, description, method, path, operation_kind,
            graphql, auth_mode, service_entity_id, variables_mapping, request_schema,
            response_mapping, status, created_by, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                   $9, $10, $11, $12, $13, $14, $15, $16, $16)
           RETURNING {API_ENDPOINT_COLS}"#,
    ))
    .bind(id)
    .bind(req.tenant_id)
    .bind(req.key)
    .bind(req.name)
    .bind(req.description)
    .bind(method)
    .bind(req.path)
    .bind(req.operation_kind)
    .bind(req.graphql)
    .bind(auth_mode)
    .bind(req.service_entity_id)
    .bind(json_object_or_default(req.variables_mapping))
    .bind(json_object_or_default(req.request_schema))
    .bind(json_object_or_default(req.response_mapping))
    .bind(status)
    .bind(created_by)
    .fetch_one(pool)
    .await
    .map_err(endpoint_db_err)
}

pub async fn get_api_endpoint(pool: &PgPool, id: Uuid) -> Result<ApiEndpoint, AppError> {
    sqlx::query_as::<_, ApiEndpoint>(&format!(
        "SELECT {API_ENDPOINT_COLS} FROM api_endpoints WHERE id = $1",
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("api endpoint {id} not found")),
        other => endpoint_db_err(other),
    })
}

pub async fn list_api_endpoints(
    pool: &PgPool,
    params: ListApiEndpoints,
) -> Result<ApiEndpointList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let tenant_id = params.tenant_id;
    let status = params.status;
    if let Some(status) = status.as_deref() {
        validate_status(status)?;
    }

    let items = sqlx::query_as::<_, ApiEndpoint>(&format!(
        r#"SELECT {API_ENDPOINT_COLS} FROM api_endpoints
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR status = $2)
           ORDER BY tenant_id NULLS FIRST, key
           LIMIT $3 OFFSET $4"#,
    ))
    .bind(tenant_id)
    .bind(status.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(endpoint_db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM api_endpoints
           WHERE ($1::uuid IS NULL OR tenant_id = $1)
             AND ($2::text IS NULL OR status = $2)"#,
    )
    .bind(tenant_id)
    .bind(status)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ApiEndpointList { items, total })
}

pub async fn update_api_endpoint(
    pool: &PgPool,
    id: Uuid,
    req: UpdateApiEndpoint,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    if let Some(method) = req.method.as_deref() {
        normalize_method(method)?;
    }
    if let Some(path) = req.path.as_deref() {
        validate_path(path)?;
    }
    if let Some(operation_kind) = req.operation_kind.as_deref() {
        validate_operation_kind(operation_kind)?;
    }
    if let Some(graphql) = req.graphql.as_deref() {
        validate_graphql_endpoint(graphql)?;
    }
    if let Some(status) = req.status.as_deref() {
        validate_status(status)?;
    }
    if let Some(value) = req.variables_mapping.as_ref() {
        validate_json_object("variables_mapping", value)?;
    }
    if let Some(value) = req.request_schema.as_ref() {
        validate_json_object("request_schema", value)?;
    }
    if let Some(value) = req.response_mapping.as_ref() {
        validate_json_object("response_mapping", value)?;
    }

    let existing = get_api_endpoint(pool, id).await?;
    let auth_mode = req
        .auth_mode
        .clone()
        .unwrap_or_else(|| existing.auth_mode.clone());
    let service_entity_id = req.service_entity_id.or(existing.service_entity_id);
    validate_auth_mode(&auth_mode, service_entity_id)?;

    sqlx::query_as::<_, ApiEndpoint>(&format!(
        r#"UPDATE api_endpoints
           SET key               = COALESCE($2, key),
               name              = COALESCE($3, name),
               description       = COALESCE($4, description),
               method            = COALESCE($5, method),
               path              = COALESCE($6, path),
               operation_kind    = COALESCE($7, operation_kind),
               graphql           = COALESCE($8, graphql),
               auth_mode         = COALESCE($9, auth_mode),
               service_entity_id = COALESCE($10, service_entity_id),
               variables_mapping = COALESCE($11, variables_mapping),
               request_schema    = COALESCE($12, request_schema),
               response_mapping  = COALESCE($13, response_mapping),
               status            = COALESCE($14, status),
               updated_by        = $15,
               updated_at        = now()
           WHERE id = $1
           RETURNING {API_ENDPOINT_COLS}"#,
    ))
    .bind(id)
    .bind(req.key)
    .bind(req.name)
    .bind(req.description)
    .bind(req.method.map(|method| method.to_uppercase()))
    .bind(req.path)
    .bind(req.operation_kind)
    .bind(req.graphql)
    .bind(req.auth_mode)
    .bind(req.service_entity_id)
    .bind(req.variables_mapping.map(json_object_or_default))
    .bind(req.request_schema.map(json_object_or_default))
    .bind(req.response_mapping.map(json_object_or_default))
    .bind(req.status)
    .bind(updated_by)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("api endpoint {id} not found")),
        other => endpoint_db_err(other),
    })
}

pub async fn enable_api_endpoint(
    pool: &PgPool,
    id: Uuid,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    let existing = get_api_endpoint(pool, id).await?;
    validate_graphql_endpoint(&existing.graphql)?;
    set_api_endpoint_status(pool, id, "active", updated_by).await
}

pub async fn disable_api_endpoint(
    pool: &PgPool,
    id: Uuid,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    set_api_endpoint_status(pool, id, "disabled", updated_by).await
}

pub async fn find_api_endpoint(
    pool: &PgPool,
    method: &str,
    path: &str,
) -> Result<ApiEndpoint, AppError> {
    let method = normalize_method(method)?;
    sqlx::query_as::<_, ApiEndpoint>(&format!(
        r#"SELECT {API_ENDPOINT_COLS} FROM api_endpoints
           WHERE method = $1 AND path = $2 AND status = 'active'"#,
    ))
    .bind(method)
    .bind(path)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::not_found(format!("custom endpoint {path} not found"))
        }
        other => endpoint_db_err(other),
    })
}

pub async fn record_api_endpoint_execution(
    pool: &PgPool,
    endpoint_id: Option<Uuid>,
    caller_entity_id: Option<Uuid>,
    status: &str,
    request_summary: Value,
    response_summary: Value,
    error: Option<String>,
) -> Result<ApiEndpointExecution, AppError> {
    validate_execution_status(status)?;
    sqlx::query_as::<_, ApiEndpointExecution>(&format!(
        r#"INSERT INTO api_endpoint_executions
           (id, endpoint_id, caller_entity_id, status, request_summary, response_summary, error)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING {API_ENDPOINT_EXECUTION_COLS}"#,
    ))
    .bind(Uuid::new_v4())
    .bind(endpoint_id)
    .bind(caller_entity_id)
    .bind(status)
    .bind(json_object_or_default(request_summary))
    .bind(json_object_or_default(response_summary))
    .bind(error)
    .fetch_one(pool)
    .await
    .map_err(endpoint_db_err)
}

pub async fn list_api_endpoint_executions(
    pool: &PgPool,
    params: ListApiEndpointExecutions,
) -> Result<ApiEndpointExecutionList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let items = sqlx::query_as::<_, ApiEndpointExecution>(&format!(
        r#"SELECT {API_ENDPOINT_EXECUTION_COLS} FROM api_endpoint_executions
           WHERE endpoint_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
    ))
    .bind(params.endpoint_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(endpoint_db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM api_endpoint_executions
           WHERE endpoint_id = $1"#,
    )
    .bind(params.endpoint_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ApiEndpointExecutionList { items, total })
}

async fn set_api_endpoint_status(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    validate_status(status)?;
    sqlx::query_as::<_, ApiEndpoint>(&format!(
        r#"UPDATE api_endpoints
           SET status = $2, updated_by = $3, updated_at = now()
           WHERE id = $1
           RETURNING {API_ENDPOINT_COLS}"#,
    ))
    .bind(id)
    .bind(status)
    .bind(updated_by)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("api endpoint {id} not found")),
        other => endpoint_db_err(other),
    })
}

fn validate_graphql_endpoint(graphql: &str) -> Result<(), AppError> {
    if contains_introspection(graphql) {
        return Err(AppError::bad_request(
            "api endpoints cannot run GraphQL introspection",
        ));
    }
    for operation in ["createDomain", "createClient", "createChannel"] {
        if graphql.contains(operation) {
            return Err(AppError::bad_request(format!(
                "api endpoints must use generic Atom GraphQL operations; found {operation}"
            )));
        }
    }
    Ok(())
}

fn contains_introspection(graphql: &str) -> bool {
    let lower = graphql.to_ascii_lowercase();
    lower.contains("__schema") || lower.contains("__type") || lower.contains("introspectionquery")
}

fn normalize_method(method: &str) -> Result<String, AppError> {
    let method = method.to_ascii_uppercase();
    match method.as_str() {
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => Ok(method),
        _ => Err(AppError::bad_request("unsupported api endpoint method")),
    }
}

fn validate_path(path: &str) -> Result<(), AppError> {
    if !path.starts_with("/api/custom/") {
        return Err(AppError::bad_request(
            "api endpoint path must start with /api/custom/",
        ));
    }
    if path.contains("//") || path.contains("..") || path.contains('?') || path.contains('#') {
        return Err(AppError::bad_request("api endpoint path is invalid"));
    }
    Ok(())
}

fn validate_auth_mode(auth_mode: &str, service_entity_id: Option<Uuid>) -> Result<(), AppError> {
    match auth_mode {
        "caller_context" => Ok(()),
        "service_context" if service_entity_id.is_some() => Ok(()),
        "service_context" => Err(AppError::bad_request(
            "service_context endpoints require serviceEntityId",
        )),
        _ => Err(AppError::bad_request("unsupported api endpoint authMode")),
    }
}

fn validate_operation_kind(operation_kind: &str) -> Result<(), AppError> {
    match operation_kind {
        "query" | "mutation" => Ok(()),
        _ => Err(AppError::bad_request(
            "unsupported api endpoint operationKind",
        )),
    }
}

fn validate_status(status: &str) -> Result<(), AppError> {
    match status {
        "draft" | "active" | "disabled" => Ok(()),
        _ => Err(AppError::bad_request("unsupported api endpoint status")),
    }
}

fn validate_execution_status(status: &str) -> Result<(), AppError> {
    match status {
        "success" | "error" | "denied" => Ok(()),
        _ => Err(AppError::bad_request(
            "unsupported api endpoint execution status",
        )),
    }
}

fn validate_json_object(name: &str, value: &Value) -> Result<(), AppError> {
    if value.is_null() || value.is_object() {
        Ok(())
    } else {
        Err(AppError::bad_request(format!(
            "{name} must be a JSON object"
        )))
    }
}

fn json_object_or_default(value: Value) -> Value {
    if value.is_null() {
        serde_json::json!({})
    } else {
        value
    }
}

fn endpoint_db_err(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &err {
        if db.code().as_deref() == Some("23505") {
            return AppError::conflict("api endpoint key or active method/path already exists");
        }
    }
    db_err(err)
}
