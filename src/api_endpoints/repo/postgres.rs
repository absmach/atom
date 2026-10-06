//! Native postgres API endpoint storage.

use serde_json::Value;
use sqlx::{PgConnection as Connection, PgPool as Database};
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

pub(super) async fn get_api_endpoint(pool: &Database, id: Uuid) -> Result<ApiEndpoint, AppError> {
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

pub(super) async fn list_api_endpoints(
    pool: &Database,
    params: ListApiEndpoints,
) -> Result<ApiEndpointList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let tenant_id = params.tenant_id;
    let status = params.status;

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

pub(super) async fn find_api_endpoint(
    pool: &Database,
    method: &str,
    path: &str,
) -> Result<ApiEndpoint, AppError> {
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

pub(super) async fn record_api_endpoint_execution(
    pool: &Database,
    endpoint_id: Option<Uuid>,
    caller_entity_id: Option<Uuid>,
    status: &str,
    request_summary: Value,
    response_summary: Value,
    error: Option<String>,
) -> Result<ApiEndpointExecution, AppError> {
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
    .bind(request_summary)
    .bind(response_summary)
    .bind(error)
    .fetch_one(pool)
    .await
    .map_err(endpoint_db_err)
}

pub(super) async fn list_api_endpoint_executions(
    pool: &Database,
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

pub(super) async fn insert_endpoint(
    conn: &mut Connection,
    id: Uuid,
    req: CreateApiEndpoint,
    actor_id: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
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
    .bind(req.method)
    .bind(req.path)
    .bind(req.operation_kind)
    .bind(req.graphql)
    .bind(req.auth_mode)
    .bind(req.service_entity_id)
    .bind(req.variables_mapping)
    .bind(req.request_schema)
    .bind(req.response_mapping)
    .bind(req.status)
    .bind(actor_id)
    .fetch_one(conn)
    .await
    .map_err(endpoint_db_err)
}

pub(super) async fn update_endpoint(
    conn: &mut Connection,
    id: Uuid,
    req: UpdateApiEndpoint,
    actor_id: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
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
    .bind(req.method)
    .bind(req.path)
    .bind(req.operation_kind)
    .bind(req.graphql)
    .bind(req.auth_mode)
    .bind(req.service_entity_id)
    .bind(req.variables_mapping)
    .bind(req.request_schema)
    .bind(req.response_mapping)
    .bind(req.status)
    .bind(actor_id)
    .fetch_one(conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("api endpoint {id} not found")),
        other => endpoint_db_err(other),
    })
}

pub(super) async fn set_status(
    conn: &mut Connection,
    id: Uuid,
    status: &str,
    actor_id: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    sqlx::query_as::<_, ApiEndpoint>(&format!(
        r#"UPDATE api_endpoints
           SET status = $2, updated_by = $3, updated_at = now()
           WHERE id = $1
           RETURNING {API_ENDPOINT_COLS}"#,
    ))
    .bind(id)
    .bind(status)
    .bind(actor_id)
    .fetch_one(conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("api endpoint {id} not found")),
        other => endpoint_db_err(other),
    })
}
fn endpoint_db_err(err: sqlx::Error) -> AppError {
    if crate::error::is_unique_violation(&err) {
        if crate::error::unique_violation_constraint(&err) == Some("protected_object_ids_pkey") {
            return AppError::conflict("api endpoint id is already used by another object");
        }
        return AppError::conflict("api endpoint key or active method/path already exists");
    }
    db_err(err)
}

pub(super) async fn service_identity(
    pool: &Database,
    id: Uuid,
) -> Result<super::ServiceIdentity, AppError> {
    sqlx::query_as::<_, super::ServiceIdentity>(
        "SELECT e.tenant_id, e.status AS entity_status, t.status AS tenant_status
         FROM entities e LEFT JOIN tenants t ON t.id = e.tenant_id WHERE e.id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}
