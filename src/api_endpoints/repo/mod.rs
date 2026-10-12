//! Custom API endpoint domain contract, validation and event orchestration.
mod postgres;
mod sqlite;

use crate::db::Database;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::api_endpoint::{
        ApiEndpoint, ApiEndpointExecution, ApiEndpointExecutionList, ApiEndpointList,
        CreateApiEndpoint, ListApiEndpointExecutions, ListApiEndpoints, UpdateApiEndpoint,
    },
};

pub async fn create_api_endpoint(
    pool: &Database,
    req: CreateApiEndpoint,
    created_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    create_api_endpoint_with_audit(pool, false, created_by, req).await
}

pub async fn create_api_endpoint_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    mut req: CreateApiEndpoint,
) -> Result<ApiEndpoint, AppError> {
    let method = normalize_method(&req.method)?;
    validate_path(&req.path)?;
    validate_operation_kind(&req.operation_kind)?;
    validate_graphql_endpoint(&req.graphql)?;
    let auth_mode = req
        .auth_mode
        .take()
        .unwrap_or_else(|| "caller_context".into());
    validate_auth_mode(&auth_mode, req.service_entity_id)?;
    let status = req.status.take().unwrap_or_else(|| "draft".into());
    validate_status(&status)?;
    validate_json_object("variables_mapping", &req.variables_mapping)?;
    validate_json_object("request_schema", &req.request_schema)?;
    validate_json_object("response_mapping", &req.response_mapping)?;

    req.method = method;
    req.auth_mode = Some(auth_mode);
    req.status = Some(status);
    req.variables_mapping = json_object_or_default(req.variables_mapping);
    req.request_schema = json_object_or_default(req.request_schema);
    req.response_mapping = json_object_or_default(req.response_mapping);

    let id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let endpoint = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => {
            postgres::insert_endpoint(conn, id, req, actor_id).await?
        }
        crate::db::DbTransaction::Sqlite(conn) => {
            sqlite::insert_endpoint(conn, id, req, actor_id).await?
        }
    };
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: endpoint.tenant_id,
            target_kind: "api_endpoint",
            target_id: Some(endpoint.id),
            event: "api_endpoint.create",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(endpoint)
}

pub async fn get_api_endpoint(pool: &Database, id: Uuid) -> Result<ApiEndpoint, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::get_api_endpoint(pool, id).await,
        Database::Sqlite(db) => sqlite::get_api_endpoint(&db.pool, id).await,
    }
}

pub async fn list_api_endpoints(
    pool: &Database,
    params: ListApiEndpoints,
) -> Result<ApiEndpointList, AppError> {
    if let Some(status) = params.status.as_deref() {
        validate_status(status)?;
    }
    match pool {
        Database::Postgres(pool) => postgres::list_api_endpoints(pool, params).await,
        Database::Sqlite(db) => sqlite::list_api_endpoints(&db.pool, params).await,
    }
}

pub async fn update_api_endpoint(
    pool: &Database,
    id: Uuid,
    req: UpdateApiEndpoint,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    update_api_endpoint_with_audit(pool, false, updated_by, id, req).await
}

pub async fn update_api_endpoint_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    mut req: UpdateApiEndpoint,
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

    req.method = req.method.map(|method| method.to_uppercase());
    req.variables_mapping = req.variables_mapping.map(json_object_or_default);
    req.request_schema = req.request_schema.map(json_object_or_default);
    req.response_mapping = req.response_mapping.map(json_object_or_default);

    let mut tx = pool.begin().await.map_err(db_err)?;
    let endpoint = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => {
            postgres::update_endpoint(conn, id, req, actor_id).await?
        }
        crate::db::DbTransaction::Sqlite(conn) => {
            sqlite::update_endpoint(conn, id, req, actor_id).await?
        }
    };
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: endpoint.tenant_id,
            target_kind: "api_endpoint",
            target_id: Some(id),
            event: "api_endpoint.update",
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(endpoint)
}

pub async fn enable_api_endpoint(
    pool: &Database,
    id: Uuid,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    enable_api_endpoint_with_audit(pool, false, updated_by, id).await
}

pub async fn enable_api_endpoint_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<ApiEndpoint, AppError> {
    let existing = get_api_endpoint(pool, id).await?;
    validate_graphql_endpoint(&existing.graphql)?;
    set_api_endpoint_status_with_audit(
        pool,
        events_enabled,
        actor_id,
        id,
        "active",
        "api_endpoint.enable",
    )
    .await
}

pub async fn disable_api_endpoint(
    pool: &Database,
    id: Uuid,
    updated_by: Option<Uuid>,
) -> Result<ApiEndpoint, AppError> {
    disable_api_endpoint_with_audit(pool, false, updated_by, id).await
}

pub async fn disable_api_endpoint_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<ApiEndpoint, AppError> {
    set_api_endpoint_status_with_audit(
        pool,
        events_enabled,
        actor_id,
        id,
        "disabled",
        "api_endpoint.disable",
    )
    .await
}

pub async fn find_api_endpoint(
    pool: &Database,
    method: &str,
    path: &str,
) -> Result<ApiEndpoint, AppError> {
    let method = normalize_method(method)?;
    match pool {
        Database::Postgres(pool) => postgres::find_api_endpoint(pool, &method, path).await,
        Database::Sqlite(db) => sqlite::find_api_endpoint(&db.pool, &method, path).await,
    }
}

pub async fn record_api_endpoint_execution(
    pool: &Database,
    endpoint_id: Option<Uuid>,
    caller_entity_id: Option<Uuid>,
    status: &str,
    request_summary: Value,
    response_summary: Value,
    error: Option<String>,
) -> Result<ApiEndpointExecution, AppError> {
    validate_execution_status(status)?;
    let request_summary = json_object_or_default(request_summary);
    let response_summary = json_object_or_default(response_summary);
    match pool {
        Database::Postgres(pool) => {
            postgres::record_api_endpoint_execution(
                pool,
                endpoint_id,
                caller_entity_id,
                status,
                request_summary,
                response_summary,
                error,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::record_api_endpoint_execution(
                &db.pool,
                endpoint_id,
                caller_entity_id,
                status,
                request_summary,
                response_summary,
                error,
            )
            .await
        }
    }
}

pub async fn list_api_endpoint_executions(
    pool: &Database,
    params: ListApiEndpointExecutions,
) -> Result<ApiEndpointExecutionList, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::list_api_endpoint_executions(pool, params).await,
        Database::Sqlite(db) => sqlite::list_api_endpoint_executions(&db.pool, params).await,
    }
}

async fn set_api_endpoint_status_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    status: &str,
    event: &str,
) -> Result<ApiEndpoint, AppError> {
    validate_status(status)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    let endpoint = match &mut tx {
        crate::db::DbTransaction::Postgres(conn) => {
            postgres::set_status(conn, id, status, actor_id).await?
        }
        crate::db::DbTransaction::Sqlite(conn) => {
            sqlite::set_status(conn, id, status, actor_id).await?
        }
    };
    crate::audit::commit_with_observation(
        tx,
        events_enabled,
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: endpoint.tenant_id,
            target_kind: "api_endpoint",
            target_id: Some(id),
            event,
        },
        &serde_json::json!({}),
    )
    .await?;
    Ok(endpoint)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::{
        normalize_method, validate_auth_mode, validate_execution_status, validate_operation_kind,
        validate_path, validate_status,
    };

    fn contract() -> Value {
        serde_json::from_str(include_str!("../../../api/v1/persisted-semantics.json"))
            .expect("valid persisted-semantics contract")
    }

    fn strings(value: &Value) -> BTreeSet<&str> {
        value
            .as_array()
            .expect("string array")
            .iter()
            .map(|value| value.as_str().expect("string value"))
            .collect()
    }

    #[test]
    fn custom_endpoint_stored_enums_match_the_v1_contract() {
        let contract = contract();
        let endpoint = &contract["customEndpoint"];

        let methods = strings(&endpoint["methods"]);
        assert_eq!(
            methods,
            BTreeSet::from(["GET", "POST", "PUT", "PATCH", "DELETE"])
        );
        for method in &methods {
            assert_eq!(
                normalize_method(&method.to_ascii_lowercase()).unwrap(),
                *method
            );
        }
        assert!(normalize_method("OPTIONS").is_err());

        let operation_kinds = strings(&endpoint["operationKinds"]);
        assert_eq!(operation_kinds, BTreeSet::from(["query", "mutation"]));
        for kind in &operation_kinds {
            assert!(validate_operation_kind(kind).is_ok());
        }
        assert!(validate_operation_kind("subscription").is_err());

        let auth_modes = strings(&endpoint["authModes"]);
        assert_eq!(
            auth_modes,
            BTreeSet::from(["caller_context", "service_context"])
        );
        assert!(validate_auth_mode("caller_context", None).is_ok());
        assert!(validate_auth_mode("service_context", Some(uuid::Uuid::nil())).is_ok());
        assert!(validate_auth_mode("service_context", None).is_err());

        let statuses = strings(&endpoint["statuses"]);
        assert_eq!(statuses, BTreeSet::from(["draft", "active", "disabled"]));
        for status in &statuses {
            assert!(validate_status(status).is_ok());
        }

        let execution_statuses = strings(&endpoint["executionStatuses"]);
        assert_eq!(
            execution_statuses,
            BTreeSet::from(["success", "error", "denied"])
        );
        for status in &execution_statuses {
            assert!(validate_execution_status(status).is_ok());
        }
    }

    #[test]
    fn custom_endpoint_path_rules_match_the_v1_contract() {
        let contract = contract();
        let endpoint = &contract["customEndpoint"];
        let prefix = endpoint["pathPrefix"].as_str().expect("path prefix");
        assert_eq!(prefix, "/api/custom/");
        assert!(validate_path(&format!("{prefix}devices/online")).is_ok());
        assert!(validate_path("/outside/custom").is_err());

        let forbidden = strings(&endpoint["forbiddenPathFragments"]);
        assert_eq!(forbidden, BTreeSet::from(["//", "..", "?", "#"]));
        for fragment in forbidden {
            assert!(
                validate_path(&format!("{prefix}devices{fragment}online")).is_err(),
                "path fragment {fragment:?} must stay forbidden"
            );
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct ServiceIdentity {
    pub tenant_id: Option<Uuid>,
    pub entity_status: crate::models::enums::EntityStatus,
    pub tenant_status: Option<crate::models::enums::TenantStatus>,
}

pub(crate) async fn service_identity(
    pool: &Database,
    id: Uuid,
) -> Result<ServiceIdentity, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::service_identity(pool, id).await,
        Database::Sqlite(db) => sqlite::service_identity(&db.pool, id).await,
    }
}
