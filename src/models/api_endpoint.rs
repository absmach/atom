use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiEndpoint {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub method: String,
    pub path: String,
    pub operation_kind: String,
    pub graphql: String,
    pub auth_mode: String,
    pub service_entity_id: Option<Uuid>,
    pub variables_mapping: Value,
    pub request_schema: Value,
    pub response_mapping: Value,
    pub status: String,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiEndpoint {
    pub tenant_id: Option<Uuid>,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub method: String,
    pub path: String,
    pub operation_kind: String,
    pub graphql: String,
    pub auth_mode: Option<String>,
    pub service_entity_id: Option<Uuid>,
    #[serde(default = "default_json_object")]
    pub variables_mapping: Value,
    #[serde(default = "default_json_object")]
    pub request_schema: Value,
    #[serde(default = "default_json_object")]
    pub response_mapping: Value,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateApiEndpoint {
    pub key: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub operation_kind: Option<String>,
    pub graphql: Option<String>,
    pub auth_mode: Option<String>,
    pub service_entity_id: Option<Uuid>,
    pub variables_mapping: Option<Value>,
    pub request_schema: Option<Value>,
    pub response_mapping: Option<Value>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListApiEndpoints {
    pub tenant_id: Option<Uuid>,
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct ApiEndpointList {
    pub items: Vec<ApiEndpoint>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListApiEndpointExecutions {
    pub endpoint_id: Uuid,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct ApiEndpointExecutionList {
    pub items: Vec<ApiEndpointExecution>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiEndpointExecution {
    pub id: Uuid,
    pub endpoint_id: Option<Uuid>,
    pub caller_entity_id: Option<Uuid>,
    pub status: String,
    pub request_summary: Value,
    pub response_summary: Value,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub fn default_json_object() -> Value {
    serde_json::json!({})
}

fn default_limit() -> i64 {
    20
}
