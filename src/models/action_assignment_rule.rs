use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::enums::{ActionAssignmentDecision, EntityKind, ObjectKind};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ActionAssignmentRule {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub entity_kind: EntityKind,
    pub action_name: String,
    pub object_kind: ObjectKind,
    pub object_type: Option<String>,
    pub decision: ActionAssignmentDecision,
    pub is_absolute: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateActionAssignmentRule {
    pub tenant_id: Option<Uuid>,
    pub entity_kind: EntityKind,
    pub action_name: String,
    pub object_kind: ObjectKind,
    pub object_type: Option<String>,
    pub decision: ActionAssignmentDecision,
    pub is_absolute: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListActionAssignmentRules {
    pub tenant_id: Option<Uuid>,
    pub entity_kind: Option<EntityKind>,
    pub action_name: Option<String>,
    pub object_kind: Option<ObjectKind>,
    pub object_type: Option<String>,
    pub decision: Option<ActionAssignmentDecision>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct ActionAssignmentRuleList {
    pub items: Vec<ActionAssignmentRule>,
    pub total: i64,
}
