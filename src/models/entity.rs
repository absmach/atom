use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::{DeletedFilter, EntityKind, EntityOrderField, EntityStatus, SortDir};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Entity {
    pub id: Uuid,
    pub kind: EntityKind,
    pub name: String,
    pub alias: Option<String>,
    /// Identifier assigned outside Atom (serial number, MAC, SKU). Opaque,
    /// case-sensitive, unique per tenant among live rows. See
    /// [`crate::models::external_id`].
    pub external_id: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub status: EntityStatus,
    pub attributes: Value,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    /// `Some("config")` when the row was provisioned from the bootstrap YAML
    /// (see src/bootstrap.rs). The API rejects update/delete/restore of these
    /// rows with 409 conflict; the UI uses this flag to render them read-only.
    /// Marked `sqlx(default)` so RETURNING / older SELECTs that omit the
    /// column still hydrate cleanly — the read paths that surface this to the
    /// UI explicitly include it.
    #[sqlx(default)]
    pub managed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEntity {
    pub id: Option<Uuid>,
    pub kind: Option<EntityKind>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub name: String,
    pub alias: Option<String>,
    pub external_id: Option<String>,
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEntity {
    pub name: Option<String>,
    pub kind: Option<EntityKind>,
    #[serde(
        default,
        deserialize_with = "crate::models::alias::deserialize_alias_update"
    )]
    pub alias: Option<Option<String>>,
    /// Patch semantics: `None` leaves it unchanged, `Some(None)` clears it.
    #[serde(
        default,
        deserialize_with = "crate::models::external_id::deserialize_external_id_update"
    )]
    pub external_id: Option<Option<String>>,
    pub tenant_id: Option<Uuid>,
    pub profile_id: Option<Uuid>,
    pub profile_version_id: Option<Uuid>,
    pub status: Option<EntityStatus>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListEntities {
    pub id: Option<String>,
    pub q: Option<String>,
    pub kind: Option<EntityKind>,
    /// Exact-match filter (case-sensitive, trimmed). Not part of the `q`
    /// substring search — an external identifier is looked up, not browsed.
    pub external_id: Option<String>,
    pub profile_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub attributes_contains: Option<Value>,
    pub status: Option<EntityStatus>,
    #[serde(default)]
    pub deleted: DeletedFilter,
    pub parent_group_id: Option<Uuid>,
    pub include_descendants: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub order: EntityOrderField,
    #[serde(default)]
    pub dir: SortDir,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct EntityList {
    pub items: Vec<Entity>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Ownership {
    pub owner_id: Uuid,
    pub owned_id: Uuid,
    pub relation: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOwnership {
    pub owned_id: Uuid,
    #[serde(default = "default_relation")]
    pub relation: String,
}

fn default_relation() -> String {
    "owner".to_string()
}
