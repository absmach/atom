//! Shared guard used by mutation endpoints to refuse writes on rows the
//! bootstrap YAML claimed (rows with `managed_by='config'`). Colocated here
//! so every module that mutates a bootstrap-touched table can call the same
//! helper — see `src/bootstrap.rs::stamp_managed_by_config` for the write
//! side of the same marker.
//!
//! The table name is looked up in a closed static match, not interpolated,
//! so a caller cannot inject arbitrary SQL.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{db_err, AppError};

/// Reject a mutation attempt on a row that was provisioned from the bootstrap
/// YAML. Returns:
///
/// - `Ok(())` — the row does not exist yet OR is API-managed (`managed_by IS NULL`).
/// - `Err(AppError::not_found)` — the row does not exist.
/// - `Err(AppError::conflict)` — the row is stamped `managed_by='config'`;
///   the operator must edit the YAML and restart Atom.
pub async fn ensure_not_config_managed(
    pool: &PgPool,
    table: &'static str,
    id: Uuid,
) -> Result<(), AppError> {
    let sql = match table {
        "tenants" => "SELECT managed_by FROM tenants WHERE id = $1",
        "resources" => "SELECT managed_by FROM resources WHERE id = $1",
        "principal_groups" => "SELECT managed_by FROM principal_groups WHERE id = $1",
        "object_groups" => "SELECT managed_by FROM object_groups WHERE id = $1",
        // The `groups` view unions principal_groups + object_groups. Group
        // mutations don't know upfront which underlying table an id belongs
        // to, so lookups go through the view.
        "groups" => "SELECT managed_by FROM groups WHERE id = $1",
        "roles" => "SELECT managed_by FROM roles WHERE id = $1",
        "permission_blocks" => "SELECT managed_by FROM permission_blocks WHERE id = $1",
        "role_assignments" => "SELECT managed_by FROM role_assignments WHERE id = $1",
        "direct_policies" => "SELECT managed_by FROM direct_policies WHERE id = $1",
        _ => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "ensure_not_config_managed called with unknown table {table}"
            )))
        }
    };
    let managed_by: Option<Option<String>> = sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    match managed_by {
        None => Err(AppError::not_found(format!(
            "{singular} {id} not found",
            singular = singular(table),
        ))),
        Some(Some(value)) if value == "config" => Err(AppError::conflict(format!(
            "{singular} is managed by the bootstrap config file and cannot be modified via the API",
            singular = singular(table),
        ))),
        _ => Ok(()),
    }
}

fn singular(table: &str) -> &'static str {
    match table {
        "tenants" => "tenant",
        "resources" => "resource",
        "principal_groups" | "object_groups" | "groups" => "group",
        "roles" => "role",
        "permission_blocks" => "permission block",
        "role_assignments" => "role assignment",
        "direct_policies" => "direct policy",
        _ => "row",
    }
}
