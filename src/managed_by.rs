//! Shared guard used by mutation endpoints to refuse writes on rows the
//! bootstrap YAML claimed (rows with `managed_by='config'`). Colocated here
//! so every module that mutates a bootstrap-touched table can call the same
//! helper. Bootstrap applies the write side of the same marker only after an
//! exact, locked reconciliation inside its transaction.
//!
//! The table name is looked up in a closed static match, not interpolated,
//! so a caller cannot inject arbitrary SQL.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{db_err, AppError};

/// Reject a mutation attempt on a row that was provisioned from the bootstrap
/// YAML. Returns:
///
/// - `Ok(())` — the row exists and is API-managed (`managed_by IS NULL`).
/// - `Err(AppError::not_found)` — the row does not exist.
/// - `Err(AppError::conflict)` — the row is stamped `managed_by='config'`;
///   the operator must edit the YAML and restart Atom.
pub async fn ensure_not_config_managed(
    pool: &PgPool,
    table: &'static str,
    id: Uuid,
) -> Result<(), AppError> {
    let sql = match table {
        "entities" => "SELECT managed_by FROM entities WHERE id = $1",
        "credentials" => "SELECT managed_by FROM credentials WHERE id = $1",
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
        "actions" => "SELECT managed_by FROM actions WHERE id = $1",
        "action_assignment_rules" => "SELECT managed_by FROM action_assignment_rules WHERE id = $1",
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

/// Transactional form of [`ensure_not_config_managed`]. The owner row is
/// locked before its marker is inspected, so a bootstrap transaction cannot
/// stamp the row `managed_by='config'` between an API precheck and the link
/// mutation it is meant to protect.
///
/// Callers must acquire any owning tenant and hierarchy advisory locks before
/// this helper. The row lock here is intentionally the final lock in that
/// order: tenant -> hierarchy advisory lock (when applicable) -> owner row.
pub(crate) async fn ensure_not_config_managed_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    table: &'static str,
    id: Uuid,
) -> Result<(), AppError> {
    // `groups` is a UNION view and cannot be row-locked. Link owners always
    // have a concrete physical type, so transactional callers must name that
    // table explicitly.
    let sql = match table {
        "entities" => "SELECT managed_by FROM entities WHERE id = $1 FOR UPDATE",
        "credentials" => "SELECT managed_by FROM credentials WHERE id = $1 FOR UPDATE",
        "tenants" => "SELECT managed_by FROM tenants WHERE id = $1 FOR UPDATE",
        "resources" => "SELECT managed_by FROM resources WHERE id = $1 FOR UPDATE",
        "principal_groups" => "SELECT managed_by FROM principal_groups WHERE id = $1 FOR UPDATE",
        "object_groups" => "SELECT managed_by FROM object_groups WHERE id = $1 FOR UPDATE",
        "actions" => "SELECT managed_by FROM actions WHERE id = $1 FOR UPDATE",
        "roles" => "SELECT managed_by FROM roles WHERE id = $1 FOR UPDATE",
        "permission_blocks" => "SELECT managed_by FROM permission_blocks WHERE id = $1 FOR UPDATE",
        "role_assignments" => "SELECT managed_by FROM role_assignments WHERE id = $1 FOR UPDATE",
        "direct_policies" => "SELECT managed_by FROM direct_policies WHERE id = $1 FOR UPDATE",
        "action_assignment_rules" => {
            "SELECT managed_by FROM action_assignment_rules WHERE id = $1 FOR UPDATE"
        }
        _ => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "ensure_not_config_managed_in_tx called with unknown or non-lockable table {table}"
            )))
        }
    };
    let managed_by: Option<Option<String>> = sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    reject_config_managed(table, id, managed_by)
}

fn reject_config_managed(
    table: &'static str,
    id: Uuid,
    managed_by: Option<Option<String>>,
) -> Result<(), AppError> {
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
        "entities" => "entity",
        "credentials" => "credential",
        "tenants" => "tenant",
        "resources" => "resource",
        "principal_groups" | "object_groups" | "groups" => "group",
        "actions" => "capability",
        "action_assignment_rules" => "action assignment rule",
        "roles" => "role",
        "permission_blocks" => "permission block",
        "role_assignments" => "role assignment",
        "direct_policies" => "direct policy",
        _ => "row",
    }
}
