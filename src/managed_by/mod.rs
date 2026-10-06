//! Shared guard used by mutation endpoints to refuse writes on rows the
//! bootstrap YAML claimed (rows with `managed_by='config'`). Colocated here
//! so every module that mutates a bootstrap-touched table can call the same
//! helper. Bootstrap applies the write side of the same marker only after an
//! exact, locked reconciliation inside its transaction.
//!
//! The table name is looked up in a closed static match, not interpolated,
//! so a caller cannot inject arbitrary SQL.

mod postgres;
mod sqlite;

use crate::db::Database;
use uuid::Uuid;

use crate::{db::DbTransaction, error::AppError};

/// Reject a mutation attempt on a row that was provisioned from the bootstrap
/// YAML. Returns:
///
/// - `Ok(())` — the row exists and is API-managed (`managed_by IS NULL`).
/// - `Err(AppError::not_found)` — the row does not exist.
/// - `Err(AppError::conflict)` — the row is stamped `managed_by='config'`;
///   the operator must edit the YAML and restart Atom.
pub async fn ensure_not_config_managed(
    pool: &Database,
    table: &'static str,
    id: Uuid,
) -> Result<(), AppError> {
    let managed_by = match pool {
        Database::Postgres(pool) => postgres::marker(pool, table, id).await?,
        Database::Sqlite(db) => sqlite::marker(&db.pool, table, id).await?,
    };
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
    tx: &mut DbTransaction<'_>,
    table: &'static str,
    id: Uuid,
) -> Result<(), AppError> {
    // `groups` is a UNION view and cannot be row-locked. Link owners always
    // have a concrete physical type, so transactional callers must name that
    // table explicitly.
    let managed_by = match tx {
        DbTransaction::Postgres(conn) => postgres::locked_marker(conn, table, id).await?,
        DbTransaction::Sqlite(conn) => sqlite::locked_marker(conn, table, id).await?,
    };
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
