use crate::error::{db_err, AppError};
use sqlx::{PgConnection as Connection, PgPool as Database};
use uuid::Uuid;

pub(super) async fn marker(
    pool: &Database,
    table: &'static str,
    id: Uuid,
) -> Result<Option<Option<String>>, AppError> {
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
    Ok(managed_by)
}

pub(super) async fn locked_marker(
    conn: &mut Connection,
    table: &'static str,
    id: Uuid,
) -> Result<Option<Option<String>>, AppError> {
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
        .fetch_optional(conn)
        .await
        .map_err(db_err)?;
    Ok(managed_by)
}
