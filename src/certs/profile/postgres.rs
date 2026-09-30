//! Native postgres certificate profile reads. Policy checks remain shared.
use super::{ProfileRow, StoredSubject};
use crate::error::{db_err, AppError};
use sqlx::Postgres as Driver;
use uuid::Uuid;

const PROFILE_COLUMNS: &str = r#"
    id,
    tenant_id,
    base_profile_id,
    name,
    permitted_key_algorithms,
    default_ttl_seconds,
    maximum_ttl_seconds,
    renewal_threshold_seconds,
    key_usages,
    extended_key_usages,
    san_policy,
    identity_uri_template,
    basic_constraints
"#;

pub(super) async fn load_subject<'e, E>(
    executor: E,
    entity_id: Uuid,
) -> Result<StoredSubject, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, StoredSubject>(
        r#"
        SELECT e.id AS entity_id, e.tenant_id
        FROM entities e
        LEFT JOIN tenants t ON t.id = e.tenant_id
        WHERE e.id = $1
          AND e.status = 'active'
          AND e.deleted_at IS NULL
          AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))
        "#,
    )
    .bind(entity_id)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

pub(super) async fn resolve_profile<'e, E>(
    executor: E,
    tenant_id: Option<Uuid>,
    name: &str,
) -> Result<ProfileRow, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    let query = format!(
        r#"
        SELECT {PROFILE_COLUMNS}
        FROM certificate_profiles
        WHERE name = $1
          AND (tenant_id IS NULL OR tenant_id = $2)
        ORDER BY (tenant_id IS NULL) ASC
        LIMIT 1
        "#
    );
    let row = sqlx::query_as::<_, ProfileRow>(&query)
        .bind(name)
        .bind(tenant_id)
        .fetch_one(executor)
        .await
        .map_err(db_err)?;
    Ok(row)
}

pub(super) async fn profile_by_id<'e, E>(
    executor: E,
    profile_id: Uuid,
) -> Result<ProfileRow, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    let query = format!("SELECT {PROFILE_COLUMNS} FROM certificate_profiles WHERE id = $1");
    let row = sqlx::query_as::<_, ProfileRow>(&query)
        .bind(profile_id)
        .fetch_one(executor)
        .await
        .map_err(db_err)?;
    Ok(row)
}
