//! Native postgres certificate profile reads. Policy checks remain shared.
use super::{ProfileRow, StoredSubject};
use crate::error::{db_err, AppError};
use sqlx::Postgres as Driver;
use uuid::Uuid;

pub(super) async fn load_subject<'e, E>(
    executor: E,
    entity_id: Uuid,
) -> Result<StoredSubject, AppError>
where
    E: sqlx::Executor<'e, Database = Driver>,
{
    sqlx::query_as::<_, StoredSubject>(super::sql::LOAD_SUBJECT)
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
    let query = super::sql::resolve_profile();
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
    let query = super::sql::profile_by_id();
    let row = sqlx::query_as::<_, ProfileRow>(&query)
        .bind(profile_id)
        .fetch_one(executor)
        .await
        .map_err(db_err)?;
    Ok(row)
}
