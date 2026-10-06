use super::*;
use crate::error::db_err;
use sqlx::Row;

pub(super) async fn load_session_entity_tenant(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    entity_id: Uuid,
) -> Result<SessionRow, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT s.revoked_at,
                  s.expires_at,
                  e.tenant_id,
                  e.status AS entity_status,
                  t.status AS tenant_status
           FROM sessions s
           JOIN entities e ON e.id = s.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE s.id = $1 AND s.entity_id = $2
             AND e.deleted_at IS NULL
             AND (t.id IS NULL OR t.deleted_at IS NULL)"#,
    )
    .bind(session_id)
    .bind(entity_id)
    .fetch_one(pool)
    .await?;
    Ok(SessionRow {
        revoked_at: row.try_get("revoked_at").unwrap_or(None),
        expires_at: row.try_get("expires_at"),
        entity_tenant_id: row.try_get("tenant_id").unwrap_or(None),
        entity_status: row.try_get("entity_status"),
        tenant_status: row.try_get("tenant_status").unwrap_or(None),
    })
}

pub(super) async fn load_credential_row(
    pool: &sqlx::PgPool,
    cred_id: Uuid,
) -> Result<CredentialRow, sqlx::Error> {
    // Only access-token credentials enter this cache. Password credentials
    // remain uncached and are verified through the normal password path.
    let row = sqlx::query(
        r#"SELECT c.entity_id,
                  c.secret_hash,
                  c.secret_lookup_hash,
                  c.status,
                  c.expires_at,
                  c.scoped,
                  e.tenant_id,
                  e.status AS entity_status,
                  t.status AS tenant_status
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE c.id = $1 AND c.kind = $2
             AND e.deleted_at IS NULL
             AND (t.id IS NULL OR t.deleted_at IS NULL)"#,
    )
    .bind(cred_id)
    .bind(CredentialKind::AccessToken)
    .fetch_one(pool)
    .await?;
    Ok(CredentialRow {
        entity_id: row.try_get("entity_id"),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        secret_hash: row.try_get("secret_hash").unwrap_or(None),
        secret_lookup_hash: row.try_get("secret_lookup_hash").unwrap_or(None),
        status: row.try_get("status"),
        expires_at: row.try_get("expires_at").unwrap_or(None),
        scoped: row.try_get("scoped").unwrap_or(false),
        entity_status: row.try_get("entity_status"),
        tenant_status: row.try_get("tenant_status").unwrap_or(None),
    })
}

pub(super) async fn actor_is_active(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<bool, AppError> {
    let active: Option<bool> = sqlx::query_scalar(
        r#"SELECT (actor.status = 'active'
                   AND actor.deleted_at IS NULL
                   AND (actor.tenant_id IS NULL OR (actor_tenant.status = 'active' AND actor_tenant.deleted_at IS NULL)))
           FROM entities actor
           LEFT JOIN tenants actor_tenant ON actor_tenant.id = actor.tenant_id
           WHERE actor.id = $1"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    Ok(active.unwrap_or(false))
}

pub(super) async fn tenant_is_active(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
) -> Result<bool, AppError> {
    let active: Option<bool> = sqlx::query_scalar(
        "SELECT status = 'active' AND deleted_at IS NULL FROM tenants WHERE id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    Ok(active.unwrap_or(false))
}

pub(super) async fn action_id_by_name(
    pool: &sqlx::PgPool,
    name: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

pub(super) async fn action_ids_by_name(
    pool: &sqlx::PgPool,
    names: &[&str],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    let owned: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let rows = sqlx::query("SELECT name, id FROM actions WHERE name = ANY($1::text[])")
        .bind(&owned)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("name").map_err(db_err)?,
                row.try_get::<Uuid, _>("id").map_err(db_err)?,
            ))
        })
        .collect()
}

pub(super) async fn upgrade_verifier(
    pool: &sqlx::PgPool,
    cred_id: Uuid,
    digest: &[u8],
) -> Result<(), AppError> {
    sqlx::query("UPDATE credentials SET secret_lookup_hash = $1, secret_hash = NULL WHERE id = $2")
        .bind(digest)
        .bind(cred_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}
pub(super) async fn touch_usage(pool: &sqlx::PgPool, cred_id: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE credentials SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')")
        .bind(cred_id).execute(pool).await.map_err(db_err)?;
    Ok(())
}
