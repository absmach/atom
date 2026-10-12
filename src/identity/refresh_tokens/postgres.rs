//! Native postgres refresh-token storage. All writes use the caller connection.

use super::{LockedRefreshToken, RefreshTokenOwner};
use crate::error::{db_err, AppError};
use chrono::{DateTime, Utc};
use sqlx::PgConnection as Connection;
use uuid::Uuid;
pub(super) async fn lookup_refresh_token_owner(
    tx: &mut Connection,
    token_id: Uuid,
) -> Result<Option<RefreshTokenOwner>, AppError> {
    sqlx::query_as::<_, RefreshTokenOwner>(
        r#"SELECT rt.session_id, s.entity_id, e.tenant_id
           FROM refresh_tokens rt
           JOIN sessions s ON s.id = rt.session_id
           JOIN entities e ON e.id = s.entity_id
           WHERE rt.id = $1"#,
    )
    .bind(token_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_refresh_token_for_exchange(
    tx: &mut Connection,
    token_id: Uuid,
) -> Result<Option<LockedRefreshToken>, AppError> {
    sqlx::query_as::<_, LockedRefreshToken>(
        r#"SELECT rt.secret_hash,
                  rt.family_expires_at,
                  rt.consumed_at,
                  rt.revoked_at,
                  rt.session_id,
                  s.entity_id,
                  e.tenant_id,
                  s.revoked_at AS session_revoked_at,
                  s.expires_at AS session_expires_at
           FROM refresh_tokens rt
           JOIN sessions s ON s.id = rt.session_id
           JOIN entities e ON e.id = s.entity_id
           WHERE rt.id = $1
           FOR UPDATE OF rt, s"#,
    )
    .bind(token_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)
}

pub(super) async fn consume_and_rotate_in_tx(
    tx: &mut Connection,
    old_id: Uuid,
    new_id: Uuid,
    session_id: Uuid,
    new_secret_hash: &[u8],
    family_expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(r#"UPDATE refresh_tokens SET consumed_at = now(), replaced_by = $2 WHERE id = $1"#)
        .bind(old_id)
        .bind(new_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, session_id, secret_hash, family_expires_at)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(new_id)
    .bind(session_id)
    .bind(new_secret_hash)
    .bind(family_expires_at)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn revoke_family_in_tx(
    tx: &mut Connection,
    session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        r#"UPDATE refresh_tokens
           SET revoked_at = now()
           WHERE session_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL"#,
    )
    .bind(session_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn insert_family(
    tx: &mut Connection,
    token_id: Uuid,
    session_id: Uuid,
    digest: &[u8],
    family_expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, session_id, secret_hash, family_expires_at)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(token_id)
    .bind(session_id)
    .bind(digest)
    .bind(family_expires_at)
    .execute(tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn purge_expired(tx: &mut Connection, batch_size: i64) -> Result<u64, AppError> {
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(super::REFRESH_TOKEN_CLEANUP_ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    if !acquired {
        return Ok(0);
    }

    let result = sqlx::query(
        r#"DELETE FROM refresh_tokens
           WHERE session_id IN (
               SELECT session_id FROM refresh_tokens
               WHERE family_expires_at < now()
               GROUP BY session_id
               ORDER BY min(family_expires_at)
               LIMIT $1
           )"#,
    )
    .bind(batch_size)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(result.rows_affected())
}
