//! Refresh-token lifecycle: issuance, rotation/replay-detection, family
//! revocation, and bounded cleanup — database-only, mirroring
//! `access_tokens.rs`. Refresh tokens live in their own table, never
//! accepted as Bearer/API-key auth (see `auth::REFRESH_TOKEN_PREFIX`).

use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    config::SigningKeyConfig,
    crypto,
    error::{db_err, AppError},
};

/// Generate a fresh 32-byte secret and its KEK-keyed HMAC digest. Refresh
/// tokens require a KEK unconditionally, so a missing one here means config
/// validation's own invariant was bypassed — fail closed rather than fall
/// back to a weaker verifier.
pub(crate) fn new_secret(signing_keys: &SigningKeyConfig) -> Result<([u8; 32], Vec<u8>), AppError> {
    let kek = signing_keys.key_encryption_key.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "refresh token issuance requires ATOM_KEY_ENCRYPTION_KEY"
        ))
    })?;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let digest = crypto::hmac_sha256(kek.expose(), &secret);
    Ok((secret, digest))
}

/// Create the first token of a new family for `session_id`, inside the
/// caller's transaction. Returns the plaintext token — never persisted,
/// shown only here.
pub async fn create_refresh_token_family_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    signing_keys: &SigningKeyConfig,
    session_id: Uuid,
    family_expires_at: DateTime<Utc>,
) -> Result<String, AppError> {
    let (secret, digest) = new_secret(signing_keys)?;
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, session_id, secret_hash, family_expires_at)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(token_id)
    .bind(session_id)
    .bind(&digest)
    .bind(family_expires_at)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(crate::auth::make_refresh_token(token_id, &secret))
}

/// Snapshot of a refresh token and its parent session, locked `FOR UPDATE`
/// against concurrent rotation/logout races. `secret_hash` is scoped to
/// this struct alone — callers verify it and drop it, so no shared type
/// ever carries a digest.
pub(crate) struct LockedRefreshToken {
    pub secret_hash: Vec<u8>,
    pub family_expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub session_id: Uuid,
    pub entity_id: Uuid,
    /// The entity's tenant, purely for labeling audit events — not locked
    /// or used for any authorization decision (that's `lock_active_entity`'s
    /// job).
    pub tenant_id: Option<Uuid>,
    pub session_revoked_at: Option<DateTime<Utc>>,
    pub session_expires_at: DateTime<Utc>,
}

/// Look up `token_id` and lock both its row and its parent session's row
/// `FOR UPDATE`, so a concurrent exchange of the same token and a concurrent
/// logout both serialize against this read. `None` when the id doesn't
/// exist — callers must map that to the same generic error as every other
/// rejection reason, never a distinguishable "not found".
pub(crate) async fn lock_refresh_token_for_exchange(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
) -> Result<Option<LockedRefreshToken>, AppError> {
    let row = sqlx::query(
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
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?;

    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(LockedRefreshToken {
        secret_hash: row.try_get("secret_hash").map_err(db_err)?,
        family_expires_at: row.try_get("family_expires_at").map_err(db_err)?,
        consumed_at: row.try_get("consumed_at").map_err(db_err)?,
        revoked_at: row.try_get("revoked_at").map_err(db_err)?,
        session_id: row.try_get("session_id").map_err(db_err)?,
        entity_id: row.try_get("entity_id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        session_revoked_at: row.try_get("session_revoked_at").map_err(db_err)?,
        session_expires_at: row.try_get("session_expires_at").map_err(db_err)?,
    }))
}

/// Consume `old_id` and insert its replacement in one statement pair, inside
/// the exchange's transaction. The replacement inherits `family_expires_at`
/// unchanged — rotation never extends the absolute deadline.
pub(crate) async fn consume_and_rotate_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    old_id: Uuid,
    new_id: Uuid,
    session_id: Uuid,
    new_secret_hash: &[u8],
    family_expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(r#"UPDATE refresh_tokens SET consumed_at = now(), replaced_by = $2 WHERE id = $1"#)
        .bind(old_id)
        .bind(new_id)
        .execute(&mut **tx)
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
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Replay/reuse response: revoke the parent session (idempotent — a no-op if
/// already revoked, e.g. by a concurrent logout) and every unconsumed,
/// unrevoked descendant token for it. Run inside the same transaction as the
/// reuse audit event, via `commit_with_audit`, so revocation and its event
/// commit atomically.
pub(crate) async fn revoke_family_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(session_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        r#"UPDATE refresh_tokens
           SET revoked_at = now()
           WHERE session_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL"#,
    )
    .bind(session_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Distinct from `purge::PURGE_ADVISORY_LOCK_ID`: an unrelated cleanup job
/// on a different table must not contend with soft-delete purge for the
/// same lock slot.
const REFRESH_TOKEN_CLEANUP_ADVISORY_LOCK_ID: i64 = 0x4154_4f4d_5254_434c;

/// Deletes whole expired families (by `session_id`), one replica at a time.
/// Every row in a family shares the same `family_expires_at`, so a
/// row-level `LIMIT` could split one across the batch boundary and violate
/// the deferred self-FK on `replaced_by` at commit; the advisory lock
/// (mirroring `purge::purge_expired`) avoids concurrent replicas
/// deadlocking on the same unordered `DELETE`.
pub async fn purge_expired(pool: &PgPool, batch_size: i64) -> Result<u64, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(REFRESH_TOKEN_CLEANUP_ADVISORY_LOCK_ID)
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
    tx.commit().await.map_err(db_err)?;
    Ok(result.rows_affected())
}
