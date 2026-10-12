//! Native postgres access-token storage.
use super::{ListAccessTokens, NewToken};
use crate::{
    error::{db_err, AppError},
    models::{
        enums::CredentialKind,
        token::{AccessTokenPermission, AccessTokenPermissionSummary, AccessTokenSummary},
    },
};
use sqlx::{PgConnection as Connection, PgPool as Database, Row};
use uuid::Uuid;

pub(super) async fn insert_token(conn: &mut Connection, input: NewToken) -> Result<(), AppError> {
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash, secret_lookup_hash, scoped, expires_at, metadata)
        VALUES ($1, $2, 'access_token', $3, $4, $5, $6, $7, $8)")
        .bind(input.id).bind(input.entity_id).bind(input.key_prefix).bind(input.secret_hash)
        .bind(input.secret_lookup_hash).bind(input.scoped).bind(input.expires_at).bind(input.metadata)
        .execute(conn).await.map_err(db_err)?;
    Ok(())
}

pub(super) async fn lock_active_token(
    conn: &mut Connection,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<Option<(bool, Option<String>)>, AppError> {
    sqlx::query_as("SELECT scoped, managed_by FROM credentials WHERE id = $1 AND entity_id = $2 AND kind = 'access_token' AND status = 'active' FOR UPDATE")
        .bind(cred_id).bind(entity_id).fetch_optional(conn).await.map_err(db_err)
}

pub(super) async fn clear_ceiling(conn: &mut Connection, cred_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM credential_permission_limits WHERE credential_id = $1")
        .bind(cred_id)
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub(super) async fn action_ids(
    conn: &mut Connection,
    names: &[String],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    let rows: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT name, id FROM actions WHERE name = ANY($1::text[])")
            .bind(names)
            .fetch_all(conn)
            .await
            .map_err(db_err)?;
    Ok(rows.into_iter().collect())
}

pub(super) async fn insert_ceiling(
    conn: &mut Connection,
    cred_id: Uuid,
    permission: &AccessTokenPermission,
    action_ids: &[Uuid],
) -> Result<(), AppError> {
    let limit_id = Uuid::new_v4();
    let conditions = permission
        .conditions
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    sqlx::query(
        "INSERT INTO credential_permission_limits
        (id, credential_id, scope_mode, tenant_id, object_kind, object_type, object_id, conditions)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(limit_id)
    .bind(cred_id)
    .bind(&permission.scope_mode)
    .bind(permission.tenant_id)
    .bind(&permission.object_kind)
    .bind(&permission.object_type)
    .bind(permission.object_id)
    .bind(conditions)
    .execute(&mut *conn)
    .await
    .map_err(|error| {
        if crate::error::is_check_violation(&error) {
            AppError::bad_request("invalid permission scope for access token")
        } else {
            AppError::Database(error)
        }
    })?;
    for action_id in action_ids {
        sqlx::query("INSERT INTO credential_permission_limit_actions (limit_id, action_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(limit_id).bind(action_id).execute(&mut *conn).await.map_err(db_err)?;
    }
    Ok(())
}

pub(super) async fn lock_token_owner(
    conn: &mut Connection,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<Option<Option<String>>, AppError> {
    sqlx::query_scalar("SELECT managed_by FROM credentials WHERE id = $1 AND entity_id = $2 AND kind = 'access_token' FOR UPDATE")
        .bind(cred_id).bind(entity_id).fetch_optional(conn).await.map_err(db_err)
}

pub(super) async fn revoke(
    conn: &mut Connection,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<(), AppError> {
    let result = sqlx::query("UPDATE credentials SET status = 'revoked',
        metadata = metadata - 'revoked_at' - 'revocation_reason' || jsonb_build_object('revoked_at', now(), 'revocation_reason', 'manual')
        WHERE id = $1 AND entity_id = $2 AND kind = 'access_token'")
        .bind(cred_id).bind(entity_id).execute(conn).await.map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("access token not found"));
    }
    Ok(())
}

pub(super) async fn list_access_tokens(
    pool: &Database,
    entity_id: Uuid,
    params: ListAccessTokens,
) -> Result<(Vec<AccessTokenSummary>, i64), AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    // Config-managed tokens are surfaced with `managed_by='config'` so the
    // UI can flag them read-only; the mutation endpoints refuse to touch
    // them with 409 conflict.
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND ($3::text IS NULL OR status = $3::text)"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .bind(params.status.clone())
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    let rows = sqlx::query(
        r#"SELECT id,
                  COALESCE(NULLIF(metadata->>'name', ''), identifier, 'Access token') AS name,
                  NULLIF(metadata->>'description', '') AS description,
                  identifier,
                  status,
                  scoped,
                  expires_at,
                  last_used_at,
                  created_at,
                  managed_by
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND ($3::text IS NULL OR status = $3::text)
           ORDER BY created_at DESC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .bind(params.status)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let credential_ids: Vec<Uuid> = rows
        .iter()
        .map(|row| row.try_get("id").map_err(db_err))
        .collect::<Result<Vec<_>, AppError>>()?;
    let mut permissions = load_access_token_permissions(pool, &credential_ids).await?;

    let items = rows
        .into_iter()
        .map(|row| {
            let credential_id: Uuid = row.try_get("id").map_err(db_err)?;
            Ok(AccessTokenSummary {
                credential_id,
                name: row.try_get("name").map_err(db_err)?,
                description: row.try_get("description").map_err(db_err)?,
                identifier: row.try_get("identifier").map_err(db_err)?,
                status: row.try_get("status").map_err(db_err)?,
                scoped: row.try_get("scoped").map_err(db_err)?,
                permissions: permissions.remove(&credential_id).unwrap_or_default(),
                expires_at: row.try_get("expires_at").map_err(db_err)?,
                last_used_at: row.try_get("last_used_at").map_err(db_err)?,
                created_at: row.try_get("created_at").map_err(db_err)?,
                managed_by: row.try_get("managed_by").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok((items, total))
}

pub(super) async fn access_token_owner(pool: &Database, cred_id: Uuid) -> Result<Uuid, AppError> {
    sqlx::query_scalar(r#"SELECT entity_id FROM credentials WHERE id = $1 AND kind = $2"#)
        .bind(cred_id)
        .bind(CredentialKind::AccessToken)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::not_found("access token not found"))
}

async fn load_access_token_permissions(
    pool: &Database,
    credential_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, Vec<AccessTokenPermissionSummary>>, AppError> {
    let rows = sqlx::query(
        r#"SELECT l.credential_id,
                  l.scope_mode,
                  l.tenant_id,
                  l.object_kind,
                  l.object_type,
                  l.object_id,
                  l.conditions,
                  COALESCE(
                      ARRAY_AGG(a.name ORDER BY a.name) FILTER (WHERE a.name IS NOT NULL),
                      '{}'
                  ) AS actions
           FROM credential_permission_limits l
           LEFT JOIN credential_permission_limit_actions la ON la.limit_id = l.id
           LEFT JOIN actions a ON a.id = la.action_id
           WHERE l.credential_id = ANY($1)
           GROUP BY l.id
           ORDER BY l.created_at"#,
    )
    .bind(credential_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut by_credential: std::collections::HashMap<Uuid, Vec<AccessTokenPermissionSummary>> =
        std::collections::HashMap::new();
    for row in rows {
        let credential_id: Uuid = row.try_get("credential_id").map_err(db_err)?;
        by_credential
            .entry(credential_id)
            .or_default()
            .push(AccessTokenPermissionSummary {
                actions: row
                    .try_get::<crate::db::TextList, _>("actions")
                    .map_err(db_err)?
                    .0,
                scope_mode: row.try_get("scope_mode").map_err(db_err)?,
                tenant_id: row.try_get("tenant_id").map_err(db_err)?,
                object_kind: row.try_get("object_kind").map_err(db_err)?,
                object_type: row.try_get("object_type").map_err(db_err)?,
                object_id: row.try_get("object_id").map_err(db_err)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
            });
    }
    Ok(by_credential)
}
