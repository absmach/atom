//! Access-token lifecycle: minting (scoped and unscoped), ceiling replacement,
//! owner listing, and revocation. Verification lives in `crate::auth`
//! (`auth_from_api_key`); ceiling evaluation lives in the PDP and the
//! ceiling-aware listing readers.

use argon2::password_hash::rand_core::OsRng;
use chrono::Utc;
use rand::RngCore;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::make_api_key,
    config::SigningKeyConfig,
    crypto,
    error::{db_err, AppError},
    models::{
        enums::{CredentialKind, CredentialStatus},
        token::{
            AccessTokenPermission, AccessTokenPermissionSummary, AccessTokenResponse,
            AccessTokenSummary, CreateAccessToken,
        },
    },
};

use super::service::hash_secret;

/// Ceiling entries are loaded in full on every authenticated request and matched
/// linearly per authorization check, so an unbounded ceiling is a per-request
/// cost. Least-privilege tokens should be narrow anyway; this cap keeps the
/// worst case flat.
pub const MAX_ACCESS_TOKEN_PERMISSIONS: usize = 100;

pub async fn create_access_token(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity_id: Uuid,
    req: CreateAccessToken,
    scoped: bool,
) -> Result<AccessTokenResponse, AppError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::bad_request("access token name is required"));
    }
    if req.permissions.len() > MAX_ACCESS_TOKEN_PERMISSIONS {
        return Err(AppError::bad_request(format!(
            "access token supports at most {MAX_ACCESS_TOKEN_PERMISSIONS} permissions"
        )));
    }
    // A scoped token needs a non-empty ceiling (an empty ceiling is closed and
    // permits nothing). An unscoped token carries the owner's full live grants and
    // must not carry a ceiling, so its permission list must be empty.
    if scoped && req.permissions.is_empty() {
        return Err(AppError::bad_request(
            "access token requires at least one permission",
        ));
    }
    if !scoped && !req.permissions.is_empty() {
        return Err(AppError::bad_request(
            "unscoped access token must not carry permissions",
        ));
    }
    if let Some(expires_at) = req.expires_at {
        if expires_at <= Utc::now() {
            return Err(AppError::bad_request(
                "access token expiration must be in the future",
            ));
        }
    }
    let description = req
        .description
        .map(|description| description.trim().to_string())
        .filter(|description| !description.is_empty());

    let cred_id = Uuid::new_v4();
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    // Verifier: keyed HMAC-SHA256 under the deployment KEK, matching the
    // shared-key lookup digest. The secret is 32 random bytes, so a memory-hard
    // KDF adds per-request CPU without adding security; the KEK keying means a
    // DB-only leak cannot verify guesses offline. Argon2 remains the fallback
    // for deployments without a KEK (and for tokens minted before this change).
    let (secret_hash, secret_lookup_hash) = match signing_keys.key_encryption_key.as_ref() {
        Some(kek) => (None, Some(crypto::hmac_sha256(kek.expose(), &secret_bytes))),
        None => (Some(hash_secret(&secret_bytes)?), None),
    };
    let token = make_api_key(cred_id, &secret_bytes);
    let key_prefix = token[..13].to_string();
    let metadata = serde_json::json!({ "name": &name, "description": &description });

    let mut tx = pool.begin().await.map_err(db_err)?;
    if super::repo::lock_active_entity(&mut tx, entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::not_found(format!(
            "active entity {entity_id} not found"
        )));
    }
    // A scoped token's authority is capped by its ceiling; an unscoped token
    // (`scoped = false`) authenticates with the owner's full live grants.
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash, secret_lookup_hash, scoped, expires_at, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .bind(key_prefix)
    .bind(secret_hash)
    .bind(secret_lookup_hash)
    .bind(scoped)
    .bind(req.expires_at)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let action_ids = resolve_ceiling_action_ids(&mut tx, &req.permissions).await?;
    for permission in &req.permissions {
        write_ceiling_limit(&mut tx, cred_id, permission, &action_ids).await?;
    }
    tx.commit().await.map_err(db_err)?;

    Ok(AccessTokenResponse {
        credential_id: cred_id,
        token,
        name,
        description,
        expires_at: req.expires_at,
    })
}

/// Replace a scoped access token's permission ceiling. `entity_id` must be the
/// token's owner (the row filter enforces it); the GraphQL layer authorizes the
/// caller — owner self-service or a delegated admin via the
/// credential-management gate — before resolving the owner id passed here.
pub async fn replace_access_token_permissions(
    pool: &PgPool,
    entity_id: Uuid,
    cred_id: Uuid,
    permissions: Vec<AccessTokenPermission>,
) -> Result<(), AppError> {
    if permissions.is_empty() {
        return Err(AppError::bad_request(
            "access token requires at least one permission",
        ));
    }
    if permissions.len() > MAX_ACCESS_TOKEN_PERMISSIONS {
        return Err(AppError::bad_request(format!(
            "access token supports at most {MAX_ACCESS_TOKEN_PERMISSIONS} permissions"
        )));
    }
    let mut tx = pool.begin().await.map_err(db_err)?;
    let scoped: Option<bool> = sqlx::query_scalar(
        r#"SELECT scoped FROM credentials
           WHERE id = $1 AND entity_id = $2 AND kind = $3 AND status = 'active'
           FOR UPDATE"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    match scoped {
        None => return Err(AppError::not_found("access token not found")),
        Some(false) => {
            return Err(AppError::bad_request(
                "cannot set permissions on an unscoped access token",
            ))
        }
        Some(true) => {}
    }

    sqlx::query("DELETE FROM credential_permission_limits WHERE credential_id = $1")
        .bind(cred_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    let action_ids = resolve_ceiling_action_ids(&mut tx, &permissions).await?;
    for permission in &permissions {
        write_ceiling_limit(&mut tx, cred_id, permission, &action_ids).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

/// Resolve every action name used by a permission list in one query, for
/// `write_ceiling_limit`. Unknown names are a bad request. Resolved inside the
/// open tx so the ids stay consistent with the FK inserts that follow.
async fn resolve_ceiling_action_ids(
    tx: &mut Transaction<'_, Postgres>,
    permissions: &[AccessTokenPermission],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    use sqlx::Row;
    let names: Vec<String> = permissions
        .iter()
        .flat_map(|permission| permission.actions.iter().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let rows = sqlx::query("SELECT name, id FROM actions WHERE name = ANY($1::text[])")
        .bind(&names)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    let action_ids = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("name").map_err(db_err)?,
                row.try_get::<Uuid, _>("id").map_err(db_err)?,
            ))
        })
        .collect::<Result<std::collections::HashMap<_, _>, AppError>>()?;
    if let Some(unknown) = names.iter().find(|name| !action_ids.contains_key(*name)) {
        return Err(AppError::bad_request(format!("unknown action: {unknown}")));
    }
    Ok(action_ids)
}

/// Insert one ceiling allow-list entry and its actions inside an open tx. Invalid
/// scope/field combinations are rejected by the table CHECK; `action_ids` comes
/// from `resolve_ceiling_action_ids` and covers every name in the permission.
async fn write_ceiling_limit(
    tx: &mut Transaction<'_, Postgres>,
    cred_id: Uuid,
    permission: &AccessTokenPermission,
    action_ids: &std::collections::HashMap<String, Uuid>,
) -> Result<(), AppError> {
    if permission.actions.is_empty() {
        return Err(AppError::bad_request(
            "each permission requires at least one action",
        ));
    }
    // `object_type` must be the full namespaced value (`entity:device`), matching
    // permission_block_scopes. A bare sub-kind (`device`) or a mismatched prefix
    // silently matches nothing at eval, so reject it up front.
    if permission.scope_mode == "object_type" {
        let kind = permission.object_kind.as_deref().unwrap_or_default();
        let valid = permission.object_type.as_deref().is_some_and(|ty| {
            ty.strip_prefix(kind)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|sub| !sub.is_empty())
        });
        if !valid {
            return Err(AppError::bad_request(
                "object_type must be the full namespaced value matching object_kind, e.g. 'entity:device'",
            ));
        }
    }
    // `platform` and `object` modes take no tenant restriction (the object mode
    // pins one UUID already); a stray tenant_id would silently narrow the entry.
    if matches!(permission.scope_mode.as_str(), "platform" | "object")
        && permission.tenant_id.is_some()
    {
        return Err(AppError::bad_request(
            "tenant_id is not supported for platform or object scope modes",
        ));
    }
    let conditions = permission
        .conditions
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let limit_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO credential_permission_limits
             (id, credential_id, scope_mode, tenant_id, object_kind, object_type, object_id, conditions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(limit_id)
    .bind(cred_id)
    .bind(&permission.scope_mode)
    .bind(permission.tenant_id)
    .bind(&permission.object_kind)
    .bind(&permission.object_type)
    .bind(permission.object_id)
    .bind(conditions)
    .execute(&mut **tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23514") => {
            AppError::bad_request("invalid permission scope for access token")
        }
        other => AppError::Database(other),
    })?;

    for action in &permission.actions {
        let action_id = action_ids
            .get(action)
            .ok_or_else(|| AppError::bad_request(format!("unknown action: {action}")))?;
        sqlx::query(
            r#"INSERT INTO credential_permission_limit_actions (limit_id, action_id)
               VALUES ($1, $2) ON CONFLICT DO NOTHING"#,
        )
        .bind(limit_id)
        .bind(action_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }
    Ok(())
}

/// Filters and paging for the token listing. `status = None` lists all tokens.
#[derive(Debug, Default)]
pub struct ListAccessTokens {
    pub status: Option<CredentialStatus>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn list_access_tokens(
    pool: &PgPool,
    entity_id: Uuid,
    params: ListAccessTokens,
) -> Result<(Vec<AccessTokenSummary>, i64), AppError> {
    use sqlx::Row;

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
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
                  COUNT(*) OVER() AS total
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

    let mut total = 0;
    let credential_ids: Vec<Uuid> = rows
        .iter()
        .map(|row| {
            total = row.try_get("total").map_err(db_err)?;
            row.try_get("id").map_err(db_err)
        })
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
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok((items, total))
}

/// The owner (entity id) of an access-token credential; `NotFound` when the id
/// does not exist or is not an access token. Used by the GraphQL layer to route
/// owner vs delegated (admin) lifecycle operations.
pub async fn access_token_owner(pool: &PgPool, cred_id: Uuid) -> Result<Uuid, AppError> {
    sqlx::query_scalar(r#"SELECT entity_id FROM credentials WHERE id = $1 AND kind = $2"#)
        .bind(cred_id)
        .bind(CredentialKind::AccessToken)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| AppError::not_found("access token not found"))
}

/// Render token ceilings for display: one entry per limit row with its action
/// names, grouped per credential in one query for the whole listing.
async fn load_access_token_permissions(
    pool: &PgPool,
    credential_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, Vec<AccessTokenPermissionSummary>>, AppError> {
    use sqlx::Row;
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
                actions: row.try_get("actions").map_err(db_err)?,
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

pub async fn revoke_access_token(
    pool: &PgPool,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"UPDATE credentials
           SET status = 'revoked',
               metadata = metadata - 'revoked_at' - 'revocation_reason'
                          || jsonb_build_object(
                              'revoked_at', now(),
                              'revocation_reason', 'manual'
                          )
           WHERE id = $1
             AND entity_id = $2
             AND kind = $3"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("access token not found"));
    }
    Ok(())
}
