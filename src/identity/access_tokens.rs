//! Access-token lifecycle: minting (scoped and unscoped), ceiling replacement,
//! owner listing, and revocation. Verification lives in `crate::auth`
//! (`auth_from_api_key`); ceiling evaluation lives in the PDP and the
//! ceiling-aware listing readers.

mod repository;

use crate::db::Database;
use argon2::password_hash::rand_core::OsRng;
use chrono::Utc;
use rand::RngCore;
use uuid::Uuid;

use crate::{
    auth::make_api_key,
    config::SigningKeyConfig,
    crypto,
    db::DbTransaction,
    error::{db_err, AppError},
    models::{
        enums::CredentialStatus,
        token::{
            AccessTokenPermission, AccessTokenResponse, AccessTokenSummary, CreateAccessToken,
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
    pool: &Database,
    signing_keys: &SigningKeyConfig,
    entity_id: Uuid,
    req: CreateAccessToken,
    scoped: bool,
) -> Result<AccessTokenResponse, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let response = create_access_token_in_tx(&mut tx, signing_keys, entity_id, req, scoped).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(response)
}

/// The caller owns the commit, so an audited caller can bind the mint and its
/// `credential.create` event into one transaction via
/// [`crate::audit::commit_with_audit`].
pub async fn create_access_token_in_tx(
    tx: &mut DbTransaction<'_>,
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

    if super::repo::lock_active_entity(tx, entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::not_found(format!(
            "active entity {entity_id} not found"
        )));
    }
    // A scoped token's authority is capped by its ceiling; an unscoped token
    // (`scoped = false`) authenticates with the owner's full live grants.
    repository::insert_token(
        tx,
        repository::NewToken {
            id: cred_id,
            entity_id,
            key_prefix,
            secret_hash,
            secret_lookup_hash,
            scoped,
            expires_at: req.expires_at,
            metadata,
        },
    )
    .await?;

    let action_ids = resolve_ceiling_action_ids(tx, &req.permissions).await?;
    for permission in &req.permissions {
        write_ceiling_limit(tx, cred_id, permission, &action_ids).await?;
    }

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
    pool: &Database,
    entity_id: Uuid,
    cred_id: Uuid,
    permissions: Vec<AccessTokenPermission>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    replace_access_token_permissions_in_tx(&mut tx, entity_id, cred_id, permissions).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

/// See [`create_access_token_in_tx`] — the caller owns the commit so the
/// ceiling rewrite and its `credential.update` event land atomically.
pub async fn replace_access_token_permissions_in_tx(
    tx: &mut DbTransaction<'_>,
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
    // Look the token up once and reject config-managed rows with a 409
    // conflict — the same shape as the entity/capability guards.
    let row = repository::lock_active_token(tx, entity_id, cred_id).await?;
    match row {
        None => return Err(AppError::not_found("access token not found")),
        Some((_, Some(mgr))) if mgr == "config" => {
            return Err(AppError::conflict(
                "access token is managed by the bootstrap config file and cannot be modified via the API",
            ))
        }
        Some((false, _)) => {
            return Err(AppError::bad_request(
                "cannot set permissions on an unscoped access token",
            ))
        }
        Some((true, _)) => {}
    }

    repository::clear_ceiling(tx, cred_id).await?;
    let action_ids = resolve_ceiling_action_ids(tx, &permissions).await?;
    for permission in &permissions {
        write_ceiling_limit(tx, cred_id, permission, &action_ids).await?;
    }
    Ok(())
}

/// Resolve every action name used by a permission list in one query, for
/// `write_ceiling_limit`. Unknown names are a bad request. Resolved inside the
/// open tx so the ids stay consistent with the FK inserts that follow.
async fn resolve_ceiling_action_ids(
    tx: &mut DbTransaction<'_>,
    permissions: &[AccessTokenPermission],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    let names: Vec<String> = permissions
        .iter()
        .flat_map(|permission| permission.actions.iter().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let action_ids = repository::action_ids(tx, &names).await?;
    if let Some(unknown) = names.iter().find(|name| !action_ids.contains_key(*name)) {
        return Err(AppError::bad_request(format!("unknown action: {unknown}")));
    }
    Ok(action_ids)
}

/// Insert one ceiling allow-list entry and its actions inside an open tx. Invalid
/// scope/field combinations are rejected by the table CHECK; `action_ids` comes
/// from `resolve_ceiling_action_ids` and covers every name in the permission.
async fn write_ceiling_limit(
    tx: &mut DbTransaction<'_>,
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
    let ids = permission
        .actions
        .iter()
        .map(|action| {
            action_ids
                .get(action)
                .copied()
                .ok_or_else(|| AppError::bad_request(format!("unknown action: {action}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    repository::insert_ceiling(tx, cred_id, permission, &ids).await?;

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
    pool: &Database,
    entity_id: Uuid,
    params: ListAccessTokens,
) -> Result<(Vec<AccessTokenSummary>, i64), AppError> {
    repository::list_access_tokens(pool, entity_id, params).await
}

/// The owner (entity id) of an access-token credential; `NotFound` when the id
/// does not exist or is not an access token. Used by the GraphQL layer to route
/// owner vs delegated (admin) lifecycle operations.
pub async fn access_token_owner(pool: &Database, cred_id: Uuid) -> Result<Uuid, AppError> {
    repository::access_token_owner(pool, cred_id).await
}

pub async fn revoke_access_token(
    pool: &Database,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    revoke_access_token_in_tx(&mut tx, entity_id, cred_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

/// See [`create_access_token_in_tx`] — the caller owns the commit so the
/// revocation and its `credential.revoke` event land atomically.
///
/// Bootstrap-provisioned tokens (`managed_by='config'`) are visible via the
/// list APIs so the UI can flag them read-only, but revoke returns 409
/// conflict — rotation lives in the YAML.
pub async fn revoke_access_token_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<(), AppError> {
    let managed_by = repository::lock_token_owner(tx, entity_id, cred_id).await?;
    match managed_by {
        None => return Err(AppError::not_found("access token not found")),
        Some(Some(value)) if value == "config" => {
            return Err(AppError::conflict(
                "access token is managed by the bootstrap config file and cannot be revoked via the API",
            ))
        }
        _ => {}
    }
    repository::revoke(tx, entity_id, cred_id).await?;

    Ok(())
}
