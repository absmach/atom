use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use chrono::Utc;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    keys::{ActiveKeys, LoadedKey},
    models::enums::{CredentialKind, CredentialStatus, EntityStatus, TenantStatus},
    state::AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub sid: String,
    pub tid: Option<String>,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthContext {
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
}

/// Extractor that requires the authenticated entity to hold a `manage` policy
/// binding with scope `all`. Returns 403 if the check fails.
#[allow(dead_code)]
pub struct RequireManage(pub AuthContext);

// ─── JWT ──────────────────────────────────────────────────────────────────────

pub fn encode_jwt(
    entity_id: Uuid,
    session_id: Uuid,
    tenant_id: Option<Uuid>,
    primary: &LoadedKey,
    expiry_secs: u64,
    issuer: &str,
    audience: &str,
) -> Result<String, AppError> {
    let header = Header {
        alg: Algorithm::ES256,
        kid: Some(primary.kid.clone()),
        ..Header::default()
    };

    let now = Utc::now().timestamp() as usize;
    let claims = Claims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        sub: entity_id.to_string(),
        sid: session_id.to_string(),
        tid: tenant_id.map(|t| t.to_string()),
        iat: now,
        exp: now + expiry_secs as usize,
    };

    let encoding_key = EncodingKey::from_ec_pem(primary.private_key_pem.as_bytes())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("encode jwt: {e}")))?;

    encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("encode jwt: {e}")))
}

fn decode_jwt(
    token: &str,
    keys: &ActiveKeys,
    issuer: &str,
    audience: &str,
) -> Result<Claims, AppError> {
    let header =
        decode_header(token).map_err(|e| AppError::unauthorized(format!("invalid token: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| AppError::unauthorized("token missing kid claim"))?;

    let key = keys
        .key_for(&kid)
        .ok_or_else(|| AppError::unauthorized("token signed with unknown or retired key"))?;

    let decoding_key = DecodingKey::from_ec_pem(key.public_key_pem.as_bytes())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode key parse: {e}")))?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|d| d.claims)
        .map_err(|e| AppError::unauthorized(format!("invalid token: {e}")))
}

// ─── API key ──────────────────────────────────────────────────────────────────

pub fn make_api_key(cred_id: Uuid, secret_bytes: &[u8; 32]) -> String {
    let id_hex = hex::encode(cred_id.as_bytes());
    let secret_hex = hex::encode(secret_bytes);
    format!("atom_{id_hex}_{secret_hex}")
}

fn parse_api_key(key: &str) -> Option<(Uuid, [u8; 32])> {
    let rest = key.strip_prefix("atom_")?;
    if rest.len() != 32 + 1 + 64 {
        return None;
    }
    let (id_hex, tail) = rest.split_at(32);
    let secret_hex = tail.strip_prefix('_')?;

    let id_bytes = hex::decode(id_hex).ok()?;
    let id: [u8; 16] = id_bytes.try_into().ok()?;
    let cred_id = Uuid::from_bytes(id);

    let secret_bytes = hex::decode(secret_hex).ok()?;
    let secret: [u8; 32] = secret_bytes.try_into().ok()?;

    Some((cred_id, secret))
}

// ─── Token dispatch ───────────────────────────────────────────────────────────

async fn auth_from_token(state: &AppState, token: &str) -> Result<AuthContext, AppError> {
    if token.starts_with("atom_") {
        return auth_from_api_key(state, token).await;
    }
    auth_from_jwt(state, token).await
}

async fn auth_from_jwt(state: &AppState, token: &str) -> Result<AuthContext, AppError> {
    let keys = state.keys.read().await;
    let claims = decode_jwt(
        token,
        &keys,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )?;
    drop(keys);

    let entity_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| AppError::unauthorized("invalid entity id in token"))?;
    let session_id: Uuid = claims
        .sid
        .parse()
        .map_err(|_| AppError::unauthorized("invalid session id in token"))?;
    let tenant_id: Option<Uuid> = claims
        .tid
        .as_deref()
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| AppError::unauthorized("invalid tenant id in token"))?;

    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT s.revoked_at,
                  s.expires_at,
                  e.tenant_id,
                  e.status AS entity_status,
                  t.status AS tenant_status
           FROM sessions s
           JOIN entities e ON e.id = s.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE s.id = $1 AND s.entity_id = $2"#,
    )
    .bind(session_id)
    .bind(entity_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::unauthorized("session not found"),
        other => AppError::Database(other),
    })?;

    let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at").unwrap_or(None);
    let expires_at: chrono::DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|_| AppError::unauthorized("corrupt session"))?;

    if revoked_at.is_some() {
        return Err(AppError::unauthorized("session revoked"));
    }
    if expires_at < Utc::now() {
        return Err(AppError::unauthorized("session expired"));
    }

    let entity_status: EntityStatus = row
        .try_get("entity_status")
        .map_err(|_| AppError::unauthorized("corrupt entity"))?;
    if entity_status != EntityStatus::Active {
        return Err(AppError::unauthorized("entity is not active"));
    }

    let entity_tenant_id: Option<Uuid> = row.try_get("tenant_id").unwrap_or(None);
    if tenant_id != entity_tenant_id {
        return Err(AppError::unauthorized("token tenant does not match entity"));
    }
    if let Some(tenant_status) = row
        .try_get::<Option<TenantStatus>, _>("tenant_status")
        .unwrap_or(None)
    {
        if tenant_status != TenantStatus::Active {
            return Err(AppError::unauthorized("tenant is not active"));
        }
    }

    Ok(AuthContext {
        entity_id,
        tenant_id: entity_tenant_id,
        session_id: Some(session_id),
    })
}

async fn auth_from_api_key(state: &AppState, key: &str) -> Result<AuthContext, AppError> {
    let (cred_id, secret_bytes) =
        parse_api_key(key).ok_or_else(|| AppError::unauthorized("malformed api key"))?;

    use sqlx::Row;

    let row = sqlx::query(
        r#"SELECT c.entity_id,
                  c.secret_hash,
                  c.status,
                  c.expires_at,
                  e.tenant_id,
                  e.status AS entity_status,
                  t.status AS tenant_status
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE c.id = $1 AND c.kind = $2"#,
    )
    .bind(cred_id)
    .bind(CredentialKind::ApiKey)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::unauthorized("api key not found"),
        other => AppError::Database(other),
    })?;

    let status: CredentialStatus = row.try_get("status").map_err(db_err)?;
    if status != CredentialStatus::Active {
        return Err(AppError::unauthorized("api key revoked"));
    }

    let expires_at: Option<chrono::DateTime<Utc>> = row.try_get("expires_at").unwrap_or(None);
    if let Some(exp) = expires_at {
        if exp < Utc::now() {
            return Err(AppError::unauthorized("api key expired"));
        }
    }

    let entity_status: EntityStatus = row
        .try_get("entity_status")
        .map_err(|_| AppError::unauthorized("corrupt entity"))?;
    if entity_status != EntityStatus::Active {
        return Err(AppError::unauthorized("entity is not active"));
    }
    if let Some(tenant_status) = row
        .try_get::<Option<TenantStatus>, _>("tenant_status")
        .unwrap_or(None)
    {
        if tenant_status != TenantStatus::Active {
            return Err(AppError::unauthorized("tenant is not active"));
        }
    }

    let hash: Option<String> = row.try_get("secret_hash").unwrap_or(None);
    let hash = hash.ok_or_else(|| AppError::unauthorized("invalid credential"))?;

    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let parsed =
        PasswordHash::new(&hash).map_err(|_| AppError::unauthorized("invalid credential"))?;
    Argon2::default()
        .verify_password(&secret_bytes, &parsed)
        .map_err(|_| AppError::unauthorized("invalid api key"))?;

    let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;

    let tenant_id: Option<Uuid> = row.try_get("tenant_id").unwrap_or(None);

    Ok(AuthContext {
        entity_id,
        tenant_id,
        session_id: None,
    })
}

/// Validate a Bearer token (JWT or API key) and return the authenticated context.
/// Used by the gRPC layer, which bypasses the Axum extractor.
pub async fn authenticate_token(state: &AppState, token: &str) -> Result<AuthContext, AppError> {
    auth_from_token(state, token).await
}

// ─── Admin authorization ──────────────────────────────────────────────────────

/// Scope an authorisation gate evaluates against. M4 introduces tenant and
/// object-scoped gates so endpoints can check the protected object they mutate.
#[derive(Debug, Clone, Copy)]
pub enum Scope {
    /// Platform layer (the top of the hierarchy). Matches a binding with
    /// `scope_kind = 'platform'`.
    Platform,
    /// Tenant layer. Matches a binding with `scope_kind = 'tenant'` and
    /// `scope_ref = <tenant>`, or a `platform` binding (which inherits).
    Tenant(Uuid),
    /// Exact object layer. Matches a binding with `scope_kind = 'object'` and
    /// `scope_ref = <object>`, or a `platform` binding (which inherits).
    Object(Uuid),
}

/// Returns true if `entity_id` holds an `allow` binding granting
/// `capability_name` at the supplied scope. Direct entity bindings, group
/// bindings, capability grants, and role grants (with the named capability in
/// the role) are all considered.
///
/// `Scope::Platform` matches only platform-scope bindings.
/// `Scope::Tenant(t)` matches tenant-scope bindings whose ref equals `t`, exact
/// object grants do the same for `scope_kind = object`, and both inherit from
/// platform-scope bindings for the same capability.
pub async fn has_capability_in_scope(
    pool: &PgPool,
    entity_id: Uuid,
    capability_name: &str,
    scope: Scope,
) -> Result<bool, AppError> {
    let (scope_clause, scope_ref): (&str, Option<String>) = match scope {
        Scope::Platform => ("pb.scope_kind = 'platform'", None),
        Scope::Tenant(t) => (
            r#"(pb.scope_kind = 'platform'
               OR (
                   pb.scope_kind = 'tenant'
                   AND pb.scope_ref = $3
                   AND EXISTS (
                       SELECT 1 FROM tenants tenant
                       WHERE tenant.id = $3::uuid AND tenant.status = 'active'
                   )
               ))"#,
            Some(t.to_string()),
        ),
        Scope::Object(id) => (
            "(pb.scope_kind = 'platform' OR (pb.scope_kind = 'object' AND pb.scope_ref = $3))",
            Some(id.to_string()),
        ),
    };

    let sql = format!(
        r#"SELECT EXISTS (
            SELECT 1
            FROM policy_bindings pb
            JOIN entities actor ON actor.id = $1 AND actor.status = 'active'
            LEFT JOIN tenants actor_tenant ON actor_tenant.id = actor.tenant_id
            WHERE (
                (pb.subject_kind = 'entity' AND pb.subject_id = $1)
                OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                    SELECT group_id FROM group_members WHERE entity_id = $1
                ))
            )
            AND (actor.tenant_id IS NULL OR actor_tenant.status = 'active')
            AND pb.effect = 'allow'
            AND {scope_clause}
            AND (
                (pb.grant_kind = 'capability' AND pb.grant_id IN (
                    SELECT id FROM capabilities WHERE name = $2 AND resource_kind IS NULL
                ))
                OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                    SELECT rc.role_id FROM role_capabilities rc
                    JOIN capabilities c ON c.id = rc.capability_id
                    WHERE c.name = $2 AND c.resource_kind IS NULL
                ))
            )
        )"#
    );

    let mut q = sqlx::query_scalar(&sql)
        .bind(entity_id)
        .bind(capability_name);
    if let Some(scope_ref) = scope_ref {
        q = q.bind(scope_ref);
    }
    q.fetch_one(pool).await.map_err(db_err)
}

pub async fn has_capability_at_scope(
    pool: &PgPool,
    entity_id: Uuid,
    capability_name: &str,
    scope: Scope,
) -> Result<bool, AppError> {
    has_capability_in_scope(pool, entity_id, capability_name, scope).await
}

pub async fn require_any_capability(
    pool: &PgPool,
    entity_id: Uuid,
    checks: &[(&str, Scope)],
) -> Result<(), AppError> {
    for (capability_name, scope) in checks {
        if has_capability_in_scope(pool, entity_id, capability_name, *scope).await? {
            return Ok(());
        }
    }
    Err(AppError::Forbidden)
}

pub fn scope_for_tenant(tenant_id: Option<Uuid>) -> Scope {
    match tenant_id {
        Some(tenant_id) => Scope::Tenant(tenant_id),
        None => Scope::Platform,
    }
}

pub async fn require_list_access(
    pool: &PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let scope = scope_for_tenant(tenant_id);
    require_any_capability(
        pool,
        entity_id,
        &[("list", scope), ("read", scope), ("manage", scope)],
    )
    .await
}

pub async fn require_read_access(
    pool: &PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
    object_id: Uuid,
) -> Result<(), AppError> {
    let tenant_scope = scope_for_tenant(tenant_id);
    require_any_capability(
        pool,
        entity_id,
        &[
            ("read", Scope::Object(object_id)),
            ("manage", Scope::Object(object_id)),
            ("read", tenant_scope),
            ("manage", tenant_scope),
        ],
    )
    .await
}

pub async fn require_role_read(
    pool: &PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let scope = scope_for_tenant(tenant_id);
    require_any_capability(
        pool,
        entity_id,
        &[("role.manage", scope), ("read", scope), ("list", scope)],
    )
    .await
}

pub async fn require_policy_read(pool: &PgPool, entity_id: Uuid) -> Result<(), AppError> {
    require_any_capability(
        pool,
        entity_id,
        &[
            ("policy.manage", Scope::Platform),
            ("read", Scope::Platform),
            ("list", Scope::Platform),
            ("manage", Scope::Platform),
        ],
    )
    .await
}

pub async fn require_explain_access(pool: &PgPool, entity_id: Uuid) -> Result<(), AppError> {
    require_any_capability(
        pool,
        entity_id,
        &[
            ("policy.manage", Scope::Platform),
            ("manage", Scope::Platform),
        ],
    )
    .await
}

/// Convenience for the common platform-`manage` check used by the existing
/// `RequireManage` extractor and admin hygiene endpoints.
pub async fn has_global_manage(pool: &PgPool, entity_id: Uuid) -> Result<bool, AppError> {
    has_capability_in_scope(pool, entity_id, "manage", Scope::Platform).await
}

/// Imperative gate: returns `Forbidden` if the entity does not hold the
/// requested capability at the given scope. Use from handlers that need a
/// finer check than `RequireManage`.
pub async fn require_capability(
    pool: &PgPool,
    entity_id: Uuid,
    capability_name: &str,
    scope: Scope,
) -> Result<(), AppError> {
    if has_capability_in_scope(pool, entity_id, capability_name, scope).await? {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

// ─── Axum extractors ──────────────────────────────────────────────────────────

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::unauthorized("expected Bearer token"))?;

        auth_from_token(&app_state, token).await
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for RequireManage
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let auth = AuthContext::from_request_parts(parts, state).await?;

        if !has_global_manage(&app_state.pool, auth.entity_id).await? {
            return Err(AppError::Forbidden);
        }

        Ok(RequireManage(auth))
    }
}
