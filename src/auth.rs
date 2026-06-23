use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, HeaderMap, Method},
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
    models::enums::{
        CredentialKind, CredentialStatus, Effect, EntityStatus, ScopeKind, TenantStatus,
    },
    state::AppState,
};

pub const AUTH_COOKIE_NAME: &str = "atom_token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTokenSource {
    Authorization,
    Cookie,
}

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

pub fn token_from_headers(
    headers: &HeaderMap,
) -> Result<Option<(&str, AuthTokenSource)>, AppError> {
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        let value = value
            .to_str()
            .map_err(|_| AppError::unauthorized("invalid Authorization header"))?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::unauthorized("Authorization header must use Bearer"))?;
        return Ok(Some((token, AuthTokenSource::Authorization)));
    }

    Ok(cookie_token(headers).map(|token| (token, AuthTokenSource::Cookie)))
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in value.split(';') {
        let (name, value) = part.trim().split_once('=')?;
        if name == AUTH_COOKIE_NAME && !value.trim().is_empty() {
            return Some(value.trim());
        }
    }
    None
}

pub fn is_unsafe_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub fn require_trusted_origin(
    headers: &HeaderMap,
    allowed_origins: &[String],
) -> Result<(), AppError> {
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return check_allowed_origin(origin, allowed_origins);
    }

    if let Some(referer) = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
    {
        let parsed = url::Url::parse(referer).map_err(|_| AppError::Forbidden)?;
        let Some(host) = parsed.host_str() else {
            return Err(AppError::Forbidden);
        };
        let mut origin = format!("{}://{}", parsed.scheme(), host);
        if let Some(port) = parsed.port() {
            origin.push(':');
            origin.push_str(&port.to_string());
        }
        return check_allowed_origin(&origin, allowed_origins);
    }

    Err(AppError::Forbidden)
}

fn check_allowed_origin(origin: &str, allowed_origins: &[String]) -> Result<(), AppError> {
    let origin = origin.trim_end_matches('/');
    if allowed_origins
        .iter()
        .any(|allowed| allowed.trim_end_matches('/') == origin)
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
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
    if !actor_is_active(pool, entity_id).await? {
        return Ok(false);
    }
    if let Scope::Tenant(tenant_id) = scope {
        if !tenant_is_active(pool, tenant_id).await? {
            return Ok(false);
        }
    }
    let Some(action_id) = action_id_by_name(pool, capability_name).await? else {
        return Ok(false);
    };
    let grants = crate::authz::repo::effective_grants_for_subject(pool, entity_id).await?;
    let gate_tenant = gate_tenant_context(pool, scope).await?;
    Ok(gate_action_allows(
        &grants,
        action_id,
        &[(scope, gate_tenant)],
    ))
}

/// The tenant whose objects the gate concerns, used to apply the same assignment
/// tenant boundary the PDP enforces (`EffectiveGrant::tenant_boundary`). A
/// platform gate has no tenant; a tenant gate is that tenant; an object gate is
/// the object's owning tenant, resolved here exactly as the PDP resolves it.
/// A missing object and a platform/global object both resolve to `None`.
async fn gate_tenant_context(pool: &PgPool, scope: Scope) -> Result<Option<Uuid>, AppError> {
    Ok(match scope {
        Scope::Platform => None,
        Scope::Tenant(tenant_id) => Some(tenant_id),
        Scope::Object(object_id) => crate::authz::repo::object_tenant_id_by_id(pool, object_id)
            .await?
            .flatten(),
    })
}

/// Coarse control-plane decision over the canonical grant expansion: does the
/// subject hold an *unconditional* `allow` for `action_id` at one of `scopes`,
/// not overridden by a deny? Group membership is already resolved recursively by
/// the expansion, and role-linked blocks carry their own scope/effect.
///
/// **All `scopes` for the action are evaluated together.** A caller that accepts
/// either an exact-object grant or a tenant-wide grant (e.g. `require_read_access`)
/// passes both scopes here, so a deny at the narrower scope (an exact-object
/// deny) overrides an allow at the broader one (a tenant-wide allow) — exactly as
/// the PDP applies deny-override. Evaluating each scope independently and
/// returning on the first allow would let a tenant allow bypass an object deny.
///
/// Gates **fail closed on ABAC conditions** because they run without request
/// context, and several callers use the gate as the final authorization (e.g.
/// `createEntity` has no object to re-check against the PDP):
/// - only an *unconditional* allow satisfies the gate — a conditional allow
///   cannot be verified here, so it does not grant the precondition (otherwise a
///   `manage if context.mfa` grant would pass without MFA);
/// - *any* matching deny blocks, conditional or not — a deny we cannot fully
///   evaluate is assumed to apply.
///
/// Object-specific decisions must still call the PDP, which evaluates the
/// conditions this gate deliberately ignores. The trade-off is that a subject
/// whose only access is conditional will not pass a coarse gate; that is the
/// safe direction for an administrative precondition.
///
/// Each scope carries its `gate_tenant` (see [`gate_tenant_context`]); a grant's
/// assignment tenant boundary is applied against the scope it matches, just as
/// the PDP does, so a platform- or object-scoped block reached through a
/// tenant-bounded assignment cannot satisfy a gate for another tenant's object.
/// A requested scope paired with the tenant whose objects it concerns (its
/// [`gate_tenant_context`]), the unit `gate_action_allows` evaluates.
type ScopeCheck = (Scope, Option<Uuid>);

fn gate_action_allows(
    grants: &[crate::authz::repo::EffectiveGrant],
    action_id: Uuid,
    scopes: &[ScopeCheck],
) -> bool {
    let mut allow = false;
    for grant in grants {
        if grant.capability_id != action_id {
            continue;
        }
        // The grant applies if it matches any requested scope under that scope's
        // assignment tenant boundary. A tenant-bounded grant only applies to that
        // tenant's objects, matching the PDP.
        let applies = scopes.iter().any(|(scope, gate_tenant)| {
            gate_scope_satisfied(grant, *scope)
                && grant
                    .tenant_boundary
                    .is_none_or(|boundary| Some(boundary) == *gate_tenant)
        });
        if !applies {
            continue;
        }
        match grant.effect {
            Effect::Deny => return false,
            Effect::Allow if is_unconditional(&grant.conditions) => allow = true,
            Effect::Allow => {}
        }
    }
    allow
}

fn gate_scope_satisfied(grant: &crate::authz::repo::EffectiveGrant, scope: Scope) -> bool {
    match scope {
        Scope::Platform => grant.scope_kind == ScopeKind::Platform,
        Scope::Tenant(tenant_id) => {
            grant.scope_kind == ScopeKind::Platform
                || (grant.scope_kind == ScopeKind::Tenant
                    && grant.scope_ref.as_deref() == Some(tenant_id.to_string().as_str()))
        }
        Scope::Object(object_id) => {
            grant.scope_kind == ScopeKind::Platform
                || (grant.scope_kind == ScopeKind::Object
                    && grant.scope_ref.as_deref() == Some(object_id.to_string().as_str()))
        }
    }
}

fn is_unconditional(conditions: &serde_json::Value) -> bool {
    conditions.as_object().is_some_and(|map| map.is_empty())
}

async fn actor_is_active(pool: &PgPool, entity_id: Uuid) -> Result<bool, AppError> {
    let active: Option<bool> = sqlx::query_scalar(
        r#"SELECT (actor.status = 'active'
                   AND (actor.tenant_id IS NULL OR actor_tenant.status = 'active'))
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

async fn tenant_is_active(pool: &PgPool, tenant_id: Uuid) -> Result<bool, AppError> {
    let active: Option<bool> =
        sqlx::query_scalar("SELECT status = 'active' FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?;
    Ok(active.unwrap_or(false))
}

async fn action_id_by_name(pool: &PgPool, name: &str) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
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
    if checks.is_empty() {
        return Err(AppError::Forbidden);
    }
    if !actor_is_active(pool, entity_id).await? {
        return Err(AppError::Forbidden);
    }
    // Load the subject's grants and resolve the candidate action names once,
    // then evaluate the candidates in memory instead of firing one expansion
    // query per candidate.
    let grants = crate::authz::repo::effective_grants_for_subject(pool, entity_id).await?;
    let names: Vec<&str> = checks.iter().map(|(name, _)| *name).collect();
    let action_ids = action_ids_by_name(pool, &names).await?;
    let mut tenant_active: std::collections::HashMap<Uuid, bool> = std::collections::HashMap::new();
    // Resolved owning tenant per object id, so a repeated object scope across the
    // candidate list (e.g. read + manage on the same object) is looked up once.
    let mut object_tenant: std::collections::HashMap<Uuid, Option<Uuid>> =
        std::collections::HashMap::new();

    // Group the requested scopes by action, preserving order, so each action is
    // evaluated across all of its scopes together (cross-scope deny-override).
    let mut by_action: Vec<(Uuid, Vec<ScopeCheck>)> = Vec::new();
    for (capability_name, scope) in checks {
        let Some(&action_id) = action_ids.get(*capability_name) else {
            continue;
        };
        if let Scope::Tenant(tenant_id) = scope {
            let active = match tenant_active.get(tenant_id) {
                Some(&active) => active,
                None => {
                    let active = tenant_is_active(pool, *tenant_id).await?;
                    tenant_active.insert(*tenant_id, active);
                    active
                }
            };
            // An inactive tenant's scope cannot grant anything; drop it.
            if !active {
                continue;
            }
        }
        let gate_tenant = match scope {
            Scope::Platform => None,
            Scope::Tenant(tenant_id) => Some(*tenant_id),
            Scope::Object(object_id) => match object_tenant.get(object_id) {
                Some(&tenant) => tenant,
                None => {
                    let tenant = gate_tenant_context(pool, *scope).await?;
                    object_tenant.insert(*object_id, tenant);
                    tenant
                }
            },
        };
        match by_action.iter_mut().find(|(id, _)| *id == action_id) {
            Some((_, action_scopes)) => action_scopes.push((*scope, gate_tenant)),
            None => by_action.push((action_id, vec![(*scope, gate_tenant)])),
        }
    }

    // Any one action whose combined scopes yield an allow (not overridden by a
    // deny at any of them) authorizes the request.
    for (action_id, action_scopes) in &by_action {
        if gate_action_allows(&grants, *action_id, action_scopes) {
            return Ok(());
        }
    }
    Err(AppError::Forbidden)
}

async fn action_ids_by_name(
    pool: &PgPool,
    names: &[&str],
) -> Result<std::collections::HashMap<String, Uuid>, AppError> {
    use sqlx::Row;
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
    require_any_capability(pool, entity_id, &[("read", scope), ("manage", scope)]).await
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
    require_any_capability(pool, entity_id, &[("role.manage", scope), ("read", scope)]).await
}

/// Gate for reading policy records in a tenant (or platform when `tenant_id` is
/// `None`): `policy.manage`, `read`, or `manage` at that scope.
pub async fn require_policy_read(
    pool: &PgPool,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let scope = scope_for_tenant(tenant_id);
    require_any_capability(
        pool,
        entity_id,
        &[("policy.manage", scope), ("read", scope), ("manage", scope)],
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

        let (token, source) = token_from_headers(&parts.headers)?
            .ok_or_else(|| AppError::unauthorized("missing authentication"))?;
        if source == AuthTokenSource::Cookie && is_unsafe_method(&parts.method) {
            require_trusted_origin(&parts.headers, &app_state.config.cors_allowed_origins)?;
        }

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
