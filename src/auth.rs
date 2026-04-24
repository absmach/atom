use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    models::enums::{CredentialKind, CredentialStatus},
    state::AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
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

pub fn encode_jwt(
    entity_id: Uuid,
    session_id: Uuid,
    tenant_id: Option<Uuid>,
    secret: &str,
    expiry_secs: u64,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: entity_id.to_string(),
        sid: session_id.to_string(),
        tid: tenant_id.map(|t| t.to_string()),
        iat: now,
        exp: now + expiry_secs as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::bad_request(format!("jwt encode error: {e}")))
}

fn decode_jwt(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|d| d.claims)
    .map_err(|e| AppError::unauthorized(format!("invalid token: {e}")))
}

// API key format: atom_<32-hex-cred-id>_<64-hex-secret>
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

async fn auth_from_token(state: &AppState, token: &str) -> Result<AuthContext, AppError> {
    if token.starts_with("atom_") {
        return auth_from_api_key(state, token).await;
    }
    auth_from_jwt(state, token).await
}

async fn auth_from_jwt(state: &AppState, token: &str) -> Result<AuthContext, AppError> {
    let claims = decode_jwt(token, &state.config.jwt_secret)?;

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
    let row = sqlx::query("SELECT revoked_at, expires_at FROM sessions WHERE id = $1")
        .bind(session_id)
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

    Ok(AuthContext {
        entity_id,
        tenant_id,
        session_id: Some(session_id),
    })
}

async fn auth_from_api_key(state: &AppState, key: &str) -> Result<AuthContext, AppError> {
    let (cred_id, secret_bytes) =
        parse_api_key(key).ok_or_else(|| AppError::unauthorized("malformed api key"))?;

    use sqlx::Row;

    let row = sqlx::query(
        "SELECT entity_id, secret_hash, status, expires_at FROM credentials WHERE id = $1 AND kind = $2",
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

    let tenant_id = sqlx::query("SELECT tenant_id FROM entities WHERE id = $1")
        .bind(entity_id)
        .fetch_one(&state.pool)
        .await
        .map_err(db_err)
        .and_then(|r: sqlx::postgres::PgRow| {
            use sqlx::Row;
            r.try_get::<Option<Uuid>, _>("tenant_id").map_err(db_err)
        })?;

    Ok(AuthContext {
        entity_id,
        tenant_id,
        session_id: None,
    })
}

/// Returns true if `entity_id` holds an allow policy with scope=all that
/// covers the `manage` capability (directly or via a role).
pub async fn has_global_manage(pool: &PgPool, entity_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
            SELECT 1
            FROM policy_bindings pb
            WHERE (
                (pb.subject_kind = 'entity' AND pb.subject_id = $1)
                OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                    SELECT group_id FROM group_members WHERE entity_id = $1
                ))
            )
            AND pb.effect = 'allow'
            AND pb.scope_kind = 'all'
            AND (
                (pb.grant_kind = 'capability' AND pb.grant_id IN (
                    SELECT id FROM capabilities WHERE name = 'manage'
                ))
                OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                    SELECT rc.role_id FROM role_capabilities rc
                    JOIN capabilities c ON c.id = rc.capability_id
                    WHERE c.name = 'manage'
                ))
            )
        )"#,
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)
}

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
