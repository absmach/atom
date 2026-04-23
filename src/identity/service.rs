use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{encode_jwt, make_api_key},
    config::Config,
    error::{db_err, AppError},
    models::{
        session::LoginResponse,
        token::{ApiKeyResponse, CreateApiKey},
    },
};

pub fn hash_secret(secret: &[u8]) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret, &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::bad_request(format!("hash error: {e}")))
}

pub fn verify_secret(secret: &[u8], hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|h| Argon2::default().verify_password(secret, &h).is_ok())
        .unwrap_or(false)
}

pub async fn login_password(
    pool: &PgPool,
    cfg: &Config,
    identifier: &str,
    secret: &str,
) -> Result<LoginResponse, AppError> {
    use sqlx::Row;

    let entity_row = sqlx::query(
        "SELECT id, tenant_id, status FROM entities WHERE name = $1"
    )
    .bind(identifier)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::unauthorized("invalid credentials"),
        other => AppError::Database(other),
    })?;

    let entity_id: Uuid = entity_row.try_get("id").map_err(db_err)?;
    let tenant_id: Option<Uuid> = entity_row.try_get("tenant_id").unwrap_or(None);
    let status: String = entity_row.try_get("status").map_err(db_err)?;

    if status != "active" {
        return Err(AppError::unauthorized("entity is not active"));
    }

    let cred_row = sqlx::query(
        "SELECT secret_hash FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active' LIMIT 1"
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::unauthorized("invalid credentials"),
        other => AppError::Database(other),
    })?;

    let hash: Option<String> = cred_row.try_get("secret_hash").unwrap_or(None);
    let hash = hash.ok_or_else(|| AppError::unauthorized("invalid credentials"))?;

    if !verify_secret(secret.as_bytes(), &hash) {
        return Err(AppError::unauthorized("invalid credentials"));
    }

    let session = super::repo::create_session(pool, entity_id, cfg.jwt_expiry_secs).await?;
    let token = encode_jwt(entity_id, session.id, tenant_id, &cfg.jwt_secret, cfg.jwt_expiry_secs)?;

    Ok(LoginResponse {
        token,
        entity_id,
        session_id: session.id,
        expires_at: session.expires_at,
    })
}

pub async fn create_password(
    pool: &PgPool,
    entity_id: Uuid,
    password: &str,
) -> Result<(), AppError> {
    let hash = hash_secret(password.as_bytes())?;
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)"
    )
    .bind(id)
    .bind(entity_id)
    .bind(hash)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn create_api_key(
    pool: &PgPool,
    entity_id: Uuid,
    req: CreateApiKey,
) -> Result<ApiKeyResponse, AppError> {
    let cred_id = Uuid::new_v4();

    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let hash = hash_secret(&secret_bytes)?;

    let key = make_api_key(cred_id, &secret_bytes);
    let key_prefix = key[..13].to_string();

    let metadata = serde_json::json!({"description": req.description});

    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash, expires_at, metadata)
           VALUES ($1, $2, 'api_key', $3, $4, $5, $6)"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(key_prefix)
    .bind(hash)
    .bind(req.expires_at)
    .bind(metadata)
    .execute(pool)
    .await
    .map_err(db_err)?;

    Ok(ApiKeyResponse {
        credential_id: cred_id,
        key,
        expires_at: req.expires_at,
    })
}

pub async fn revoke_credential(pool: &PgPool, entity_id: Uuid, cred_id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE credentials SET status = 'revoked' WHERE id = $1 AND entity_id = $2"
    )
    .bind(cred_id)
    .bind(entity_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("credential not found"));
    }
    Ok(())
}

pub async fn list_credentials(pool: &PgPool, entity_id: Uuid) -> Result<Vec<CredentialSummary>, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, kind, identifier, status, expires_at, created_at FROM credentials WHERE entity_id = $1 ORDER BY created_at DESC"
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let summaries = rows
        .into_iter()
        .map(|r| CredentialSummary {
            id: r.try_get("id").unwrap(),
            kind: r.try_get("kind").unwrap(),
            identifier: r.try_get("identifier").unwrap_or(None),
            status: r.try_get("status").unwrap(),
            expires_at: r.try_get("expires_at").unwrap_or(None),
            created_at: r.try_get("created_at").unwrap(),
        })
        .collect();

    Ok(summaries)
}

#[derive(serde::Serialize)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub kind: String,
    pub identifier: Option<String>,
    pub status: String,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
}
