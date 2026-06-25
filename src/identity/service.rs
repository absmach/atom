use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use rand::RngCore;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use url::Url;
use uuid::Uuid;

use crate::{
    audit,
    auth::{encode_jwt, make_api_key},
    config::{Config, OidcProviderConfig, SmtpTls},
    error::{db_err, AppError},
    keys::LoadedKey,
    models::{
        enums::{AuditOutcome, CredentialKind, CredentialStatus, EntityKind, EntityStatus},
        session::{
            LoginResponse, PasswordResetConfirmRequest, PasswordResetRequest, SignupRequest,
            SignupResponse,
        },
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

const DEFAULT_MIN_PASSWORD_CHARS: usize = 12;

#[derive(Debug, Clone)]
pub struct CredentialAuthentication {
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub credential_id: Uuid,
    pub email_verified: Option<bool>,
}

pub fn validate_password_strength(password: &str) -> Result<(), AppError> {
    let min_password_chars = std::env::var("ATOM_MIN_PASSWORD_CHARS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MIN_PASSWORD_CHARS);
    if password.chars().count() < min_password_chars {
        return Err(AppError::bad_request(format!(
            "password must be at least {min_password_chars} characters"
        )));
    }
    if password.chars().all(char::is_whitespace) {
        return Err(AppError::bad_request("password cannot be blank"));
    }
    Ok(())
}

pub async fn login_password(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    identifier: &str,
    secret: &str,
) -> Result<LoginResponse, AppError> {
    login_password_with_tenant(pool, cfg, primary_key, identifier, secret, None, None).await
}

pub async fn login_password_with_tenant(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    identifier: &str,
    secret: &str,
    tenant_id: Option<Uuid>,
    tenant_alias: Option<&str>,
) -> Result<LoginResponse, AppError> {
    let result = do_login_password(
        pool,
        cfg,
        primary_key,
        identifier,
        secret,
        tenant_id,
        tenant_alias,
    )
    .await;

    let (entity_id_opt, tenant_id_opt, outcome) = match &result {
        Ok(r) => {
            let tenant_id = sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
                .bind(r.entity_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
            (Some(r.entity_id), tenant_id, AuditOutcome::Allow)
        }
        Err(AppError::Unauthorized(_)) => (None, None, AuditOutcome::Deny),
        Err(_) => return result,
    };

    audit::write(
        pool,
        entity_id_opt,
        tenant_id_opt,
        "auth.login",
        outcome,
        serde_json::json!({"identifier": identifier, "entity_id": entity_id_opt}),
    )
    .await;

    result
}

async fn do_login_password(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    identifier: &str,
    secret: &str,
    requested_tenant_id: Option<Uuid>,
    tenant_alias: Option<&str>,
) -> Result<LoginResponse, AppError> {
    let login_tenant_id = resolve_login_tenant(pool, requested_tenant_id, tenant_alias).await?;
    let authenticated =
        authenticate_password_credential_in_tenant(pool, cfg, identifier, secret, login_tenant_id)
            .await?;
    create_login_response(
        pool,
        cfg,
        primary_key,
        authenticated.entity_id,
        authenticated.email_verified,
    )
    .await
}

pub async fn resolve_credential_auth_tenant(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    tenant_alias: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    resolve_login_tenant(pool, tenant_id, tenant_alias).await
}

pub async fn authenticate_password_credential_in_tenant(
    pool: &PgPool,
    cfg: &Config,
    identifier: &str,
    secret: &str,
    tenant_id: Option<Uuid>,
) -> Result<CredentialAuthentication, AppError> {
    let attempt_identifier = login_attempt_identifier(identifier);
    if let Err(err) = ensure_login_not_throttled(
        pool,
        &attempt_identifier,
        tenant_id,
        cfg.login_failure_limit,
        cfg.login_failure_window_secs,
    )
    .await
    {
        record_login_attempt(pool, &attempt_identifier, tenant_id, false).await;
        return Err(err);
    }

    let result = async {
        let identity = resolve_login_identity(pool, identifier, tenant_id).await?;

        if identity.status != EntityStatus::Active {
            return Err(AppError::unauthorized("entity is not active"));
        }
        // Avoid password verification work for a principal that cannot receive
        // a session. Session creation repeats this check under a row lock.
        ensure_login_target_active(pool, identity.entity_id).await?;

        let credential = password_credential_for_login(
            pool,
            identity.entity_id,
            identity.credential_identifier.as_deref(),
        )
        .await?;
        if !verify_secret(secret.as_bytes(), &credential.secret_hash) {
            return Err(AppError::unauthorized("invalid credentials"));
        }

        if identity.email_verified == Some(false) && !cfg.dev_allow_unverified_email_login {
            return Err(AppError::unauthorized("email verification required"));
        }

        Ok(CredentialAuthentication {
            entity_id: identity.entity_id,
            tenant_id: tenant_id.or(identity.tenant_id),
            credential_id: credential.id,
            email_verified: identity.email_verified,
        })
    }
    .await;

    record_login_attempt(pool, &attempt_identifier, tenant_id, result.is_ok()).await;
    result
}

fn login_attempt_identifier(identifier: &str) -> String {
    normalize_email_lossy(identifier)
}

async fn ensure_login_target_active(pool: &PgPool, entity_id: Uuid) -> Result<(), AppError> {
    let ok: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT e.id
           FROM entities e
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE e.id = $1
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND (e.tenant_id IS NULL OR (t.deleted_at IS NULL AND t.status = 'active'))"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    if ok.is_none() {
        return Err(AppError::unauthorized("entity is not active"));
    }
    Ok(())
}

async fn ensure_login_not_throttled(
    pool: &PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
    failure_limit: i64,
    failure_window_secs: i64,
) -> Result<(), AppError> {
    let failures: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM auth_login_attempts
           WHERE identifier = $1
             AND (($2::uuid IS NULL AND tenant_id IS NULL) OR tenant_id = $2)
             AND success = FALSE
             AND created_at >= now() - ($3::text || ' seconds')::interval"#,
    )
    .bind(identifier)
    .bind(tenant_id)
    .bind(failure_window_secs.to_string())
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    if failures >= failure_limit {
        Err(AppError::rate_limited(
            "too many failed login attempts",
            u64::try_from(failure_window_secs).unwrap_or(1),
        ))
    } else {
        Ok(())
    }
}

async fn record_login_attempt(
    pool: &PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
    success: bool,
) {
    if let Err(err) = sqlx::query(
        r#"INSERT INTO auth_login_attempts (identifier, tenant_id, success)
           VALUES ($1, $2, $3)"#,
    )
    .bind(identifier)
    .bind(tenant_id)
    .bind(success)
    .execute(pool)
    .await
    {
        tracing::warn!("login attempt record failed: {err}");
    }
}

pub async fn signup_human(
    pool: &PgPool,
    cfg: &Config,
    req: SignupRequest,
) -> Result<SignupResponse, AppError> {
    let name = req.name.clone();
    let email = req.email.clone();
    let result = do_signup_human(pool, cfg, req).await;

    let (entity_id_opt, outcome) = match &result {
        Ok(r) => (Some(r.entity_id), AuditOutcome::Allow),
        Err(AppError::Unauthorized(_) | AppError::BadRequest(_) | AppError::Forbidden) => {
            (None, AuditOutcome::Deny)
        }
        Err(_) => return result,
    };

    audit::write(
        pool,
        entity_id_opt,
        None,
        "auth.signup",
        outcome,
        serde_json::json!({"name": name, "email": normalize_email_lossy(&email), "entity_id": entity_id_opt}),
    )
    .await;

    result
}

async fn do_signup_human(
    pool: &PgPool,
    cfg: &Config,
    req: SignupRequest,
) -> Result<SignupResponse, AppError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    if req.password.is_empty() {
        return Err(AppError::bad_request("password is required"));
    }
    validate_password_strength(&req.password)?;
    let email = normalize_email(&req.email)?;
    let attributes = normalize_json_object(req.attributes);
    let password_hash = hash_secret(req.password.as_bytes())?;
    let (token_id, token_secret, token) = new_secret_token("atomv");
    let token_hash = hash_secret(token_secret.as_bytes())?;
    let expires_at = Utc::now() + Duration::seconds(cfg.email_verification_expiry_secs as i64);

    let mut tx = pool.begin().await.map_err(db_err)?;
    let entity_id = Uuid::new_v4();
    let email_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, tenant_id, attributes)
           VALUES ($1, $2, $3, NULL, $4)"#,
    )
    .bind(entity_id)
    .bind(EntityKind::Human)
    .bind(name)
    .bind(attributes)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    super::repo::add_authenticated_user_membership_in_tx(&mut tx, entity_id).await?;

    sqlx::query(
        r#"INSERT INTO entity_emails (id, entity_id, email)
           VALUES ($1, $2, $3)"#,
    )
    .bind(email_id)
    .bind(entity_id)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(CredentialKind::Password)
    .bind(&email)
    .bind(password_hash)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    insert_email_token_in_tx(
        &mut tx, token_id, entity_id, email_id, token_hash, expires_at,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;

    send_verification_email(cfg, &email, &token).await?;

    Ok(SignupResponse {
        entity_id,
        email,
        verification_required: true,
    })
}

pub async fn verify_email(pool: &PgPool, token: &str) -> Result<(), AppError> {
    let (token_id, token_secret) = parse_secret_token(token, "atomv")
        .ok_or_else(|| AppError::bad_request("invalid verification token"))?;

    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT entity_id, email_id, secret_hash, expires_at, consumed_at
           FROM email_verification_tokens
           WHERE id = $1"#,
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::bad_request("invalid verification token"),
        other => AppError::Database(other),
    })?;

    let secret_hash: String = row.try_get("secret_hash").map_err(db_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at").unwrap_or(None);
    if consumed_at.is_some() || expires_at < Utc::now() {
        return Err(AppError::bad_request("verification token expired"));
    }
    if !verify_secret(token_secret.as_bytes(), &secret_hash) {
        return Err(AppError::bad_request("invalid verification token"));
    }

    let email_id: Uuid = row.try_get("email_id").map_err(db_err)?;
    let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    if super::repo::lock_active_entity(&mut tx, entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::bad_request("invalid verification token"));
    }
    let updated = sqlx::query(
        "UPDATE email_verification_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::bad_request("verification token expired"));
    }
    sqlx::query("UPDATE entity_emails SET verified_at = now(), updated_at = now() WHERE id = $1")
        .bind(email_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn resend_verification(pool: &PgPool, cfg: &Config, email: &str) -> Result<(), AppError> {
    let email = normalize_email(email)?;
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT ee.id AS email_id, ee.entity_id
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE ee.email = $1
             AND ee.verified_at IS NULL
             AND e.kind = 'human'
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))"#,
    )
    .bind(&email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let Some(row) = row else {
        return Ok(());
    };

    let email_id: Uuid = row.try_get("email_id").map_err(db_err)?;
    let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;
    let (token_id, token_secret, token) = new_secret_token("atomv");
    let token_hash = hash_secret(token_secret.as_bytes())?;
    let expires_at = Utc::now() + Duration::seconds(cfg.email_verification_expiry_secs as i64);

    sqlx::query(
        r#"INSERT INTO email_verification_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(db_err)?;

    if let Err(err) = send_verification_email(cfg, &email, &token).await {
        tracing::warn!("verification email resend failed: {err}");
    }
    Ok(())
}

pub async fn request_password_reset(
    pool: &PgPool,
    cfg: &Config,
    req: PasswordResetRequest,
) -> Result<(), AppError> {
    let email = normalize_email(&req.email)?;
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT ee.id AS email_id, ee.entity_id
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE ee.email = $1
             AND e.kind = 'human'
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))"#,
    )
    .bind(&email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let Some(row) = row else {
        return Ok(());
    };

    let email_id: Uuid = row.try_get("email_id").map_err(db_err)?;
    let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;
    let (token_id, token_secret, token) = new_secret_token("atomr");
    let token_hash = hash_secret(token_secret.as_bytes())?;
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        r#"INSERT INTO password_reset_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let redirect = req
        .redirect_url
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| cfg.password_reset_redirect.clone());
    if let Err(err) = send_password_reset_email(cfg, &email, &redirect, &token).await {
        tracing::warn!("password reset email send failed: {err}");
    }
    Ok(())
}

pub async fn reset_password(
    pool: &PgPool,
    req: PasswordResetConfirmRequest,
) -> Result<(), AppError> {
    if let Some(confirm_password) = req.confirm_password.as_deref() {
        if confirm_password != req.password {
            return Err(AppError::bad_request(
                "password confirmation does not match",
            ));
        }
    }
    validate_password_strength(&req.password)?;
    let (token_id, token_secret) = parse_secret_token(&req.token, "atomr")
        .ok_or_else(|| AppError::bad_request("invalid password reset token"))?;

    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT entity_id, email_id, secret_hash, expires_at, consumed_at
           FROM password_reset_tokens
           WHERE id = $1"#,
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::bad_request("invalid password reset token"),
        other => AppError::Database(other),
    })?;

    let secret_hash: String = row.try_get("secret_hash").map_err(db_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at").unwrap_or(None);
    if consumed_at.is_some() || expires_at < Utc::now() {
        return Err(AppError::bad_request("password reset token expired"));
    }
    if !verify_secret(token_secret.as_bytes(), &secret_hash) {
        return Err(AppError::bad_request("invalid password reset token"));
    }

    let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;
    let email_id: Uuid = row.try_get("email_id").map_err(db_err)?;
    let email: String = sqlx::query_scalar("SELECT email FROM entity_emails WHERE id = $1")
        .bind(email_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    let password_hash = hash_secret(req.password.as_bytes())?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    if super::repo::lock_active_entity(&mut tx, entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::bad_request("invalid password reset token"));
    }
    let updated = sqlx::query(
        "UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::bad_request("password reset token expired"));
    }
    sqlx::query(
        r#"UPDATE credentials
           SET status = 'revoked'
           WHERE entity_id = $1 AND kind = 'password' AND status = 'active'"#,
    )
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(CredentialKind::Password)
    .bind(email)
    .bind(password_hash)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE entity_id = $1 AND revoked_at IS NULL",
    )
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn oauth_start(
    pool: &PgPool,
    cfg: &Config,
    provider_name: &str,
    return_to: Option<String>,
) -> Result<String, AppError> {
    let provider = oidc_provider(cfg, provider_name)?;
    let client = oidc_client(cfg, provider).await?;
    let return_to = normalize_return_to(return_to)?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (state_id, state_secret, state_token) = new_secret_token("atoms");
    let state_hash = hash_secret(state_secret.as_bytes())?;
    let nonce = Nonce::new_random();

    sqlx::query(
        r#"INSERT INTO oauth_login_states
             (id, provider, state_hash, pkce_verifier, nonce, return_to, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(state_id)
    .bind(&provider.name)
    .bind(state_hash)
    .bind(pkce_verifier.secret())
    .bind(nonce.secret())
    .bind(return_to.as_deref())
    .bind(Utc::now() + Duration::seconds(cfg.oauth_state_expiry_secs as i64))
    .execute(pool)
    .await
    .map_err(db_err)?;

    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || CsrfToken::new(state_token),
            || nonce,
        )
        .set_pkce_challenge(pkce_challenge);
    for scope in oidc_scopes(provider) {
        request = request.add_scope(Scope::new(scope));
    }
    let (url, _, _) = request.url();
    Ok(url.to_string())
}

pub async fn oauth_callback(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    provider_name: &str,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> String {
    match oauth_callback_inner(pool, cfg, primary_key, provider_name, code, state, error).await {
        Ok(url) => url,
        Err(err) => redirect_with_error(cfg, &err.to_string()),
    }
}

async fn oauth_callback_inner(
    pool: &PgPool,
    cfg: &Config,
    _primary_key: &LoadedKey,
    provider_name: &str,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> Result<String, AppError> {
    if let Some(error) = error {
        return Err(AppError::unauthorized(format!(
            "oauth provider error: {error}"
        )));
    }
    let code = code.ok_or_else(|| AppError::bad_request("missing oauth code"))?;
    let state = state.ok_or_else(|| AppError::bad_request("missing oauth state"))?;
    let provider = oidc_provider(cfg, provider_name)?;
    let state_row = consume_oauth_state(pool, &provider.name, &state).await?;
    let client = oidc_client(cfg, provider).await?;

    let http_client = oidc_http_client()?;
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("oauth code exchange setup: {e}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(state_row.pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|e| AppError::unauthorized(format!("oauth token exchange failed: {e}")))?;

    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or_else(|| AppError::unauthorized("oauth provider did not return id_token"))?;
    let verifier = client.id_token_verifier();
    let nonce = Nonce::new(state_row.nonce);
    let claims = id_token
        .claims(&verifier, &nonce)
        .map_err(|e| AppError::unauthorized(format!("invalid id_token: {e}")))?;

    if claims.email_verified() != Some(true) {
        return Err(AppError::unauthorized("oauth email is not verified"));
    }
    let email = claims
        .email()
        .map(|email| normalize_email_lossy(email.as_str()))
        .ok_or_else(|| AppError::unauthorized("oauth provider did not return email"))?;
    let subject = claims.subject().as_str().to_string();
    let profile = serde_json::json!({
        "subject": subject,
        "email": email,
        "email_verified": true
    });
    let entity_id = upsert_oauth_identity(pool, &provider.name, &subject, &email, profile).await?;
    let code = create_exchange_code(pool, entity_id, cfg.auth_exchange_code_expiry_secs).await?;

    Ok(redirect_with_code(
        cfg,
        &code,
        state_row.return_to.as_deref(),
    ))
}

pub async fn oauth_exchange(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    code: &str,
) -> Result<LoginResponse, AppError> {
    let (code_id, code_secret) = parse_secret_token(code, "atomx")
        .ok_or_else(|| AppError::bad_request("invalid exchange code"))?;
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT entity_id, secret_hash, expires_at, consumed_at
           FROM auth_exchange_codes
           WHERE id = $1"#,
    )
    .bind(code_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::bad_request("invalid exchange code"),
        other => AppError::Database(other),
    })?;

    let hash: String = row.try_get("secret_hash").map_err(db_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at").unwrap_or(None);
    if consumed_at.is_some()
        || expires_at < Utc::now()
        || !verify_secret(code_secret.as_bytes(), &hash)
    {
        return Err(AppError::bad_request("invalid exchange code"));
    }

    let updated = sqlx::query(
        "UPDATE auth_exchange_codes SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(code_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::bad_request("invalid exchange code"));
    }
    let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;
    create_login_response(pool, cfg, primary_key, entity_id, Some(true)).await
}

async fn create_login_response(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    entity_id: Uuid,
    email_verified: Option<bool>,
) -> Result<LoginResponse, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let Some((_, tenant_id)) = super::repo::lock_active_entity(&mut tx, entity_id).await? else {
        return Err(AppError::unauthorized("entity is not active"));
    };

    let session =
        super::repo::create_session_in_tx(&mut tx, entity_id, cfg.jwt_expiry_secs).await?;
    let token = encode_jwt(
        entity_id,
        session.id,
        tenant_id,
        primary_key,
        cfg.jwt_expiry_secs,
        &cfg.jwt_issuer,
        &cfg.jwt_audience,
    )?;
    tx.commit().await.map_err(db_err)?;
    Ok(LoginResponse {
        token,
        entity_id,
        session_id: session.id,
        expires_at: session.expires_at,
        email_verified,
        verification_required: email_verified == Some(false),
    })
}

struct LoginIdentity {
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
    status: EntityStatus,
    email_verified: Option<bool>,
    credential_identifier: Option<String>,
}

struct PasswordCredential {
    id: Uuid,
    secret_hash: String,
}

async fn resolve_login_identity(
    pool: &PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
) -> Result<LoginIdentity, AppError> {
    if let Ok(email) = normalize_email(identifier) {
        if let Some(identity) = login_identity_by_email(pool, &email).await? {
            return Ok(identity);
        }
    }

    let row = login_entity_row(pool, identifier, tenant_id).await?;
    use sqlx::Row;
    Ok(LoginIdentity {
        entity_id: row.try_get("id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        status: row.try_get("status").map_err(db_err)?,
        email_verified: None,
        credential_identifier: None,
    })
}

async fn login_identity_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<LoginIdentity>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT e.id, e.tenant_id, e.status, ee.verified_at
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           WHERE ee.email = $1
             AND e.deleted_at IS NULL"#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    row.map(|row| {
        let verified_at: Option<DateTime<Utc>> = row.try_get("verified_at").unwrap_or(None);
        Ok(LoginIdentity {
            entity_id: row.try_get("id").map_err(db_err)?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            status: row.try_get("status").map_err(db_err)?,
            email_verified: Some(verified_at.is_some()),
            credential_identifier: Some(email.to_string()),
        })
    })
    .transpose()
}

async fn password_credential_for_login(
    pool: &PgPool,
    entity_id: Uuid,
    identifier: Option<&str>,
) -> Result<PasswordCredential, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT id, secret_hash
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND status = $3
             AND (($4::text IS NULL AND identifier IS NULL) OR identifier = $4)
           ORDER BY created_at DESC
           LIMIT 1"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::Password)
    .bind(CredentialStatus::Active)
    .bind(identifier)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::unauthorized("invalid credentials"),
        other => AppError::Database(other),
    })?;

    let secret_hash = row
        .try_get::<Option<String>, _>("secret_hash")
        .unwrap_or(None)
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    Ok(PasswordCredential {
        id: row.try_get("id").map_err(db_err)?,
        secret_hash,
    })
}

async fn login_entity_row(
    pool: &PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
) -> Result<sqlx::postgres::PgRow, AppError> {
    if let Ok(entity_id) = Uuid::parse_str(identifier) {
        let row = match tenant_id {
            Some(tenant_id) => {
                sqlx::query(
                    "SELECT id, tenant_id, status
                     FROM entities
                     WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
                )
                .bind(entity_id)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await
            }
            None => {
                sqlx::query(
                    "SELECT id, tenant_id, status
                         FROM entities
                         WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(entity_id)
                .fetch_optional(pool)
                .await
            }
        }
        .map_err(db_err)?;

        return row.ok_or_else(|| AppError::unauthorized("invalid credentials"));
    }

    let mut rows = match tenant_id {
        Some(tenant_id) => {
            sqlx::query(
                "SELECT id, tenant_id, status
                 FROM entities
                 WHERE name = $1 AND tenant_id = $2 AND deleted_at IS NULL",
            )
            .bind(identifier)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query(
                "SELECT id, tenant_id, status
                 FROM entities
                 WHERE name = $1 AND deleted_at IS NULL
                 LIMIT 2",
            )
            .bind(identifier)
            .fetch_all(pool)
            .await
        }
    }
    .map_err(db_err)?;

    if rows.is_empty() {
        if let (Some(tenant_id), Some(alias)) = (tenant_id, normalize_alias(Some(identifier))) {
            rows = sqlx::query(
                "SELECT id, tenant_id, status
                 FROM entities
                 WHERE lower(alias) = $1 AND tenant_id = $2 AND deleted_at IS NULL",
            )
            .bind(alias)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
            .map_err(db_err)?;
        }
    }

    if rows.is_empty() {
        return Err(AppError::unauthorized("invalid credentials"));
    }
    if tenant_id.is_none() && rows.len() > 1 {
        return Err(AppError::unauthorized(
            "tenant_id or tenant_alias required for this identifier",
        ));
    }
    Ok(rows.remove(0))
}

async fn resolve_login_tenant(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    tenant_alias: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    let tenant_alias = normalize_alias(tenant_alias);
    validate_tenant_selector(tenant_id, tenant_alias.as_deref())?;

    use sqlx::Row;
    let Some(row) = (match (tenant_id, tenant_alias) {
        (Some(tenant_id), None) => {
            sqlx::query("SELECT id, status FROM tenants WHERE id = $1 AND deleted_at IS NULL")
                .bind(tenant_id)
                .fetch_optional(pool)
                .await
        }
        (None, Some(tenant_alias)) => {
            sqlx::query(
                "SELECT id, status
                 FROM tenants
                 WHERE lower(alias) = $1 AND deleted_at IS NULL",
            )
            .bind(tenant_alias)
            .fetch_optional(pool)
            .await
        }
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return Err(AppError::bad_request(
                "provide either tenant_id or tenant_alias, not both",
            ))
        }
    })
    .map_err(db_err)?
    else {
        return Err(AppError::unauthorized("invalid credentials"));
    };

    let status: String = row.try_get("status").map_err(db_err)?;
    if status != "active" {
        return Err(AppError::unauthorized("tenant is not active"));
    }
    row.try_get("id").map(Some).map_err(db_err)
}

async fn insert_email_token_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO email_verification_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn send_verification_email(cfg: &Config, email: &str, token: &str) -> Result<(), AppError> {
    let verification_url = url_with_params(&cfg.email_verification_redirect, &[("token", token)]);
    let Some(smtp) = cfg.smtp.as_ref() else {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email,
                verification_url,
                "SMTP is not configured; skipping verification email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "SMTP is not configured"
        )));
    };

    let message = Message::builder()
        .from(
            smtp.from
                .parse()
                .map_err(|e| AppError::bad_request(format!("invalid SMTP from address: {e}")))?,
        )
        .to(email
            .parse()
            .map_err(|e| AppError::bad_request(format!("invalid email address: {e}")))?)
        .subject("Verify your Atom account")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Verify your Atom account by opening this link:\n\n{verification_url}\n"
        ))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("build email: {e}")))?;

    let mut builder = match smtp.tls {
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp starttls: {e}")))?,
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp tls: {e}")))?,
    }
    .port(smtp.port);

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    let mailer = builder.build();
    if let Err(err) = mailer.send(message).await {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email,
                verification_url,
                error = %err,
                "SMTP send failed; skipping verification email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "send verification email: {err}"
        )));
    }
    Ok(())
}

async fn send_password_reset_email(
    cfg: &Config,
    email: &str,
    redirect_url: &str,
    token: &str,
) -> Result<(), AppError> {
    let reset_url = url_with_params(redirect_url, &[("token", token)]);
    let Some(smtp) = cfg.smtp.as_ref() else {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email,
                reset_url,
                "SMTP is not configured; skipping password reset email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "SMTP is not configured"
        )));
    };

    let message = Message::builder()
        .from(
            smtp.from
                .parse()
                .map_err(|e| AppError::bad_request(format!("invalid SMTP from address: {e}")))?,
        )
        .to(email
            .parse()
            .map_err(|e| AppError::bad_request(format!("invalid email address: {e}")))?)
        .subject("Reset your Atom password")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Reset your Atom password by opening this link:\n\n{reset_url}\n"
        ))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("build email: {e}")))?;

    let mut builder = match smtp.tls {
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp starttls: {e}")))?,
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp tls: {e}")))?,
    }
    .port(smtp.port);

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    let mailer = builder.build();
    if let Err(err) = mailer.send(message).await {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email,
                reset_url,
                error = %err,
                "SMTP send failed; skipping password reset email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "send password reset email: {err}"
        )));
    }
    Ok(())
}

struct OAuthStateRow {
    pkce_verifier: String,
    nonce: String,
    return_to: Option<String>,
}

async fn consume_oauth_state(
    pool: &PgPool,
    provider: &str,
    state: &str,
) -> Result<OAuthStateRow, AppError> {
    let (state_id, state_secret) = parse_secret_token(state, "atoms")
        .ok_or_else(|| AppError::bad_request("invalid oauth state"))?;
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT state_hash, pkce_verifier, nonce, return_to, expires_at, consumed_at
           FROM oauth_login_states
           WHERE id = $1 AND provider = $2"#,
    )
    .bind(state_id)
    .bind(provider)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::bad_request("invalid oauth state"),
        other => AppError::Database(other),
    })?;

    let state_hash: String = row.try_get("state_hash").map_err(db_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at").unwrap_or(None);
    if consumed_at.is_some()
        || expires_at < Utc::now()
        || !verify_secret(state_secret.as_bytes(), &state_hash)
    {
        return Err(AppError::bad_request("invalid oauth state"));
    }

    let updated = sqlx::query(
        "UPDATE oauth_login_states SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(state_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::bad_request("invalid oauth state"));
    }

    Ok(OAuthStateRow {
        pkce_verifier: row.try_get("pkce_verifier").map_err(db_err)?,
        nonce: row.try_get("nonce").map_err(db_err)?,
        return_to: row.try_get("return_to").unwrap_or(None),
    })
}

async fn upsert_oauth_identity(
    pool: &PgPool,
    provider: &str,
    subject: &str,
    email: &str,
    profile: Value,
) -> Result<Uuid, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    use sqlx::Row;
    if let Some(row) =
        sqlx::query("SELECT entity_id FROM oauth_identities WHERE provider = $1 AND subject = $2")
            .bind(provider)
            .bind(subject)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?
    {
        let entity_id: Uuid = row.try_get("entity_id").map_err(db_err)?;
        if super::repo::lock_active_entity(&mut tx, entity_id)
            .await?
            .is_none()
        {
            return Err(AppError::unauthorized("entity is not active"));
        }
        sqlx::query(
            r#"UPDATE oauth_identities
               SET email = $3, email_verified = true, profile = $4, updated_at = now()
               WHERE provider = $1 AND subject = $2"#,
        )
        .bind(provider)
        .bind(subject)
        .bind(email)
        .bind(profile)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        return Ok(entity_id);
    }

    let entity_id = match sqlx::query(
        "SELECT entity_id FROM entity_emails WHERE email = $1 AND deleted_at IS NULL",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?
    {
        Some(row) => {
            let entity_id = row.try_get("entity_id").map_err(db_err)?;
            if super::repo::lock_active_entity(&mut tx, entity_id)
                .await?
                .is_none()
            {
                return Err(AppError::unauthorized("entity is not active"));
            }
            entity_id
        }
        None => {
            let entity_id = Uuid::new_v4();
            let name = email.split('@').next().unwrap_or("human");
            sqlx::query(
                r#"INSERT INTO entities (id, kind, name, tenant_id, attributes)
                   VALUES ($1, $2, $3, NULL, '{}')"#,
            )
            .bind(entity_id)
            .bind(EntityKind::Human)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            sqlx::query(
                r#"INSERT INTO entity_emails (id, entity_id, email, verified_at)
                   VALUES ($1, $2, $3, now())"#,
            )
            .bind(Uuid::new_v4())
            .bind(entity_id)
            .bind(email)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            entity_id
        }
    };

    sqlx::query(
        r#"UPDATE entity_emails
           SET verified_at = COALESCE(verified_at, now()), updated_at = now()
           WHERE entity_id = $1 AND email = $2"#,
    )
    .bind(entity_id)
    .bind(email)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        r#"INSERT INTO oauth_identities
             (id, entity_id, provider, subject, email, email_verified, profile)
           VALUES ($1, $2, $3, $4, $5, true, $6)"#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(provider)
    .bind(subject)
    .bind(email)
    .bind(profile)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(entity_id)
}

async fn create_exchange_code(
    pool: &PgPool,
    entity_id: Uuid,
    expiry_secs: u64,
) -> Result<String, AppError> {
    let (code_id, code_secret, code) = new_secret_token("atomx");
    let code_hash = hash_secret(code_secret.as_bytes())?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    if super::repo::lock_active_entity(&mut tx, entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::unauthorized("entity is not active"));
    }
    sqlx::query(
        r#"INSERT INTO auth_exchange_codes (id, entity_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(code_id)
    .bind(entity_id)
    .bind(code_hash)
    .bind(Utc::now() + Duration::seconds(expiry_secs as i64))
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(code)
}

async fn oidc_client(
    cfg: &Config,
    provider: &OidcProviderConfig,
) -> Result<
    CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    >,
    AppError,
> {
    let http_client = oidc_http_client()?;
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(provider.issuer.clone())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid oidc issuer: {e}")))?,
        &http_client,
    )
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("oidc discovery failed: {e}")))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!(
            "{}/auth/oauth/{}/callback",
            cfg.public_base_url.trim_end_matches('/'),
            provider.name
        ))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid oidc redirect url: {e}")))?,
    );
    Ok(client)
}

fn oidc_http_client() -> Result<reqwest::Client, AppError> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("build oidc http client: {e}")))
}

fn oidc_provider<'a>(
    cfg: &'a Config,
    provider_name: &str,
) -> Result<&'a OidcProviderConfig, AppError> {
    cfg.oidc_providers
        .iter()
        .find(|provider| provider.name == provider_name)
        .ok_or_else(|| AppError::not_found("oauth provider not configured"))
}

fn oidc_scopes(provider: &OidcProviderConfig) -> Vec<String> {
    let mut scopes = provider.scopes.clone();
    if !scopes.iter().any(|scope| scope == "openid") {
        scopes.push("openid".into());
    }
    if !scopes.iter().any(|scope| scope == "email") {
        scopes.push("email".into());
    }
    scopes
}

fn redirect_with_code(cfg: &Config, code: &str, return_to: Option<&str>) -> String {
    url_with_params(
        &cfg.oauth_success_redirect,
        &[("code", code), ("return_to", return_to.unwrap_or(""))],
    )
}

fn redirect_with_error(cfg: &Config, error: &str) -> String {
    url_with_params(&cfg.oauth_error_redirect, &[("error", error)])
}

fn url_with_params(base: &str, params: &[(&str, &str)]) -> String {
    match Url::parse(base) {
        Ok(mut url) => {
            {
                let mut query = url.query_pairs_mut();
                for (key, value) in params {
                    if !value.is_empty() {
                        query.append_pair(key, value);
                    }
                }
            }
            url.to_string()
        }
        Err(_) => {
            let mut url = base.to_string();
            let mut first = !url.contains('?');
            for (key, value) in params {
                if !value.is_empty() {
                    url.push(if first { '?' } else { '&' });
                    first = false;
                    url.push_str(key);
                    url.push('=');
                    url.push_str(value);
                }
            }
            url
        }
    }
}

fn new_secret_token(prefix: &str) -> (Uuid, String, String) {
    let id = Uuid::new_v4();
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);
    let token = format!("{prefix}_{}_{}", hex::encode(id.as_bytes()), secret);
    (id, secret, token)
}

fn parse_secret_token(token: &str, prefix: &str) -> Option<(Uuid, String)> {
    let rest = token.strip_prefix(&format!("{prefix}_"))?;
    if rest.len() != 32 + 1 + 64 {
        return None;
    }
    let (id_hex, tail) = rest.split_at(32);
    let secret = tail.strip_prefix('_')?;
    let id_bytes = hex::decode(id_hex).ok()?;
    let id: [u8; 16] = id_bytes.try_into().ok()?;
    if hex::decode(secret).ok()?.len() != 32 {
        return None;
    }
    Some((Uuid::from_bytes(id), secret.to_string()))
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    let normalized = normalize_email_lossy(email);
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(AppError::bad_request("email is required"));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(AppError::bad_request("invalid email"));
    }
    Ok(normalized)
}

fn normalize_email_lossy(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn normalize_json_object(value: Value) -> Value {
    if value.is_null() {
        serde_json::json!({})
    } else {
        value
    }
}

/// Normalize a alias for *lookup* (login/selector): trim, drop empty, and
/// case-fold so it matches the `lower(alias)` unique index. Lookup does not
/// reject malformed slugs (a non-matching alias simply finds no tenant); strict
/// slug validation happens on the write path via `models::alias::validate_alias`.
fn normalize_alias(alias: Option<&str>) -> Option<String> {
    alias
        .map(str::trim)
        .filter(|alias| !alias.is_empty())
        .map(str::to_ascii_lowercase)
}

fn validate_tenant_selector(
    tenant_id: Option<Uuid>,
    tenant_alias: Option<&str>,
) -> Result<(), AppError> {
    if tenant_id.is_some() && tenant_alias.is_some() {
        return Err(AppError::bad_request(
            "provide either tenant_id or tenant_alias, not both",
        ));
    }
    Ok(())
}

fn normalize_return_to(return_to: Option<String>) -> Result<Option<String>, AppError> {
    let Some(return_to) = return_to.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if return_to.is_empty() {
        return Ok(None);
    }
    if return_to.starts_with('/') && !return_to.starts_with("//") && !return_to.contains("://") {
        return Ok(Some(return_to));
    }
    Err(AppError::bad_request(
        "return_to must be a same-origin path",
    ))
}

pub async fn create_password(
    pool: &PgPool,
    entity_id: Uuid,
    password: &str,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let Some((kind, _)) = super::repo::lock_active_entity(&mut tx, entity_id).await? else {
        return Err(AppError::not_found(format!(
            "active entity {entity_id} not found"
        )));
    };
    validate_password_for_kind(&kind, password)?;
    let hash = hash_secret(password.as_bytes())?;
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(entity_id)
    .bind(CredentialKind::Password)
    .bind(hash)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

fn validate_password_for_kind(kind: &EntityKind, password: &str) -> Result<(), AppError> {
    match kind {
        EntityKind::Human => validate_password_strength(password),
        EntityKind::Device
        | EntityKind::Service
        | EntityKind::Workload
        | EntityKind::Application => validate_machine_secret(password),
    }
}

fn validate_machine_secret(secret: &str) -> Result<(), AppError> {
    if secret.chars().all(char::is_whitespace) {
        return Err(AppError::bad_request("password cannot be blank"));
    }
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
    let mut tx = pool.begin().await.map_err(db_err)?;
    if super::repo::lock_active_entity(&mut tx, entity_id)
        .await?
        .is_none()
    {
        return Err(AppError::not_found(format!(
            "active entity {entity_id} not found"
        )));
    }

    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash, expires_at, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(CredentialKind::ApiKey)
    .bind(key_prefix)
    .bind(hash)
    .bind(req.expires_at)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(ApiKeyResponse {
        credential_id: cred_id,
        key,
        expires_at: req.expires_at,
    })
}

pub async fn revoke_credential(
    pool: &PgPool,
    entity_id: Uuid,
    cred_id: Uuid,
) -> Result<(), AppError> {
    // Overwrite any prior revocation provenance (e.g. a `tenant_deleted` marker
    // from a tenant soft delete) with this explicit revocation, so a later tenant
    // restore — which only reactivates credentials still marked `tenant_deleted` —
    // cannot resurrect a credential an admin has deliberately revoked.
    let result = sqlx::query(
        r#"UPDATE credentials
           SET status = 'revoked',
               metadata = metadata - 'revoked_at' - 'revocation_reason'
                          || jsonb_build_object(
                              'revoked_at', now(),
                              'revocation_reason', 'manual'
                          )
           WHERE id = $1 AND entity_id = $2"#,
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

pub async fn list_credentials(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Vec<CredentialSummary>, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, kind, identifier, status, expires_at, created_at FROM credentials WHERE entity_id = $1 ORDER BY created_at DESC",
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let summaries = rows
        .into_iter()
        .map(|r| {
            Ok(CredentialSummary {
                id: r.try_get("id").map_err(db_err)?,
                kind: r.try_get("kind").map_err(db_err)?,
                identifier: r.try_get("identifier").map_err(db_err)?,
                status: r.try_get("status").map_err(db_err)?,
                expires_at: r.try_get("expires_at").map_err(db_err)?,
                created_at: r.try_get("created_at").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    Ok(summaries)
}

#[derive(serde::Serialize)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub kind: CredentialKind,
    pub identifier: Option<String>,
    pub status: CredentialStatus,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
}
