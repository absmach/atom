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
    config::{Config, OidcProviderConfig, SigningKeyConfig, SmtpTls},
    crypto,
    error::{db_err, AppError},
    keys::LoadedKey,
    models::{
        enums::{AuditOutcome, CredentialKind, CredentialStatus, EntityKind, EntityStatus},
        session::{
            LoginResponse, PasswordResetConfirmRequest, PasswordResetRequest, SignupRequest,
            SignupResponse,
        },
        token::{
            AccessTokenPermission, AccessTokenPermissionSummary, AccessTokenResponse,
            AccessTokenSummary, CreateAccessToken, CreateSharedKey, SharedKeyResponse,
        },
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
    /// The credential kind that actually authenticated, so callers (audit, gRPC)
    /// report the truth rather than the kind the client claimed.
    pub kind: CredentialKind,
    pub email_verified: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
pub struct CredentialLoginRequest<'a> {
    pub identifier: &'a str,
    pub secret: &'a str,
    pub tenant_id: Option<Uuid>,
    pub tenant_alias: Option<&'a str>,
    pub kind: CredentialKind,
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
    login_credential_with_tenant(
        pool,
        cfg,
        primary_key,
        CredentialLoginRequest {
            identifier,
            secret,
            tenant_id,
            tenant_alias,
            kind: CredentialKind::Password,
        },
    )
    .await
}

pub async fn login_credential_with_tenant(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    request: CredentialLoginRequest<'_>,
) -> Result<LoginResponse, AppError> {
    let result = do_login_credential(pool, cfg, primary_key, request).await;

    let (entity_id_opt, tenant_id_opt, outcome, kind) = match &result {
        Ok((r, kind)) => {
            let tenant_id = sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1")
                .bind(r.entity_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
            (
                Some(r.entity_id),
                tenant_id,
                AuditOutcome::Allow,
                Some(*kind),
            )
        }
        Err(AppError::Unauthorized(_)) => (None, None, AuditOutcome::Deny, None),
        Err(_) => return result.map(|(r, _)| r),
    };

    audit::write_hot_path(
        pool,
        cfg.audit_policy,
        audit::HotPathAuditKind::AuthLogin,
        audit::AuditEvent {
            actor_entity_id: entity_id_opt,
            tenant_id: tenant_id_opt,
            target_kind: entity_id_opt.map(|_| "entity"),
            target_id: entity_id_opt,
            event: "auth.login",
            outcome,
            details: serde_json::json!({
                "identifier": request.identifier,
                "credential_kind": kind,
            }),
        },
    )
    .await;

    result.map(|(r, _)| r)
}

async fn do_login_credential(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    request: CredentialLoginRequest<'_>,
) -> Result<(LoginResponse, CredentialKind), AppError> {
    let login_tenant_id =
        resolve_login_tenant(pool, request.tenant_id, request.tenant_alias).await?;
    let authenticated = authenticate_credential_in_tenant(
        pool,
        cfg,
        request.identifier,
        request.secret,
        login_tenant_id,
        request.kind,
    )
    .await?;
    let response = create_login_response(
        pool,
        cfg,
        primary_key,
        authenticated.entity_id,
        authenticated.email_verified,
    )
    .await?;
    Ok((response, authenticated.kind))
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
    authenticate_credential_in_tenant(
        pool,
        cfg,
        identifier,
        secret,
        tenant_id,
        CredentialKind::Password,
    )
    .await
}

pub async fn authenticate_credential_in_tenant(
    pool: &PgPool,
    cfg: &Config,
    identifier: &str,
    secret: &str,
    tenant_id: Option<Uuid>,
    requested_kind: CredentialKind,
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

        let credential = credential_for_login(
            pool,
            &cfg.signing_keys,
            identity.entity_id,
            secret,
            identity.credential_identifier.as_deref(),
            requested_kind,
        )
        .await?;

        if credential.kind == CredentialKind::Password
            && identity.email_verified == Some(false)
            && !cfg.dev_allow_unverified_email_login
        {
            return Err(AppError::unauthorized("email verification required"));
        }

        Ok(CredentialAuthentication {
            entity_id: identity.entity_id,
            tenant_id: tenant_id.or(identity.tenant_id),
            credential_id: credential.id,
            kind: credential.kind,
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
        audit::AuditEvent {
            actor_entity_id: entity_id_opt,
            tenant_id: None,
            target_kind: entity_id_opt.map(|_| "entity"),
            target_id: entity_id_opt,
            event: "auth.signup",
            outcome,
            details: serde_json::json!({
                "name": name,
                "email": normalize_email_lossy(&email),
            }),
        },
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

pub async fn refresh_session(
    pool: &PgPool,
    cfg: &Config,
    primary_key: &LoadedKey,
    entity_id: Uuid,
    session_id: Uuid,
) -> Result<LoginResponse, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let Some((_, tenant_id)) = super::repo::lock_active_entity(&mut tx, entity_id).await? else {
        return Err(AppError::unauthorized("entity is not active"));
    };

    let session =
        super::repo::refresh_session_in_tx(&mut tx, session_id, entity_id, cfg.jwt_expiry_secs)
            .await?;
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
        email_verified: None,
        verification_required: false,
    })
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
    kind: CredentialKind,
    secret_hash: String,
}

async fn resolve_login_identity(
    pool: &PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
) -> Result<LoginIdentity, AppError> {
    if let Ok(email) = normalize_email(identifier) {
        if let Some(identity) = login_identity_by_email(pool, &email, tenant_id).await? {
            return Ok(identity);
        }
    }

    let row = login_entity_row(pool, identifier, tenant_id).await?;
    use sqlx::Row;
    let entity_id = row.try_get("id").map_err(db_err)?;
    Ok(LoginIdentity {
        entity_id,
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        status: row.try_get("status").map_err(db_err)?,
        email_verified: entity_email_verified(pool, entity_id).await?,
        credential_identifier: None,
    })
}

async fn entity_email_verified(pool: &PgPool, entity_id: Uuid) -> Result<Option<bool>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT COUNT(*) AS email_count,
                  COALESCE(bool_or(verified_at IS NOT NULL), false) AS any_verified
           FROM entity_emails
           WHERE entity_id = $1"#,
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    let email_count: i64 = row.try_get("email_count").map_err(db_err)?;
    if email_count == 0 {
        return Ok(None);
    }
    row.try_get("any_verified").map(Some).map_err(db_err)
}

async fn login_identity_by_email(
    pool: &PgPool,
    email: &str,
    tenant_id: Option<Uuid>,
) -> Result<Option<LoginIdentity>, AppError> {
    use sqlx::Row;
    let canonical = sqlx::query(
        r#"SELECT e.id, e.tenant_id, e.status, ee.verified_at
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           WHERE ee.email = $1
             AND ee.deleted_at IS NULL
             AND e.deleted_at IS NULL
             AND ($2::uuid IS NULL OR e.tenant_id = $2)"#,
    )
    .bind(email)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    if let Some(row) = canonical {
        let verified_at: Option<DateTime<Utc>> = row.try_get("verified_at").unwrap_or(None);
        return Ok(Some(LoginIdentity {
            entity_id: row.try_get("id").map_err(db_err)?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            status: row.try_get("status").map_err(db_err)?,
            email_verified: Some(verified_at.is_some()),
            credential_identifier: Some(email.to_string()),
        }));
    }

    let mut rows = sqlx::query(
        r#"SELECT e.id, e.tenant_id, e.status
           FROM entities e
           WHERE lower(btrim(e.attributes->>'email')) = $1
             AND e.deleted_at IS NULL
             AND ($2::uuid IS NULL OR e.tenant_id = $2)
           LIMIT 2"#,
    )
    .bind(email)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() > 1 {
        let message = if tenant_id.is_none() {
            "tenant_id or tenant_alias required for this identifier"
        } else {
            "invalid credentials"
        };
        return Err(AppError::unauthorized(message));
    }

    let row = rows.remove(0);
    Ok(Some(LoginIdentity {
        entity_id: row.try_get("id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        status: row.try_get("status").map_err(db_err)?,
        email_verified: None,
        credential_identifier: None,
    }))
}

async fn credential_for_login(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity_id: Uuid,
    secret: &str,
    identifier: Option<&str>,
    requested_kind: CredentialKind,
) -> Result<PasswordCredential, AppError> {
    match requested_kind {
        CredentialKind::Password => {
            if let Some(credential) =
                password_credential_for_login(pool, entity_id, identifier).await?
            {
                if verify_secret(secret.as_bytes(), &credential.secret_hash) {
                    return Ok(credential);
                }
            }
            Err(AppError::unauthorized("invalid credentials"))
        }
        CredentialKind::SharedKey => {
            shared_key_credential_for_login(pool, signing_keys, entity_id, secret).await
        }
        CredentialKind::AccessToken | CredentialKind::Certificate => Err(AppError::bad_request(
            format!("unsupported credential kind: {requested_kind:?}"),
        )),
    }
}

async fn password_credential_for_login(
    pool: &PgPool,
    entity_id: Uuid,
    identifier: Option<&str>,
) -> Result<Option<PasswordCredential>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT id, secret_hash
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND status = $3
             AND ($4::text IS NULL OR identifier = $4 OR identifier IS NULL)
           ORDER BY
             CASE
               WHEN $4::text IS NOT NULL AND identifier = $4 THEN 0
               WHEN identifier IS NULL THEN 1
               ELSE 2
             END,
             created_at DESC
           LIMIT 1"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::Password)
    .bind(CredentialStatus::Active)
    .bind(identifier)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let secret_hash = row
        .try_get::<Option<String>, _>("secret_hash")
        .unwrap_or(None)
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    Ok(Some(PasswordCredential {
        id: row.try_get("id").map_err(db_err)?,
        kind: CredentialKind::Password,
        secret_hash,
    }))
}

async fn shared_key_credential_for_login(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity_id: Uuid,
    secret: &str,
) -> Result<PasswordCredential, AppError> {
    // Fast path: server-generated shared keys embed their own credential id, so a
    // single indexed lookup + one verify authenticates in O(1) regardless of how
    // many keys the entity holds.
    if let Some(cred_id) = embedded_shared_key_credential_id(secret) {
        if let Some(credential) = active_shared_key_by_id(pool, entity_id, cred_id).await? {
            if verify_secret(secret.as_bytes(), &credential.secret_hash) {
                return Ok(credential);
            }
        }
    }

    let lookup_hash = shared_key_lookup_hash(signing_keys, secret.as_bytes())?;
    for credential in active_shared_keys_by_lookup_hash(pool, entity_id, &lookup_hash).await? {
        if verify_secret(secret.as_bytes(), &credential.secret_hash) {
            return Ok(credential);
        }
    }

    // Compatibility fallback for rows created before lookup digests existed.
    // Modern shared-key rows must be found by credential id or lookup hash.
    for credential in active_shared_keys_without_lookup_hash(pool, entity_id).await? {
        if verify_secret(secret.as_bytes(), &credential.secret_hash) {
            return Ok(credential);
        }
    }
    Err(AppError::unauthorized("invalid credentials"))
}

/// Parse the credential UUID embedded in a server-generated shared key
/// (`atom_shared_<credid-hex>_<random-hex>`). Returns `None` for operator-supplied
/// keys that do not follow this layout.
fn embedded_shared_key_credential_id(secret: &str) -> Option<Uuid> {
    let rest = secret.strip_prefix("atom_shared_")?;
    let id_hex = rest.split('_').next()?;
    let bytes = hex::decode(id_hex).ok()?;
    Uuid::from_slice(&bytes).ok()
}

async fn active_shared_key_by_id(
    pool: &PgPool,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<PasswordCredential>, AppError> {
    let row = sqlx::query(
        r#"SELECT c.id, c.secret_hash
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.id = $1
             AND c.entity_id = $2
             AND c.kind = $3
             AND c.status = $4
             AND e.kind <> 'human'
             AND (c.expires_at IS NULL OR c.expires_at > now())"#,
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(CredentialKind::SharedKey)
    .bind(CredentialStatus::Active)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    row.map(shared_key_credential_from_row).transpose()
}

async fn active_shared_keys_by_lookup_hash(
    pool: &PgPool,
    entity_id: Uuid,
    lookup_hash: &[u8],
) -> Result<Vec<PasswordCredential>, AppError> {
    let rows = sqlx::query(
        r#"SELECT c.id, c.secret_hash
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.entity_id = $1
             AND c.kind = $2
             AND c.status = $3
             AND c.secret_lookup_hash = $4
             AND e.kind <> 'human'
             AND (c.expires_at IS NULL OR c.expires_at > now())
           ORDER BY c.created_at DESC"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::SharedKey)
    .bind(CredentialStatus::Active)
    .bind(lookup_hash)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(shared_key_credential_from_row)
        .collect()
}

async fn active_shared_keys_without_lookup_hash(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Vec<PasswordCredential>, AppError> {
    let rows = sqlx::query(
        r#"SELECT c.id, c.secret_hash
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.entity_id = $1
             AND c.kind = $2
             AND c.status = $3
             AND c.secret_lookup_hash IS NULL
             AND e.kind <> 'human'
             AND (c.expires_at IS NULL OR c.expires_at > now())
           ORDER BY c.created_at DESC"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::SharedKey)
    .bind(CredentialStatus::Active)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(shared_key_credential_from_row)
        .collect()
}

fn shared_key_credential_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<PasswordCredential, AppError> {
    use sqlx::Row;
    let secret_hash = row
        .try_get::<Option<String>, _>("secret_hash")
        .unwrap_or(None)
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    Ok(PasswordCredential {
        id: row.try_get("id").map_err(db_err)?,
        kind: CredentialKind::SharedKey,
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
) -> Result<Uuid, AppError> {
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
    Ok(id)
}

fn validate_password_for_kind(kind: &EntityKind, password: &str) -> Result<(), AppError> {
    if kind.is_machine() {
        validate_machine_secret(password)
    } else {
        validate_password_strength(password)
    }
}

fn validate_machine_secret(secret: &str) -> Result<(), AppError> {
    if secret.chars().all(char::is_whitespace) {
        return Err(AppError::bad_request("password cannot be blank"));
    }
    Ok(())
}

pub async fn create_access_token(
    pool: &PgPool,
    entity_id: Uuid,
    req: CreateAccessToken,
    scoped: bool,
) -> Result<AccessTokenResponse, AppError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::bad_request("access token name is required"));
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
    let description = req
        .description
        .map(|description| description.trim().to_string())
        .filter(|description| !description.is_empty());

    let cred_id = Uuid::new_v4();
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let hash = hash_secret(&secret_bytes)?;
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
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash, scoped, expires_at, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .bind(key_prefix)
    .bind(hash)
    .bind(scoped)
    .bind(req.expires_at)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    for permission in &req.permissions {
        write_ceiling_limit(&mut tx, cred_id, permission).await?;
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

/// Owner-only replacement of a scoped access token's permission ceiling.
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
    for permission in &permissions {
        write_ceiling_limit(&mut tx, cred_id, permission).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

/// Insert one ceiling allow-list entry and its actions inside an open tx. Invalid
/// scope/field combinations are rejected by the table CHECK; unknown action names
/// are a bad request.
async fn write_ceiling_limit(
    tx: &mut Transaction<'_, Postgres>,
    cred_id: Uuid,
    permission: &AccessTokenPermission,
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
        let action_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM actions WHERE name = $1")
            .bind(action)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;
        let action_id =
            action_id.ok_or_else(|| AppError::bad_request(format!("unknown action: {action}")))?;
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

pub async fn list_access_tokens(
    pool: &PgPool,
    entity_id: Uuid,
) -> Result<Vec<AccessTokenSummary>, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT id,
                  COALESCE(NULLIF(metadata->>'name', ''), identifier, 'Access token') AS name,
                  NULLIF(metadata->>'description', '') AS description,
                  identifier,
                  status,
                  scoped,
                  expires_at,
                  created_at
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
           ORDER BY created_at DESC"#,
    )
    .bind(entity_id)
    .bind(CredentialKind::AccessToken)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        let credential_id: Uuid = row.try_get("id").map_err(db_err)?;
        summaries.push(AccessTokenSummary {
            credential_id,
            name: row.try_get("name").map_err(db_err)?,
            description: row.try_get("description").map_err(db_err)?,
            identifier: row.try_get("identifier").map_err(db_err)?,
            status: row.try_get("status").map_err(db_err)?,
            scoped: row.try_get("scoped").map_err(db_err)?,
            permissions: load_access_token_permissions(pool, credential_id).await?,
            expires_at: row.try_get("expires_at").map_err(db_err)?,
            created_at: row.try_get("created_at").map_err(db_err)?,
        });
    }
    Ok(summaries)
}

/// Render a token's ceiling for display: one entry per limit row with its action
/// names, grouped from credential_permission_limits.
async fn load_access_token_permissions(
    pool: &PgPool,
    credential_id: Uuid,
) -> Result<Vec<AccessTokenPermissionSummary>, AppError> {
    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT l.id,
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
           WHERE l.credential_id = $1
           GROUP BY l.id
           ORDER BY l.created_at"#,
    )
    .bind(credential_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(|row| {
            Ok(AccessTokenPermissionSummary {
                actions: row.try_get("actions").map_err(db_err)?,
                scope_mode: row.try_get("scope_mode").map_err(db_err)?,
                tenant_id: row.try_get("tenant_id").map_err(db_err)?,
                object_kind: row.try_get("object_kind").map_err(db_err)?,
                object_type: row.try_get("object_type").map_err(db_err)?,
                object_id: row.try_get("object_id").map_err(db_err)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()
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

pub async fn create_shared_key(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity_id: Uuid,
    req: CreateSharedKey,
) -> Result<SharedKeyResponse, AppError> {
    let cred_id = Uuid::new_v4();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let Some((kind, _)) = super::repo::lock_active_entity(&mut tx, entity_id).await? else {
        return Err(AppError::not_found(format!(
            "active entity {entity_id} not found"
        )));
    };
    if !CredentialKind::SharedKey.allowed_for(&kind) {
        return Err(AppError::bad_request(
            "shared keys cannot be created for human entities",
        ));
    }

    let key = match req.key {
        Some(key) => {
            validate_machine_secret(&key)?;
            key
        }
        None => make_shared_key(cred_id),
    };
    let hash = hash_secret(key.as_bytes())?;
    // The recoverable copy is envelope-encrypted; the plaintext never touches the DB.
    let sealed = encrypt_recoverable_secret(signing_keys, cred_id, key.as_bytes())?;
    let lookup_hash = shared_key_lookup_hash(signing_keys, key.as_bytes())?;
    let metadata = serde_json::json!({ "description": req.description });

    sqlx::query(
        r#"INSERT INTO credentials
             (id, entity_id, kind, secret_hash,
              secret_ciphertext, secret_nonce, secret_key_id, secret_enc_alg,
              secret_lookup_hash, expires_at, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(CredentialKind::SharedKey)
    .bind(hash)
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(&signing_keys.key_encryption_key_id)
    .bind(crypto::AEAD_ALG)
    .bind(lookup_hash)
    .bind(req.expires_at)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(SharedKeyResponse {
        credential_id: cred_id,
        key,
        expires_at: req.expires_at,
    })
}

pub async fn reveal_shared_key(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Result<SharedKeyResponse, AppError> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"SELECT c.expires_at,
                  c.status,
                  c.secret_hash,
                  c.secret_ciphertext,
                  c.secret_nonce,
                  e.status AS entity_status,
                  t.status AS tenant_status
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE c.id = $1
             AND c.entity_id = $2
             AND c.kind = $3
             AND e.kind <> 'human'
             AND e.deleted_at IS NULL
             AND (t.id IS NULL OR t.deleted_at IS NULL)"#,
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(CredentialKind::SharedKey)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found("shared key not found"),
        other => AppError::Database(other),
    })?;

    let status: CredentialStatus = row.try_get("status").map_err(db_err)?;
    if status != CredentialStatus::Active {
        return Err(AppError::unauthorized("shared key revoked"));
    }
    let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at").map_err(db_err)?;
    if expires_at.is_some_and(|expires_at| expires_at < Utc::now()) {
        return Err(AppError::unauthorized("shared key expired"));
    }

    let entity_status: EntityStatus = row.try_get("entity_status").map_err(db_err)?;
    if entity_status != EntityStatus::Active {
        return Err(AppError::unauthorized("entity is not active"));
    }
    if let Some(tenant_status) = row
        .try_get::<Option<crate::models::enums::TenantStatus>, _>("tenant_status")
        .unwrap_or(None)
    {
        if tenant_status != crate::models::enums::TenantStatus::Active {
            return Err(AppError::unauthorized("tenant is not active"));
        }
    }

    let secret_hash: Option<String> = row.try_get("secret_hash").map_err(db_err)?;
    let secret_hash = secret_hash.ok_or_else(lost_shared_key_error)?;
    let ciphertext: Option<Vec<u8>> = row.try_get("secret_ciphertext").map_err(db_err)?;
    let nonce: Option<Vec<u8>> = row.try_get("secret_nonce").map_err(db_err)?;
    let (Some(ciphertext), Some(nonce)) = (ciphertext, nonce) else {
        return Err(lost_shared_key_error());
    };

    let kek = signing_keys
        .key_encryption_key
        .as_ref()
        .ok_or_else(lost_shared_key_error)?;
    let key_bytes = crypto::decrypt(kek.expose(), credential_id.as_bytes(), &ciphertext, &nonce)
        .map_err(|_| lost_shared_key_error())?;
    let key = String::from_utf8(key_bytes).map_err(|_| lost_shared_key_error())?;

    if !verify_secret(key.as_bytes(), &secret_hash) {
        return Err(lost_shared_key_error());
    }

    Ok(SharedKeyResponse {
        credential_id,
        key,
        expires_at,
    })
}

/// Envelope-encrypt a recoverable credential secret, binding the ciphertext to the
/// credential id. Requires the deployment KEK; refuses to fall back to plaintext.
fn encrypt_recoverable_secret(
    signing_keys: &SigningKeyConfig,
    credential_id: Uuid,
    plaintext: &[u8],
) -> Result<crypto::Sealed, AppError> {
    let kek = signing_keys.key_encryption_key.as_ref().ok_or_else(|| {
        AppError::bad_request(
            "ATOM_KEY_ENCRYPTION_KEY must be set to create retrievable shared keys",
        )
    })?;
    crypto::encrypt(kek.expose(), credential_id.as_bytes(), plaintext)
}

fn shared_key_lookup_hash(
    signing_keys: &SigningKeyConfig,
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let kek = signing_keys.key_encryption_key.as_ref().ok_or_else(|| {
        AppError::bad_request(
            "ATOM_KEY_ENCRYPTION_KEY must be set to authenticate retrievable shared keys",
        )
    })?;
    Ok(crypto::hmac_sha256(kek.expose(), plaintext))
}

fn lost_shared_key_error() -> AppError {
    AppError::conflict(
        "could not retrieve the shared key; the stored key is lost, please set a new shared key",
    )
}

fn make_shared_key(cred_id: Uuid) -> String {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    format!(
        "atom_shared_{}_{}",
        hex::encode(cred_id.as_bytes()),
        hex::encode(secret_bytes)
    )
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
