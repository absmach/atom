use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ipnet::IpNet;
use serde::Deserialize;
use std::{fmt, str::FromStr};
use uuid::Uuid;

// 00000000-0000-0000-0000-000000000001
pub const ADMIN_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
pub const SERVICE_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub db_pool: DbPoolConfig,
    pub listen_addr: String,
    pub grpc_addr: String,
    pub signing_keys: SigningKeyConfig,
    pub audit_retention: AuditRetentionConfig,
    pub rate_limits: RateLimitConfig,
    pub body_limits: BodyLimitConfig,
    pub graphql_limits: GraphqlLimitConfig,
    pub jwt_expiry_secs: u64,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    /// UUID of the seeded admin entity. Defaults to the well-known seed UUID.
    pub admin_entity_id: Uuid,
    /// If set, the admin entity's password credential is created on first boot.
    pub admin_secret: Option<String>,
    /// If set, the service entity's password credential is created on first boot.
    pub service_secret: Option<String>,
    pub service_entity_id: Uuid,
    /// Enables unauthenticated global human self-registration.
    pub self_registration_enabled: bool,
    /// Development-only: allow password login before the signup email is verified.
    pub dev_allow_unverified_email_login: bool,
    pub public_base_url: String,
    pub cors_allowed_origins: Vec<String>,
    pub auth_cookie_secure: bool,
    pub auth_cookie_domain: Option<String>,
    pub email_verification_redirect: String,
    pub password_reset_redirect: String,
    pub invitation_redirect: String,
    pub oauth_success_redirect: String,
    pub oauth_error_redirect: String,
    pub oidc_providers: Vec<OidcProviderConfig>,
    pub smtp: Option<SmtpConfig>,
    pub email_verification_expiry_secs: u64,
    pub invitation_expiry_secs: u64,
    pub oauth_state_expiry_secs: u64,
    pub auth_exchange_code_expiry_secs: u64,
    pub login_failure_limit: i64,
    pub login_failure_window_secs: i64,
    pub certs_enabled: bool,
    pub certs_ca_mode: CertsCaMode,
    pub certs_root_ca_cert_path: Option<String>,
    pub certs_intermediate_ca_cert_path: Option<String>,
    pub certs_intermediate_ca_key_path: Option<String>,
    pub certs_root_ca_key_path: Option<String>,
    pub certs_leaf_default_ttl_secs: u64,
    pub certs_leaf_max_ttl_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 20,
            min_connections: 0,
            acquire_timeout_secs: 30,
            connect_timeout_secs: 10,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("secret bytes must be exactly 32 bytes");
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyConfig {
    pub key_encryption_key: Option<SecretBytes>,
    pub key_encryption_key_id: String,
    pub allow_plaintext_signing_keys: bool,
}

impl Default for SigningKeyConfig {
    fn default() -> Self {
        Self {
            key_encryption_key: None,
            key_encryption_key_id: "local:v1".to_string(),
            allow_plaintext_signing_keys: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionConfig {
    pub enabled: bool,
    pub days: i64,
    pub cleanup_interval_secs: u64,
    pub cleanup_batch_size: i64,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            days: 365,
            cleanup_interval_secs: 86_400,
            cleanup_batch_size: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicyConfig {
    pub max_requests: u32,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub auth_routes: RateLimitPolicyConfig,
    pub public_routes: RateLimitPolicyConfig,
    pub graphql: RateLimitPolicyConfig,
    pub custom_endpoints: RateLimitPolicyConfig,
    pub admin_routes: RateLimitPolicyConfig,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth_routes: RateLimitPolicyConfig {
                max_requests: 30,
                window_secs: 60,
            },
            public_routes: RateLimitPolicyConfig {
                max_requests: 120,
                window_secs: 60,
            },
            graphql: RateLimitPolicyConfig {
                max_requests: 120,
                window_secs: 60,
            },
            custom_endpoints: RateLimitPolicyConfig {
                max_requests: 120,
                window_secs: 60,
            },
            admin_routes: RateLimitPolicyConfig {
                max_requests: 300,
                window_secs: 60,
            },
            trusted_proxy_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimitConfig {
    pub auth_bytes: usize,
    pub graphql_bytes: usize,
    pub custom_endpoint_bytes: usize,
}

impl Default for BodyLimitConfig {
    fn default() -> Self {
        Self {
            auth_bytes: 32 * 1024,
            graphql_bytes: 1024 * 1024,
            custom_endpoint_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphqlLimitConfig {
    pub max_depth: usize,
    pub max_complexity: usize,
    pub introspection_enabled: bool,
}

impl Default for GraphqlLimitConfig {
    fn default() -> Self {
        Self {
            max_depth: 20,
            max_complexity: 1_000,
            // Off by default: introspection exposes the full schema, so
            // production is safe without remembering to disable it. Dev opts in
            // with ATOM_GRAPHQL_INTROSPECTION_ENABLED=true.
            introspection_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertsCaMode {
    FileIntermediateIssuer,
    FileRootIssuer,
}

impl CertsCaMode {
    pub fn from_env_value(value: &str) -> Result<Self> {
        match value {
            "file_intermediate_issuer" => Ok(Self::FileIntermediateIssuer),
            "file_root_issuer" => Ok(Self::FileRootIssuer),
            other => anyhow::bail!(
                "ATOM_CERTS_CA_MODE must be file_intermediate_issuer or file_root_issuer, got {other}"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileIntermediateIssuer => "file_intermediate_issuer",
            Self::FileRootIssuer => "file_root_issuer",
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let public_base_url = std::env::var("ATOM_PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".into());
        let ui_auth_callback = public_url(&public_base_url, "/auth/callback");
        Ok(Config {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?,
            db_pool: db_pool_from_env()?,
            listen_addr: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            grpc_addr: std::env::var("GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
            signing_keys: signing_keys_from_env()?,
            audit_retention: audit_retention_from_env()?,
            rate_limits: rate_limits_from_env()?,
            body_limits: body_limits_from_env()?,
            graphql_limits: graphql_limits_from_env()?,
            jwt_expiry_secs: std::env::var("JWT_EXPIRY_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
            jwt_issuer: std::env::var("ATOM_JWT_ISSUER")
                .unwrap_or_else(|_| public_base_url.trim_end_matches('/').to_string()),
            jwt_audience: std::env::var("ATOM_JWT_AUDIENCE")
                .unwrap_or_else(|_| "magistrala".to_string()),
            admin_entity_id: std::env::var("ADMIN_ENTITY_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(ADMIN_ENTITY_ID),
            admin_secret: std::env::var("ADMIN_SECRET").ok(),
            service_secret: std::env::var("ATOM_SERVICE_SECRET").ok(),
            service_entity_id: std::env::var("ATOM_SERVICE_ENTITY_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(SERVICE_ENTITY_ID),
            self_registration_enabled: env_bool_default("ATOM_SELF_REGISTRATION_ENABLED", true),
            dev_allow_unverified_email_login: env_bool("ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN"),
            cors_allowed_origins: parse_cors_allowed_origins(&public_base_url),
            auth_cookie_secure: std::env::var("ATOM_AUTH_COOKIE_SECURE")
                .map(|_| env_bool("ATOM_AUTH_COOKIE_SECURE"))
                .unwrap_or_else(|_| public_base_url.starts_with("https://")),
            auth_cookie_domain: std::env::var("ATOM_AUTH_COOKIE_DOMAIN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            email_verification_redirect: std::env::var("ATOM_EMAIL_VERIFICATION_REDIRECT")
                .unwrap_or_else(|_| public_url(&public_base_url, "/auth/email/verify")),
            password_reset_redirect: std::env::var("ATOM_PASSWORD_RESET_REDIRECT")
                .unwrap_or_else(|_| public_url(&public_base_url, "/reset-password")),
            invitation_redirect: std::env::var("ATOM_INVITATION_REDIRECT")
                .unwrap_or_else(|_| public_url(&public_base_url, "/invitations/accept")),
            oauth_success_redirect: std::env::var("ATOM_OAUTH_SUCCESS_REDIRECT")
                .unwrap_or_else(|_| ui_auth_callback.clone()),
            oauth_error_redirect: std::env::var("ATOM_OAUTH_ERROR_REDIRECT")
                .unwrap_or_else(|_| ui_auth_callback.clone()),
            oidc_providers: parse_oidc_providers()?,
            smtp: smtp_from_env(),
            email_verification_expiry_secs: env_u64("ATOM_EMAIL_VERIFICATION_EXPIRY_SECS", 86_400),
            invitation_expiry_secs: env_u64("ATOM_INVITATION_EXPIRY_SECS", 604_800),
            oauth_state_expiry_secs: env_u64("ATOM_OAUTH_STATE_EXPIRY_SECS", 600),
            auth_exchange_code_expiry_secs: env_u64("ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS", 300),
            login_failure_limit: env_positive_i64("ATOM_LOGIN_FAILURE_LIMIT", 5)?,
            login_failure_window_secs: env_positive_i64("ATOM_LOGIN_FAILURE_WINDOW_SECS", 15 * 60)?,
            certs_enabled: env_bool_default("ATOM_CERTS_ENABLED", true),
            certs_ca_mode: CertsCaMode::from_env_value(
                &std::env::var("ATOM_CERTS_CA_MODE")
                    .unwrap_or_else(|_| "file_intermediate_issuer".to_string()),
            )?,
            certs_root_ca_cert_path: std::env::var("ATOM_CERTS_ROOT_CA_CERT_PATH").ok(),
            certs_intermediate_ca_cert_path: std::env::var("ATOM_CERTS_INTERMEDIATE_CA_CERT_PATH")
                .ok(),
            certs_intermediate_ca_key_path: std::env::var("ATOM_CERTS_INTERMEDIATE_CA_KEY_PATH")
                .ok(),
            certs_root_ca_key_path: std::env::var("ATOM_CERTS_ROOT_CA_KEY_PATH").ok(),
            certs_leaf_default_ttl_secs: env_u64("ATOM_CERTS_LEAF_DEFAULT_TTL_SECS", 2_592_000),
            certs_leaf_max_ttl_secs: env_u64("ATOM_CERTS_LEAF_MAX_TTL_SECS", 2_592_000),
            public_base_url,
        })
    }

    #[doc(hidden)]
    pub fn for_tests() -> Self {
        Self {
            database_url: "postgres://atom:atom@localhost/atom_test".into(),
            db_pool: DbPoolConfig::default(),
            listen_addr: "127.0.0.1:0".into(),
            grpc_addr: "127.0.0.1:0".into(),
            signing_keys: SigningKeyConfig {
                allow_plaintext_signing_keys: true,
                ..SigningKeyConfig::default()
            },
            audit_retention: AuditRetentionConfig::default(),
            rate_limits: RateLimitConfig {
                enabled: false,
                ..RateLimitConfig::default()
            },
            body_limits: BodyLimitConfig::default(),
            graphql_limits: GraphqlLimitConfig::default(),
            jwt_expiry_secs: 3600,
            jwt_issuer: "http://localhost:8080".to_string(),
            jwt_audience: "magistrala".to_string(),
            admin_entity_id: ADMIN_ENTITY_ID,
            admin_secret: None,
            service_secret: None,
            service_entity_id: SERVICE_ENTITY_ID,
            self_registration_enabled: false,
            dev_allow_unverified_email_login: false,
            public_base_url: "http://localhost:8080".into(),
            cors_allowed_origins: vec!["http://localhost:8080".into()],
            auth_cookie_secure: false,
            auth_cookie_domain: None,
            email_verification_redirect: "http://localhost:8080/auth/email/verify".into(),
            password_reset_redirect: "http://localhost:8080/reset-password".into(),
            invitation_redirect: "http://localhost:8080/invitations/accept".into(),
            oauth_success_redirect: "http://localhost:8080".into(),
            oauth_error_redirect: "http://localhost:8080".into(),
            oidc_providers: vec![],
            smtp: None,
            email_verification_expiry_secs: 86_400,
            invitation_expiry_secs: 604_800,
            oauth_state_expiry_secs: 600,
            auth_exchange_code_expiry_secs: 300,
            login_failure_limit: 5,
            login_failure_window_secs: 15 * 60,
            certs_enabled: false,
            certs_ca_mode: CertsCaMode::FileIntermediateIssuer,
            certs_root_ca_cert_path: None,
            certs_intermediate_ca_cert_path: None,
            certs_intermediate_ca_key_path: None,
            certs_root_ca_key_path: None,
            certs_leaf_default_ttl_secs: 2_592_000,
            certs_leaf_max_ttl_secs: 2_592_000,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::for_tests()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub tls: SmtpTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    None,
    StartTls,
    Tls,
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| parse_env_bool(&value))
        .unwrap_or(false)
}

fn env_bool_default(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|value| parse_env_bool(&value))
        .unwrap_or(default)
}

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_parse<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|err| anyhow::anyhow!("{name} must be a valid value: {err}")),
        Err(_) => Ok(default),
    }
}

fn env_positive_i64(name: &str, default: i64) -> Result<i64> {
    let value = env_parse(name, default)?;
    if value <= 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn db_pool_from_env() -> Result<DbPoolConfig> {
    let default = DbPoolConfig::default();
    let cfg = DbPoolConfig {
        max_connections: env_parse("ATOM_DB_MAX_CONNECTIONS", default.max_connections)?,
        min_connections: env_parse("ATOM_DB_MIN_CONNECTIONS", default.min_connections)?,
        acquire_timeout_secs: env_parse(
            "ATOM_DB_ACQUIRE_TIMEOUT_SECS",
            default.acquire_timeout_secs,
        )?,
        connect_timeout_secs: env_parse(
            "ATOM_DB_CONNECT_TIMEOUT_SECS",
            default.connect_timeout_secs,
        )?,
        idle_timeout_secs: env_parse("ATOM_DB_IDLE_TIMEOUT_SECS", default.idle_timeout_secs)?,
        max_lifetime_secs: env_parse("ATOM_DB_MAX_LIFETIME_SECS", default.max_lifetime_secs)?,
    };
    if cfg.max_connections == 0 {
        anyhow::bail!("ATOM_DB_MAX_CONNECTIONS must be greater than zero");
    }
    if cfg.min_connections > cfg.max_connections {
        anyhow::bail!("ATOM_DB_MIN_CONNECTIONS cannot exceed ATOM_DB_MAX_CONNECTIONS");
    }
    Ok(cfg)
}

fn signing_keys_from_env() -> Result<SigningKeyConfig> {
    let default = SigningKeyConfig::default();
    Ok(SigningKeyConfig {
        key_encryption_key: parse_key_encryption_key()?,
        key_encryption_key_id: std::env::var("ATOM_KEY_ENCRYPTION_KEY_ID")
            .unwrap_or(default.key_encryption_key_id),
        allow_plaintext_signing_keys: env_bool_default(
            "ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS",
            default.allow_plaintext_signing_keys,
        ),
    })
}

fn parse_key_encryption_key() -> Result<Option<SecretBytes>> {
    let value = match std::env::var("ATOM_KEY_ENCRYPTION_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let bytes = STANDARD
        .decode(value.trim())
        .context("ATOM_KEY_ENCRYPTION_KEY must be base64 encoded")?;
    SecretBytes::new(bytes)
        .map(Some)
        .context("ATOM_KEY_ENCRYPTION_KEY must decode to exactly 32 bytes")
}

fn audit_retention_from_env() -> Result<AuditRetentionConfig> {
    let default = AuditRetentionConfig::default();
    let cfg = AuditRetentionConfig {
        enabled: env_bool_default("ATOM_AUDIT_RETENTION_ENABLED", default.enabled),
        days: env_parse("ATOM_AUDIT_RETENTION_DAYS", default.days)?,
        cleanup_interval_secs: env_parse(
            "ATOM_AUDIT_CLEANUP_INTERVAL_SECS",
            default.cleanup_interval_secs,
        )?,
        cleanup_batch_size: env_parse("ATOM_AUDIT_CLEANUP_BATCH_SIZE", default.cleanup_batch_size)?,
    };
    if cfg.days <= 0 {
        anyhow::bail!("ATOM_AUDIT_RETENTION_DAYS must be greater than zero");
    }
    if cfg.cleanup_interval_secs == 0 {
        anyhow::bail!("ATOM_AUDIT_CLEANUP_INTERVAL_SECS must be greater than zero");
    }
    if cfg.cleanup_batch_size <= 0 {
        anyhow::bail!("ATOM_AUDIT_CLEANUP_BATCH_SIZE must be greater than zero");
    }
    Ok(cfg)
}

fn rate_limits_from_env() -> Result<RateLimitConfig> {
    let default = RateLimitConfig::default();
    Ok(RateLimitConfig {
        enabled: env_bool_default("ATOM_RATE_LIMIT_ENABLED", default.enabled),
        auth_routes: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_AUTH_ROUTES",
            "ATOM_HTTP_RATE_LIMIT_AUTH_WINDOW_SECS",
            default.auth_routes,
        )?,
        public_routes: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_PUBLIC_ROUTES",
            "ATOM_HTTP_RATE_LIMIT_PUBLIC_WINDOW_SECS",
            default.public_routes,
        )?,
        graphql: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_GRAPHQL",
            "ATOM_HTTP_RATE_LIMIT_GRAPHQL_WINDOW_SECS",
            default.graphql,
        )?,
        custom_endpoints: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS",
            "ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS_WINDOW_SECS",
            default.custom_endpoints,
        )?,
        admin_routes: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_ADMIN_ROUTES",
            "ATOM_HTTP_RATE_LIMIT_ADMIN_WINDOW_SECS",
            default.admin_routes,
        )?,
        trusted_proxy_cidrs: trusted_proxy_cidrs_from_env()?,
    })
}

fn rate_limit_policy_from_env(
    max_name: &str,
    window_name: &str,
    default: RateLimitPolicyConfig,
) -> Result<RateLimitPolicyConfig> {
    let policy = RateLimitPolicyConfig {
        max_requests: env_parse(max_name, default.max_requests)?,
        window_secs: env_parse(window_name, default.window_secs)?,
    };
    if policy.max_requests == 0 {
        anyhow::bail!("{max_name} must be greater than zero");
    }
    if policy.window_secs == 0 {
        anyhow::bail!("{window_name} must be greater than zero");
    }
    Ok(policy)
}

fn trusted_proxy_cidrs_from_env() -> Result<Vec<IpNet>> {
    let value = match std::env::var("ATOM_TRUSTED_PROXY_CIDRS") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(Vec::new()),
    };

    value
        .split(',')
        .map(str::trim)
        .filter(|cidr| !cidr.is_empty())
        .map(|cidr| {
            cidr.parse::<IpNet>()
                .with_context(|| format!("ATOM_TRUSTED_PROXY_CIDRS contains invalid CIDR {cidr}"))
        })
        .collect()
}

fn body_limits_from_env() -> Result<BodyLimitConfig> {
    let default = BodyLimitConfig::default();
    Ok(BodyLimitConfig {
        auth_bytes: env_parse("ATOM_AUTH_BODY_LIMIT_BYTES", default.auth_bytes)?,
        graphql_bytes: env_parse("ATOM_GRAPHQL_BODY_LIMIT_BYTES", default.graphql_bytes)?,
        custom_endpoint_bytes: env_parse(
            "ATOM_CUSTOM_ENDPOINT_BODY_LIMIT_BYTES",
            default.custom_endpoint_bytes,
        )?,
    })
}

fn graphql_limits_from_env() -> Result<GraphqlLimitConfig> {
    let default = GraphqlLimitConfig::default();
    let cfg = GraphqlLimitConfig {
        max_depth: env_parse("ATOM_GRAPHQL_MAX_DEPTH", default.max_depth)?,
        max_complexity: env_parse("ATOM_GRAPHQL_MAX_COMPLEXITY", default.max_complexity)?,
        introspection_enabled: env_bool_default(
            "ATOM_GRAPHQL_INTROSPECTION_ENABLED",
            default.introspection_enabled,
        ),
    };
    if cfg.max_depth == 0 {
        anyhow::bail!("ATOM_GRAPHQL_MAX_DEPTH must be greater than zero");
    }
    if cfg.max_complexity == 0 {
        anyhow::bail!("ATOM_GRAPHQL_MAX_COMPLEXITY must be greater than zero");
    }
    Ok(cfg)
}

fn parse_cors_allowed_origins(public_base_url: &str) -> Vec<String> {
    std::env::var("ATOM_CORS_ALLOWED_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|origins| !origins.is_empty())
        .unwrap_or_else(|| vec![public_base_url.trim_end_matches('/').to_string()])
}

fn parse_oidc_providers() -> Result<Vec<OidcProviderConfig>> {
    match std::env::var("ATOM_OIDC_PROVIDERS") {
        Ok(value) if !value.trim().is_empty() => {
            serde_json::from_str(&value).context("ATOM_OIDC_PROVIDERS must be valid JSON")
        }
        _ => Ok(Vec::new()),
    }
}

fn smtp_from_env() -> Option<SmtpConfig> {
    let host = std::env::var("ATOM_SMTP_HOST").ok()?;
    let from = std::env::var("ATOM_SMTP_FROM").ok()?;
    let tls = match std::env::var("ATOM_SMTP_TLS")
        .unwrap_or_else(|_| "starttls".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "none" => SmtpTls::None,
        "tls" => SmtpTls::Tls,
        "starttls" => SmtpTls::StartTls,
        _ => SmtpTls::StartTls,
    };
    Some(SmtpConfig {
        host,
        port: std::env::var("ATOM_SMTP_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(match tls {
                SmtpTls::None => 25,
                SmtpTls::StartTls => 587,
                SmtpTls::Tls => 465,
            }),
        username: std::env::var("ATOM_SMTP_USERNAME").ok(),
        password: std::env::var("ATOM_SMTP_PASSWORD").ok(),
        from,
        tls,
    })
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}

fn public_url(public_base_url: &str, path: &str) -> String {
    format!(
        "{}{}",
        public_base_url.trim_end_matches('/'),
        path.strip_prefix('/')
            .map(|p| format!("/{p}"))
            .unwrap_or_else(|| path.to_string())
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{public_url, Config};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn public_url_joins_base_and_ui_paths() {
        assert_eq!(
            public_url("http://localhost:8080/", "/auth/callback"),
            "http://localhost:8080/auth/callback"
        );
        assert_eq!(
            public_url("https://atom.example", "/invitations/accept"),
            "https://atom.example/invitations/accept"
        );
    }

    #[test]
    fn production_hardening_config_defaults_are_parsed() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("config");

        assert_eq!(cfg.db_pool.max_connections, 20);
        assert_eq!(cfg.db_pool.acquire_timeout_secs, 30);
        assert!(!cfg.signing_keys.allow_plaintext_signing_keys);
        assert!(cfg.signing_keys.key_encryption_key.is_none());
        assert_eq!(cfg.audit_retention.days, 365);
        assert_eq!(cfg.login_failure_limit, 5);
        assert_eq!(cfg.login_failure_window_secs, 900);
        assert!(cfg.rate_limits.enabled);
        assert!(
            !cfg.graphql_limits.introspection_enabled,
            "GraphQL introspection must default off"
        );

        clear_hardening_env();
    }

    #[test]
    fn graphql_introspection_opts_in_via_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_GRAPHQL_INTROSPECTION_ENABLED", "true");

        let cfg = Config::from_env().expect("config");
        assert!(cfg.graphql_limits.introspection_enabled);

        clear_hardening_env();
    }

    #[test]
    fn invalid_pool_env_value_fails_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_DB_MAX_CONNECTIONS", "not-a-number");

        let err = Config::from_env().expect_err("invalid config");
        assert!(err.to_string().contains("ATOM_DB_MAX_CONNECTIONS"));

        clear_hardening_env();
    }

    #[test]
    fn key_encryption_key_must_be_base64_32_bytes() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_KEY_ENCRYPTION_KEY", "too-short");

        let err = Config::from_env().expect_err("invalid key");
        assert!(err.to_string().contains("ATOM_KEY_ENCRYPTION_KEY"));

        clear_hardening_env();
    }

    #[test]
    fn trusted_proxy_cidrs_must_be_valid() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,not-a-cidr");

        let err = Config::from_env().expect_err("invalid trusted proxy cidr");
        assert!(err.to_string().contains("ATOM_TRUSTED_PROXY_CIDRS"));

        clear_hardening_env();
    }

    /// Sets `DATABASE_URL` to a fixture value for config-parsing tests and
    /// restores the prior value (or unsets it) on drop, so DB-gated tests that
    /// share the same test binary keep the real `DATABASE_URL`.
    struct DatabaseUrlGuard(Option<String>);

    impl DatabaseUrlGuard {
        fn set() -> Self {
            let prev = std::env::var("DATABASE_URL").ok();
            std::env::set_var("DATABASE_URL", "postgres://atom:atom@localhost/atom");
            Self(prev)
        }
    }

    impl Drop for DatabaseUrlGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("DATABASE_URL", value),
                None => std::env::remove_var("DATABASE_URL"),
            }
        }
    }

    fn clear_hardening_env() {
        for name in [
            "ATOM_DB_MAX_CONNECTIONS",
            "ATOM_DB_MIN_CONNECTIONS",
            "ATOM_DB_ACQUIRE_TIMEOUT_SECS",
            "ATOM_DB_CONNECT_TIMEOUT_SECS",
            "ATOM_DB_IDLE_TIMEOUT_SECS",
            "ATOM_DB_MAX_LIFETIME_SECS",
            "ATOM_KEY_ENCRYPTION_KEY",
            "ATOM_KEY_ENCRYPTION_KEY_ID",
            "ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS",
            "ATOM_AUDIT_RETENTION_DAYS",
            "ATOM_AUDIT_RETENTION_ENABLED",
            "ATOM_AUDIT_CLEANUP_INTERVAL_SECS",
            "ATOM_AUDIT_CLEANUP_BATCH_SIZE",
            "ATOM_LOGIN_FAILURE_LIMIT",
            "ATOM_LOGIN_FAILURE_WINDOW_SECS",
            "ATOM_RATE_LIMIT_ENABLED",
            "ATOM_TRUSTED_PROXY_CIDRS",
            "ATOM_GRAPHQL_INTROSPECTION_ENABLED",
        ] {
            std::env::remove_var(name);
        }
    }
}
