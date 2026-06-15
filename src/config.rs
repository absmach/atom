use anyhow::{Context, Result};
use serde::Deserialize;
use uuid::Uuid;

// 00000000-0000-0000-0000-000000000001
pub const ADMIN_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
pub const SERVICE_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub listen_addr: String,
    pub grpc_addr: String,
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
            listen_addr: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            grpc_addr: std::env::var("GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
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
            self_registration_enabled: env_bool_default_with_legacy(
                "ATOM_SELF_REGISTRATION_ENABLED",
                "ATOM_SIGNUP_ENABLED",
                true,
            ),
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

fn env_bool_default_with_legacy(name: &str, legacy_name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|value| parse_env_bool(&value))
        .or_else(|_| std::env::var(legacy_name).map(|value| parse_env_bool(&value)))
        .unwrap_or(default)
}

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
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
    use super::public_url;

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
}
