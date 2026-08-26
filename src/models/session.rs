use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::enums::CredentialKind;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub entity_id: Uuid,
    pub session_id: Uuid,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "is_false")]
    pub verification_required: bool,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub identifier: String,
    pub secret: String,
    pub tenant_id: Option<Uuid>,
    pub tenant_alias: Option<String>,
    #[serde(default = "default_kind")]
    pub kind: CredentialKind,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Serialize)]
pub struct SignupResponse {
    pub entity_id: Uuid,
    pub email: String,
    pub verification_required: bool,
}

#[derive(Debug, Serialize)]
pub struct PublicAuthConfigResponse {
    /// Backward-compatible alias for self_registration_enabled.
    pub signup_enabled: bool,
    pub self_registration_enabled: bool,
    pub oauth_providers: Vec<String>,
    pub email_verification_required: bool,
    pub dev_allow_unverified_email_login: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub password: String,
    pub confirm_password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthStartQuery {
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthExchangeRequest {
    pub code: String,
}

fn default_kind() -> CredentialKind {
    CredentialKind::Password
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::PasswordResetRequest;

    #[test]
    fn password_reset_request_rejects_client_redirects() {
        let error = serde_json::from_value::<PasswordResetRequest>(serde_json::json!({
            "email": "alice@example.test",
            "redirect_url": "https://attacker.example/reset"
        }))
        .expect_err("redirect_url must not be part of the public request DTO");

        assert!(error.to_string().contains("unknown field `redirect_url`"));
    }

    #[test]
    fn password_reset_request_accepts_email_only() {
        let request = serde_json::from_value::<PasswordResetRequest>(serde_json::json!({
            "email": "alice@example.test"
        }))
        .expect("email-only password reset request");

        assert_eq!(request.email, "alice@example.test");
    }
}
