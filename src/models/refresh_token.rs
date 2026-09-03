use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Response from a successful `refreshToken` exchange — every field is
/// always present, unlike `LoginResponse`'s optional refresh fields.
/// No separate `token` alias field: this type is resolved field-by-field by
/// the GraphQL wrapper in `graphql::types` rather than serialized directly.
#[derive(Serialize)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token_expires_at: DateTime<Utc>,
    pub entity_id: Uuid,
    pub session_id: Uuid,
}

/// Hand-written and redacting, rather than `#[derive(Debug)]`: this struct
/// carries a live refresh-token secret and access JWT, which a derived impl
/// would print verbatim into any `{:?}` log line or panic message.
impl std::fmt::Debug for TokenPairResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPairResponse")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .field("entity_id", &self.entity_id)
            .field("session_id", &self.session_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::TokenPairResponse;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn debug_never_prints_the_live_tokens() {
        let now = Utc::now();
        let response = TokenPairResponse {
            access_token: "super-secret-jwt".into(),
            refresh_token: "atom_rt_super-secret-refresh-token".into(),
            access_token_expires_at: now,
            refresh_token_expires_at: now,
            entity_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("super-secret"));
    }
}
