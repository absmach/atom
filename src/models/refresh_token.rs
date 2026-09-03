use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Response from a successful `refreshToken` exchange. Unlike `LoginResponse`
/// (whose refresh fields are optional, for the feature-flagged login path),
/// every field here is always present — a successful exchange always returns
/// a full new pair.
#[derive(Debug, Serialize)]
pub struct TokenPairResponse {
    /// Compatibility alias for `access_token` — always equal to it.
    pub token: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token_expires_at: DateTime<Utc>,
    pub entity_id: Uuid,
    pub session_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::TokenPairResponse;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn token_alias_matches_access_token() {
        let now = Utc::now();
        let response = TokenPairResponse {
            token: "jwt".into(),
            access_token: "jwt".into(),
            refresh_token: "atom_rt_...".into(),
            access_token_expires_at: now,
            refresh_token_expires_at: now,
            entity_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
        };
        assert_eq!(response.token, response.access_token);
    }
}
