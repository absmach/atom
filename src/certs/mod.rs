use crate::error::AppError;

pub mod authority;
pub mod enrollment;
pub mod graphql;
pub mod http;
pub mod lifecycle;
pub mod pki_core;
pub mod profile;
pub mod repo;
pub mod service;

#[cfg(test)]
pub(crate) fn test_state_without_database() -> crate::state::AppState {
    use std::time::Duration;

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use crate::{
        config::Config,
        keys::{ActiveKeys, LoadedKey},
    };

    // Tests that assert an authorization/extraction guard runs before a query
    // must not point at a real local database. A connection reaching this
    // closed loopback port fails immediately and changes the expected result.
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(10))
        .connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(9)
                .username("atom")
                .password("atom")
                .database("atom_test"),
        );
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    crate::state::AppState::new(
        pool,
        Config::for_tests(),
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

pub(crate) fn normalize_serial(serial_number: &str) -> Result<String, AppError> {
    let normalized = serial_number
        .chars()
        .filter(|ch| *ch != ':' && !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if normalized.is_empty() || normalized.len() % 2 != 0 || hex::decode(&normalized).is_err() {
        return Err(AppError::bad_request("invalid certificate serial number"));
    }
    Ok(normalized)
}
