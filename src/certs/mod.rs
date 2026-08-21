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
