//! Expiring download links. A link carries its expiry and an HMAC-SHA256 over
//! the file id and that expiry, under a key derived from the deployment KEK,
//! so verifying one needs no database read or write, and a link for one file
//! opens no other.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use uuid::Uuid;

use crate::{crypto, error::AppError, state::AppState};

/// Separates this use of the KEK from every other key derived from it.
const DOMAIN: &[u8] = b"atom/files/signed-url/v1";

fn key(state: &AppState) -> Result<Vec<u8>, AppError> {
    let kek = state
        .config
        .signing_keys
        .key_encryption_key
        .as_ref()
        .ok_or_else(|| {
            AppError::service_unavailable("signed file URLs need ATOM_KEY_ENCRYPTION_KEY to be set")
        })?;
    Ok(crypto::hmac_sha256(kek.expose(), DOMAIN))
}

fn message(file_id: Uuid, expires: i64) -> String {
    format!("{file_id}\n{expires}")
}

/// The signature for `file_id` valid until `expires` (Unix seconds).
pub(crate) fn sign(state: &AppState, file_id: Uuid, expires: i64) -> Result<String, AppError> {
    let digest = crypto::hmac_sha256(&key(state)?, message(file_id, expires).as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// True when `signature` was issued for `file_id` and `expires` has not passed.
pub(crate) fn verify(
    state: &AppState,
    file_id: Uuid,
    expires: i64,
    signature: &str,
    now: i64,
) -> bool {
    if expires < now {
        return false;
    }
    let (Ok(key), Ok(signature)) = (key(state), URL_SAFE_NO_PAD.decode(signature)) else {
        return false;
    };
    crypto::hmac_sha256_verify(&key, message(file_id, expires).as_bytes(), &signature)
}
