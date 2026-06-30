//! Reusable authenticated-encryption (AEAD) primitive shared by everything that
//! stores recoverable secrets at rest: signing private keys (`keys.rs`) and
//! retrievable credential secrets such as shared keys (`identity::service`).
//!
//! One implementation, one algorithm (AES-256-GCM), keyed by the deployment's
//! key-encryption key (`ATOM_KEY_ENCRYPTION_KEY`). Callers bind each ciphertext to
//! its logical owner via the `aad` argument (e.g. the signing key's `kid` or a
//! credential's UUID) so a ciphertext cannot be transplanted between rows.

use rand::{rngs::OsRng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use crate::error::AppError;

/// Label stored alongside ciphertext so future algorithm changes are detectable.
pub const AEAD_ALG: &str = "AES-256-GCM";
const NONCE_LEN: usize = 12;

/// Ciphertext plus the random nonce it was sealed with. Both are needed to decrypt.
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Encrypt `plaintext` under `key` (32 bytes for AES-256), binding it to `aad`.
pub fn encrypt(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, AppError> {
    let sealing = aead_key(key)?;
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut ciphertext = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| AppError::Internal(anyhow::anyhow!("aead encrypt")))?;
    Ok(Sealed {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

/// Decrypt `ciphertext` produced by [`encrypt`] with the same `key` and `aad`.
pub fn decrypt(key: &[u8], aad: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AppError> {
    if nonce.len() != NONCE_LEN {
        return Err(AppError::Internal(anyhow::anyhow!("invalid aead nonce length")));
    }
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);
    let opening = aead_key(key)?;
    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| AppError::Internal(anyhow::anyhow!("aead decrypt")))?;
    Ok(plaintext.to_vec())
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, AppError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid aead key")))?;
    Ok(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn round_trips() {
        let sealed = encrypt(&key(), b"aad", b"secret").unwrap();
        let plaintext = decrypt(&key(), b"aad", &sealed.ciphertext, &sealed.nonce).unwrap();
        assert_eq!(plaintext, b"secret");
    }

    #[test]
    fn rejects_wrong_aad() {
        let sealed = encrypt(&key(), b"aad", b"secret").unwrap();
        assert!(decrypt(&key(), b"other", &sealed.ciphertext, &sealed.nonce).is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let mut sealed = encrypt(&key(), b"aad", b"secret").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(decrypt(&key(), b"aad", &sealed.ciphertext, &sealed.nonce).is_err());
    }
}
