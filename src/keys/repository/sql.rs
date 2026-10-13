//! SQL that is identical on both supported databases. Driver calls stay in the adapters.
pub(super) const ACTIVE_KEYS: &str = "SELECT kid, public_key, private_key, private_key_ciphertext, private_key_nonce, private_key_key_id, private_key_encryption_alg, status
        FROM signing_keys WHERE status IN ('primary', 'standby') ORDER BY created_at DESC";
pub(super) const INSERT_PRIMARY: &str = "INSERT INTO signing_keys (kid, public_key, private_key, private_key_ciphertext, private_key_nonce, private_key_key_id, private_key_encryption_alg, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'primary')";
pub(super) const PRIMARY_COUNT: &str = "SELECT COUNT(*) FROM signing_keys WHERE status = 'primary'";
pub(super) const RETIRE_STANDBY: &str =
    "UPDATE signing_keys SET status = 'retired' WHERE status = 'standby'";
pub(super) const DEMOTE_PRIMARY: &str =
    "UPDATE signing_keys SET status = 'standby' WHERE status = 'primary'";
pub(super) const LEGACY_KEYS: &str = "SELECT kid, private_key FROM signing_keys WHERE private_key IS NOT NULL AND private_key_ciphertext IS NULL";
pub(super) const ENCRYPT_LEGACY: &str = "UPDATE signing_keys SET private_key = NULL, private_key_ciphertext = $2, private_key_nonce = $3, private_key_key_id = $4, private_key_encryption_alg = $5 WHERE kid = $1";
pub(super) const KEY_METADATA: &str = "SELECT kid, algorithm, status, created_at, private_key IS NOT NULL AS has_plaintext, private_key_ciphertext IS NOT NULL AS has_ciphertext, private_key_key_id FROM signing_keys ORDER BY created_at DESC";
