mod repository;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    SecretKey,
};
use rand::rngs::OsRng;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    auth::{require_capability, AuthContext, Scope},
    config::SigningKeyConfig,
    crypto,
    db::{Database, DbTransaction},
    error::{db_err, AppError},
    state::AppState,
};

const SIGNING_KEY_ENCRYPTION_ALG: &str = crypto::AEAD_ALG;

// ─── Types ────────────────────────────────────────────────────────────────────

/// A signing key pair loaded from the database.
/// `private_key_pem` is only used when this is the primary (signing) key.
#[derive(Clone)]
pub struct LoadedKey {
    pub kid: String,
    /// SubjectPublicKeyInfo PEM — used for JWT verification and JWKS output.
    pub public_key_pem: String,
    /// PKCS8 PEM — used for JWT signing (primary key only).
    pub private_key_pem: String,
    /// Base64url-encoded x coordinate of the EC public key (for JWKS).
    pub x_b64: String,
    /// Base64url-encoded y coordinate of the EC public key (for JWKS).
    pub y_b64: String,
}

/// The two keys active at any point in time.
/// Tokens are always signed with `primary`; both keys validate incoming tokens.
#[derive(Clone)]
pub struct ActiveKeys {
    pub primary: LoadedKey,
    pub standby: Option<LoadedKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyStorageMode {
    Encrypted,
    Plaintext,
}

impl SigningKeyStorageMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Plaintext => "plaintext",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningKeyMetadata {
    pub kid: String,
    pub algorithm: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub storage_mode: SigningKeyStorageMode,
    pub key_encryption_key_id: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigningKeyStorageSummary {
    pub total: i64,
    pub encrypted: i64,
    pub plaintext: i64,
}

impl ActiveKeys {
    /// Find the key matching `kid`, checking primary then standby.
    pub fn key_for(&self, kid: &str) -> Option<&LoadedKey> {
        if self.primary.kid == kid {
            return Some(&self.primary);
        }
        self.standby.as_ref().filter(|k| k.kid == kid)
    }

    pub fn to_jwks(&self) -> JwksResponse {
        let mut keys = vec![to_jwk(&self.primary)];
        if let Some(ref s) = self.standby {
            keys.push(to_jwk(s));
        }
        JwksResponse { keys }
    }
}

// ─── JWKS serialization ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: String,
    pub y: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
}

fn to_jwk(key: &LoadedKey) -> Jwk {
    Jwk {
        kty: "EC",
        crv: "P-256",
        x: key.x_b64.clone(),
        y: key.y_b64.clone(),
        kid: key.kid.clone(),
        use_: "sig",
        alg: "ES256",
    }
}

// ─── Key generation ───────────────────────────────────────────────────────────

/// Generate a fresh ES256 key pair. Returns (kid, public_key_pem, private_key_pem).
pub fn generate_key_pair() -> Result<(String, String, String), AppError> {
    let kid = Uuid::new_v4().to_string();
    let secret_key = SecretKey::random(&mut OsRng);

    let private_pem = secret_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("private key serialization: {e}")))?
        .as_str()
        .to_owned();

    let public_pem = secret_key
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("public key serialization: {e}")))?;

    Ok((kid, public_pem, private_pem))
}

/// Parse x/y JWK coordinates from a SubjectPublicKeyInfo PEM.
fn coords_from_public_pem(pem: &str) -> Result<(String, String), AppError> {
    let public_key = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("parse public key: {e}")))?;
    let point = public_key.to_encoded_point(false); // uncompressed: always has x and y
    let x = point
        .x()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("public key point is missing x")))?;
    let y = point
        .y()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("public key point is missing y")))?;
    Ok((URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)))
}

fn load_key_row(
    kid: String,
    public_pem: String,
    private_pem: String,
) -> Result<LoadedKey, AppError> {
    let (x_b64, y_b64) = coords_from_public_pem(&public_pem)?;
    Ok(LoadedKey {
        kid,
        public_key_pem: public_pem,
        private_key_pem: private_pem,
        x_b64,
        y_b64,
    })
}

#[derive(Debug)]
struct KeyStorageValues {
    plaintext: Option<String>,
    ciphertext: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    key_id: Option<String>,
    encryption_alg: Option<String>,
}

fn storage_values_for_private_key(
    cfg: &SigningKeyConfig,
    kid: &str,
    private_pem: String,
) -> Result<KeyStorageValues, AppError> {
    if cfg.key_encryption_key.is_some() {
        let encrypted = encrypt_private_key(cfg, kid, &private_pem)?;
        return Ok(KeyStorageValues {
            plaintext: None,
            ciphertext: Some(encrypted.ciphertext),
            nonce: Some(encrypted.nonce),
            key_id: Some(cfg.key_encryption_key_id.clone()),
            encryption_alg: Some(SIGNING_KEY_ENCRYPTION_ALG.to_string()),
        });
    }

    if cfg.allow_plaintext_signing_keys {
        return Ok(KeyStorageValues {
            plaintext: Some(private_pem),
            ciphertext: None,
            nonce: None,
            key_id: None,
            encryption_alg: None,
        });
    }

    Err(AppError::Internal(anyhow::anyhow!(
        "ATOM_KEY_ENCRYPTION_KEY must be set or ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS=true before signing keys can be stored"
    )))
}

struct EncryptedPrivateKey {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

fn encrypt_private_key(
    cfg: &SigningKeyConfig,
    kid: &str,
    private_pem: &str,
) -> Result<EncryptedPrivateKey, AppError> {
    let sealed = crypto::encrypt(kek(cfg)?, kid.as_bytes(), private_pem.as_bytes())?;
    Ok(EncryptedPrivateKey {
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
    })
}

fn decrypt_private_key(
    cfg: &SigningKeyConfig,
    kid: &str,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<String, AppError> {
    let plaintext = crypto::decrypt(kek(cfg)?, kid.as_bytes(), ciphertext, nonce)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("decrypt signing private key {kid}")))?;
    String::from_utf8(plaintext)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("signing key {kid} is not UTF-8: {e}")))
}

fn kek(cfg: &SigningKeyConfig) -> Result<&[u8], AppError> {
    cfg.key_encryption_key
        .as_ref()
        .map(|k| k.expose())
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "ATOM_KEY_ENCRYPTION_KEY is required to load encrypted signing keys"
            ))
        })
}

// ─── Database operations ──────────────────────────────────────────────────────

/// Load primary and standby keys from the database into memory.
pub async fn load_active_keys(
    pool: &Database,
    cfg: &SigningKeyConfig,
) -> Result<ActiveKeys, AppError> {
    fetch_active_keys(pool, cfg).await
}

/// Executor-generic [`load_active_keys`], so a rotation can read the key set it
/// just wrote from inside its own transaction rather than after the commit.
async fn fetch_active_keys<'e, E>(
    executor: E,
    cfg: &SigningKeyConfig,
) -> Result<ActiveKeys, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    let rows = repository::active_keys(executor).await?;

    let mut primary: Option<LoadedKey> = None;
    let mut standby: Option<LoadedKey> = None;

    for row in rows {
        let kid = row.kid;
        let status = row.status;
        let public_pem = row.public_key;
        let private_pem = private_key_from_row(
            cfg,
            &kid,
            row.private_key,
            row.private_key_ciphertext,
            row.private_key_nonce,
            row.private_key_key_id,
            row.private_key_encryption_alg,
        )?;

        let loaded = load_key_row(kid, public_pem, private_pem)?;
        match status.as_str() {
            "primary" => primary = Some(loaded),
            "standby" => standby = Some(loaded),
            _ => {}
        }
    }

    let primary = primary
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("no primary signing key in database")))?;

    Ok(ActiveKeys { primary, standby })
}

/// On first boot, generate the initial primary key if none exists.
pub async fn bootstrap_if_needed(pool: &Database, cfg: &SigningKeyConfig) -> Result<(), AppError> {
    encrypt_legacy_plaintext_keys(pool, cfg).await?;

    let count = repository::primary_count(pool).await?;

    if count == 0 {
        let (kid, public_pem, private_pem) = generate_key_pair()?;
        let storage = storage_values_for_private_key(cfg, &kid, private_pem)?;
        repository::insert_primary(pool, &kid, &public_pem, storage).await?;
        tracing::info!("generated initial signing key kid={kid}");
    }

    Ok(())
}

/// Rotate signing keys:
/// - current standby → retired
/// - current primary → standby
/// - new key         → primary
///
/// All three steps run in a single transaction.
/// After the JWT TTL elapses, no outstanding tokens reference the retired key.
pub async fn rotate(pool: &Database, cfg: &SigningKeyConfig) -> Result<ActiveKeys, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let keys = rotate_in_tx(&mut tx, cfg).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(keys)
}

/// The caller owns the commit, so an audited caller can bind the rotation and
/// its `signing_key.rotate` event into one transaction via
/// [`crate::audit::commit_with_audit`].
pub async fn rotate_in_tx(
    tx: &mut DbTransaction<'_>,
    cfg: &SigningKeyConfig,
) -> Result<ActiveKeys, AppError> {
    repository::demote_active(tx).await?;

    let (kid, public_pem, private_pem) = generate_key_pair()?;
    let storage = storage_values_for_private_key(cfg, &kid, private_pem)?;
    repository::insert_primary(tx.exec(), &kid, &public_pem, storage).await?;

    tracing::info!("signing key rotated, new primary kid={kid}");

    // Read inside the transaction: loading after the commit would let a
    // transient failure report an already-applied rotation as an error.
    fetch_active_keys(tx, cfg).await
}

fn private_key_from_row(
    cfg: &SigningKeyConfig,
    kid: &str,
    private_key: Option<String>,
    ciphertext: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    key_id: Option<String>,
    encryption_alg: Option<String>,
) -> Result<String, AppError> {
    if let Some(ciphertext) = ciphertext {
        let row_key_id = key_id.ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "encrypted signing key {kid} is missing private_key_key_id"
            ))
        })?;
        if row_key_id != cfg.key_encryption_key_id {
            return Err(AppError::Internal(anyhow::anyhow!(
                "encrypted signing key {kid} uses key id {row_key_id}, but ATOM_KEY_ENCRYPTION_KEY_ID is {}",
                cfg.key_encryption_key_id
            )));
        }
        let alg = encryption_alg.ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "encrypted signing key {kid} is missing private_key_encryption_alg"
            ))
        })?;
        if alg != SIGNING_KEY_ENCRYPTION_ALG {
            return Err(AppError::Internal(anyhow::anyhow!(
                "encrypted signing key {kid} uses unsupported encryption algorithm {alg}"
            )));
        }
        let nonce = nonce.ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "encrypted signing key {kid} is missing private_key_nonce"
            ))
        })?;
        return decrypt_private_key(cfg, kid, &ciphertext, &nonce);
    }

    if let Some(private_key) = private_key {
        if cfg.allow_plaintext_signing_keys {
            return Ok(private_key);
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "signing key {kid} is stored in plaintext; set ATOM_KEY_ENCRYPTION_KEY to migrate it or ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS=true for development"
        )));
    }

    Err(AppError::Internal(anyhow::anyhow!(
        "signing key {kid} has no private key material"
    )))
}

pub async fn encrypt_legacy_plaintext_keys(
    pool: &Database,
    cfg: &SigningKeyConfig,
) -> Result<u64, AppError> {
    if cfg.key_encryption_key.is_none() {
        return Ok(0);
    }

    let rows = repository::legacy_keys(pool).await?;

    let mut encrypted = 0_u64;
    for (kid, private_pem) in rows {
        let material = encrypt_private_key(cfg, &kid, &private_pem)?;
        repository::encrypt_legacy(
            pool,
            &kid,
            &material.ciphertext,
            &material.nonce,
            &cfg.key_encryption_key_id,
            SIGNING_KEY_ENCRYPTION_ALG,
        )
        .await?;
        encrypted += 1;
    }

    if encrypted > 0 {
        tracing::info!("encrypted {encrypted} legacy plaintext signing keys");
    }
    Ok(encrypted)
}

pub async fn list_metadata(pool: &Database) -> Result<Vec<SigningKeyMetadata>, AppError> {
    let rows = repository::metadata(pool).await?;

    rows.into_iter()
        .map(|row| {
            let has_ciphertext = row.has_ciphertext;
            let has_plaintext = row.has_plaintext;
            let storage_mode = if has_ciphertext {
                SigningKeyStorageMode::Encrypted
            } else if has_plaintext {
                SigningKeyStorageMode::Plaintext
            } else {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "signing key row is missing private key material"
                )));
            };
            Ok(SigningKeyMetadata {
                kid: row.kid,
                algorithm: row.algorithm,
                status: row.status,
                created_at: row.created_at,
                storage_mode,
                key_encryption_key_id: row.private_key_key_id,
            })
        })
        .collect()
}

pub async fn storage_summary(pool: &Database) -> Result<SigningKeyStorageSummary, AppError> {
    repository::storage_summary(pool).await
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// GET /.well-known/jwks.json — unauthenticated, returns public keys.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let keys = state.keys.read().await;
    Json(keys.to_jwks())
}

/// POST /auth/keys/rotate — requires signing-key rotation permission.
pub async fn rotate_keys(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, AppError> {
    require_capability(state.pool(), &auth, "rotate", Scope::Platform).await?;
    let new_keys = rotate(state.pool(), &state.config.signing_keys).await?;
    *state.keys.write().await = new_keys;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretBytes;

    fn encrypted_config() -> SigningKeyConfig {
        SigningKeyConfig {
            key_encryption_key: Some(SecretBytes::new(vec![7; 32]).expect("test key")),
            key_encryption_key_id: "local:test".to_string(),
            allow_plaintext_signing_keys: false,
        }
    }

    #[test]
    fn signing_private_key_round_trips_through_encryption() {
        let cfg = encrypted_config();
        let encrypted = encrypt_private_key(&cfg, "kid-1", "private-pem").expect("encrypt");
        assert_ne!(encrypted.ciphertext, b"private-pem");

        let decrypted = decrypt_private_key(&cfg, "kid-1", &encrypted.ciphertext, &encrypted.nonce)
            .expect("decrypt");

        assert_eq!(decrypted, "private-pem");
    }

    #[test]
    fn encrypted_signing_key_requires_configured_key() {
        let cfg = SigningKeyConfig::default();
        let err =
            decrypt_private_key(&cfg, "kid-1", b"ciphertext", &[0; 12]).expect_err("missing key");
        assert!(err.to_string().contains("internal error"));
    }

    #[test]
    fn plaintext_storage_requires_explicit_dev_opt_in() {
        let cfg = SigningKeyConfig::default();
        let err = storage_values_for_private_key(&cfg, "kid-1", "private-pem".to_string())
            .expect_err("plaintext rejected");
        assert!(err.to_string().contains("internal error"));
    }
}
