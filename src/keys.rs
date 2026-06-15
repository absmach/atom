use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    SecretKey,
};
use rand::{rngs::OsRng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{require_capability, AuthContext, Scope},
    config::SigningKeyConfig,
    error::{db_err, AppError},
    state::AppState,
};

const SIGNING_KEY_ENCRYPTION_ALG: &str = "AES-256-GCM";
const AES_GCM_NONCE_LEN: usize = 12;

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

#[derive(Debug, Clone)]
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
    let key = aead_key(cfg)?;
    let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut ciphertext = private_pem.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(kid.as_bytes()),
        &mut ciphertext,
    )
    .map_err(|_| AppError::Internal(anyhow::anyhow!("encrypt signing private key")))?;
    Ok(EncryptedPrivateKey {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

fn decrypt_private_key(
    cfg: &SigningKeyConfig,
    kid: &str,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<String, AppError> {
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(AppError::Internal(anyhow::anyhow!(
            "signing key {kid} has invalid nonce length"
        )));
    }
    let mut nonce_bytes = [0_u8; AES_GCM_NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);
    let key = aead_key(cfg)?;
    let mut plaintext = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(kid.as_bytes()),
            &mut plaintext,
        )
        .map_err(|_| AppError::Internal(anyhow::anyhow!("decrypt signing private key {kid}")))?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("signing key {kid} is not UTF-8: {e}")))
}

fn aead_key(cfg: &SigningKeyConfig) -> Result<LessSafeKey, AppError> {
    let key = cfg.key_encryption_key.as_ref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "ATOM_KEY_ENCRYPTION_KEY is required to load encrypted signing keys"
        ))
    })?;
    let unbound = UnboundKey::new(&AES_256_GCM, key.expose())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid signing key encryption key")))?;
    Ok(LessSafeKey::new(unbound))
}

// ─── Database operations ──────────────────────────────────────────────────────

/// Load primary and standby keys from the database into memory.
pub async fn load_active_keys(
    pool: &PgPool,
    cfg: &SigningKeyConfig,
) -> Result<ActiveKeys, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT kid,
                  public_key,
                  private_key,
                  private_key_ciphertext,
                  private_key_nonce,
                  private_key_key_id,
                  private_key_encryption_alg,
                  status
           FROM signing_keys
           WHERE status IN ('primary', 'standby')
           ORDER BY created_at DESC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut primary: Option<LoadedKey> = None;
    let mut standby: Option<LoadedKey> = None;

    for row in rows {
        let kid: String = row.try_get("kid").map_err(db_err)?;
        let status: String = row.try_get("status").map_err(db_err)?;
        let public_pem: String = row.try_get("public_key").map_err(db_err)?;
        let private_pem = private_key_from_row(
            cfg,
            &kid,
            row.try_get("private_key").map_err(db_err)?,
            row.try_get("private_key_ciphertext").map_err(db_err)?,
            row.try_get("private_key_nonce").map_err(db_err)?,
            row.try_get("private_key_key_id").map_err(db_err)?,
            row.try_get("private_key_encryption_alg").map_err(db_err)?,
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
pub async fn bootstrap_if_needed(pool: &PgPool, cfg: &SigningKeyConfig) -> Result<(), AppError> {
    encrypt_legacy_plaintext_keys(pool, cfg).await?;

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys WHERE status = 'primary'")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    if count == 0 {
        let (kid, public_pem, private_pem) = generate_key_pair()?;
        let storage = storage_values_for_private_key(cfg, &kid, private_pem)?;
        sqlx::query(
            r#"INSERT INTO signing_keys (
                   kid,
                   public_key,
                   private_key,
                   private_key_ciphertext,
                   private_key_nonce,
                   private_key_key_id,
                   private_key_encryption_alg,
                   status
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'primary')"#,
        )
        .bind(&kid)
        .bind(&public_pem)
        .bind(storage.plaintext)
        .bind(storage.ciphertext)
        .bind(storage.nonce)
        .bind(storage.key_id)
        .bind(storage.encryption_alg)
        .execute(pool)
        .await
        .map_err(db_err)?;
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
pub async fn rotate(pool: &PgPool, cfg: &SigningKeyConfig) -> Result<ActiveKeys, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    sqlx::query("UPDATE signing_keys SET status = 'retired' WHERE status = 'standby'")
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    sqlx::query("UPDATE signing_keys SET status = 'standby' WHERE status = 'primary'")
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    let (kid, public_pem, private_pem) = generate_key_pair()?;
    let storage = storage_values_for_private_key(cfg, &kid, private_pem)?;
    sqlx::query(
        r#"INSERT INTO signing_keys (
               kid,
               public_key,
               private_key,
               private_key_ciphertext,
               private_key_nonce,
               private_key_key_id,
               private_key_encryption_alg,
               status
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'primary')"#,
    )
    .bind(&kid)
    .bind(&public_pem)
    .bind(storage.plaintext)
    .bind(storage.ciphertext)
    .bind(storage.nonce)
    .bind(storage.key_id)
    .bind(storage.encryption_alg)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    tracing::info!("signing key rotated, new primary kid={kid}");

    load_active_keys(pool, cfg).await
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
    pool: &PgPool,
    cfg: &SigningKeyConfig,
) -> Result<u64, AppError> {
    use sqlx::Row;

    if cfg.key_encryption_key.is_none() {
        return Ok(0);
    }

    let rows = sqlx::query(
        r#"SELECT kid, private_key
           FROM signing_keys
           WHERE private_key IS NOT NULL
             AND private_key_ciphertext IS NULL"#,
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut encrypted = 0_u64;
    for row in rows {
        let kid: String = row.try_get("kid").map_err(db_err)?;
        let private_pem: String = row.try_get("private_key").map_err(db_err)?;
        let material = encrypt_private_key(cfg, &kid, &private_pem)?;
        sqlx::query(
            r#"UPDATE signing_keys
               SET private_key = NULL,
                   private_key_ciphertext = $2,
                   private_key_nonce = $3,
                   private_key_key_id = $4,
                   private_key_encryption_alg = $5
               WHERE kid = $1"#,
        )
        .bind(&kid)
        .bind(material.ciphertext)
        .bind(material.nonce)
        .bind(&cfg.key_encryption_key_id)
        .bind(SIGNING_KEY_ENCRYPTION_ALG)
        .execute(pool)
        .await
        .map_err(db_err)?;
        encrypted += 1;
    }

    if encrypted > 0 {
        tracing::info!("encrypted {encrypted} legacy plaintext signing keys");
    }
    Ok(encrypted)
}

pub async fn list_metadata(pool: &PgPool) -> Result<Vec<SigningKeyMetadata>, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT kid,
                  algorithm,
                  status,
                  created_at,
                  private_key IS NOT NULL AS has_plaintext,
                  private_key_ciphertext IS NOT NULL AS has_ciphertext,
                  private_key_key_id
           FROM signing_keys
           ORDER BY created_at DESC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(|row| {
            let has_ciphertext: bool = row.try_get("has_ciphertext").map_err(db_err)?;
            let has_plaintext: bool = row.try_get("has_plaintext").map_err(db_err)?;
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
                kid: row.try_get("kid").map_err(db_err)?,
                algorithm: row.try_get("algorithm").map_err(db_err)?,
                status: row.try_get("status").map_err(db_err)?,
                created_at: row.try_get("created_at").map_err(db_err)?,
                storage_mode,
                key_encryption_key_id: row.try_get("private_key_key_id").map_err(db_err)?,
            })
        })
        .collect()
}

pub async fn storage_summary(pool: &PgPool) -> Result<SigningKeyStorageSummary, AppError> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"SELECT COUNT(*)::bigint AS total,
                  COUNT(*) FILTER (WHERE private_key_ciphertext IS NOT NULL)::bigint AS encrypted,
                  COUNT(*) FILTER (WHERE private_key IS NOT NULL)::bigint AS plaintext
           FROM signing_keys"#,
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(SigningKeyStorageSummary {
        total: row.try_get("total").map_err(db_err)?,
        encrypted: row.try_get("encrypted").map_err(db_err)?,
        plaintext: row.try_get("plaintext").map_err(db_err)?,
    })
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
    require_capability(&state.pool, auth.entity_id, "rotate", Scope::Platform).await?;
    let new_keys = rotate(&state.pool, &state.config.signing_keys).await?;
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
