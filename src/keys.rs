use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    SecretKey,
};
use rand::rngs::OsRng;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::RequireManage,
    error::{db_err, AppError},
    state::AppState,
};

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
    let x = point.x().expect("uncompressed EC point always has x");
    let y = point.y().expect("uncompressed EC point always has y");
    Ok((URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)))
}

fn load_key_row(kid: String, public_pem: String, private_pem: String) -> Result<LoadedKey, AppError> {
    let (x_b64, y_b64) = coords_from_public_pem(&public_pem)?;
    Ok(LoadedKey {
        kid,
        public_key_pem: public_pem,
        private_key_pem: private_pem,
        x_b64,
        y_b64,
    })
}

// ─── Database operations ──────────────────────────────────────────────────────

/// Load primary and standby keys from the database into memory.
pub async fn load_active_keys(pool: &PgPool) -> Result<ActiveKeys, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT kid, public_key, private_key, status
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
        let private_pem: String = row.try_get("private_key").map_err(db_err)?;

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
pub async fn bootstrap_if_needed(pool: &PgPool) -> Result<(), AppError> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys WHERE status = 'primary'")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    if count == 0 {
        let (kid, public_pem, private_pem) = generate_key_pair()?;
        sqlx::query(
            "INSERT INTO signing_keys (kid, public_key, private_key, status) VALUES ($1, $2, $3, 'primary')",
        )
        .bind(&kid)
        .bind(&public_pem)
        .bind(&private_pem)
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
pub async fn rotate(pool: &PgPool) -> Result<ActiveKeys, AppError> {
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
    sqlx::query(
        "INSERT INTO signing_keys (kid, public_key, private_key, status) VALUES ($1, $2, $3, 'primary')",
    )
    .bind(&kid)
    .bind(&public_pem)
    .bind(&private_pem)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    tracing::info!("signing key rotated, new primary kid={kid}");

    load_active_keys(pool).await
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// GET /.well-known/jwks.json — unauthenticated, returns public keys.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let keys = state.keys.read().await;
    Json(keys.to_jwks())
}

/// POST /auth/keys/rotate — requires manage permission.
pub async fn rotate_keys(
    State(state): State<AppState>,
    _auth: RequireManage,
) -> Result<impl IntoResponse, AppError> {
    let new_keys = rotate(&state.pool).await?;
    *state.keys.write().await = new_keys;
    Ok(StatusCode::NO_CONTENT)
}
