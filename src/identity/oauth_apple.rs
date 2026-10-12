//! Apple ID tokens use string booleans that the generic OIDC claims parser rejects.
use crate::{
    config::{Config, OidcProviderConfig},
    error::AppError,
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Token {
    id_token: String,
}
#[derive(Deserialize)]
struct Claims {
    iat: i64,
    sub: String,
    nonce: String,
    email: String,
    email_verified: Value,
}

pub(super) async fn exchange(
    cfg: &Config,
    provider: &OidcProviderConfig,
    code: &str,
    nonce: &str,
) -> Result<(String, String), AppError> {
    let client = super::service::oidc_http_client()?;
    let refused = |_| AppError::unauthorized("Apple authentication failed");
    let issuer = provider.issuer.trim_end_matches('/');
    let callback = format!(
        "{}/auth/oauth/apple/callback",
        cfg.public_base_url.trim_end_matches('/')
    );
    let token: Token = client
        .post(format!("{issuer}/auth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", provider.client_id.as_str()),
            ("client_secret", provider.client_secret.as_str()),
            ("redirect_uri", callback.as_str()),
            ("code", code),
        ])
        .send()
        .await
        .map_err(refused)?
        .error_for_status()
        .map_err(refused)?
        .json()
        .await
        .map_err(refused)?;
    let jwks: JwkSet = client
        .get(format!("{issuer}/auth/keys"))
        .send()
        .await
        .map_err(refused)?
        .error_for_status()
        .map_err(refused)?
        .json()
        .await
        .map_err(refused)?;
    verify(&token.id_token, &jwks, provider, nonce)
}

fn verify(
    token: &str,
    jwks: &JwkSet,
    provider: &OidcProviderConfig,
    nonce: &str,
) -> Result<(String, String), AppError> {
    let refused = || AppError::unauthorized("invalid Apple ID token");
    let header = decode_header(token).map_err(|_| refused())?;
    if header.alg != Algorithm::RS256 {
        return Err(refused());
    }
    let kid = header.kid.ok_or_else(refused)?;
    let jwk = jwks.find(&kid).ok_or_else(refused)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| refused())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 0;
    validation.validate_nbf = true;
    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(|_| refused())?
        .claims;
    if claims.iat > chrono::Utc::now().timestamp() + 60
        || claims.nonce != nonce
        || claims.sub.is_empty()
        || !(claims.email_verified == Value::Bool(true)
            || claims.email_verified == Value::String("true".into()))
    {
        return Err(refused());
    }
    let email = claims.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(refused());
    }
    Ok((claims.sub, email))
}
