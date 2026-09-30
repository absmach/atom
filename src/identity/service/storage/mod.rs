//! Typed identity persistence; credential policy, cryptography and transaction ownership stay in the service.
mod postgres;
mod sqlite;
use super::*;

#[derive(sqlx::FromRow)]
pub(super) struct EmailToken {
    pub(super) entity_id: Uuid,
    pub(super) email_id: Uuid,
    pub(super) secret_hash: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) consumed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct EmailOwner {
    pub(super) email_id: Uuid,
    pub(super) entity_id: Uuid,
}

#[derive(sqlx::FromRow)]
pub(super) struct EmailChangeToken {
    pub(super) entity_id: Uuid,
    pub(super) current_email: String,
    pub(super) new_email: String,
    pub(super) secret_hash: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) consumed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct EntityEmailMirror {
    pub(super) attributes: Value,
    pub(super) external_id: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(super) struct ExchangeCode {
    pub(super) entity_id: Uuid,
    pub(super) secret_hash: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) consumed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct EmailVerificationStatus {
    pub(super) email_count: i64,
    pub(super) any_verified: bool,
}

#[derive(sqlx::FromRow)]
pub(super) struct CanonicalLoginIdentity {
    pub(super) id: Uuid,
    pub(super) tenant_id: Option<Uuid>,
    pub(super) status: EntityStatus,
    pub(super) verified_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct StoredLoginIdentity {
    pub(super) id: Uuid,
    pub(super) tenant_id: Option<Uuid>,
    pub(super) status: EntityStatus,
}

#[derive(sqlx::FromRow)]
pub(super) struct SecretCredential {
    pub(super) id: Uuid,
    pub(super) secret_hash: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(super) struct StoredTenant {
    pub(super) id: Uuid,
    pub(super) status: String,
}

#[derive(sqlx::FromRow)]
pub(super) struct StoredOAuthState {
    pub(super) state_hash: String,
    pub(super) pkce_verifier: String,
    pub(super) nonce: String,
    pub(super) return_to: Option<String>,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) consumed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct OAuthEntity {
    pub(super) entity_id: Uuid,
}

#[derive(sqlx::FromRow)]
pub(super) struct OAuthEmail {
    pub(super) entity_id: Uuid,
    pub(super) verified_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct PasswordHashRecord {
    pub(super) secret_hash: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(super) struct RecoverableSharedKey {
    pub(super) expires_at: Option<DateTime<Utc>>,
    pub(super) status: CredentialStatus,
    pub(super) secret_hash: Option<String>,
    pub(super) secret_ciphertext: Option<Vec<u8>>,
    pub(super) secret_nonce: Option<Vec<u8>>,
    pub(super) entity_status: EntityStatus,
    pub(super) tenant_status: Option<crate::models::enums::TenantStatus>,
}

pub(super) async fn entity_tenant(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::entity_tenant(p, entity_id).await,
        Database::Sqlite(d) => sqlite::entity_tenant(&d.pool, entity_id).await,
    }
}

pub(super) async fn active_login_entity(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::active_login_entity(p, entity_id).await,
        Database::Sqlite(d) => sqlite::active_login_entity(&d.pool, entity_id).await,
    }
}

pub(super) async fn recent_failed_logins(
    pool: &Database,
    identifier: &str,
    tenant_id: Option<Uuid>,
    window_seconds: String,
) -> Result<i64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::recent_failed_logins(p, identifier, tenant_id, window_seconds).await
        }
        Database::Sqlite(d) => {
            sqlite::recent_failed_logins(&d.pool, identifier, tenant_id, window_seconds).await
        }
    }
}

pub(super) async fn record_login_attempt(
    pool: &Database,
    identifier: &str,
    tenant_id: Option<Uuid>,
    success: bool,
) -> Result<u64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::record_login_attempt(p, identifier, tenant_id, success).await
        }
        Database::Sqlite(d) => {
            sqlite::record_login_attempt(&d.pool, identifier, tenant_id, success).await
        }
    }
}

pub(super) async fn insert_signup_entity(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    kind: EntityKind,
    name: &str,
    attributes: &Value,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_signup_entity(c, entity_id, kind, name, attributes).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_signup_entity(c, entity_id, kind, name, attributes).await
        }
    }
}

pub(super) async fn insert_signup_email(
    conn: &mut DbTransaction<'_>,
    email_id: Uuid,
    entity_id: Uuid,
    email: &str,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_signup_email(c, email_id, entity_id, email).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_signup_email(c, email_id, entity_id, email).await
        }
    }
}

pub(super) async fn insert_signup_password(
    conn: &mut DbTransaction<'_>,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    email: &str,
    password_hash: &str,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_signup_password(
                c,
                credential_id,
                entity_id,
                kind,
                email,
                password_hash,
            )
            .await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_signup_password(c, credential_id, entity_id, kind, email, password_hash)
                .await
        }
    }
}

pub(super) async fn verification_token(
    pool: &Database,
    token_id: Uuid,
) -> Result<EmailToken, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::verification_token(p, token_id).await,
        Database::Sqlite(d) => sqlite::verification_token(&d.pool, token_id).await,
    }
}

pub(super) async fn consume_verification_token(
    conn: &mut DbTransaction<'_>,
    token_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::consume_verification_token(c, token_id).await,
        DbTransaction::Sqlite(c) => sqlite::consume_verification_token(c, token_id).await,
    }
}

pub(super) async fn verify_canonical_email(
    conn: &mut DbTransaction<'_>,
    email_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::verify_canonical_email(c, email_id).await,
        DbTransaction::Sqlite(c) => sqlite::verify_canonical_email(c, email_id).await,
    }
}

pub(super) async fn unverified_email_owner(
    pool: &Database,
    email: &str,
) -> Result<Option<EmailOwner>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::unverified_email_owner(p, email).await,
        Database::Sqlite(d) => sqlite::unverified_email_owner(&d.pool, email).await,
    }
}

pub(super) async fn insert_verification_token(
    pool: &Database,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::insert_verification_token(
                p, token_id, entity_id, email_id, token_hash, expires_at,
            )
            .await
        }
        Database::Sqlite(d) => {
            sqlite::insert_verification_token(
                &d.pool, token_id, entity_id, email_id, token_hash, expires_at,
            )
            .await
        }
    }
}

pub(super) async fn password_reset_email_owner(
    pool: &Database,
    email: &str,
) -> Result<Option<EmailOwner>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::password_reset_email_owner(p, email).await,
        Database::Sqlite(d) => sqlite::password_reset_email_owner(&d.pool, email).await,
    }
}

pub(super) async fn insert_password_reset_token(
    pool: &Database,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::insert_password_reset_token(
                p, token_id, entity_id, email_id, token_hash, expires_at,
            )
            .await
        }
        Database::Sqlite(d) => {
            sqlite::insert_password_reset_token(
                &d.pool, token_id, entity_id, email_id, token_hash, expires_at,
            )
            .await
        }
    }
}

pub(super) async fn password_reset_token(
    pool: &Database,
    token_id: Uuid,
) -> Result<EmailToken, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::password_reset_token(p, token_id).await,
        Database::Sqlite(d) => sqlite::password_reset_token(&d.pool, token_id).await,
    }
}

pub(super) async fn email_address(pool: &Database, email_id: Uuid) -> Result<String, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::email_address(p, email_id).await,
        Database::Sqlite(d) => sqlite::email_address(&d.pool, email_id).await,
    }
}

pub(super) async fn active_session_ids(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::active_session_ids(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::active_session_ids(c, entity_id).await,
    }
}

pub(super) async fn consume_password_reset_token(
    conn: &mut DbTransaction<'_>,
    token_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::consume_password_reset_token(c, token_id).await,
        DbTransaction::Sqlite(c) => sqlite::consume_password_reset_token(c, token_id).await,
    }
}

pub(super) async fn revoke_passwords(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::revoke_passwords(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::revoke_passwords(c, entity_id).await,
    }
}

pub(super) async fn insert_replacement_password(
    conn: &mut DbTransaction<'_>,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    email: &str,
    password_hash: String,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_replacement_password(
                c,
                credential_id,
                entity_id,
                kind,
                email,
                password_hash,
            )
            .await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_replacement_password(
                c,
                credential_id,
                entity_id,
                kind,
                email,
                password_hash,
            )
            .await
        }
    }
}

pub(super) async fn revoke_sessions(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::revoke_sessions(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::revoke_sessions(c, entity_id).await,
    }
}

pub(super) async fn invalidate_email_changes(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::invalidate_email_changes(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::invalidate_email_changes(c, entity_id).await,
    }
}

pub(super) async fn session_created_at(
    pool: &Database,
    session_id: Uuid,
) -> Result<DateTime<Utc>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::session_created_at(p, session_id).await,
        Database::Sqlite(d) => sqlite::session_created_at(&d.pool, session_id).await,
    }
}

pub(super) async fn current_email(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::current_email(p, entity_id).await,
        Database::Sqlite(d) => sqlite::current_email(&d.pool, entity_id).await,
    }
}

pub(super) async fn email_is_taken(pool: &Database, new_email: &str) -> Result<bool, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::email_is_taken(p, new_email).await,
        Database::Sqlite(d) => sqlite::email_is_taken(&d.pool, new_email).await,
    }
}

pub(super) async fn supersede_email_changes(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::supersede_email_changes(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::supersede_email_changes(c, entity_id).await,
    }
}

pub(super) struct InsertEmailChange<'a> {
    pub(super) token_id: Uuid,
    pub(super) entity_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) current_email: &'a str,
    pub(super) new_email: &'a str,
    pub(super) token_hash: &'a str,
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) async fn insert_email_change(
    conn: &mut DbTransaction<'_>,
    input: InsertEmailChange<'_>,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::insert_email_change(c, input).await,
        DbTransaction::Sqlite(c) => sqlite::insert_email_change(c, input).await,
    }
}

pub(super) async fn email_change_token(
    pool: &Database,
    token_id: Uuid,
) -> Result<EmailChangeToken, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::email_change_token(p, token_id).await,
        Database::Sqlite(d) => sqlite::email_change_token(&d.pool, token_id).await,
    }
}

pub(super) async fn lock_current_email(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::lock_current_email(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::lock_current_email(c, entity_id).await,
    }
}

pub(super) async fn consume_email_change(
    conn: &mut DbTransaction<'_>,
    token_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::consume_email_change(c, token_id).await,
        DbTransaction::Sqlite(c) => sqlite::consume_email_change(c, token_id).await,
    }
}

pub(super) async fn consume_other_email_changes(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::consume_other_email_changes(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::consume_other_email_changes(c, entity_id).await,
    }
}

pub(super) async fn entity_email_mirror(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<EntityEmailMirror, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::entity_email_mirror(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::entity_email_mirror(c, entity_id).await,
    }
}

pub(super) async fn email_collision(
    conn: &mut DbTransaction<'_>,
    new_email: &str,
    entity_id: Uuid,
) -> Result<bool, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::email_collision(c, new_email, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::email_collision(c, new_email, entity_id).await,
    }
}

pub(super) async fn change_canonical_email(
    conn: &mut DbTransaction<'_>,
    email_id: Uuid,
    new_email: &str,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::change_canonical_email(c, email_id, new_email).await
        }
        DbTransaction::Sqlite(c) => sqlite::change_canonical_email(c, email_id, new_email).await,
    }
}

pub(super) async fn change_password_identifier(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    new_email: &str,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::change_password_identifier(c, entity_id, new_email).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::change_password_identifier(c, entity_id, new_email).await
        }
    }
}

pub(super) async fn change_email_mirror(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    updated: Value,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::change_email_mirror(c, entity_id, updated).await,
        DbTransaction::Sqlite(c) => sqlite::change_email_mirror(c, entity_id, updated).await,
    }
}

pub(super) async fn email_change_sessions(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::email_change_sessions(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::email_change_sessions(c, entity_id).await,
    }
}

pub(super) async fn revoke_email_change_sessions(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::revoke_email_change_sessions(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::revoke_email_change_sessions(c, entity_id).await,
    }
}

pub(super) struct InsertOauthState<'a> {
    pub(super) state_id: Uuid,
    pub(super) name: &'a str,
    pub(super) state_hash: String,
    pub(super) pkce_verifier: &'a str,
    pub(super) nonce: &'a str,
    pub(super) return_to: Option<&'a str>,
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) async fn insert_oauth_state(
    pool: &Database,
    input: InsertOauthState<'_>,
) -> Result<u64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::insert_oauth_state(p, input).await,
        Database::Sqlite(d) => sqlite::insert_oauth_state(&d.pool, input).await,
    }
}

pub(super) async fn exchange_code(
    pool: &Database,
    code_id: Uuid,
) -> Result<ExchangeCode, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::exchange_code(p, code_id).await,
        Database::Sqlite(d) => sqlite::exchange_code(&d.pool, code_id).await,
    }
}

pub(super) async fn consume_exchange_code(
    pool: &Database,
    code_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::consume_exchange_code(p, code_id).await,
        Database::Sqlite(d) => sqlite::consume_exchange_code(&d.pool, code_id).await,
    }
}

pub(super) async fn email_verification_status(
    pool: &Database,
    entity_id: Uuid,
) -> Result<EmailVerificationStatus, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::email_verification_status(p, entity_id).await,
        Database::Sqlite(d) => sqlite::email_verification_status(&d.pool, entity_id).await,
    }
}

pub(super) async fn canonical_login_identity(
    pool: &Database,
    email: &str,
    tenant_id: Option<Uuid>,
) -> Result<Option<CanonicalLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::canonical_login_identity(p, email, tenant_id).await,
        Database::Sqlite(d) => sqlite::canonical_login_identity(&d.pool, email, tenant_id).await,
    }
}

pub(super) async fn legacy_login_identities(
    pool: &Database,
    email: &str,
    tenant_id: Option<Uuid>,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::legacy_login_identities(p, email, tenant_id).await,
        Database::Sqlite(d) => sqlite::legacy_login_identities(&d.pool, email, tenant_id).await,
    }
}

pub(super) async fn password_credential(
    pool: &Database,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
    identifier: Option<&str>,
) -> Result<Option<SecretCredential>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::password_credential(p, entity_id, kind, status, identifier).await
        }
        Database::Sqlite(d) => {
            sqlite::password_credential(&d.pool, entity_id, kind, status, identifier).await
        }
    }
}

pub(super) async fn shared_key_by_id(
    pool: &Database,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
) -> Result<Option<SecretCredential>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::shared_key_by_id(p, credential_id, entity_id, kind, status).await
        }
        Database::Sqlite(d) => {
            sqlite::shared_key_by_id(&d.pool, credential_id, entity_id, kind, status).await
        }
    }
}

pub(super) async fn shared_keys_by_digest(
    pool: &Database,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
    lookup_hash: &[u8],
) -> Result<Vec<SecretCredential>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::shared_keys_by_digest(p, entity_id, kind, status, lookup_hash).await
        }
        Database::Sqlite(d) => {
            sqlite::shared_keys_by_digest(&d.pool, entity_id, kind, status, lookup_hash).await
        }
    }
}

pub(super) async fn legacy_shared_keys(
    pool: &Database,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
) -> Result<Vec<SecretCredential>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::legacy_shared_keys(p, entity_id, kind, status).await,
        Database::Sqlite(d) => sqlite::legacy_shared_keys(&d.pool, entity_id, kind, status).await,
    }
}

pub(super) async fn login_entity_in_tenant(
    pool: &Database,
    entity_id: Uuid,
    tenant_id: Uuid,
) -> Result<Option<StoredLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::login_entity_in_tenant(p, entity_id, tenant_id).await,
        Database::Sqlite(d) => sqlite::login_entity_in_tenant(&d.pool, entity_id, tenant_id).await,
    }
}

pub(super) async fn login_entity_by_id(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<StoredLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::login_entity_by_id(p, entity_id).await,
        Database::Sqlite(d) => sqlite::login_entity_by_id(&d.pool, entity_id).await,
    }
}

pub(super) async fn login_entities_by_tenant_name(
    pool: &Database,
    identifier: &str,
    tenant_id: Uuid,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::login_entities_by_tenant_name(p, identifier, tenant_id).await
        }
        Database::Sqlite(d) => {
            sqlite::login_entities_by_tenant_name(&d.pool, identifier, tenant_id).await
        }
    }
}

pub(super) async fn login_entities_by_name(
    pool: &Database,
    identifier: &str,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::login_entities_by_name(p, identifier).await,
        Database::Sqlite(d) => sqlite::login_entities_by_name(&d.pool, identifier).await,
    }
}

pub(super) async fn login_entities_by_alias(
    pool: &Database,
    alias: String,
    tenant_id: Uuid,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::login_entities_by_alias(p, alias, tenant_id).await,
        Database::Sqlite(d) => sqlite::login_entities_by_alias(&d.pool, alias, tenant_id).await,
    }
}

pub(super) async fn login_tenant_by_id(
    pool: &Database,
    tenant_id: Uuid,
) -> Result<Option<StoredTenant>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::login_tenant_by_id(p, tenant_id).await,
        Database::Sqlite(d) => sqlite::login_tenant_by_id(&d.pool, tenant_id).await,
    }
}

pub(super) async fn login_tenant_by_alias(
    pool: &Database,
    tenant_alias: String,
) -> Result<Option<StoredTenant>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::login_tenant_by_alias(p, tenant_alias).await,
        Database::Sqlite(d) => sqlite::login_tenant_by_alias(&d.pool, tenant_alias).await,
    }
}

pub(super) async fn insert_email_token(
    conn: &mut DbTransaction<'_>,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_email_token(c, token_id, entity_id, email_id, token_hash, expires_at)
                .await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_email_token(c, token_id, entity_id, email_id, token_hash, expires_at)
                .await
        }
    }
}

pub(super) async fn oauth_state(
    pool: &Database,
    state_id: Uuid,
    provider: &str,
) -> Result<StoredOAuthState, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::oauth_state(p, state_id, provider).await,
        Database::Sqlite(d) => sqlite::oauth_state(&d.pool, state_id, provider).await,
    }
}

pub(super) async fn consume_oauth_state(
    pool: &Database,
    state_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::consume_oauth_state(p, state_id).await,
        Database::Sqlite(d) => sqlite::consume_oauth_state(&d.pool, state_id).await,
    }
}

pub(super) async fn linked_oauth_entity(
    conn: &mut DbTransaction<'_>,
    provider: &str,
    subject: &str,
) -> Result<Option<OAuthEntity>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::linked_oauth_entity(c, provider, subject).await,
        DbTransaction::Sqlite(c) => sqlite::linked_oauth_entity(c, provider, subject).await,
    }
}

pub(super) async fn update_oauth_identity(
    conn: &mut DbTransaction<'_>,
    provider: &str,
    subject: &str,
    email: &str,
    profile: Value,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::update_oauth_identity(c, provider, subject, email, profile).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::update_oauth_identity(c, provider, subject, email, profile).await
        }
    }
}

pub(super) async fn lock_oauth_email(
    conn: &mut DbTransaction<'_>,
    email: &str,
) -> Result<Option<OAuthEmail>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::lock_oauth_email(c, email).await,
        DbTransaction::Sqlite(c) => sqlite::lock_oauth_email(c, email).await,
    }
}

pub(super) async fn insert_oauth_entity(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    kind: EntityKind,
    name: &str,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::insert_oauth_entity(c, entity_id, kind, name).await,
        DbTransaction::Sqlite(c) => sqlite::insert_oauth_entity(c, entity_id, kind, name).await,
    }
}

pub(super) async fn insert_verified_oauth_email(
    conn: &mut DbTransaction<'_>,
    email_id: Uuid,
    entity_id: Uuid,
    email: &str,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_verified_oauth_email(c, email_id, entity_id, email).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_verified_oauth_email(c, email_id, entity_id, email).await
        }
    }
}

pub(super) struct InsertOauthIdentity<'a> {
    pub(super) id: Uuid,
    pub(super) entity_id: Uuid,
    pub(super) provider: &'a str,
    pub(super) subject: &'a str,
    pub(super) email: &'a str,
    pub(super) profile: Value,
}

pub(super) async fn insert_oauth_identity(
    conn: &mut DbTransaction<'_>,
    input: InsertOauthIdentity<'_>,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::insert_oauth_identity(c, input).await,
        DbTransaction::Sqlite(c) => sqlite::insert_oauth_identity(c, input).await,
    }
}

pub(super) async fn insert_exchange_code(
    conn: &mut DbTransaction<'_>,
    code_id: Uuid,
    entity_id: Uuid,
    code_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_exchange_code(c, code_id, entity_id, code_hash, expires_at).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_exchange_code(c, code_id, entity_id, code_hash, expires_at).await
        }
    }
}

pub(super) async fn insert_password(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    hash: String,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::insert_password(c, id, entity_id, kind, hash).await,
        DbTransaction::Sqlite(c) => sqlite::insert_password(c, id, entity_id, kind, hash).await,
    }
}

pub(super) async fn active_password_hashes(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
) -> Result<Vec<PasswordHashRecord>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::active_password_hashes(c, entity_id, kind, status).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::active_password_hashes(c, entity_id, kind, status).await
        }
    }
}

pub(super) async fn password_identifier(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::password_identifier(c, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::password_identifier(c, entity_id).await,
    }
}

pub(super) async fn revoke_unmanaged_passwords(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
    status4: CredentialStatus,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::revoke_unmanaged_passwords(c, entity_id, kind, status, status4).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::revoke_unmanaged_passwords(c, entity_id, kind, status, status4).await
        }
    }
}

pub(super) async fn insert_changed_password(
    conn: &mut DbTransaction<'_>,
    id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    identifier: Option<String>,
    hash: String,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => {
            postgres::insert_changed_password(c, id, entity_id, kind, identifier, hash).await
        }
        DbTransaction::Sqlite(c) => {
            sqlite::insert_changed_password(c, id, entity_id, kind, identifier, hash).await
        }
    }
}

pub(super) struct InsertSharedKey<'a> {
    pub(super) cred_id: Uuid,
    pub(super) entity_id: Uuid,
    pub(super) kind: CredentialKind,
    pub(super) hash: String,
    pub(super) ciphertext: Vec<u8>,
    pub(super) nonce: Vec<u8>,
    pub(super) key_encryption_key_id: &'a str,
    pub(super) encryption_algorithm: &'a str,
    pub(super) lookup_hash: Vec<u8>,
    pub(super) expires_at: Option<DateTime<Utc>>,
    pub(super) metadata: Value,
}

pub(super) async fn insert_shared_key(
    conn: &mut DbTransaction<'_>,
    input: InsertSharedKey<'_>,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::insert_shared_key(c, input).await,
        DbTransaction::Sqlite(c) => sqlite::insert_shared_key(c, input).await,
    }
}

pub(super) async fn lock_managed_credential(
    conn: &mut DbTransaction<'_>,
    entity_id: Uuid,
    kind: CredentialKind,
) -> Result<Option<Uuid>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::lock_managed_credential(c, entity_id, kind).await,
        DbTransaction::Sqlite(c) => sqlite::lock_managed_credential(c, entity_id, kind).await,
    }
}

pub(super) async fn reveal_shared_key(
    pool: &Database,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
) -> Result<RecoverableSharedKey, sqlx::Error> {
    match pool {
        Database::Postgres(p) => {
            postgres::reveal_shared_key(p, credential_id, entity_id, kind).await
        }
        Database::Sqlite(d) => {
            sqlite::reveal_shared_key(&d.pool, credential_id, entity_id, kind).await
        }
    }
}

pub(super) async fn lock_credential_owner(
    conn: &mut DbTransaction<'_>,
    cred_id: Uuid,
    entity_id: Uuid,
) -> Result<Option<(String, Option<String>)>, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::lock_credential_owner(c, cred_id, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::lock_credential_owner(c, cred_id, entity_id).await,
    }
}

pub(super) async fn revoke_credential(
    conn: &mut DbTransaction<'_>,
    cred_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match conn {
        DbTransaction::Postgres(c) => postgres::revoke_credential(c, cred_id, entity_id).await,
        DbTransaction::Sqlite(c) => sqlite::revoke_credential(c, cred_id, entity_id).await,
    }
}

pub(super) async fn credentials(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<CredentialSummary>, sqlx::Error> {
    match pool {
        Database::Postgres(p) => postgres::credentials(p, entity_id).await,
        Database::Sqlite(d) => sqlite::credentials(&d.pool, entity_id).await,
    }
}
