use super::*;

pub(super) async fn entity_tenant(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<Uuid>>(r#"SELECT tenant_id FROM entities WHERE id = $1"#)
        .bind(entity_id)
        .fetch_optional(pool)
        .await
}

pub(super) async fn active_login_entity(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT e.id
           FROM entities e
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE e.id = $1
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND (e.tenant_id IS NULL OR (t.deleted_at IS NULL AND t.status = 'active'))"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn recent_failed_logins(
    pool: &sqlx::PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
    window_seconds: String,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)
           FROM auth_login_attempts
           WHERE identifier = $1
             AND (($2::uuid IS NULL AND tenant_id IS NULL) OR tenant_id = $2)
             AND success = FALSE
             AND created_at >= now() - ($3::text || ' seconds')::interval"#,
    )
    .bind(identifier)
    .bind(tenant_id)
    .bind(window_seconds)
    .fetch_one(pool)
    .await
}

pub(super) async fn record_login_attempt(
    pool: &sqlx::PgPool,
    identifier: &str,
    tenant_id: Option<Uuid>,
    success: bool,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO auth_login_attempts (identifier, tenant_id, success)
           VALUES ($1, $2, $3)"#,
    )
    .bind(identifier)
    .bind(tenant_id)
    .bind(success)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_signup_entity(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    kind: EntityKind,
    name: &str,
    attributes: &Value,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, tenant_id, attributes)
           VALUES ($1, $2, $3, NULL, $4)"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(name)
    .bind(attributes)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_signup_email(
    conn: &mut sqlx::PgConnection,
    email_id: Uuid,
    entity_id: Uuid,
    email: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO entity_emails (id, entity_id, email)
           VALUES ($1, $2, $3)"#,
    )
    .bind(email_id)
    .bind(entity_id)
    .bind(email)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_signup_password(
    conn: &mut sqlx::PgConnection,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    email: &str,
    password_hash: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(kind)
    .bind(email)
    .bind(password_hash)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn verification_token(
    pool: &sqlx::PgPool,
    token_id: Uuid,
) -> Result<EmailToken, sqlx::Error> {
    sqlx::query_as::<_, EmailToken>(
        r#"SELECT entity_id, email_id, secret_hash, expires_at, consumed_at
           FROM email_verification_tokens
           WHERE id = $1"#,
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
}

pub(super) async fn consume_verification_token(
    conn: &mut sqlx::PgConnection,
    token_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE email_verification_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL"#).bind(token_id).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn verify_canonical_email(
    conn: &mut sqlx::PgConnection,
    email_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE entity_emails SET verified_at = now(), updated_at = now() WHERE id = $1"#)
        .bind(email_id)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
}

pub(super) async fn unverified_email_owner(
    pool: &sqlx::PgPool,
    email: &str,
) -> Result<Option<EmailOwner>, sqlx::Error> {
    sqlx::query_as::<_, EmailOwner>(
        r#"SELECT ee.id AS email_id, ee.entity_id
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE ee.email = $1
             AND ee.verified_at IS NULL
             AND e.kind = 'human'
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))"#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub(super) async fn insert_verification_token(
    pool: &sqlx::PgPool,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO email_verification_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn password_reset_email_owner(
    pool: &sqlx::PgPool,
    email: &str,
) -> Result<Option<EmailOwner>, sqlx::Error> {
    sqlx::query_as::<_, EmailOwner>(
        r#"SELECT ee.id AS email_id, ee.entity_id
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE ee.email = $1
             AND e.kind = 'human'
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))
             AND NOT EXISTS (
                   SELECT 1
                   FROM credentials c
                   WHERE c.entity_id = e.id
                     AND c.kind = 'password'
                     AND c.status = 'active'
                     AND c.managed_by = 'config'
             )"#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub(super) async fn insert_password_reset_token(
    pool: &sqlx::PgPool,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO password_reset_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn password_reset_token(
    pool: &sqlx::PgPool,
    token_id: Uuid,
) -> Result<EmailToken, sqlx::Error> {
    sqlx::query_as::<_, EmailToken>(
        r#"SELECT entity_id, email_id, secret_hash, expires_at, consumed_at
           FROM password_reset_tokens
           WHERE id = $1"#,
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
}

pub(super) async fn email_address(
    pool: &sqlx::PgPool,
    email_id: Uuid,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar::<_, String>(r#"SELECT email FROM entity_emails WHERE id = $1"#)
        .bind(email_id)
        .fetch_one(pool)
        .await
}

pub(super) async fn active_session_ids(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id FROM sessions WHERE entity_id = $1 AND revoked_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn consume_password_reset_token(
    conn: &mut sqlx::PgConnection,
    token_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL"#).bind(token_id).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn revoke_passwords(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE credentials
           SET status = 'revoked'
           WHERE entity_id = $1 AND kind = 'password' AND status = 'active'"#,
    )
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_replacement_password(
    conn: &mut sqlx::PgConnection,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    email: &str,
    password_hash: String,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(kind)
    .bind(email)
    .bind(password_hash)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn revoke_sessions(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE sessions SET revoked_at = now() WHERE entity_id = $1 AND revoked_at IS NULL"#,
    )
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn invalidate_email_changes(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE email_change_tokens SET consumed_at = now() WHERE entity_id = $1 AND consumed_at IS NULL"#).bind(entity_id).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn session_created_at(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Result<DateTime<Utc>, sqlx::Error> {
    sqlx::query_scalar::<_, DateTime<Utc>>(r#"SELECT created_at FROM sessions WHERE id = $1"#)
        .bind(session_id)
        .fetch_one(pool)
        .await
}

pub(super) async fn current_email(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT email FROM entity_emails WHERE entity_id = $1 AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn email_is_taken(
    pool: &sqlx::PgPool,
    new_email: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (SELECT 1 FROM entity_emails WHERE email = $1 AND deleted_at IS NULL)"#,
    )
    .bind(new_email)
    .fetch_one(pool)
    .await
}

pub(super) async fn supersede_email_changes(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE email_change_tokens SET consumed_at = now() WHERE entity_id = $1 AND consumed_at IS NULL"#).bind(entity_id).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn insert_email_change(
    conn: &mut sqlx::PgConnection,
    input: InsertEmailChange<'_>,
) -> Result<u64, sqlx::Error> {
    let InsertEmailChange {
        token_id,
        entity_id,
        session_id,
        current_email,
        new_email,
        token_hash,
        expires_at,
    } = input;
    sqlx::query(
        r#"INSERT INTO email_change_tokens
             (id, entity_id, session_id, current_email, new_email, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(session_id)
    .bind(current_email)
    .bind(new_email)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn email_change_token(
    pool: &sqlx::PgPool,
    token_id: Uuid,
) -> Result<EmailChangeToken, sqlx::Error> {
    sqlx::query_as::<_, EmailChangeToken>(
        r#"SELECT entity_id, current_email, new_email, secret_hash, expires_at, consumed_at
           FROM email_change_tokens
           WHERE id = $1"#,
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
}

pub(super) async fn lock_current_email(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String)>(r#"SELECT id, email FROM entity_emails WHERE entity_id = $1 AND deleted_at IS NULL FOR UPDATE"#).bind(entity_id).fetch_optional(&mut *conn).await
}

pub(super) async fn consume_email_change(
    conn: &mut sqlx::PgConnection,
    token_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE email_change_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL"#).bind(token_id).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn consume_other_email_changes(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE email_change_tokens SET consumed_at = now() WHERE entity_id = $1 AND consumed_at IS NULL"#).bind(entity_id).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn entity_email_mirror(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<EntityEmailMirror, sqlx::Error> {
    sqlx::query_as::<_, EntityEmailMirror>(
        r#"SELECT attributes, external_id FROM entities WHERE id = $1"#,
    )
    .bind(entity_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn email_collision(
    conn: &mut sqlx::PgConnection,
    new_email: &str,
    entity_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
             SELECT 1 FROM entity_emails
             WHERE lower(email) = lower($1) AND deleted_at IS NULL AND entity_id != $2
         )"#,
    )
    .bind(new_email)
    .bind(entity_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn change_canonical_email(
    conn: &mut sqlx::PgConnection,
    email_id: Uuid,
    new_email: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE entity_emails SET email = $2, verified_at = now(), updated_at = now() WHERE id = $1"#).bind(email_id).bind(new_email).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn change_password_identifier(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    new_email: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE credentials SET identifier = $2 WHERE entity_id = $1 AND kind = 'password' AND status = 'active'"#).bind(entity_id).bind(new_email).execute(&mut *conn).await.map(|r|r.rows_affected())
}

pub(super) async fn change_email_mirror(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    updated: Value,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE entities SET attributes = $2, updated_at = now() WHERE id = $1"#)
        .bind(entity_id)
        .bind(updated)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
}

pub(super) async fn email_change_sessions(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id FROM sessions WHERE entity_id = $1 AND revoked_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn revoke_email_change_sessions(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE sessions SET revoked_at = now() WHERE entity_id = $1 AND revoked_at IS NULL"#,
    )
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_oauth_state(
    pool: &sqlx::PgPool,
    input: InsertOauthState<'_>,
) -> Result<u64, sqlx::Error> {
    let InsertOauthState {
        state_id,
        name,
        state_hash,
        pkce_verifier,
        nonce,
        return_to,
        expires_at,
    } = input;
    sqlx::query(
        r#"INSERT INTO oauth_login_states
             (id, provider, state_hash, pkce_verifier, nonce, return_to, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(state_id)
    .bind(name)
    .bind(state_hash)
    .bind(pkce_verifier)
    .bind(nonce)
    .bind(return_to)
    .bind(expires_at)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn exchange_code(
    pool: &sqlx::PgPool,
    code_id: Uuid,
) -> Result<ExchangeCode, sqlx::Error> {
    sqlx::query_as::<_, ExchangeCode>(
        r#"SELECT entity_id, secret_hash, expires_at, consumed_at
           FROM auth_exchange_codes
           WHERE id = $1"#,
    )
    .bind(code_id)
    .fetch_one(pool)
    .await
}

pub(super) async fn consume_exchange_code(
    pool: &sqlx::PgPool,
    code_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE auth_exchange_codes SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL"#).bind(code_id).execute(pool).await.map(|r|r.rows_affected())
}

pub(super) async fn email_verification_status(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<EmailVerificationStatus, sqlx::Error> {
    sqlx::query_as::<_, EmailVerificationStatus>(
        r#"SELECT COUNT(*) AS email_count,
                  COALESCE(bool_or(verified_at IS NOT NULL), false) AS any_verified
           FROM entity_emails
           WHERE entity_id = $1"#,
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
}

pub(super) async fn canonical_login_identity(
    pool: &sqlx::PgPool,
    email: &str,
    tenant_id: Option<Uuid>,
) -> Result<Option<CanonicalLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, CanonicalLoginIdentity>(
        r#"SELECT e.id, e.tenant_id, e.status, ee.verified_at
           FROM entity_emails ee
           JOIN entities e ON e.id = ee.entity_id
           WHERE ee.email = $1
             AND ee.deleted_at IS NULL
             AND e.deleted_at IS NULL
             AND ($2::uuid IS NULL OR e.tenant_id = $2)"#,
    )
    .bind(email)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn legacy_login_identities(
    pool: &sqlx::PgPool,
    email: &str,
    tenant_id: Option<Uuid>,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, StoredLoginIdentity>(
        r#"SELECT e.id, e.tenant_id, e.status
           FROM entities e
           WHERE lower(btrim(e.attributes->>'email')) = $1
             AND e.deleted_at IS NULL
             AND ($2::uuid IS NULL OR e.tenant_id = $2)
           LIMIT 2"#,
    )
    .bind(email)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub(super) async fn password_credential(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
    identifier: Option<&str>,
) -> Result<Option<SecretCredential>, sqlx::Error> {
    sqlx::query_as::<_, SecretCredential>(
        r#"SELECT id, secret_hash
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND status = $3
             AND ($4::text IS NULL OR identifier = $4 OR identifier IS NULL)
           ORDER BY
             CASE
               WHEN $4::text IS NOT NULL AND identifier = $4 THEN 0
               WHEN identifier IS NULL THEN 1
               ELSE 2
             END,
             created_at DESC
           LIMIT 1"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(status)
    .bind(identifier)
    .fetch_optional(pool)
    .await
}

pub(super) async fn shared_key_by_id(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
) -> Result<Option<SecretCredential>, sqlx::Error> {
    sqlx::query_as::<_, SecretCredential>(
        r#"SELECT c.id, c.secret_hash
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.id = $1
             AND c.entity_id = $2
             AND c.kind = $3
             AND c.status = $4
             AND e.kind <> 'human'
             AND (c.expires_at IS NULL OR c.expires_at > now())"#,
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(kind)
    .bind(status)
    .fetch_optional(pool)
    .await
}

pub(super) async fn shared_keys_by_digest(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
    lookup_hash: &[u8],
) -> Result<Vec<SecretCredential>, sqlx::Error> {
    sqlx::query_as::<_, SecretCredential>(
        r#"SELECT c.id, c.secret_hash
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.entity_id = $1
             AND c.kind = $2
             AND c.status = $3
             AND c.secret_lookup_hash = $4
             AND e.kind <> 'human'
             AND (c.expires_at IS NULL OR c.expires_at > now())
           ORDER BY c.created_at DESC"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(status)
    .bind(lookup_hash)
    .fetch_all(pool)
    .await
}

pub(super) async fn legacy_shared_keys(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
) -> Result<Vec<SecretCredential>, sqlx::Error> {
    sqlx::query_as::<_, SecretCredential>(
        r#"SELECT c.id, c.secret_hash
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.entity_id = $1
             AND c.kind = $2
             AND c.status = $3
             AND c.secret_lookup_hash IS NULL
             AND e.kind <> 'human'
             AND (c.expires_at IS NULL OR c.expires_at > now())
           ORDER BY c.created_at DESC"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(status)
    .fetch_all(pool)
    .await
}

pub(super) async fn login_entity_in_tenant(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
    tenant_id: Uuid,
) -> Result<Option<StoredLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, StoredLoginIdentity>(
        r#"SELECT id, tenant_id, status
                     FROM entities
                     WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn login_entity_by_id(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Option<StoredLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, StoredLoginIdentity>(
        r#"SELECT id, tenant_id, status
                         FROM entities
                         WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn login_entities_by_tenant_name(
    pool: &sqlx::PgPool,
    identifier: &str,
    tenant_id: Uuid,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, StoredLoginIdentity>(
        r#"SELECT id, tenant_id, status
                 FROM entities
                 WHERE name = $1 AND tenant_id = $2 AND deleted_at IS NULL"#,
    )
    .bind(identifier)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub(super) async fn login_entities_by_name(
    pool: &sqlx::PgPool,
    identifier: &str,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, StoredLoginIdentity>(
        r#"SELECT id, tenant_id, status
                 FROM entities
                 WHERE name = $1 AND deleted_at IS NULL
                 LIMIT 2"#,
    )
    .bind(identifier)
    .fetch_all(pool)
    .await
}

pub(super) async fn login_entities_by_alias(
    pool: &sqlx::PgPool,
    alias: String,
    tenant_id: Uuid,
) -> Result<Vec<StoredLoginIdentity>, sqlx::Error> {
    sqlx::query_as::<_, StoredLoginIdentity>(
        r#"SELECT id, tenant_id, status
                 FROM entities
                 WHERE lower(alias) = $1 AND tenant_id = $2 AND deleted_at IS NULL"#,
    )
    .bind(alias)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub(super) async fn login_tenant_by_id(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
) -> Result<Option<StoredTenant>, sqlx::Error> {
    sqlx::query_as::<_, StoredTenant>(
        r#"SELECT id, status FROM tenants WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
}

pub(super) async fn login_tenant_by_alias(
    pool: &sqlx::PgPool,
    tenant_alias: String,
) -> Result<Option<StoredTenant>, sqlx::Error> {
    sqlx::query_as::<_, StoredTenant>(
        r#"SELECT id, status
                 FROM tenants
                 WHERE lower(alias) = $1 AND deleted_at IS NULL"#,
    )
    .bind(tenant_alias)
    .fetch_optional(pool)
    .await
}

pub(super) async fn insert_email_token(
    conn: &mut sqlx::PgConnection,
    token_id: Uuid,
    entity_id: Uuid,
    email_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO email_verification_tokens
             (id, entity_id, email_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(token_id)
    .bind(entity_id)
    .bind(email_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn oauth_state(
    pool: &sqlx::PgPool,
    state_id: Uuid,
    provider: &str,
) -> Result<StoredOAuthState, sqlx::Error> {
    sqlx::query_as::<_, StoredOAuthState>(
        r#"SELECT state_hash, pkce_verifier, nonce, return_to, expires_at, consumed_at
           FROM oauth_login_states
           WHERE id = $1 AND provider = $2"#,
    )
    .bind(state_id)
    .bind(provider)
    .fetch_one(pool)
    .await
}

pub(super) async fn consume_oauth_state(
    pool: &sqlx::PgPool,
    state_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"UPDATE oauth_login_states SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL"#).bind(state_id).execute(pool).await.map(|r|r.rows_affected())
}

pub(super) async fn linked_oauth_entity(
    conn: &mut sqlx::PgConnection,
    provider: &str,
    subject: &str,
) -> Result<Option<OAuthEntity>, sqlx::Error> {
    sqlx::query_as::<_, OAuthEntity>(
        r#"SELECT entity_id FROM oauth_identities WHERE provider = $1 AND subject = $2"#,
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn update_oauth_identity(
    conn: &mut sqlx::PgConnection,
    provider: &str,
    subject: &str,
    email: &str,
    profile: Value,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE oauth_identities
               SET email = $3, email_verified = true, profile = $4, updated_at = now()
               WHERE provider = $1 AND subject = $2"#,
    )
    .bind(provider)
    .bind(subject)
    .bind(email)
    .bind(profile)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn lock_oauth_email(
    conn: &mut sqlx::PgConnection,
    email: &str,
) -> Result<Option<OAuthEmail>, sqlx::Error> {
    sqlx::query_as::<_, OAuthEmail>(
        r#"SELECT ee.entity_id, ee.verified_at
         FROM entity_emails ee
         JOIN entities e ON e.id = ee.entity_id
         WHERE ee.email = $1 AND ee.deleted_at IS NULL
         FOR UPDATE OF e, ee"#,
    )
    .bind(email)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn insert_oauth_entity(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    kind: EntityKind,
    name: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO entities (id, kind, name, tenant_id, attributes)
                   VALUES ($1, $2, $3, NULL, '{}')"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(name)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_verified_oauth_email(
    conn: &mut sqlx::PgConnection,
    email_id: Uuid,
    entity_id: Uuid,
    email: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO entity_emails (id, entity_id, email, verified_at)
                   VALUES ($1, $2, $3, now())"#,
    )
    .bind(email_id)
    .bind(entity_id)
    .bind(email)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_oauth_identity(
    conn: &mut sqlx::PgConnection,
    input: InsertOauthIdentity<'_>,
) -> Result<u64, sqlx::Error> {
    let InsertOauthIdentity {
        id,
        entity_id,
        provider,
        subject,
        email,
        profile,
    } = input;
    sqlx::query(
        r#"INSERT INTO oauth_identities
             (id, entity_id, provider, subject, email, email_verified, profile)
           VALUES ($1, $2, $3, $4, $5, true, $6)"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(provider)
    .bind(subject)
    .bind(email)
    .bind(profile)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_exchange_code(
    conn: &mut sqlx::PgConnection,
    code_id: Uuid,
    entity_id: Uuid,
    code_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO auth_exchange_codes (id, entity_id, secret_hash, expires_at)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(code_id)
    .bind(entity_id)
    .bind(code_hash)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_password(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    hash: String,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(kind)
    .bind(hash)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn active_password_hashes(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
) -> Result<Vec<PasswordHashRecord>, sqlx::Error> {
    sqlx::query_as::<_, PasswordHashRecord>(
        r#"SELECT secret_hash
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND status = $3"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(status)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn password_identifier(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT email
           FROM entity_emails
           WHERE entity_id = $1 AND deleted_at IS NULL
           ORDER BY verified_at DESC NULLS LAST, created_at DESC
           LIMIT 1"#,
    )
    .bind(entity_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn revoke_unmanaged_passwords(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    kind: CredentialKind,
    status: CredentialStatus,
    status4: CredentialStatus,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE credentials
           SET status = $3
           WHERE entity_id = $1
             AND kind = $2
             AND status = $4
             AND managed_by IS DISTINCT FROM 'config'"#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(status)
    .bind(status4)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_changed_password(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
    identifier: Option<String>,
    hash: String,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO credentials (id, entity_id, kind, identifier, secret_hash)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(kind)
    .bind(identifier)
    .bind(hash)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn insert_shared_key(
    conn: &mut sqlx::PgConnection,
    input: InsertSharedKey<'_>,
) -> Result<u64, sqlx::Error> {
    let InsertSharedKey {
        cred_id,
        entity_id,
        kind,
        hash,
        ciphertext,
        nonce,
        key_encryption_key_id,
        encryption_algorithm,
        lookup_hash,
        expires_at,
        metadata,
    } = input;
    sqlx::query(
        r#"INSERT INTO credentials
             (id, entity_id, kind, secret_hash,
              secret_ciphertext, secret_nonce, secret_key_id, secret_enc_alg,
              secret_lookup_hash, expires_at, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .bind(kind)
    .bind(hash)
    .bind(ciphertext)
    .bind(nonce)
    .bind(key_encryption_key_id)
    .bind(encryption_algorithm)
    .bind(lookup_hash)
    .bind(expires_at)
    .bind(metadata)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn lock_managed_credential(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    kind: CredentialKind,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id
           FROM credentials
           WHERE entity_id = $1
             AND kind = $2
             AND status = 'active'
             AND managed_by = 'config'
           ORDER BY id
           LIMIT 1
           FOR UPDATE"#,
    )
    .bind(entity_id)
    .bind(kind)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn reveal_shared_key(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
    entity_id: Uuid,
    kind: CredentialKind,
) -> Result<RecoverableSharedKey, sqlx::Error> {
    sqlx::query_as::<_, RecoverableSharedKey>(
        r#"SELECT c.expires_at,
                  c.status,
                  c.secret_hash,
                  c.secret_ciphertext,
                  c.secret_nonce,
                  e.status AS entity_status,
                  t.status AS tenant_status
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           LEFT JOIN tenants t ON t.id = e.tenant_id
           WHERE c.id = $1
             AND c.entity_id = $2
             AND c.kind = $3
             AND c.managed_by IS NULL
             AND e.kind <> 'human'
             AND e.deleted_at IS NULL
             AND (t.id IS NULL OR t.deleted_at IS NULL)
           FOR SHARE OF c"#,
    )
    .bind(credential_id)
    .bind(entity_id)
    .bind(kind)
    .fetch_one(pool)
    .await
}

pub(super) async fn lock_credential_owner(
    conn: &mut sqlx::PgConnection,
    cred_id: Uuid,
    entity_id: Uuid,
) -> Result<Option<(String, Option<String>)>, sqlx::Error> {
    sqlx::query_as::<_, (String, Option<String>)>(
        r#"SELECT kind, managed_by FROM credentials
         WHERE id = $1 AND entity_id = $2
         FOR UPDATE"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn revoke_credential(
    conn: &mut sqlx::PgConnection,
    cred_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"UPDATE credentials
           SET status = 'revoked',
               metadata = metadata - 'revoked_at' - 'revocation_reason'
                          || jsonb_build_object(
                              'revoked_at', now(),
                              'revocation_reason', 'manual'
                          )
           WHERE id = $1 AND entity_id = $2"#,
    )
    .bind(cred_id)
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

pub(super) async fn credentials(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Vec<CredentialSummary>, sqlx::Error> {
    sqlx::query_as::<_, CredentialSummary>(
        r#"SELECT id, kind, identifier, status, expires_at, created_at, managed_by
         FROM credentials
         WHERE entity_id = $1
         ORDER BY created_at DESC"#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
}
