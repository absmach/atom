//! Upgrade coverage for certificate credentials that predate issuer_id.
//!
//! Run with a disposable PostgreSQL database:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m45_pki_legacy_certificate_migration -- --ignored
//! ```

use std::{borrow::Cow, path::Path};

use atom::{
    certs::service::{self, ResolveCertificateV2},
    error::AppError,
};
use ring::digest;
use sqlx::{migrate::Migrator, Connection, Executor, PgConnection, PgPool};
use url::Url;
use uuid::Uuid;

const PRE_PKI_MIGRATION_VERSION: i64 = 10;

#[tokio::test]
#[ignore]
async fn migration_preserves_and_marks_pre_authority_certificate_credentials() {
    let admin_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let scratch = format!("atom_m45_{}", Uuid::new_v4().simple());
    let scratch_url = database_url_with_name(&admin_url, &scratch).expect("scratch database URL");

    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("connect for scratch database");
    admin
        .execute(format!(r#"CREATE DATABASE "{scratch}""#).as_str())
        .await
        .expect("create scratch database");

    let result = seed_and_migrate(&scratch_url).await;

    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)"#).as_str())
        .await;
    admin.close().await.expect("close admin connection");
    result.expect("legacy certificates survive the authority migration");
}

async fn seed_and_migrate(scratch_url: &str) -> Result<(), String> {
    let mut conn = PgConnection::connect(scratch_url)
        .await
        .map_err(|error| format!("connect scratch: {error}"))?;

    let migrator = Migrator::new(Path::new("./migrations"))
        .await
        .map_err(|error| format!("load migrations: {error}"))?;
    let pre_pki_migrations = migrator
        .iter()
        .filter(|migration| migration.version <= PRE_PKI_MIGRATION_VERSION)
        .cloned()
        .collect::<Vec<_>>();
    if pre_pki_migrations.last().map(|migration| migration.version)
        != Some(PRE_PKI_MIGRATION_VERSION)
    {
        return Err(format!(
            "migration {PRE_PKI_MIGRATION_VERSION} must remain the pre-PKI boundary"
        ));
    }
    Migrator {
        migrations: Cow::Owned(pre_pki_migrations),
        ..Migrator::DEFAULT
    }
    .run_direct(&mut conn)
    .await
    .map_err(|error| format!("apply pre-PKI migrations: {error}"))?;

    let entity_id = Uuid::new_v4();
    let active_legacy_id = Uuid::new_v4();
    let revoked_legacy_id = Uuid::new_v4();
    let legacy_certificate =
        rcgen::generate_simple_self_signed(vec!["legacy-unmanaged.example".to_string()])
            .map_err(|error| format!("generate legacy certificate: {error}"))?;
    let legacy_certificate_der = legacy_certificate.cert.der().to_vec();
    let legacy_fingerprint =
        hex::encode(digest::digest(&digest::SHA256, &legacy_certificate_der).as_ref());
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'device', $2, 'active')",
    )
    .bind(entity_id)
    .bind("m45-legacy-device")
    .execute(&mut conn)
    .await
    .map_err(|error| format!("seed legacy entity: {error}"))?;
    sqlx::query(
        r#"
        INSERT INTO credentials
            (id, entity_id, kind, identifier, status, metadata, expires_at)
        VALUES
            ($1, $2, 'certificate', $3, $4, $5, now() + interval '1 day')
        "#,
    )
    .bind(active_legacy_id)
    .bind(entity_id)
    .bind("a1")
    .bind("active")
    .bind(serde_json::json!({"fingerprint_sha256": legacy_fingerprint.clone()}))
    .execute(&mut conn)
    .await
    .map_err(|error| format!("seed active legacy certificate: {error}"))?;
    sqlx::query(
        r#"
        INSERT INTO credentials (id, entity_id, kind, identifier, status)
        VALUES ($1, $2, 'certificate', $3, $4)
        "#,
    )
    .bind(revoked_legacy_id)
    .bind(entity_id)
    .bind("a2")
    .bind("revoked")
    .execute(&mut conn)
    .await
    .map_err(|error| format!("seed revoked legacy certificate: {error}"))?;

    migrator
        .run_direct(&mut conn)
        .await
        .map_err(|error| format!("apply complete migration set: {error}"))?;

    let legacy_rows: Vec<(Uuid, Option<Uuid>, String, String)> = sqlx::query_as(
        r#"
        SELECT id, issuer_id, metadata->>'issuer_migration', status
        FROM credentials
        WHERE id = ANY($1)
        ORDER BY id
        "#,
    )
    .bind(vec![active_legacy_id, revoked_legacy_id])
    .fetch_all(&mut conn)
    .await
    .map_err(|error| format!("read migrated legacy certificates: {error}"))?;
    if legacy_rows.len() != 2
        || legacy_rows
            .iter()
            .any(|(_, issuer_id, marker, _)| issuer_id.is_some() || marker != "legacy_unmanaged")
    {
        return Err(format!(
            "legacy issuer migration marker missing: {legacy_rows:?}"
        ));
    }

    let ledger_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM certificate_revocations WHERE credential_id = $1")
            .bind(revoked_legacy_id)
            .fetch_one(&mut conn)
            .await
            .map_err(|error| format!("read legacy revocation ledger: {error}"))?;
    if ledger_count != 0 {
        return Err(
            "legacy revoked certificate was fabricated into the managed ledger".to_string(),
        );
    }

    sqlx::query("UPDATE credentials SET status = 'revoked' WHERE id = $1")
        .bind(active_legacy_id)
        .execute(&mut conn)
        .await
        .map_err(|error| format!("revoke marked legacy certificate: {error}"))?;
    let new_ledger_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM certificate_revocations WHERE credential_id = $1")
            .bind(active_legacy_id)
            .fetch_one(&mut conn)
            .await
            .map_err(|error| format!("read updated legacy revocation ledger: {error}"))?;
    if new_ledger_count != 0 {
        return Err("legacy revocation created a managed issuer ledger row".to_string());
    }

    let unmarked_insert = sqlx::query(
        "INSERT INTO credentials (entity_id, kind, identifier) VALUES ($1, 'certificate', 'a3')",
    )
    .bind(entity_id)
    .execute(&mut conn)
    .await;
    if unmarked_insert.is_ok() {
        return Err("new certificate without issuer_id was accepted".to_string());
    }

    let forged_marker_insert = sqlx::query(
        r#"
        INSERT INTO credentials (entity_id, kind, identifier, metadata)
        VALUES ($1, 'certificate', 'a4', '{"issuer_migration":"legacy_unmanaged"}')
        "#,
    )
    .bind(entity_id)
    .execute(&mut conn)
    .await;
    if forged_marker_insert.is_ok() {
        return Err("new certificate bypassed issuer binding with a legacy marker".to_string());
    }

    let pool = PgPool::connect(scratch_url)
        .await
        .map_err(|error| format!("connect resolver pool: {error}"))?;
    for input in [
        ResolveCertificateV2 {
            certificate_der: None,
            fingerprint_sha256: Some(legacy_fingerprint),
            issuer_fingerprint_sha256: None,
            serial_number: None,
            expected_tenant_id: None,
        },
        ResolveCertificateV2 {
            certificate_der: Some(legacy_certificate_der),
            fingerprint_sha256: None,
            issuer_fingerprint_sha256: None,
            serial_number: None,
            expected_tenant_id: None,
        },
    ] {
        let resolved = service::resolve_certificate_identity_v2(&pool, input).await;
        if !matches!(resolved, Err(AppError::NotFound(_))) {
            return Err(format!(
                "legacy issuer-less certificate reached the runtime resolver: {resolved:?}"
            ));
        }
    }
    pool.close().await;

    conn.close()
        .await
        .map_err(|error| format!("close scratch: {error}"))
}

fn database_url_with_name(database_url: &str, database_name: &str) -> Result<String, String> {
    let mut url =
        Url::parse(database_url).map_err(|error| format!("parse database URL: {error}"))?;
    url.set_path(&format!("/{database_name}"));
    Ok(url.to_string())
}

#[test]
fn scratch_database_url_preserves_connection_parameters() {
    let scratch = database_url_with_name(
        "postgres://atom:secret@db.example/atom?sslmode=require&application_name=atom-test",
        "atom_m45_test",
    )
    .expect("scratch URL");
    let parsed = Url::parse(&scratch).expect("parse scratch URL");

    assert_eq!(parsed.path(), "/atom_m45_test");
    assert_eq!(
        parsed.query(),
        Some("sslmode=require&application_name=atom-test")
    );
}
