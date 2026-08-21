//! Upgrade coverage for certificate credentials that predate issuer_id.
//!
//! Run with a disposable PostgreSQL database:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m45_pki_legacy_certificate_migration -- --ignored
//! ```

use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn migration_preserves_and_marks_pre_authority_certificate_credentials() {
    let admin_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let scratch = format!("atom_m45_{}", Uuid::new_v4().simple());
    let (base, _) = admin_url
        .rsplit_once('/')
        .expect("database url with a path");
    let scratch_url = format!("{base}/{scratch}");

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

    apply_migrations(
        &mut conn,
        &[
            "001_initial.sql",
            "002_platform_filtered_permission_scopes.sql",
            "003_access_token_usage_and_ceiling_scope.sql",
            "004_event_outbox.sql",
            "005_managed_by.sql",
            "006_managed_by_identity.sql",
            "007_strip_product_specific_applicability.sql",
            "008_managed_by_rbac.sql",
            "009_many_to_many_object_group_membership.sql",
            "010_entity_external_id.sql",
        ],
    )
    .await?;

    let entity_id = Uuid::new_v4();
    let active_legacy_id = Uuid::new_v4();
    let revoked_legacy_id = Uuid::new_v4();
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
        INSERT INTO credentials (id, entity_id, kind, identifier, status)
        VALUES ($1, $2, 'certificate', $3, $4)
        "#,
    )
    .bind(active_legacy_id)
    .bind(entity_id)
    .bind("a1")
    .bind("active")
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

    apply_migrations(
        &mut conn,
        &[
            "011_pki_authorities.sql",
            "012_pki_ca_provisioning.sql",
            "013_pki_certificate_profiles.sql",
            "014_pki_csr_issuance.sql",
            "015_pki_certificate_renewal.sql",
            "016_pki_certificate_revocation.sql",
            "017_pki_issuer_crls.sql",
            "018_pki_runtime_resolver_v2.sql",
            "019_pki_enrollment.sql",
            "020_pki_lifecycle_automation.sql",
            "021_pki_profile_usage_invariants.sql",
            "022_pki_durable_revocation_evidence.sql",
            "023_pki_purgeable_authorities.sql",
            "024_pki_config_bootstrap_provisioning_mode.sql",
        ],
    )
    .await?;

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

    conn.close()
        .await
        .map_err(|error| format!("close scratch: {error}"))
}

async fn apply_migrations(conn: &mut PgConnection, migrations: &[&str]) -> Result<(), String> {
    for file in migrations {
        let sql = std::fs::read_to_string(format!("./migrations/{file}"))
            .map_err(|error| format!("read {file}: {error}"))?;
        sqlx::raw_sql(&sql)
            .execute(&mut *conn)
            .await
            .map_err(|error| format!("apply {file}: {error}"))?;
    }
    Ok(())
}
