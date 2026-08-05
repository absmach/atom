mod common;

use atom::certs::authority::{self, repo, AuthorityKeyBackend, AuthorityKind, AuthorityStatus};
use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

struct TestAuthority {
    id: Uuid,
    tenant_id: Option<Uuid>,
    parent_id: Option<Uuid>,
    kind: &'static str,
    version: i32,
    status: &'static str,
    issuance_enabled: bool,
    fingerprint: String,
    key_backend: &'static str,
    key_reference: Option<String>,
}

impl TestAuthority {
    fn root(id: Uuid) -> Self {
        Self {
            id,
            tenant_id: None,
            parent_id: None,
            kind: "root",
            version: 1,
            status: "active",
            issuance_enabled: false,
            fingerprint: fingerprint(1),
            key_backend: "public_only",
            key_reference: None,
        }
    }

    fn platform(id: Uuid, root_id: Uuid) -> Self {
        Self {
            id,
            tenant_id: None,
            parent_id: Some(root_id),
            kind: "platform_intermediate",
            version: 1,
            status: "active",
            issuance_enabled: false,
            fingerprint: fingerprint(2),
            key_backend: "file",
            key_reference: Some("/test/platform-ca.key".into()),
        }
    }

    fn tenant(id: Uuid, tenant_id: Uuid, parent_id: Uuid, version: i32, marker: u64) -> Self {
        Self {
            id,
            tenant_id: Some(tenant_id),
            parent_id: Some(parent_id),
            kind: "tenant_intermediate",
            version,
            status: "active",
            issuance_enabled: true,
            fingerprint: fingerprint(marker),
            key_backend: "file",
            key_reference: Some(format!("/test/tenant-{tenant_id}-v{version}.key")),
        }
    }
}

#[tokio::test]
#[ignore]
async fn tenant_authorities_are_isolated_and_rotation_safe() {
    let pool = common::pool().await;
    let tenant_a = create_tenant(&pool, "pki-tenant-a").await;
    let tenant_b = create_tenant(&pool, "pki-tenant-b").await;

    let root_id = Uuid::new_v4();
    let platform_id = Uuid::new_v4();
    insert_authority(&pool, &TestAuthority::root(root_id))
        .await
        .unwrap();
    insert_authority(&pool, &TestAuthority::platform(platform_id, root_id))
        .await
        .unwrap();

    // The application validation mirrors the database CHECK constraints.
    assert!(authority::validate_authority_shape(AuthorityKind::Root, None, None).is_ok());
    assert!(authority::validate_leaf_issuance(
        AuthorityKind::TenantIntermediate,
        AuthorityStatus::Active,
        AuthorityKeyBackend::File,
        true,
    )
    .is_ok());

    let tenant_a_v1 = TestAuthority::tenant(Uuid::new_v4(), tenant_a, platform_id, 1, 11);
    let tenant_b_v1 = TestAuthority::tenant(Uuid::new_v4(), tenant_b, platform_id, 1, 21);
    insert_authority(&pool, &tenant_a_v1).await.unwrap();
    insert_authority(&pool, &tenant_b_v1).await.unwrap();

    let active_a = repo::active_tenant_leaf_issuer(&pool, tenant_a)
        .await
        .unwrap();
    assert_eq!(active_a.id, tenant_a_v1.id);
    assert!(active_a.can_issue_leaves_at(Utc::now()));

    // A tenant cannot have two authorities enabled for new leaf issuance.
    let conflicting_v2 = TestAuthority::tenant(Uuid::new_v4(), tenant_a, platform_id, 2, 12);
    let conflict = insert_authority(&pool, &conflicting_v2)
        .await
        .unwrap_err();
    assert!(is_database_code(&conflict, "23505"));

    // Rotation is an explicit handover: retire issuance on v1, then activate v2.
    sqlx::query(
        "UPDATE pki_authorities SET status = 'retiring', issuance_enabled = false, \
         retiring_at = now(), updated_at = now() WHERE id = $1",
    )
    .bind(tenant_a_v1.id)
    .execute(&pool)
    .await
    .unwrap();
    insert_authority(&pool, &conflicting_v2).await.unwrap();

    let active_a = repo::active_tenant_leaf_issuer(&pool, tenant_a)
        .await
        .unwrap();
    assert_eq!(active_a.id, conflicting_v2.id);
    assert_eq!(active_a.version, 2);

    let versions = repo::list_tenant_authorities(&pool, tenant_a)
        .await
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, 2);
    assert_eq!(versions[1].status, AuthorityStatus::Retiring);

    let entity_a = create_device(&pool, tenant_a, "pki-device-a").await;
    let entity_b = create_device(&pool, tenant_b, "pki-device-b").await;
    let shared_serial = "01020304";

    insert_certificate(
        &pool,
        entity_a,
        conflicting_v2.id,
        shared_serial,
        &fingerprint(101),
    )
    .await
    .unwrap();
    insert_certificate(
        &pool,
        entity_b,
        tenant_b_v1.id,
        shared_serial,
        &fingerprint(102),
    )
    .await
    .unwrap();

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credentials WHERE kind = 'certificate' AND identifier = $1",
    )
    .bind(shared_serial)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2, "serials are scoped to their issuing authority");

    // The same issuer cannot reuse a serial even for another entity.
    let duplicate_serial = insert_certificate(
        &pool,
        entity_b,
        conflicting_v2.id,
        shared_serial,
        &fingerprint(103),
    )
    .await
    .unwrap_err();
    assert!(is_database_code(&duplicate_serial, "23505"));

    // Fingerprint remains globally unique and is the preferred runtime lookup key.
    let duplicate_fingerprint = insert_certificate(
        &pool,
        entity_b,
        tenant_b_v1.id,
        "05060708",
        &fingerprint(101),
    )
    .await
    .unwrap_err();
    assert!(is_database_code(&duplicate_fingerprint, "23505"));

    // Static constraints also prevent a platform CA from being enabled as a leaf issuer.
    let invalid_platform = TestAuthority {
        id: Uuid::new_v4(),
        version: 2,
        issuance_enabled: true,
        fingerprint: fingerprint(3),
        ..TestAuthority::platform(Uuid::new_v4(), root_id)
    };
    let invalid = insert_authority(&pool, &invalid_platform)
        .await
        .unwrap_err();
    assert!(is_database_code(&invalid, "23514"));
}

async fn create_tenant(pool: &PgPool, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{prefix}-{id}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn create_device(pool: &PgPool, tenant_id: Uuid, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, tenant_id, name, kind) VALUES ($1, $2, $3, 'device')")
        .bind(id)
        .bind(tenant_id)
        .bind(format!("{prefix}-{id}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn insert_authority(
    pool: &PgPool,
    authority: &TestAuthority,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO pki_authorities (
            id, tenant_id, parent_id, kind, version, status, issuance_enabled,
            subject, serial_number, fingerprint_sha256, certificate_pem, chain_pem,
            not_before, not_after, key_backend, key_reference, activated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17
        )
        "#,
    )
    .bind(authority.id)
    .bind(authority.tenant_id)
    .bind(authority.parent_id)
    .bind(authority.kind)
    .bind(authority.version)
    .bind(authority.status)
    .bind(authority.issuance_enabled)
    .bind(format!("CN={}-v{}", authority.kind, authority.version))
    .bind(format!("{:02x}", authority.version))
    .bind(&authority.fingerprint)
    .bind("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
    .bind("-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----\n")
    .bind(now - Duration::hours(1))
    .bind(now + Duration::days(365))
    .bind(authority.key_backend)
    .bind(&authority.key_reference)
    .bind((authority.status == "active").then_some(now))
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_certificate(
    pool: &PgPool,
    entity_id: Uuid,
    issuer_id: Uuid,
    serial: &str,
    certificate_fingerprint: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO credentials (
            id, entity_id, kind, identifier, issuer_id, metadata, expires_at
        )
        VALUES ($1, $2, 'certificate', $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(serial)
    .bind(issuer_id)
    .bind(json!({"fingerprint_sha256": certificate_fingerprint}))
    .bind(Utc::now() + Duration::days(30))
    .execute(pool)
    .await?;
    Ok(())
}

fn fingerprint(value: u64) -> String {
    format!("{value:064x}")
}

fn is_database_code(error: &sqlx::Error, code: &str) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some(code))
}
