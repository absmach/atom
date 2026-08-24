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

    fn platform_intermediate(id: Uuid, root_id: Uuid) -> Self {
        Self {
            id,
            tenant_id: None,
            parent_id: Some(root_id),
            kind: "platform_intermediate",
            version: 1,
            status: "active",
            issuance_enabled: false,
            fingerprint: fingerprint(2),
            key_backend: "pkcs11",
            key_reference: Some("pkcs11:object=platform-ca".into()),
        }
    }

    fn platform_leaf(id: Uuid, root_id: Uuid, version: i32, marker: u64) -> Self {
        Self {
            id,
            tenant_id: None,
            parent_id: Some(root_id),
            kind: "platform_leaf_issuer",
            version,
            status: "active",
            issuance_enabled: true,
            fingerprint: fingerprint(marker),
            key_backend: "pkcs11",
            key_reference: Some(format!("pkcs11:object=platform-leaf-v{version}")),
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
            key_backend: "pkcs11",
            key_reference: Some(format!("pkcs11:object=tenant-{tenant_id}-v{version}")),
        }
    }
}

#[tokio::test]
#[ignore]
async fn authorities_are_scope_safe_and_rotation_ready() {
    let pool = common::pool().await;
    let tenant_a = create_tenant(&pool, "pki-tenant-a").await;
    let tenant_b = create_tenant(&pool, "pki-tenant-b").await;

    let root_id = Uuid::new_v4();
    let platform_id = Uuid::new_v4();
    let platform_leaf_id = Uuid::new_v4();
    insert_authority(&pool, &TestAuthority::root(root_id))
        .await
        .unwrap();
    insert_authority(
        &pool,
        &TestAuthority::platform_intermediate(platform_id, root_id),
    )
    .await
    .unwrap();
    insert_authority(
        &pool,
        &TestAuthority::platform_leaf(platform_leaf_id, root_id, 1, 3),
    )
    .await
    .unwrap();

    assert!(authority::validate_authority_shape(AuthorityKind::Root, None, None).is_ok());
    assert!(authority::validate_authority_shape(
        AuthorityKind::PlatformLeafIssuer,
        None,
        Some(root_id)
    )
    .is_ok());
    assert!(authority::validate_leaf_issuance(
        AuthorityKind::PlatformLeafIssuer,
        AuthorityStatus::Active,
        AuthorityKeyBackend::Pkcs11,
        true,
    )
    .is_ok());

    let tenant_a_v1 = TestAuthority::tenant(Uuid::new_v4(), tenant_a, platform_id, 1, 11);
    let tenant_b_v1 = TestAuthority::tenant(Uuid::new_v4(), tenant_b, platform_id, 1, 21);
    insert_authority(&pool, &tenant_a_v1).await.unwrap();
    insert_authority(&pool, &tenant_b_v1).await.unwrap();

    let readiness = repo::leaf_issuer_readiness(&pool).await.unwrap();
    assert_eq!(readiness.configured_count, 3);
    assert_eq!(readiness.active_backends, vec![AuthorityKeyBackend::Pkcs11]);

    let active_a = repo::active_leaf_issuer_for_scope(&pool, Some(tenant_a))
        .await
        .unwrap();
    assert_eq!(active_a.id, tenant_a_v1.id);
    assert!(active_a.can_issue_leaves_at(Utc::now()));

    let active_global = repo::active_leaf_issuer_for_scope(&pool, None)
        .await
        .unwrap();
    assert_eq!(active_global.id, platform_leaf_id);

    let conflicting_v2 = TestAuthority::tenant(Uuid::new_v4(), tenant_a, platform_id, 2, 12);
    let conflict = insert_authority(&pool, &conflicting_v2).await.unwrap_err();
    assert!(is_database_code(&conflict, "23505"));

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

    let entity_a = create_entity(&pool, Some(tenant_a), "pki-device-a").await;
    let entity_b = create_entity(&pool, Some(tenant_b), "pki-device-b").await;
    let global_entity = create_entity(&pool, None, "pki-global-service").await;

    insert_certificate(
        &pool,
        entity_a,
        conflicting_v2.id,
        "01020304",
        &fingerprint(101),
    )
    .await
    .unwrap();
    insert_certificate(
        &pool,
        global_entity,
        platform_leaf_id,
        "02030405",
        &fingerprint(102),
    )
    .await
    .unwrap();

    let cross_tenant = insert_certificate(
        &pool,
        entity_b,
        conflicting_v2.id,
        "03040506",
        &fingerprint(103),
    )
    .await
    .unwrap_err();
    assert!(is_database_code(&cross_tenant, "23514"));

    let wrong_global_issuer = insert_certificate(
        &pool,
        global_entity,
        conflicting_v2.id,
        "04050607",
        &fingerprint(104),
    )
    .await
    .unwrap_err();
    assert!(is_database_code(&wrong_global_issuer, "23514"));

    let delete_in_use_issuer = sqlx::query("DELETE FROM pki_authorities WHERE id = $1")
        .bind(platform_leaf_id)
        .execute(&pool)
        .await
        .unwrap_err();
    // Postgres 18 tightened RESTRICT violations to SQLSTATE 23001
    // (restrict_violation); earlier versions returned the generic 23503
    // (foreign_key_violation). Both mean the same thing here.
    assert!(
        is_database_code(&delete_in_use_issuer, "23001")
            || is_database_code(&delete_in_use_issuer, "23503")
    );

    let tenant_move = sqlx::query("UPDATE entities SET tenant_id = $1 WHERE id = $2")
        .bind(tenant_b)
        .bind(entity_a)
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(is_database_code(&tenant_move, "23514"));

    let invalid_parent = TestAuthority::tenant(Uuid::new_v4(), tenant_b, platform_leaf_id, 2, 31);
    let invalid_parent_error = insert_authority(&pool, &invalid_parent).await.unwrap_err();
    assert!(is_database_code(&invalid_parent_error, "23514"));

    let duplicate_global_issuer = TestAuthority::platform_leaf(Uuid::new_v4(), root_id, 2, 32);
    let duplicate_global_error = insert_authority(&pool, &duplicate_global_issuer)
        .await
        .unwrap_err();
    assert!(is_database_code(&duplicate_global_error, "23505"));

    let outside_parent_validity = sqlx::query(
        "UPDATE pki_authorities SET not_after = now() + interval '500 days' WHERE id = $1",
    )
    .bind(conflicting_v2.id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(is_database_code(&outside_parent_validity, "23514"));

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

    // Resolver v2 scopes managed serials by issuer, so a second issuer may use
    // the same serial while each issuer-local key remains unique.
    insert_certificate(
        &pool,
        entity_b,
        tenant_b_v1.id,
        "01020304",
        &fingerprint(105),
    )
    .await
    .unwrap();
    let shared_serial_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE kind = 'certificate' AND identifier = $1",
    )
    .bind("01020304")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(shared_serial_count, 2);

    let null_entity = sqlx::query(
        r#"INSERT INTO credentials
             (id, entity_id, kind, identifier, issuer_id, metadata, expires_at)
           VALUES ($1, NULL, 'certificate', $2, $3, $4, $5)"#,
    )
    .bind(Uuid::new_v4())
    .bind("06070809")
    .bind(platform_leaf_id)
    .bind(json!({"fingerprint_sha256": fingerprint(106)}))
    .bind(Utc::now() + Duration::days(30))
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(is_database_code(&null_entity, "23514"));

    let purge_tenant_id = create_tenant(&pool, "pki-purge").await;
    let purge_authority =
        TestAuthority::tenant(Uuid::new_v4(), purge_tenant_id, platform_id, 1, 41);
    insert_authority(&pool, &purge_authority).await.unwrap();
    let purge_entity = create_entity(&pool, Some(purge_tenant_id), "pki-purge-device").await;
    insert_certificate(
        &pool,
        purge_entity,
        purge_authority.id,
        "0708090a",
        &fingerprint(107),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE tenants SET status = 'deleted', deleted_at = now() WHERE id = $1")
        .bind(purge_tenant_id)
        .execute(&pool)
        .await
        .unwrap();

    atom::tenants::repo::purge_tenant(&pool, purge_tenant_id)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tenants WHERE id = $1")
            .bind(purge_tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pki_authorities WHERE id = $1")
            .bind(purge_authority.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
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

async fn create_entity(pool: &PgPool, tenant_id: Option<Uuid>, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, tenant_id, name, kind) VALUES ($1, $2, $3, 'service')")
        .bind(id)
        .bind(tenant_id)
        .bind(format!("{prefix}-{id}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn insert_authority(pool: &PgPool, authority: &TestAuthority) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let (not_before, not_after) = match authority.kind {
        "root" => (now - Duration::hours(3), now + Duration::days(400)),
        "platform_intermediate" => (now - Duration::hours(2), now + Duration::days(390)),
        _ => (now - Duration::hours(1), now + Duration::days(365)),
    };
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
    .bind(not_before)
    .bind(not_after)
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
