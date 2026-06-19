//! Alias (human-friendly handle) integration tests.
//!
//! Covers scoped uniqueness (unique per tenant, reusable across tenants),
//! case-folding, slug/UUID-shape validation, and the two-level alias resolver.
//! All `#[ignore]`; run with:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m18_aliases -- --ignored
//! ```

mod common;

use common::pool;

use atom::authz::repo as authz_repo;
use atom::identity::repo as identity_repo;
use atom::models::alias::AliasObjectClass;
use atom::models::entity::{CreateEntity, UpdateEntity};
use atom::models::enums::EntityKind;
use atom::models::resource::{CreateResource, UpdateResource};
use atom::models::tenant::{CreateTenant, UpdateTenant};
use atom::tenants::repo as tenant_repo;
use serde_json::json;
use uuid::Uuid;

/// A short, valid, unique slug for a test (aliases must be `[a-z0-9][a-z0-9-]*`).
fn slug(prefix: &str) -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..12])
}

async fn make_tenant(pool: &sqlx::PgPool, alias: &str) -> Uuid {
    tenant_repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: slug("tenant"),
            alias: Some(alias.to_string()),
            tags: vec![],
            attributes: json!({}),
        },
        None,
    )
    .await
    .expect("create tenant")
    .id
}

fn resource_req(tenant_id: Uuid, alias: &str) -> CreateResource {
    CreateResource {
        id: None,
        kind: "resource:channel".to_string(),
        name: Some("chan".to_string()),
        alias: Some(alias.to_string()),
        tenant_id: Some(tenant_id),
        owner_id: None,
        attributes: json!({}),
    }
}

#[tokio::test]
#[ignore]
async fn alias_unique_within_tenant_but_reusable_across_tenants() {
    let p = pool().await;
    let tenant_a = make_tenant(&p, &slug("a")).await;
    let tenant_b = make_tenant(&p, &slug("b")).await;
    let alias = slug("chan");

    authz_repo::create_resource(&p, resource_req(tenant_a, &alias))
        .await
        .expect("first resource in tenant A");

    // Same alias in a different tenant is allowed.
    authz_repo::create_resource(&p, resource_req(tenant_b, &alias))
        .await
        .expect("same alias reusable across tenants");

    // Same alias again within tenant A is rejected (scoped uniqueness).
    let dup = authz_repo::create_resource(&p, resource_req(tenant_a, &alias)).await;
    assert!(
        dup.is_err(),
        "duplicate alias within a tenant must be rejected"
    );
}

#[tokio::test]
#[ignore]
async fn resolve_alias_resolves_tenant_and_object() {
    let p = pool().await;
    let tenant_alias = slug("dom");
    let tenant_id = make_tenant(&p, &tenant_alias).await;
    let object_alias = slug("meter");
    let resource = authz_repo::create_resource(&p, resource_req(tenant_id, &object_alias))
        .await
        .expect("create resource");
    let tenant_lookup = format!("  {}  ", tenant_alias.to_uppercase());

    let resolved = authz_repo::resolve_alias(
        &p,
        None,
        Some(&tenant_lookup),
        false,
        AliasObjectClass::Resource,
        &object_alias,
    )
    .await
    .expect("resolve by tenant alias + object alias");
    assert_eq!(resolved.tenant_id, Some(tenant_id));
    assert_eq!(resolved.object_id, resource.id);

    // Unknown object alias → NotFound.
    let miss = authz_repo::resolve_alias(
        &p,
        Some(tenant_id),
        None,
        false,
        AliasObjectClass::Resource,
        "does-not-exist",
    )
    .await;
    assert!(miss.is_err(), "unknown alias must not resolve");
}

#[tokio::test]
#[ignore]
async fn resolve_alias_is_case_insensitive() {
    let p = pool().await;
    let tenant_alias = slug("dom");
    let tenant_id = make_tenant(&p, &tenant_alias).await;
    // Stored lowercased on write; resolve with mixed case must still match.
    let resource = authz_repo::create_resource(&p, resource_req(tenant_id, "watermeters"))
        .await
        .expect("create resource");

    let resolved = authz_repo::resolve_alias(
        &p,
        Some(tenant_id),
        None,
        false,
        AliasObjectClass::Resource,
        "WaterMeters",
    )
    .await
    .expect("case-insensitive resolve");
    assert_eq!(resolved.object_id, resource.id);
}

#[tokio::test]
#[ignore]
async fn resolve_alias_supports_explicit_global_scope() {
    let p = pool().await;
    let object_alias = slug("global");
    let resource = authz_repo::create_resource(
        &p,
        CreateResource {
            id: None,
            kind: "resource:global".to_string(),
            name: Some("global".to_string()),
            alias: Some(object_alias.clone()),
            tenant_id: None,
            owner_id: None,
            attributes: json!({}),
        },
    )
    .await
    .expect("create global resource");

    let resolved = authz_repo::resolve_alias(
        &p,
        None,
        None,
        true,
        AliasObjectClass::Resource,
        &object_alias,
    )
    .await
    .expect("resolve global resource");

    assert_eq!(resolved.tenant_id, None);
    assert_eq!(resolved.object_id, resource.id);
}

#[tokio::test]
#[ignore]
async fn alias_updates_can_clear_existing_values() {
    let p = pool().await;
    let tenant_id = make_tenant(&p, &slug("tenant")).await;
    let entity = identity_repo::create_entity(
        &p,
        CreateEntity {
            id: None,
            kind: Some(EntityKind::Device),
            profile_id: None,
            profile_version_id: None,
            name: slug("device"),
            alias: Some(slug("entity")),
            tenant_id: Some(tenant_id),
            attributes: json!({}),
        },
    )
    .await
    .expect("create entity");
    let resource = authz_repo::create_resource(&p, resource_req(tenant_id, &slug("resource")))
        .await
        .expect("create resource");

    let entity = identity_repo::update_entity(
        &p,
        entity.id,
        UpdateEntity {
            name: None,
            kind: None,
            alias: Some(None),
            tenant_id: None,
            profile_id: None,
            profile_version_id: None,
            status: None,
            attributes: None,
        },
    )
    .await
    .expect("clear entity alias");
    let resource = authz_repo::update_resource(
        &p,
        resource.id,
        UpdateResource {
            name: None,
            alias: Some(None),
            attributes: None,
        },
    )
    .await
    .expect("clear resource alias");
    let tenant = tenant_repo::update_tenant(
        &p,
        tenant_id,
        UpdateTenant {
            name: None,
            alias: Some(None),
            tags: None,
            attributes: None,
        },
        None,
    )
    .await
    .expect("clear tenant alias");

    assert_eq!(entity.alias, None);
    assert_eq!(resource.alias, None);
    assert_eq!(tenant.alias, None);
}

#[tokio::test]
#[ignore]
async fn database_rejects_uuid_shaped_aliases() {
    let p = pool().await;
    let tenant_id = make_tenant(&p, &slug("tenant")).await;
    let uuid_alias = "465358f9-07f4-4ea0-8cbb-2abc654442bd";

    for result in [
        sqlx::query("INSERT INTO tenants (name, alias) VALUES ($1, $2)")
            .bind(slug("bad-tenant"))
            .bind(uuid_alias)
            .execute(&p)
            .await,
        sqlx::query(
            "INSERT INTO entities (kind, name, alias, tenant_id) \
             VALUES ('device', $1, $2, $3)",
        )
        .bind(slug("bad-entity"))
        .bind(uuid_alias)
        .bind(tenant_id)
        .execute(&p)
        .await,
        sqlx::query(
            "INSERT INTO resources (kind, name, alias, tenant_id) \
             VALUES ('resource:channel', $1, $2, $3)",
        )
        .bind("bad resource")
        .bind(uuid_alias)
        .bind(tenant_id)
        .execute(&p)
        .await,
    ] {
        let err = result.expect_err("UUID-shaped alias must violate a CHECK constraint");
        let code = err
            .as_database_error()
            .and_then(|db| db.code())
            .map(|code| code.into_owned());
        assert_eq!(code.as_deref(), Some("23514"));
    }
}

#[tokio::test]
#[ignore]
async fn create_resource_rejects_invalid_aliases() {
    let p = pool().await;
    let tenant_id = make_tenant(&p, &slug("dom")).await;

    assert!(
        authz_repo::create_resource(&p, resource_req(tenant_id, "has space"))
            .await
            .is_err(),
        "non-slug alias must be rejected"
    );
    assert!(
        authz_repo::create_resource(
            &p,
            resource_req(tenant_id, "465358f9-07f4-4ea0-8cbb-2abc654442bd"),
        )
        .await
        .is_err(),
        "UUID-shaped alias must be rejected"
    );
}

#[tokio::test]
#[ignore]
async fn resource_alias_is_stored_case_folded() {
    let p = pool().await;
    let tenant_id = make_tenant(&p, &slug("dom")).await;
    let created = authz_repo::create_resource(&p, resource_req(tenant_id, "Sensor-01"))
        .await
        .expect("create resource with mixed-case alias");
    assert_eq!(created.alias.as_deref(), Some("sensor-01"));
}
