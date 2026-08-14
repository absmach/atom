//! Server-side ordering tests for paginated Atom listings.
//!
//! These tests require a reachable Postgres at `DATABASE_URL` and are ignored
//! by default:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m44_list_sorting -- --ignored
//! ```

mod common;

use atom::models::{
    entity::ListEntities,
    enums::{
        DeletedFilter, EntityOrderField, GroupOrderField, ResourceOrderField, SortDir,
        TenantOrderField,
    },
    group::{CreateGroup, ListGroups},
    resource::ListResources,
    tenant::ListTenants,
};
use serde_json::json;
use uuid::Uuid;

async fn make_tenant(pool: &sqlx::PgPool, name: &str, alias: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, alias, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(name)
        .bind(alias)
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_entity(pool: &sqlx::PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'device', $2, $3, 'active')",
    )
    .bind(id)
    .bind(name)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn make_resource(pool: &sqlx::PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, name, tenant_id) VALUES ($1, 'channel', $2, $3)")
        .bind(id)
        .bind(name)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert resource");
    id
}

#[tokio::test]
#[ignore]
async fn direct_lists_apply_order_before_pagination() {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();
    let prefix = format!("m44-sort-{suffix}");
    let tenant_id = make_tenant(
        &pool,
        &format!("{prefix}-tenant"),
        &format!("{prefix}-tenant"),
    )
    .await;

    make_entity(&pool, tenant_id, &format!("{prefix}-c-entity")).await;
    make_entity(&pool, tenant_id, &format!("{prefix}-a-entity")).await;
    make_entity(&pool, tenant_id, &format!("{prefix}-b-entity")).await;

    let entities = atom::identity::repo::list_entities(
        &pool,
        ListEntities {
            q: Some(prefix.clone()),
            kind: None,
            profile_id: None,
            tenant_id: Some(tenant_id),
            status: None,
            deleted: DeletedFilter::Live,
            parent_group_id: None,
            include_descendants: false,
            limit: 2,
            offset: 0,
            order: EntityOrderField::Name,
            dir: SortDir::Asc,
        },
    )
    .await
    .expect("list entities");
    let entity_names: Vec<_> = entities
        .items
        .into_iter()
        .map(|entity| entity.name)
        .collect();
    assert_eq!(
        entity_names,
        vec![format!("{prefix}-a-entity"), format!("{prefix}-b-entity")]
    );

    make_resource(&pool, tenant_id, &format!("{prefix}-c-resource")).await;
    make_resource(&pool, tenant_id, &format!("{prefix}-a-resource")).await;
    make_resource(&pool, tenant_id, &format!("{prefix}-b-resource")).await;

    let resources = atom::authz::repo::list_resources(
        &pool,
        ListResources {
            q: Some(prefix.clone()),
            kind: Some("channel".to_string()),
            tenant_id: Some(tenant_id),
            attributes_contains: None,
            parent_group_id: None,
            include_descendants: false,
            deleted: DeletedFilter::Live,
            limit: 2,
            offset: 0,
            order: ResourceOrderField::Name,
            dir: SortDir::Asc,
        },
    )
    .await
    .expect("list resources");
    let resource_names: Vec<_> = resources
        .items
        .into_iter()
        .map(|resource| resource.name.expect("resource name"))
        .collect();
    assert_eq!(
        resource_names,
        vec![
            format!("{prefix}-a-resource"),
            format!("{prefix}-b-resource")
        ]
    );

    for name in ["c-group", "a-group", "b-group"] {
        atom::identity::repo::create_group(
            &pool,
            CreateGroup {
                id: None,
                name: format!("{prefix}-{name}"),
                tenant_id: Some(tenant_id),
                group_type: Some("object".to_string()),
                description: None,
                attributes: json!({}),
            },
        )
        .await
        .expect("create group");
    }

    let groups = atom::identity::repo::list_groups(
        &pool,
        ListGroups {
            q: Some(prefix.clone()),
            tenant_id: Some(tenant_id),
            group_type: Some("object".to_string()),
            parent_id: None,
            status: None,
            deleted: DeletedFilter::Live,
            limit: 2,
            offset: 0,
            order: GroupOrderField::Name,
            dir: SortDir::Asc,
        },
    )
    .await
    .expect("list groups");
    let group_names: Vec<_> = groups.items.into_iter().map(|group| group.name).collect();
    assert_eq!(
        group_names,
        vec![format!("{prefix}-a-group"), format!("{prefix}-b-group")]
    );
}

#[tokio::test]
#[ignore]
async fn tenant_lists_apply_order_before_pagination() {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();
    let prefix = format!("m44-tenant-sort-{suffix}");

    make_tenant(&pool, &format!("{prefix}-c"), &format!("{prefix}-alias-c")).await;
    make_tenant(&pool, &format!("{prefix}-a"), &format!("{prefix}-alias-a")).await;
    make_tenant(&pool, &format!("{prefix}-b"), &format!("{prefix}-alias-b")).await;

    let tenants = atom::tenants::repo::list_tenants(
        &pool,
        ListTenants {
            q: Some(prefix.clone()),
            name: None,
            alias: None,
            status: None,
            deleted: DeletedFilter::Live,
            limit: 2,
            offset: 0,
            order: TenantOrderField::Name,
            dir: SortDir::Asc,
        },
    )
    .await
    .expect("list tenants");
    let tenant_names: Vec<_> = tenants
        .items
        .into_iter()
        .map(|tenant| tenant.name)
        .collect();
    assert_eq!(
        tenant_names,
        vec![format!("{prefix}-a"), format!("{prefix}-b")]
    );
}
