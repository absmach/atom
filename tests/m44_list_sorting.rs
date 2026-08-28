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
    access::AuthorizedObjectIdsQuery,
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

async fn grant_entity_read(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    subject_id: Uuid,
    object_id: Uuid,
) {
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (tenant_id, scope_mode, object_id, effect)
           VALUES ($1, 'object', $2, 'allow') RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(object_id)
    .fetch_one(pool)
    .await
    .expect("insert read block");
    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
           SELECT $1, id FROM actions WHERE name = 'read'"#,
    )
    .bind(block_id)
    .execute(pool)
    .await
    .expect("insert read action");
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("assign read policy");
}

async fn make_updated_entity(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    name: &str,
    days_ago: i64,
) -> Uuid {
    let id = make_entity(pool, tenant_id, name).await;
    sqlx::query("UPDATE entities SET updated_at = now() - ($2::text::interval) WHERE id = $1")
        .bind(id)
        .bind(format!("{days_ago} days"))
        .execute(pool)
        .await
        .expect("set entity updated_at");
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
            id: None,
            q: Some(prefix.clone()),
            kind: None,
            external_id: None,
            profile_id: None,
            tenant_id: Some(tenant_id),
            attributes_contains: None,
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
            attributes_contains: None,
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
async fn authorized_entity_order_survives_id_refetch_and_paginates() {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();
    let prefix = format!("m44-auth-sort-{suffix}");
    let tenant_id = make_tenant(
        &pool,
        &format!("{prefix}-tenant"),
        &format!("{prefix}-tenant"),
    )
    .await;
    let subject_id = make_entity(&pool, tenant_id, &format!("{prefix}-subject")).await;
    let c = make_entity(&pool, tenant_id, &format!("{prefix}-c")).await;
    let a = make_entity(&pool, tenant_id, &format!("{prefix}-a")).await;
    let b = make_entity(&pool, tenant_id, &format!("{prefix}-b")).await;
    for entity_id in [a, b, c] {
        grant_entity_read(&pool, tenant_id, subject_id, entity_id).await;
    }

    let page = atom::authz::repo::authorized_object_ids_with_ceiling(
        &pool,
        AuthorizedObjectIdsQuery {
            subject_id,
            action: "read".to_string(),
            object_kind: "entity".to_string(),
            object_type: Some("entity:device".to_string()),
            tenant_id: Some(tenant_id),
            id: None,
            q: Some(prefix.clone()),
            attributes_contains: None,
            external_id: None,
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id: None,
            include_descendants: false,
            limit: 2,
            offset: 0,
            entity_order: EntityOrderField::Name,
            resource_order: Default::default(),
            group_order: Default::default(),
            dir: SortDir::Desc,
        },
        None,
    )
    .await
    .expect("authorized entity listing");
    assert_eq!(page.total, 3);
    assert_eq!(page.ids, vec![c, b]);

    let rehydrated = atom::identity::repo::list_entities_by_ids(&pool, &page.ids)
        .await
        .expect("rehydrate authorized entity page");
    let names: Vec<_> = rehydrated.into_iter().map(|entity| entity.name).collect();
    assert_eq!(names, vec![format!("{prefix}-c"), format!("{prefix}-b")]);
}

#[tokio::test]
#[ignore]
async fn descending_nullable_sorts_put_nulls_last() {
    let pool = common::pool().await;
    let suffix = Uuid::new_v4();
    let prefix = format!("m44-null-sort-{suffix}");
    let tenant_id = make_tenant(
        &pool,
        &format!("{prefix}-tenant"),
        &format!("{prefix}-tenant"),
    )
    .await;

    make_entity(&pool, tenant_id, &format!("{prefix}-never-updated")).await;
    make_updated_entity(&pool, tenant_id, &format!("{prefix}-old"), 7).await;
    make_updated_entity(&pool, tenant_id, &format!("{prefix}-new"), 1).await;

    let entities = atom::identity::repo::list_entities(
        &pool,
        ListEntities {
            id: None,
            q: Some(prefix.clone()),
            kind: None,
            external_id: None,
            profile_id: None,
            tenant_id: Some(tenant_id),
            attributes_contains: None,
            status: None,
            deleted: DeletedFilter::Live,
            parent_group_id: None,
            include_descendants: false,
            limit: 3,
            offset: 0,
            order: EntityOrderField::UpdatedAt,
            dir: SortDir::Desc,
        },
    )
    .await
    .expect("list entities by updated_at desc");
    let entity_names: Vec<_> = entities
        .items
        .into_iter()
        .map(|entity| entity.name)
        .collect();
    assert_eq!(
        entity_names,
        vec![
            format!("{prefix}-new"),
            format!("{prefix}-old"),
            format!("{prefix}-never-updated")
        ]
    );

    make_resource(&pool, tenant_id, &format!("{prefix}-named")).await;
    let unnamed_resource_id = Uuid::new_v4();
    sqlx::query("INSERT INTO resources (id, kind, tenant_id) VALUES ($1, 'channel', $2)")
        .bind(unnamed_resource_id)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("insert unnamed resource");

    let resources = atom::authz::repo::list_resources(
        &pool,
        ListResources {
            q: None,
            kind: Some("channel".to_string()),
            tenant_id: Some(tenant_id),
            attributes_contains: None,
            parent_group_id: None,
            include_descendants: false,
            deleted: DeletedFilter::Live,
            limit: 2,
            offset: 0,
            order: ResourceOrderField::Name,
            dir: SortDir::Desc,
        },
    )
    .await
    .expect("list resources by name desc");
    let resource_names: Vec<_> = resources
        .items
        .into_iter()
        .map(|resource| resource.name)
        .collect();
    assert_eq!(resource_names, vec![Some(format!("{prefix}-named")), None]);
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
            id: None,
            id_contains: None,
            tags: None,
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
