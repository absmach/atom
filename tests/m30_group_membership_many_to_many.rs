//! Many-to-many object group membership.
//!
//! An entity or resource may belong to any number of object groups. The
//! security-relevant case is that a grant scoped to *either* of an object's
//! groups must authorize it. A single-membership evaluation path would read
//! one arbitrary membership row through `fetch_optional`, so grants held
//! through the object's other groups would be silently ignored —
//! non-deterministically, since which row won was unspecified.
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m30_group_membership_many_to_many -- --ignored
//! ```

mod common;

use atom::models::{
    access::AuthorizedObjectIdsQuery,
    entity::{CreateEntity, ListEntities},
    enums::{DeletedFilter, EntityKind},
    policy::AuthzRequest,
    resource::CreateResource,
};
use uuid::Uuid;

// ─── Fixtures ─────────────────────────────────────────────────────────────────

async fn make_tenant(pool: &sqlx::PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{name}-{id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn make_entity(pool: &sqlx::PgPool, tenant_id: Uuid, kind: EntityKind, name: &str) -> Uuid {
    atom::identity::repo::create_entity(
        pool,
        CreateEntity {
            id: None,
            kind: Some(kind),
            profile_id: None,
            profile_version_id: None,
            name: format!("m30-{name}-{}", Uuid::new_v4()),
            alias: None,
            external_id: None,
            tenant_id: Some(tenant_id),
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect("create entity")
    .id
}

async fn make_resource(pool: &sqlx::PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    atom::authz::repo::create_resource(
        pool,
        CreateResource {
            id: None,
            kind: "channel".to_string(),
            name: Some(format!("m30-{name}-{}", Uuid::new_v4())),
            alias: None,
            tenant_id: Some(tenant_id),
            owner_id: None,
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect("create resource")
    .id
}

async fn make_object_group(pool: &sqlx::PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO object_groups (id, name, tenant_id) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("m30-{name}-{id}"))
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert object group");
    id
}

async fn link_object_groups(pool: &sqlx::PgPool, tenant_id: Uuid, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO object_group_hierarchy (parent_id, child_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(parent)
    .bind(child)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("link object groups");
}

async fn action_id(pool: &sqlx::PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM actions WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("action")
}

/// Grant `subject` the named action over the objects of one group, directly
/// (`group_direct_objects`) or across its whole subtree
/// (`group_descendant_objects`).
async fn grant_over_group(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    subject_id: Uuid,
    group_id: Uuid,
    scope_mode: &str,
    object_type: &str,
    action: Uuid,
) {
    let object_kind = object_type.split(':').next().expect("namespaced type");
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
           (scope_mode, object_kind, object_type, tenant_id, group_id, effect)
           VALUES ($1, $2, $3, $4, $5, 'allow')
           RETURNING id"#,
    )
    .bind(scope_mode)
    .bind(object_kind)
    .bind(object_type)
    .bind(tenant_id)
    .bind(group_id)
    .fetch_one(pool)
    .await
    .expect("insert permission block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(action)
    .execute(pool)
    .await
    .expect("insert block action");
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("assign direct policy");
}

async fn grant_tenant_wide(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    subject_id: Uuid,
    object_type: &str,
    action: Uuid,
) {
    let object_kind = object_type.split(':').next().expect("namespaced type");
    let block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks
           (scope_mode, object_kind, object_type, tenant_id, effect)
           VALUES ('object_type', $1, $2, $3, 'allow')
           RETURNING id"#,
    )
    .bind(object_kind)
    .bind(object_type)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("insert permission block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) VALUES ($1, $2)",
    )
    .bind(block_id)
    .bind(action)
    .execute(pool)
    .await
    .expect("insert block action");
    sqlx::query(
        r#"INSERT INTO direct_policies (tenant_id, subject_kind, subject_id, permission_block_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(tenant_id)
    .bind(subject_id)
    .bind(block_id)
    .execute(pool)
    .await
    .expect("assign direct policy");
}

async fn pdp_allows(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    object_kind: &str,
    object_id: Uuid,
) -> bool {
    atom::authz::engine::evaluate_with_ceiling(
        pool,
        &AuthzRequest {
            subject_id,
            action: "read".to_string(),
            resource_id: None,
            object_kind: Some(object_kind.to_string()),
            object_id: Some(object_id),
            context: serde_json::Value::Null,
        },
        None,
    )
    .await
    .expect("authz evaluate")
    .allowed
}

async fn authorized(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    object_kind: &str,
    object_type: &str,
    tenant_id: Uuid,
    parent_group_id: Option<Uuid>,
) -> atom::models::access::AuthorizedObjectIdsResponse {
    atom::authz::repo::authorized_object_ids_with_ceiling(
        pool,
        AuthorizedObjectIdsQuery {
            subject_id,
            action: "read".to_string(),
            object_kind: object_kind.to_string(),
            object_type: Some(object_type.to_string()),
            tenant_id: Some(tenant_id),
            q: None,
            attributes_contains: None,
            external_id: None,
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id,
            include_descendants: false,
            limit: 100,
            offset: 0,
        },
        None,
    )
    .await
    .expect("authorized listing")
}

// ─── An object belongs to several groups ───────────────────────────────────

#[tokio::test]
#[ignore]
async fn entity_belongs_to_every_group_it_is_added_to() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "membership").await;
    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let group_a = make_object_group(&pool, tenant_id, "customer-a").await;
    let group_b = make_object_group(&pool, tenant_id, "building-5").await;

    atom::identity::repo::add_entity_to_object_group(&pool, device, group_a)
        .await
        .expect("add to group a");
    atom::identity::repo::add_entity_to_object_group(&pool, device, group_b)
        .await
        .expect("add to group b");

    let mut groups = atom::identity::repo::get_entity_object_groups(&pool, device)
        .await
        .expect("entity object groups");
    groups.sort();
    let mut expected = vec![group_a, group_b];
    expected.sort();
    assert_eq!(
        groups, expected,
        "adding to a second group must not move the entity out of the first"
    );

    // The group-filtered listing finds the entity through either group.
    for group in [group_a, group_b] {
        let listed = atom::identity::repo::list_entities(
            &pool,
            ListEntities {
                q: None,
                kind: Some(EntityKind::Device),
                external_id: None,
                profile_id: None,
                tenant_id: Some(tenant_id),
                attributes_contains: None,
                status: None,
                deleted: DeletedFilter::Live,
                parent_group_id: Some(group),
                include_descendants: false,
                limit: 50,
                offset: 0,
            },
        )
        .await
        .expect("list entities");
        assert_eq!(listed.total, 1, "entity must be listed under {group}");
        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].id, device);
    }
}

#[tokio::test]
#[ignore]
async fn resource_belongs_to_every_group_it_is_added_to() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "res-membership").await;
    let channel = make_resource(&pool, tenant_id, "meter").await;
    let group_a = make_object_group(&pool, tenant_id, "customer-a").await;
    let group_b = make_object_group(&pool, tenant_id, "building-5").await;

    atom::authz::repo::add_resource_to_object_group(&pool, channel, group_a)
        .await
        .expect("add to group a");
    atom::authz::repo::add_resource_to_object_group(&pool, channel, group_b)
        .await
        .expect("add to group b");

    let mut groups = atom::authz::repo::get_resource_object_groups(&pool, channel)
        .await
        .expect("resource object groups");
    groups.sort();
    let mut expected = vec![group_a, group_b];
    expected.sort();
    assert_eq!(groups, expected);
}

// ─── Listings de-duplicate and count once ──────────────────────────────────

#[tokio::test]
#[ignore]
async fn multi_group_membership_does_not_duplicate_listings_or_inflate_total() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "dedup").await;
    let subject = make_entity(&pool, tenant_id, EntityKind::Human, "subject").await;
    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let read = action_id(&pool, "read").await;

    let groups = [
        make_object_group(&pool, tenant_id, "g1").await,
        make_object_group(&pool, tenant_id, "g2").await,
        make_object_group(&pool, tenant_id, "g3").await,
    ];
    for group in groups {
        atom::identity::repo::add_entity_to_object_group(&pool, device, group)
            .await
            .expect("add to group");
    }

    grant_tenant_wide(&pool, tenant_id, subject, "entity:device", read).await;

    // Unfiltered: three membership rows must still yield exactly one candidate.
    let listing = authorized(&pool, subject, "entity", "entity:device", tenant_id, None).await;
    assert_eq!(
        listing.ids,
        vec![device],
        "an entity in three groups must be listed once"
    );
    assert_eq!(listing.total, 1, "total must count the entity once");

    // Filtered by any one of the groups: still exactly one row.
    for group in groups {
        let listing = authorized(
            &pool,
            subject,
            "entity",
            "entity:device",
            tenant_id,
            Some(group),
        )
        .await;
        assert_eq!(listing.ids, vec![device], "filtered by {group}");
        assert_eq!(listing.total, 1, "filtered total for {group}");
    }

    // Pagination: a second multi-group device must page as two rows, not six.
    // A duplicating join would inflate `total` and make every page repeat rows.
    let second = make_entity(&pool, tenant_id, EntityKind::Device, "device-2").await;
    for group in groups {
        atom::identity::repo::add_entity_to_object_group(&pool, second, group)
            .await
            .expect("add second device to group");
    }

    let mut paged = Vec::new();
    for offset in [0, 1] {
        let page = atom::authz::repo::authorized_object_ids_with_ceiling(
            &pool,
            AuthorizedObjectIdsQuery {
                subject_id: subject,
                action: "read".to_string(),
                object_kind: "entity".to_string(),
                object_type: Some("entity:device".to_string()),
                tenant_id: Some(tenant_id),
                q: None,
                attributes_contains: None,
                external_id: None,
                profile_id: None,
                entity_status: None,
                group_type: None,
                parent_group_id: None,
                include_descendants: false,
                limit: 1,
                offset,
            },
            None,
        )
        .await
        .expect("authorized listing page");
        assert_eq!(page.total, 2, "total must count each device once");
        assert_eq!(page.ids.len(), 1, "limit must cap the page");
        paged.extend(page.ids);
    }
    paged.sort();
    let mut expected = vec![device, second];
    expected.sort();
    assert_eq!(
        paged, expected,
        "paging must walk each device exactly once across pages"
    );
}

// ─── A grant via EITHER group authorizes the object ───────────────────────────

/// The security-critical case: a device in G1 and G2, with the grant held
/// only through G2, must be authorized — and symmetrically when the grant is
/// held only through G1. An evaluation path that keeps one arbitrary
/// membership row fails one of these two directions depending on row order.
#[tokio::test]
#[ignore]
async fn grant_via_either_group_authorizes_the_entity() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "either-group").await;
    let read = action_id(&pool, "read").await;

    let device = make_entity(&pool, tenant_id, EntityKind::Device, "meter-7").await;
    let group_a = make_object_group(&pool, tenant_id, "customer-a").await;
    let group_b = make_object_group(&pool, tenant_id, "building-5").await;
    let unrelated = make_object_group(&pool, tenant_id, "unrelated").await;

    atom::identity::repo::add_entity_to_object_group(&pool, device, group_a)
        .await
        .expect("add to group a");
    atom::identity::repo::add_entity_to_object_group(&pool, device, group_b)
        .await
        .expect("add to group b");

    // One subject per group, so each direction is checked independently and
    // neither can be satisfied by the other's grant.
    let via_a = make_entity(&pool, tenant_id, EntityKind::Human, "via-a").await;
    let via_b = make_entity(&pool, tenant_id, EntityKind::Human, "via-b").await;
    let via_unrelated = make_entity(&pool, tenant_id, EntityKind::Human, "via-none").await;
    grant_over_group(
        &pool,
        tenant_id,
        via_a,
        group_a,
        "group_direct_objects",
        "entity:device",
        read,
    )
    .await;
    grant_over_group(
        &pool,
        tenant_id,
        via_b,
        group_b,
        "group_direct_objects",
        "entity:device",
        read,
    )
    .await;
    grant_over_group(
        &pool,
        tenant_id,
        via_unrelated,
        unrelated,
        "group_direct_objects",
        "entity:device",
        read,
    )
    .await;

    for (subject, group) in [(via_a, group_a), (via_b, group_b)] {
        assert!(
            pdp_allows(&pool, subject, "entity", device).await,
            "PDP must allow a grant held via {group}"
        );
        let listing = authorized(&pool, subject, "entity", "entity:device", tenant_id, None).await;
        assert_eq!(
            listing.ids,
            vec![device],
            "authorized listing must surface the entity for a grant via {group}"
        );
    }

    assert!(
        !pdp_allows(&pool, via_unrelated, "entity", device).await,
        "a grant over a group the entity is not in must not authorize it"
    );
    assert!(
        authorized(
            &pool,
            via_unrelated,
            "entity",
            "entity:device",
            tenant_id,
            None
        )
        .await
        .ids
        .is_empty(),
        "listing must not surface the entity for an unrelated group grant"
    );
}

#[tokio::test]
#[ignore]
async fn grant_via_either_group_authorizes_the_resource() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "either-group-res").await;
    let read = action_id(&pool, "read").await;

    let channel = make_resource(&pool, tenant_id, "meter-7").await;
    let group_a = make_object_group(&pool, tenant_id, "customer-a").await;
    let group_b = make_object_group(&pool, tenant_id, "building-5").await;
    atom::authz::repo::add_resource_to_object_group(&pool, channel, group_a)
        .await
        .expect("add to group a");
    atom::authz::repo::add_resource_to_object_group(&pool, channel, group_b)
        .await
        .expect("add to group b");

    let via_a = make_entity(&pool, tenant_id, EntityKind::Human, "res-via-a").await;
    let via_b = make_entity(&pool, tenant_id, EntityKind::Human, "res-via-b").await;
    grant_over_group(
        &pool,
        tenant_id,
        via_a,
        group_a,
        "group_direct_objects",
        "resource:channel",
        read,
    )
    .await;
    grant_over_group(
        &pool,
        tenant_id,
        via_b,
        group_b,
        "group_direct_objects",
        "resource:channel",
        read,
    )
    .await;

    for (subject, group) in [(via_a, group_a), (via_b, group_b)] {
        assert!(
            pdp_allows(&pool, subject, "resource", channel).await,
            "PDP must allow a resource grant held via {group}"
        );
        assert_eq!(
            authorized(
                &pool,
                subject,
                "resource",
                "resource:channel",
                tenant_id,
                None
            )
            .await
            .ids,
            vec![channel],
            "listing must surface the resource for a grant via {group}"
        );
    }
}

// ─── Removing one membership leaves the others intact ─────────────────────────

#[tokio::test]
#[ignore]
async fn removing_one_group_leaves_the_other_membership_and_its_grants() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "remove-one").await;
    let read = action_id(&pool, "read").await;

    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let group_a = make_object_group(&pool, tenant_id, "g-a").await;
    let group_b = make_object_group(&pool, tenant_id, "g-b").await;
    atom::identity::repo::add_entity_to_object_group(&pool, device, group_a)
        .await
        .expect("add a");
    atom::identity::repo::add_entity_to_object_group(&pool, device, group_b)
        .await
        .expect("add b");

    let via_a = make_entity(&pool, tenant_id, EntityKind::Human, "via-a").await;
    let via_b = make_entity(&pool, tenant_id, EntityKind::Human, "via-b").await;
    grant_over_group(
        &pool,
        tenant_id,
        via_a,
        group_a,
        "group_direct_objects",
        "entity:device",
        read,
    )
    .await;
    grant_over_group(
        &pool,
        tenant_id,
        via_b,
        group_b,
        "group_direct_objects",
        "entity:device",
        read,
    )
    .await;

    atom::identity::repo::remove_entity_from_object_group(&pool, device, group_a)
        .await
        .expect("remove from group a");

    assert_eq!(
        atom::identity::repo::get_entity_object_groups(&pool, device)
            .await
            .expect("groups"),
        vec![group_b],
        "removing one membership must leave the other"
    );
    assert!(
        !pdp_allows(&pool, via_a, "entity", device).await,
        "the removed group's grant must no longer authorize"
    );
    assert!(
        pdp_allows(&pool, via_b, "entity", device).await,
        "the surviving group's grant must still authorize"
    );

    // Remove-from-all is a separate, explicitly named operation.
    atom::identity::repo::clear_entity_object_groups(&pool, device)
        .await
        .expect("clear all groups");
    assert!(
        atom::identity::repo::get_entity_object_groups(&pool, device)
            .await
            .expect("groups")
            .is_empty()
    );
    assert!(!pdp_allows(&pool, via_b, "entity", device).await);
}

// ─── No-op removals do not publish membership-change events ───────────────────

async fn outbox_row_exists(pool: &sqlx::PgPool, event: &str, target_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM event_outbox
                         WHERE event = $1 AND (payload->>'target_id')::uuid = $2)",
    )
    .bind(event)
    .bind(target_id)
    .fetch_one(pool)
    .await
    .expect("query event_outbox")
}

#[tokio::test]
#[ignore]
async fn removing_a_membership_that_never_existed_publishes_no_event() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "noop-entity-remove").await;
    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let group = make_object_group(&pool, tenant_id, "g").await;

    atom::identity::repo::remove_entity_from_object_group_with_audit(
        &pool, true, None, device, group,
    )
    .await
    .expect("no-op remove must still succeed");

    assert!(
        !outbox_row_exists(&pool, "entity.object_group.remove", device).await,
        "removing a membership that never existed must not publish an event"
    );
}

#[tokio::test]
#[ignore]
async fn removing_an_existing_membership_still_publishes_its_event() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "real-entity-remove").await;
    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let group = make_object_group(&pool, tenant_id, "g").await;
    atom::identity::repo::add_entity_to_object_group(&pool, device, group)
        .await
        .expect("add membership");

    atom::identity::repo::remove_entity_from_object_group_with_audit(
        &pool, true, None, device, group,
    )
    .await
    .expect("remove");

    assert!(
        outbox_row_exists(&pool, "entity.object_group.remove", device).await,
        "an actual removal must still publish its event"
    );
}

#[tokio::test]
#[ignore]
async fn clearing_an_already_empty_entity_membership_set_publishes_no_event() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "noop-entity-clear").await;
    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;

    atom::identity::repo::clear_entity_object_groups_with_audit(&pool, true, None, device)
        .await
        .expect("no-op clear must still succeed");

    assert!(
        !outbox_row_exists(&pool, "entity.object_groups.clear", device).await,
        "clearing an already-empty membership set must not publish an event"
    );
}

#[tokio::test]
#[ignore]
async fn removing_a_resource_membership_that_never_existed_publishes_no_event() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "noop-resource-remove").await;
    let resource = make_resource(&pool, tenant_id, "channel").await;
    let group = make_object_group(&pool, tenant_id, "g").await;

    atom::authz::repo::remove_resource_from_object_group_with_audit(
        &pool, true, None, resource, group,
    )
    .await
    .expect("no-op remove must still succeed");

    assert!(
        !outbox_row_exists(&pool, "resource.object_group.remove", resource).await,
        "removing a membership that never existed must not publish an event"
    );
}

#[tokio::test]
#[ignore]
async fn clearing_an_already_empty_resource_membership_set_publishes_no_event() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "noop-resource-clear").await;
    let resource = make_resource(&pool, tenant_id, "channel").await;

    atom::authz::repo::clear_resource_object_groups_with_audit(&pool, true, None, resource)
        .await
        .expect("no-op clear must still succeed");

    assert!(
        !outbox_row_exists(&pool, "resource.object_groups.clear", resource).await,
        "clearing an already-empty membership set must not publish an event"
    );
}

// ─── Descendant traversal across two subtrees ──────────────────────────────

#[tokio::test]
#[ignore]
async fn descendant_traversal_covers_every_subtree_the_object_sits_in() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "subtrees").await;
    let read = action_id(&pool, "read").await;

    let root_a = make_object_group(&pool, tenant_id, "root-a").await;
    let child_a = make_object_group(&pool, tenant_id, "child-a").await;
    let root_b = make_object_group(&pool, tenant_id, "root-b").await;
    let child_b = make_object_group(&pool, tenant_id, "child-b").await;
    link_object_groups(&pool, tenant_id, root_a, child_a).await;
    link_object_groups(&pool, tenant_id, root_b, child_b).await;

    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    atom::identity::repo::add_entity_to_object_group(&pool, device, child_a)
        .await
        .expect("add to child a");
    atom::identity::repo::add_entity_to_object_group(&pool, device, child_b)
        .await
        .expect("add to child b");

    let via_a = make_entity(&pool, tenant_id, EntityKind::Human, "tree-a").await;
    let via_b = make_entity(&pool, tenant_id, EntityKind::Human, "tree-b").await;
    let via_none = make_entity(&pool, tenant_id, EntityKind::Human, "tree-none").await;
    let unrelated_root = make_object_group(&pool, tenant_id, "root-c").await;
    for (subject, root) in [(via_a, root_a), (via_b, root_b), (via_none, unrelated_root)] {
        grant_over_group(
            &pool,
            tenant_id,
            subject,
            root,
            "group_descendant_objects",
            "entity:device",
            read,
        )
        .await;
    }

    for (subject, root) in [(via_a, root_a), (via_b, root_b)] {
        assert!(
            pdp_allows(&pool, subject, "entity", device).await,
            "a descendant grant on {root} must reach an entity in that subtree"
        );
        assert_eq!(
            authorized(&pool, subject, "entity", "entity:device", tenant_id, None)
                .await
                .ids,
            vec![device],
            "descendant listing must surface the entity for subtree {root}"
        );
    }
    assert!(
        !pdp_allows(&pool, via_none, "entity", device).await,
        "a descendant grant on an unrelated subtree must not reach the entity"
    );
}

// ─── Re-adding is idempotent ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn re_adding_an_existing_membership_is_idempotent() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "idempotent").await;
    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let channel = make_resource(&pool, tenant_id, "channel").await;
    let group = make_object_group(&pool, tenant_id, "g").await;

    for _ in 0..3 {
        atom::identity::repo::add_entity_to_object_group(&pool, device, group)
            .await
            .expect("re-add entity membership");
        atom::authz::repo::add_resource_to_object_group(&pool, channel, group)
            .await
            .expect("re-add resource membership");
    }

    let entity_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_entities WHERE entity_id = $1 AND group_id = $2",
    )
    .bind(device)
    .bind(group)
    .fetch_one(&pool)
    .await
    .expect("count entity memberships");
    assert_eq!(entity_rows, 1);

    let resource_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM object_group_resources WHERE resource_id = $1 AND group_id = $2",
    )
    .bind(channel)
    .bind(group)
    .fetch_one(&pool)
    .await
    .expect("count resource memberships");
    assert_eq!(resource_rows, 1);
}

// ─── Cross-tenant membership stays rejected ────────────────────────────────

#[tokio::test]
#[ignore]
async fn cross_tenant_membership_is_rejected() {
    let pool = common::pool().await;
    let tenant_a = make_tenant(&pool, "xt-a").await;
    let tenant_b = make_tenant(&pool, "xt-b").await;
    let device = make_entity(&pool, tenant_a, EntityKind::Device, "device").await;
    let channel = make_resource(&pool, tenant_a, "channel").await;
    let foreign_group = make_object_group(&pool, tenant_b, "foreign").await;

    assert!(
        atom::identity::repo::add_entity_to_object_group(&pool, device, foreign_group)
            .await
            .is_err(),
        "an entity must not join a group in another tenant"
    );
    assert!(
        atom::authz::repo::add_resource_to_object_group(&pool, channel, foreign_group)
            .await
            .is_err(),
        "a resource must not join a group in another tenant"
    );

    let rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM object_group_entities WHERE group_id = $1)
              + (SELECT COUNT(*) FROM object_group_resources WHERE group_id = $1)",
    )
    .bind(foreign_group)
    .fetch_one(&pool)
    .await
    .expect("count foreign memberships");
    assert_eq!(rows, 0);
}

// ─── The `parent_group_id` attribute path is gone ─────────────────────────────

/// Membership is a set, which a scalar attribute cannot express, so the
/// attribute write path was removed rather than kept as a "sole membership"
/// convenience. It is rejected rather than ignored: a caller that still sends it
/// would otherwise believe it had placed the object in a group.
#[tokio::test]
#[ignore]
async fn parent_group_id_attribute_is_rejected_on_create_and_update() {
    let pool = common::pool().await;
    let tenant_id = make_tenant(&pool, "attr").await;
    let group = make_object_group(&pool, tenant_id, "g").await;

    let entity_err = atom::identity::repo::create_entity(
        &pool,
        CreateEntity {
            id: None,
            kind: Some(EntityKind::Device),
            profile_id: None,
            profile_version_id: None,
            name: format!("m30-attr-{}", Uuid::new_v4()),
            alias: None,
            external_id: None,
            tenant_id: Some(tenant_id),
            attributes: serde_json::json!({ "parent_group_id": group.to_string() }),
        },
    )
    .await;
    assert!(
        entity_err.is_err(),
        "createEntity must reject the parent_group_id attribute"
    );

    let resource_err = atom::authz::repo::create_resource(
        &pool,
        CreateResource {
            id: None,
            kind: "channel".to_string(),
            name: Some(format!("m30-attr-{}", Uuid::new_v4())),
            alias: None,
            tenant_id: Some(tenant_id),
            owner_id: None,
            attributes: serde_json::json!({ "parent_group_id": group.to_string() }),
        },
    )
    .await;
    assert!(
        resource_err.is_err(),
        "createResource must reject the parent_group_id attribute"
    );

    let device = make_entity(&pool, tenant_id, EntityKind::Device, "device").await;
    let update_err = atom::identity::repo::update_entity(
        &pool,
        device,
        atom::models::entity::UpdateEntity {
            name: None,
            kind: None,
            alias: None,
            external_id: None,
            tenant_id: None,
            profile_id: None,
            profile_version_id: None,
            status: None,
            attributes: Some(serde_json::json!({ "parent_group_id": group.to_string() })),
        },
    )
    .await;
    assert!(
        update_err.is_err(),
        "updateEntity must reject the parent_group_id attribute"
    );
    assert!(
        atom::identity::repo::get_entity_object_groups(&pool, device)
            .await
            .expect("groups")
            .is_empty(),
        "a rejected attribute must not have created a membership"
    );
}

// ─── The migration preserves existing single memberships ──────────────────────

/// Seeds single memberships against the pre-change schema (migrations 001–004),
/// then applies 005 and asserts every row survives unchanged, in a scratch
/// database so the shared test database is untouched.
#[tokio::test]
#[ignore]
async fn migration_preserves_existing_single_memberships() {
    use sqlx::{Connection, Executor, PgConnection};

    let admin_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let scratch = format!("atom_m30_{}", Uuid::new_v4().simple());
    let scratch_url = {
        let (base, _) = admin_url
            .rsplit_once('/')
            .expect("database url with a path");
        format!("{base}/{scratch}")
    };

    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("connect for scratch database");
    admin
        .execute(format!(r#"CREATE DATABASE "{scratch}""#).as_str())
        .await
        .expect("create scratch database");

    let result = seed_and_migrate(&scratch_url).await;

    // Always drop the scratch database, then surface any failure.
    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)"#).as_str())
        .await;
    admin.close().await.expect("close admin connection");
    result.expect("migration preserved pre-change memberships");
}

async fn seed_and_migrate(scratch_url: &str) -> Result<(), String> {
    use sqlx::Connection;

    let mut conn = sqlx::PgConnection::connect(scratch_url)
        .await
        .map_err(|e| format!("connect scratch: {e}"))?;

    for file in [
        "001_initial.sql",
        "002_platform_filtered_permission_scopes.sql",
        "003_access_token_usage_and_ceiling_scope.sql",
        "004_event_outbox.sql",
    ] {
        let sql = std::fs::read_to_string(format!("./migrations/{file}"))
            .map_err(|e| format!("read {file}: {e}"))?;
        sqlx::raw_sql(&sql)
            .execute(&mut conn)
            .await
            .map_err(|e| format!("apply {file}: {e}"))?;
    }

    // Pre-change data: one membership per entity and per resource, which is all
    // the old `PRIMARY KEY (entity_id)` / `(resource_id)` allowed.
    let tenant = Uuid::new_v4();
    let group_one = Uuid::new_v4();
    let group_two = Uuid::new_v4();
    let entity_one = Uuid::new_v4();
    let entity_two = Uuid::new_v4();
    let resource_one = Uuid::new_v4();

    let seed = format!(
        r#"
        INSERT INTO tenants (id, name) VALUES ('{tenant}', 'm30-migration');
        INSERT INTO object_groups (id, name, tenant_id) VALUES
            ('{group_one}', 'm30-g1', '{tenant}'),
            ('{group_two}', 'm30-g2', '{tenant}');
        INSERT INTO entities (id, kind, name, tenant_id, status) VALUES
            ('{entity_one}', 'device', 'm30-e1', '{tenant}', 'active'),
            ('{entity_two}', 'device', 'm30-e2', '{tenant}', 'active');
        INSERT INTO resources (id, kind, name, tenant_id) VALUES
            ('{resource_one}', 'channel', 'm30-r1', '{tenant}');
        INSERT INTO object_group_entities (group_id, entity_id, tenant_id) VALUES
            ('{group_one}', '{entity_one}', '{tenant}'),
            ('{group_two}', '{entity_two}', '{tenant}');
        INSERT INTO object_group_resources (group_id, resource_id, tenant_id) VALUES
            ('{group_one}', '{resource_one}', '{tenant}');
        "#
    );
    sqlx::raw_sql(&seed)
        .execute(&mut conn)
        .await
        .map_err(|e| format!("seed: {e}"))?;

    let migration =
        std::fs::read_to_string("./migrations/009_many_to_many_object_group_membership.sql")
            .map_err(|e| format!("read 009: {e}"))?;
    sqlx::raw_sql(&migration)
        .execute(&mut conn)
        .await
        .map_err(|e| format!("apply 009: {e}"))?;

    let entity_memberships: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT group_id, entity_id FROM object_group_entities ORDER BY entity_id")
            .fetch_all(&mut conn)
            .await
            .map_err(|e| format!("read entity memberships: {e}"))?;
    let mut expected = vec![(group_one, entity_one), (group_two, entity_two)];
    expected.sort_by_key(|(_, entity)| *entity);
    if entity_memberships != expected {
        return Err(format!(
            "entity memberships changed across the migration: {entity_memberships:?} != {expected:?}"
        ));
    }

    let resource_memberships: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT group_id, resource_id FROM object_group_resources")
            .fetch_all(&mut conn)
            .await
            .map_err(|e| format!("read resource memberships: {e}"))?;
    if resource_memberships != vec![(group_one, resource_one)] {
        return Err(format!(
            "resource memberships changed across the migration: {resource_memberships:?}"
        ));
    }

    // The widened key is in force: the same entity can now join a second group,
    // and the old member-only key would have rejected it.
    sqlx::query(
        "INSERT INTO object_group_entities (group_id, entity_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(group_two)
    .bind(entity_one)
    .bind(tenant)
    .execute(&mut conn)
    .await
    .map_err(|e| format!("second membership rejected after migration: {e}"))?;

    conn.close().await.map_err(|e| format!("close: {e}"))?;
    Ok(())
}
