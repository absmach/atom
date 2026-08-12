//! Entity `external_id` integration tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m31_entity_external_id -- --ignored
//! ```

mod common;

use common::pool;

use atom::authz::repo as authz_repo;
use atom::error::AppError;
use atom::identity::repo as identity_repo;
use atom::models::access::AuthorizedObjectIdsQuery;
use atom::models::entity::{CreateEntity, Entity, ListEntities, UpdateEntity};
use atom::models::enums::{DeletedFilter, EntityKind};
use atom::models::external_id::MAX_EXTERNAL_ID_LEN;
use atom::models::tenant::CreateTenant;
use atom::tenants::repo as tenant_repo;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn slug(prefix: &str) -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..12])
}

async fn make_tenant(pool: &PgPool) -> Uuid {
    tenant_repo::create_tenant(
        pool,
        CreateTenant {
            id: None,
            name: slug("tenant"),
            alias: Some(slug("t")),
            tags: vec![],
            attributes: json!({}),
        },
        None,
    )
    .await
    .expect("create tenant")
    .id
}

fn device(tenant_id: Option<Uuid>, external_id: Option<&str>) -> CreateEntity {
    CreateEntity {
        id: None,
        kind: Some(EntityKind::Device),
        profile_id: None,
        profile_version_id: None,
        name: slug("device"),
        alias: None,
        external_id: external_id.map(ToOwned::to_owned),
        tenant_id,
        attributes: json!({}),
    }
}

/// `UpdateEntity` with every field left unchanged, so a test can set exactly one.
fn no_op_update() -> UpdateEntity {
    UpdateEntity {
        name: None,
        kind: None,
        alias: None,
        external_id: None,
        tenant_id: None,
        profile_id: None,
        profile_version_id: None,
        status: None,
        attributes: None,
    }
}

async fn create(pool: &PgPool, req: CreateEntity) -> Entity {
    identity_repo::create_entity(pool, req)
        .await
        .expect("create entity")
}

// ─── Arbitrary strings round-trip byte-identical ───────────────────────────

#[tokio::test]
#[ignore]
async fn hostile_external_ids_round_trip_byte_identical() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // Every one of these is rejected by the `alias` slug rule. That is the
    // point: `external_id` is a foreign key into someone else's namespace and
    // Atom must not constrain its format.
    let hostile = [
        "WM-2024-ABC.123",
        "MixedCase-SERIAL",
        "topic/with/slashes",
        "serial with interior spaces",
        "quote's and \"double quotes\"",
        "back\\slash",
        "semicolon; DROP TABLE entities;--",
        "序列号-42",
        "emoji-🦀-serial",
        "ünïcödé-ÅÄÖ",
        "465358f9-07f4-4ea0-8cbb-2abc654442bd",
        "%s %d {} $1 ${x}",
    ];

    for value in hostile {
        let created = create(&p, device(Some(tenant_id), Some(value))).await;
        assert_eq!(
            created.external_id.as_deref(),
            Some(value),
            "{value:?} must be stored verbatim"
        );

        let read_back = identity_repo::get_entity(&p, created.id)
            .await
            .expect("read entity back");
        assert_eq!(
            read_back.external_id.as_deref(),
            Some(value),
            "{value:?} must read back byte-identical"
        );
    }
}

#[tokio::test]
#[ignore]
async fn a_nul_byte_is_rejected_rather_than_surfacing_as_an_encoding_error() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // The one value a `TEXT` column physically cannot hold. Left unchecked it
    // reaches Postgres and comes back as `22021 invalid byte sequence`, which
    // the error mapper reports as a bare 500 "database error".
    let err = identity_repo::create_entity(&p, device(Some(tenant_id), Some("ab\0cd")))
        .await
        .expect_err("a NUL byte must be rejected");

    match err {
        AppError::BadRequest(msg) => assert!(
            msg.contains("NUL"),
            "the error must explain the NUL byte, got: {msg}"
        ),
        other => panic!("expected a BadRequest about the NUL byte, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn external_id_accepts_values_up_to_the_length_cap() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // The cap counts characters, not bytes, so a multi-byte value at the cap
    // must still be accepted.
    let at_cap: String = "é".repeat(MAX_EXTERNAL_ID_LEN);
    let created = create(&p, device(Some(tenant_id), Some(&at_cap))).await;
    assert_eq!(created.external_id.as_deref(), Some(at_cap.as_str()));
}

#[tokio::test]
#[ignore]
async fn over_long_external_ids_are_rejected_with_an_actionable_error() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // A ~1KB value must be rejected, not silently truncated or accepted: an
    // index entry over a multi-kilobyte value is pathological, and past
    // ~2704 bytes Postgres refuses the insert outright with an unreadable
    // internal error. The rejection must be a plain validation message
    // (see the cap in `models::external_id`), not that internal error.
    let kilobyte = "x".repeat(1024);
    let err = identity_repo::create_entity(&p, device(Some(tenant_id), Some(&kilobyte)))
        .await
        .expect_err("a 1KB external_id must be rejected");

    match err {
        AppError::BadRequest(msg) => assert!(
            msg.contains("externalId") && msg.contains("255"),
            "error must name the field and the cap, got: {msg}"
        ),
        other => panic!("expected a BadRequest, got {other:?}"),
    }

    // One character over the cap is rejected too — the boundary is exact.
    let over_by_one = "x".repeat(MAX_EXTERNAL_ID_LEN + 1);
    assert!(
        identity_repo::create_entity(&p, device(Some(tenant_id), Some(&over_by_one)))
            .await
            .is_err(),
        "{} characters must be rejected",
        MAX_EXTERNAL_ID_LEN + 1
    );
}

// ─── Case sensitivity ───────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn external_id_is_case_sensitive() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let base = slug("SN").to_uppercase();
    let lower = base.to_lowercase();

    // DECISION: case-sensitive. `ABC123` and `abc123` are two different
    // devices and both must coexist in one tenant. Folding them would merge two
    // physical devices into one row with no migration back, so this test is the
    // guard on that door — if it ever fails, the change is not a bug fix.
    let upper_entity = create(&p, device(Some(tenant_id), Some(&base))).await;
    let lower_entity = create(&p, device(Some(tenant_id), Some(&lower))).await;

    assert_ne!(upper_entity.id, lower_entity.id);
    assert_eq!(upper_entity.external_id.as_deref(), Some(base.as_str()));
    assert_eq!(lower_entity.external_id.as_deref(), Some(lower.as_str()));

    // Lookup is case-sensitive too: the uppercase value must not find the
    // lowercase row.
    let found = list_by_external_id(&p, &base).await;
    assert_eq!(found, vec![upper_entity.id]);
}

// ─── Whitespace ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn edge_whitespace_is_trimmed_so_padded_values_are_the_same_entity() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("WM").to_uppercase();

    // DECISION: leading/trailing whitespace is trimmed. Edge whitespace is a
    // transport artifact (a trailing newline off a serial console, a padded CSV
    // cell), never data.
    let padded = format!("  {serial}\t\n");
    let created = create(&p, device(Some(tenant_id), Some(&padded))).await;
    assert_eq!(
        created.external_id.as_deref(),
        Some(serial.as_str()),
        "edge whitespace must be trimmed before storing"
    );

    // ...and because it is trimmed, the padded and unpadded forms are the *same*
    // entity, so writing the bare form collides.
    let dup = identity_repo::create_entity(&p, device(Some(tenant_id), Some(&serial))).await;
    assert!(
        dup.is_err(),
        "the padded and unpadded forms must be one identity, not two"
    );

    // Interior whitespace is data and is preserved.
    let interior = format!("{serial} REV B");
    let kept = create(&p, device(Some(tenant_id), Some(&interior))).await;
    assert_eq!(kept.external_id.as_deref(), Some(interior.as_str()));

    // The lookup side is trimmed the same way, so a padded filter finds the row.
    let found = list_by_external_id(&p, &format!("  {serial}  ")).await;
    assert_eq!(found, vec![created.id]);
}

#[tokio::test]
#[ignore]
async fn the_schema_enforces_the_trim_and_length_decisions_against_direct_writes() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // The application normalizes, but the decisions are also CHECK constraints,
    // so they are properties of the data rather than of whichever client wrote
    // the row. Bypass the repo entirely and confirm the schema still holds.
    for bad in [
        " leading".to_string(),
        "trailing ".to_string(),
        "trailing-newline\n".to_string(),
        String::new(),
        "x".repeat(MAX_EXTERNAL_ID_LEN + 1),
    ] {
        let err = sqlx::query(
            "INSERT INTO entities (kind, name, external_id, tenant_id)
             VALUES ('device', $1, $2, $3)",
        )
        .bind(slug("direct"))
        .bind(&bad)
        .bind(tenant_id)
        .execute(&p)
        .await
        .expect_err("the schema must reject {bad:?}");

        let code = err
            .as_database_error()
            .and_then(|db| db.code())
            .map(|code| code.into_owned());
        assert_eq!(
            code.as_deref(),
            Some("23514"),
            "{bad:?} must violate a CHECK constraint"
        );
    }
}

// ─── Uniqueness scope ───────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn same_tenant_collision_is_a_clear_conflict_not_a_raw_constraint_violation() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN");

    create(&p, device(Some(tenant_id), Some(&serial))).await;
    let err = identity_repo::create_entity(&p, device(Some(tenant_id), Some(&serial)))
        .await
        .expect_err("a same-tenant duplicate must be rejected");

    // The generic 23505 handling reports a bare "already exists", which a caller
    // writing several unique fields at once cannot act on. This must name the
    // field.
    match err {
        AppError::Conflict(msg) => assert!(
            msg.contains("externalId"),
            "the conflict must name externalId, got: {msg}"
        ),
        other => panic!("expected a Conflict naming externalId, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn updating_onto_a_taken_external_id_is_the_same_clear_conflict() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let taken = slug("SN");

    create(&p, device(Some(tenant_id), Some(&taken))).await;
    let other = create(&p, device(Some(tenant_id), None)).await;

    let err = identity_repo::update_entity(
        &p,
        other.id,
        UpdateEntity {
            external_id: Some(Some(taken)),
            ..no_op_update()
        },
    )
    .await
    .expect_err("updating onto a taken external_id must be rejected");

    match err {
        AppError::Conflict(msg) => assert!(
            msg.contains("externalId"),
            "the conflict must name externalId, got: {msg}"
        ),
        other => panic!("expected a Conflict naming externalId, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn a_name_collision_still_reports_the_generic_conflict() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let name = slug("shared-name");

    let first = CreateEntity {
        name: name.clone(),
        ..device(Some(tenant_id), None)
    };
    let second = CreateEntity {
        name,
        ..device(Some(tenant_id), None)
    };
    create(&p, first).await;

    // Attributing 23505 to `external_id` must not swallow the *other* unique
    // indexes on the table — a name clash keeps its existing behaviour.
    let err = identity_repo::create_entity(&p, second)
        .await
        .expect_err("a duplicate name must still be rejected");
    assert!(
        matches!(err, AppError::Database(_)),
        "a name collision must keep the generic 23505 path, got {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn the_same_external_id_is_reusable_across_tenants() {
    let p = pool().await;
    let tenant_a = make_tenant(&p).await;
    let tenant_b = make_tenant(&p).await;
    let serial = slug("SN");

    let a = create(&p, device(Some(tenant_a), Some(&serial))).await;
    let b = create(&p, device(Some(tenant_b), Some(&serial))).await;

    assert_ne!(a.id, b.id);
    assert_eq!(a.external_id, b.external_id);
}

#[tokio::test]
#[ignore]
async fn tenant_less_entities_share_one_global_uniqueness_namespace() {
    let p = pool().await;
    let serial = slug("SN");

    // `tenant_id` is nullable, and raw SQL NULL semantics would make every NULL
    // distinct — leaving platform-level entities with no uniqueness at all. The
    // index coalesces NULL to the zero UUID so they share one namespace.
    create(&p, device(None, Some(&serial))).await;
    let dup = identity_repo::create_entity(&p, device(None, Some(&serial))).await;
    assert!(
        dup.is_err(),
        "two tenant-less entities must not share an external_id"
    );

    // A tenant-scoped entity may still take the same value.
    let tenant_id = make_tenant(&p).await;
    create(&p, device(Some(tenant_id), Some(&serial))).await;
}

#[tokio::test]
#[ignore]
async fn many_entities_may_have_no_external_id() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // Most entities have none; the partial index must not treat NULLs as
    // colliding with each other.
    for _ in 0..5 {
        let created = create(&p, device(Some(tenant_id), None)).await;
        assert_eq!(created.external_id, None);
    }

    // An empty / whitespace-only value is absent, not a value — so it does not
    // collide either.
    for blank in ["", "   ", "\t"] {
        let created = create(&p, device(Some(tenant_id), Some(blank))).await;
        assert_eq!(
            created.external_id, None,
            "{blank:?} must be stored as absent"
        );
    }
}

// ─── Mutable, and clearable ─────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn external_id_can_be_changed_and_cleared() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let first = slug("SN-first");
    let second = slug("SN-second");

    let entity = create(&p, device(Some(tenant_id), Some(&first))).await;

    let changed = identity_repo::update_entity(
        &p,
        entity.id,
        UpdateEntity {
            external_id: Some(Some(second.clone())),
            ..no_op_update()
        },
    )
    .await
    .expect("change external_id");
    assert_eq!(changed.external_id.as_deref(), Some(second.as_str()));

    // The old value is free again once nothing holds it.
    create(&p, device(Some(tenant_id), Some(&first))).await;

    let cleared = identity_repo::update_entity(
        &p,
        entity.id,
        UpdateEntity {
            external_id: Some(None),
            ..no_op_update()
        },
    )
    .await
    .expect("clear external_id");
    assert_eq!(cleared.external_id, None, "explicit null must clear it");

    // ...and clearing frees the value for another entity.
    create(&p, device(Some(tenant_id), Some(&second))).await;
}

#[tokio::test]
#[ignore]
async fn an_omitted_external_id_leaves_the_stored_value_untouched() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN");
    let entity = create(&p, device(Some(tenant_id), Some(&serial))).await;

    // Patch semantics: omitted is not the same as null. A rename must not wipe
    // the identifier.
    let renamed = identity_repo::update_entity(
        &p,
        entity.id,
        UpdateEntity {
            name: Some(slug("renamed")),
            ..no_op_update()
        },
    )
    .await
    .expect("rename without touching external_id");
    assert_eq!(renamed.external_id.as_deref(), Some(serial.as_str()));
}

// ─── Soft delete frees the value; restore can conflict ────────────────────────

#[tokio::test]
#[ignore]
async fn soft_delete_frees_the_external_id_and_a_reused_one_blocks_restore() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN");

    let old_meter = create(&p, device(Some(tenant_id), Some(&serial))).await;
    identity_repo::delete_entity(&p, old_meter.id, None)
        .await
        .expect("soft delete the old meter");

    // The index excludes soft-deleted rows, so replacing a meter with the same
    // serial works. That is the wanted behaviour...
    let replacement = create(&p, device(Some(tenant_id), Some(&serial))).await;
    assert_ne!(replacement.id, old_meter.id);

    // ...and its cost is that restoring the original now conflicts. It must be a
    // comprehensible error naming the field to free, not a raw constraint
    // violation.
    let err = identity_repo::restore_entity(&p, old_meter.id, None)
        .await
        .expect_err("restore must fail while the identifier is taken");
    match err {
        AppError::Conflict(msg) => assert!(
            msg.contains("externalId"),
            "the restore conflict must name externalId, got: {msg}"
        ),
        other => panic!("expected a Conflict naming externalId, got {other:?}"),
    }

    // The documented remedy works: free the identifier, then restore.
    identity_repo::update_entity(
        &p,
        replacement.id,
        UpdateEntity {
            external_id: Some(None),
            ..no_op_update()
        },
    )
    .await
    .expect("clear the replacement's external_id");
    identity_repo::restore_entity(&p, old_meter.id, None)
        .await
        .expect("restore once the identifier is free");

    let restored = identity_repo::get_entity(&p, old_meter.id)
        .await
        .expect("read the restored entity");
    assert_eq!(restored.external_id.as_deref(), Some(serial.as_str()));
}

#[tokio::test]
#[ignore]
async fn restore_succeeds_when_the_external_id_was_not_reused() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN");

    let entity = create(&p, device(Some(tenant_id), Some(&serial))).await;
    identity_repo::delete_entity(&p, entity.id, None)
        .await
        .expect("soft delete");
    identity_repo::restore_entity(&p, entity.id, None)
        .await
        .expect("restore must succeed when nothing took the identifier");

    let restored = identity_repo::get_entity(&p, entity.id)
        .await
        .expect("read the restored entity");
    assert_eq!(restored.external_id.as_deref(), Some(serial.as_str()));
}

// ─── The filter matches exactly, scoped, and uses the index ───────────────────

/// The live `entities(externalId:)` path: the authorized listing the resolver
/// calls, run as the seeded platform admin.
async fn list_by_external_id(pool: &PgPool, external_id: &str) -> Vec<Uuid> {
    authz_repo::authorized_object_ids_with_ceiling(
        pool,
        AuthorizedObjectIdsQuery {
            subject_id: common::admin_id(),
            action: "read".to_string(),
            object_kind: "entity".to_string(),
            object_type: None,
            tenant_id: None,
            q: None,
            attributes_contains: None,
            external_id: Some(external_id.to_string()),
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id: None,
            include_descendants: false,
            limit: 100,
            offset: 0,
        },
        None,
    )
    .await
    .expect("authorized entity listing")
    .ids
}

#[tokio::test]
#[ignore]
async fn the_external_id_filter_matches_exactly_and_scopes_to_tenant() {
    let p = pool().await;
    let tenant_a = make_tenant(&p).await;
    let tenant_b = make_tenant(&p).await;
    let serial = slug("SN").to_uppercase();

    let in_a = create(&p, device(Some(tenant_a), Some(&serial))).await;
    let in_b = create(&p, device(Some(tenant_b), Some(&serial))).await;
    // A near-miss that a substring search would wrongly return.
    create(&p, device(Some(tenant_a), Some(&format!("{serial}-EXTRA")))).await;

    let unscoped = list_by_external_id(&p, &serial).await;
    assert_eq!(
        unscoped.len(),
        2,
        "an un-scoped lookup returns the holder in each tenant, and nothing partially matching"
    );
    assert!(unscoped.contains(&in_a.id) && unscoped.contains(&in_b.id));

    let scoped = authz_repo::authorized_object_ids_with_ceiling(
        &p,
        AuthorizedObjectIdsQuery {
            subject_id: common::admin_id(),
            action: "read".to_string(),
            object_kind: "entity".to_string(),
            object_type: None,
            tenant_id: Some(tenant_a),
            q: None,
            attributes_contains: None,
            external_id: Some(serial.clone()),
            profile_id: None,
            entity_status: None,
            group_type: None,
            parent_group_id: None,
            include_descendants: false,
            limit: 100,
            offset: 0,
        },
        None,
    )
    .await
    .expect("tenant-scoped listing")
    .ids;
    assert_eq!(scoped, vec![in_a.id], "the filter must scope to the tenant");

    // An unknown identifier matches nothing rather than everything.
    assert!(list_by_external_id(&p, &slug("SN-absent")).await.is_empty());
}

/// A blank filter is a caller mistake, not "no filter": it must match zero
/// rows, not silently fall back to the unfiltered authorized set.
#[tokio::test]
#[ignore]
async fn a_blank_external_id_filter_matches_nothing_via_authorized_listing() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    create(&p, device(Some(tenant_id), Some(&slug("SN")))).await;
    create(&p, device(Some(tenant_id), None)).await;

    assert!(list_by_external_id(&p, "   ").await.is_empty());
}

#[tokio::test]
#[ignore]
async fn the_admin_deleted_listing_filters_by_external_id_too() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN");
    let entity = create(&p, device(Some(tenant_id), Some(&serial))).await;
    identity_repo::delete_entity(&p, entity.id, None)
        .await
        .expect("soft delete");

    let list = identity_repo::list_entities(
        &p,
        ListEntities {
            q: None,
            kind: None,
            external_id: Some(format!(" {serial} ")),
            profile_id: None,
            tenant_id: Some(tenant_id),
            attributes_contains: None,
            status: None,
            deleted: DeletedFilter::Deleted,
            parent_group_id: None,
            include_descendants: false,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("deleted listing");

    assert_eq!(list.total, 1);
    assert_eq!(list.items[0].id, entity.id);
}

/// Same caller-mistake guarantee as `authorized_object_ids`, on the other
/// `external_id` call site (`identity::repo::list_entities`).
#[tokio::test]
#[ignore]
async fn a_blank_external_id_filter_matches_nothing_via_list_entities() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    create(&p, device(Some(tenant_id), Some(&slug("SN")))).await;
    create(&p, device(Some(tenant_id), None)).await;

    let list = identity_repo::list_entities(
        &p,
        ListEntities {
            q: None,
            kind: None,
            external_id: Some("   ".to_string()),
            profile_id: None,
            tenant_id: Some(tenant_id),
            attributes_contains: None,
            status: None,
            deleted: DeletedFilter::Live,
            parent_group_id: None,
            include_descendants: false,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("blank external_id listing");

    assert_eq!(
        list.total, 0,
        "a blank external_id filter must match nothing"
    );
    assert!(list.items.is_empty());
}

#[tokio::test]
#[ignore]
async fn the_external_id_filter_uses_the_index_rather_than_scanning() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN-planned").to_uppercase();
    create(&p, device(Some(tenant_id), Some(&serial))).await;

    // A seq scan is genuinely cheapest on a handful of rows, so the plan only
    // means something once the table is big enough for the choice to matter.
    sqlx::query(
        "INSERT INTO entities (kind, name, external_id, tenant_id)
         SELECT 'device', 'plan-filler-' || g, 'PLAN-FILLER-' || g, $1
         FROM generate_series(1, 5000) g",
    )
    .bind(tenant_id)
    .execute(&p)
    .await
    .expect("seed filler entities");
    sqlx::query("ANALYZE entities")
        .execute(&p)
        .await
        .expect("analyze");

    // The predicate shape is the one `authorized_entity_ids` builds, parameter
    // form and all — testing a hand-simplified query would prove nothing about
    // the resolver.
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT e.id
         FROM entities e
         WHERE e.deleted_at IS NULL
           AND ($1::uuid IS NULL OR e.tenant_id = $1)
           AND ($2::text IS NULL OR e.external_id = $2)",
    )
    .bind(Option::<Uuid>::None)
    .bind(&serial)
    .fetch_all(&p)
    .await
    .expect("explain the external_id filter");
    let plan = plan.join("\n");

    // Drop the filler before asserting, so a failure does not also leave 5000
    // rows behind for every other test sharing this database.
    sqlx::query("DELETE FROM entities WHERE tenant_id = $1 AND name LIKE 'plan-filler-%'")
        .bind(tenant_id)
        .execute(&p)
        .await
        .expect("remove filler entities");

    assert!(
        plan.contains("idx_entities_external_id"),
        "the externalId filter must seek the index, not scan the table. Plan was:\n{plan}"
    );
    assert!(
        !plan.contains("Seq Scan on entities"),
        "the externalId filter must not fall back to a sequential scan. Plan was:\n{plan}"
    );
}

// ─── The value travels on the domain events ────────────────────────────────

async fn latest_outbox_details(pool: &PgPool, target_id: Uuid, event: &str) -> serde_json::Value {
    sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload -> 'details'
         FROM event_outbox
         WHERE event = $1 AND payload ->> 'target_id' = $2::text
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(event)
    .bind(target_id.to_string())
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("no {event} outbox row for {target_id}: {e}"))
}

#[tokio::test]
#[ignore]
async fn create_and_update_events_carry_the_external_id() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;
    let serial = slug("SN-evented");

    // Consumers denormalize this value onto their own rows (Magistrala keeps it
    // on every message), so the event has to carry the value itself, not merely
    // the fact that something changed.
    let entity = identity_repo::create_entity_with_audit(
        &p,
        true,
        None,
        device(Some(tenant_id), Some(&serial)),
    )
    .await
    .expect("create entity with events enabled");

    let created = latest_outbox_details(&p, entity.id, "entity.create").await;
    assert_eq!(created["external_id"], json!(serial));

    let changed = slug("SN-changed");
    identity_repo::update_entity_with_audit(
        &p,
        true,
        None,
        entity.id,
        UpdateEntity {
            external_id: Some(Some(changed.clone())),
            ..no_op_update()
        },
        "entity.update",
        json!({ "updated_fields": ["external_id"] }),
    )
    .await
    .expect("update entity with events enabled");

    let updated = latest_outbox_details(&p, entity.id, "entity.update").await;
    assert_eq!(updated["external_id"], json!(changed));
    assert_eq!(
        updated["updated_fields"],
        json!(["external_id"]),
        "the caller's own details must survive alongside it"
    );

    // Clearing it publishes an explicit null, so a consumer can drop its copy
    // rather than keeping a stale one.
    identity_repo::update_entity_with_audit(
        &p,
        true,
        None,
        entity.id,
        UpdateEntity {
            external_id: Some(None),
            ..no_op_update()
        },
        "entity.update",
        json!({ "updated_fields": ["external_id"] }),
    )
    .await
    .expect("clear external_id with events enabled");

    let cleared = latest_outbox_details(&p, entity.id, "entity.update").await;
    assert!(
        cleared["external_id"].is_null(),
        "clearing must publish an explicit null, got {}",
        cleared["external_id"]
    );
}

// ─── Existing entities are unaffected ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn rows_written_without_an_external_id_are_untouched_by_the_migration() {
    let p = pool().await;
    let tenant_id = make_tenant(&p).await;

    // Stands in for a row that predates the migration: written through the
    // column list as it was before, so the new column takes its default.
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, tenant_id) VALUES ($1, 'device', $2, $3)")
        .bind(id)
        .bind(slug("legacy"))
        .bind(tenant_id)
        .execute(&p)
        .await
        .expect("insert a pre-migration-shaped row");

    let legacy = identity_repo::get_entity(&p, id)
        .await
        .expect("read the legacy row");
    assert_eq!(legacy.external_id, None);

    // It still updates, deletes and restores normally.
    identity_repo::update_entity(
        &p,
        id,
        UpdateEntity {
            name: Some(slug("legacy-renamed")),
            ..no_op_update()
        },
    )
    .await
    .expect("update a legacy row");
    identity_repo::delete_entity(&p, id, None)
        .await
        .expect("delete a legacy row");
    identity_repo::restore_entity(&p, id, None)
        .await
        .expect("restore a legacy row");
}

#[tokio::test]
#[ignore]
async fn every_pre_existing_entity_survived_the_migration_with_a_null_external_id() {
    let p = pool().await;

    // The seeded bootstrap rows (`atom-admin` et al.) predate this column in
    // every existing deployment.
    let seeded: Option<String> =
        sqlx::query_scalar("SELECT external_id FROM entities WHERE id = $1")
            .bind(common::admin_id())
            .fetch_one(&p)
            .await
            .expect("read the seeded admin entity");
    assert_eq!(seeded, None);
}
