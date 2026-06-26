//! Regression tests for generic role attributes and role attribute filtering.
//!
//! DATABASE_URL=postgres://... cargo test --test m24_role_attributes -- --ignored

mod common;

use atom::{
    authz::repo,
    models::{
        enums::DeletedFilter,
        role::{CreateRole, ListRoles, UpdateRole},
    },
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn role_attributes_default_persist_update_and_filter() {
    let pool = common::pool().await;

    let default_role = repo::create_role(
        &pool,
        CreateRole {
            name: format!("m24-default-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
            attributes: serde_json::Value::Null,
        },
    )
    .await
    .expect("create default role");
    assert_eq!(default_role.attributes, json!({}));

    let owner_id = Uuid::new_v4().to_string();
    let role_name = format!("m24-attrs-{}", Uuid::new_v4());
    let role = repo::create_role(
        &pool,
        CreateRole {
            name: role_name.clone(),
            tenant_id: None,
            description: Some("role with attributes".into()),
            attributes: json!({
                "magistrala": {
                    "roleKind": "object_group_role",
                    "ownerType": "object_group",
                    "ownerId": owner_id
                },
                "debug": true
            }),
        },
    )
    .await
    .expect("create role with attributes");
    assert_eq!(
        role.attributes["magistrala"]["roleKind"],
        "object_group_role"
    );

    let updated_owner_id = Uuid::new_v4().to_string();
    let updated = repo::update_role(
        &pool,
        role.id,
        UpdateRole {
            name: None,
            description: None,
            attributes: Some(json!({
                "magistrala": {
                    "roleKind": "tenant_role",
                    "ownerType": "tenant",
                    "ownerId": updated_owner_id
                }
            })),
        },
    )
    .await
    .expect("update role attributes");
    assert_eq!(updated.attributes["magistrala"]["roleKind"], "tenant_role");
    assert!(updated.attributes.get("debug").is_none());

    let non_matching = repo::create_role(
        &pool,
        CreateRole {
            name: format!("m24-other-{}", Uuid::new_v4()),
            tenant_id: None,
            description: None,
            attributes: json!({
                "magistrala": {
                    "roleKind": "tenant_role",
                    "ownerType": "tenant",
                    "ownerId": "different-owner"
                }
            }),
        },
    )
    .await
    .expect("create non-matching role");

    let filtered = repo::list_roles(
        &pool,
        ListRoles {
            tenant_id: None,
            derived_kind: None,
            q: None,
            attributes_contains: Some(json!({
                "magistrala": {
                    "roleKind": "tenant_role",
                    "ownerType": "tenant",
                    "ownerId": updated_owner_id
                }
            })),
            deleted: DeletedFilter::Live,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("filter roles by attributes");
    assert!(filtered.items.iter().any(|item| item.id == role.id));
    assert!(filtered.items.iter().all(|item| item.id != non_matching.id));
    assert!(filtered.items.iter().all(|item| item.id != default_role.id));

    let filtered_by_q = repo::list_roles(
        &pool,
        ListRoles {
            tenant_id: None,
            derived_kind: None,
            q: Some(role_name),
            attributes_contains: Some(json!({
                "magistrala": {
                    "roleKind": "tenant_role",
                    "ownerType": "tenant"
                }
            })),
            deleted: DeletedFilter::Live,
            limit: 20,
            offset: 0,
        },
    )
    .await
    .expect("filter roles by q and attributes");
    assert_eq!(filtered_by_q.items.len(), 1);
    assert_eq!(filtered_by_q.items[0].id, role.id);
}
