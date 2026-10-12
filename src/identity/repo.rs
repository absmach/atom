mod storage;

use crate::db::Database;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    db::DbTransaction,
    error::{db_err, entity_write_conflict, restore_conflict, AppError},
    models::{
        entity::{CreateEntity, Entity, EntityList, ListEntities, Ownership, UpdateEntity},
        enums::{EntityKind, EntityOrderField, GroupOrderField, SortDir},
        group::{CreateGroup, Group, GroupList, ListGroups, UpdateGroup},
        session::Session,
    },
    schema,
};

// ─── Entities ────────────────────────────────────────────────────────────────

pub const AUTHENTICATED_USERS_GROUP_ID: Uuid = Uuid::from_u128(5);

/// Refuse mutations against an entity provisioned from the bootstrap config
/// file. Config-managed entities can only be reshaped by editing the YAML and
/// restarting Atom, so all API-facing update/delete/restore paths funnel
/// through this guard.
pub async fn ensure_not_config_managed_entity(pool: &Database, id: Uuid) -> Result<(), AppError> {
    crate::managed_by::ensure_not_config_managed(pool, "entities", id).await
}

/// Companion for credential mutations. Config-managed credentials are visible
/// in list/read responses (so the UI can flag them read-only), but mutation
/// endpoints (revoke, replace ceiling) reject them with 409 conflict so the
/// operator's declared row can only be reshaped by editing the YAML.
///
/// `reveal_shared_key` uses a different guard — it must not return the
/// plaintext key of a config-managed row and returns not_found instead, per
/// its own module.
pub async fn ensure_not_config_managed_credential(
    pool: &Database,
    cred_id: Uuid,
) -> Result<(), AppError> {
    crate::managed_by::ensure_not_config_managed(pool, "credentials", cred_id).await
}

pub async fn lock_active_entity(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Option<(EntityKind, Option<Uuid>)>, AppError> {
    let tenant_id: Option<Option<Uuid>> = storage::active_entity_tenant(tx, id).await?;
    let Some(tenant_id) = tenant_id else {
        return Ok(None);
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;

    storage::lock_active_entity(tx, id, tenant_id).await
}

pub async fn create_entity_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateEntity,
) -> Result<Entity, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = normalize_attributes(req.attributes);
    reject_parent_group_attribute(&attrs)?;
    let (kind, profile_id, profile_version_id) = resolve_entity_profile(
        pool,
        req.kind,
        req.profile_id,
        req.profile_version_id,
        &attrs,
    )
    .await?;
    let is_human = kind == EntityKind::Human;
    let alias = crate::models::alias::validate_alias_opt(req.alias)?;
    let external_id = crate::models::external_id::validate_external_id_opt(req.external_id)?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, req.tenant_id).await?;
    let entity = storage::insert_entity(
        &mut tx,
        storage::NewEntity {
            id,
            kind,
            name: req.name,
            alias,
            external_id,
            tenant_id: req.tenant_id,
            profile_id,
            profile_version_id,
            attributes: attrs,
        },
    )
    .await?;

    if is_human {
        add_authenticated_user_membership_in_tx(&mut tx, entity.id).await?;
    }
    sync_entity_email_from_attrs_in_tx(&mut tx, entity.id, &entity.kind, &entity.attributes)
        .await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: entity.tenant_id,
        target_kind: Some("entity"),
        target_id: Some(entity.id),
        event: "entity.create",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({
            "kind": entity.kind,
            "name": entity.name,
            "alias": entity.alias,
            "external_id": entity.external_id,
        }),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(entity)
}

pub async fn create_entity(pool: &Database, req: CreateEntity) -> Result<Entity, AppError> {
    create_entity_with_audit(pool, false, None, req).await
}

pub async fn add_authenticated_user_membership_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    storage::add_authenticated_user_membership_in_tx(tx, entity_id).await
}

pub async fn get_entity(pool: &Database, id: Uuid) -> Result<Entity, AppError> {
    fetch_entity(pool, id).await
}

/// Executor-generic `get_entity`, so a mutation can read the row it just wrote
/// from inside its own transaction instead of re-reading it after the commit.
async fn fetch_entity<'e, E>(executor: E, id: Uuid) -> Result<Entity, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    storage::fetch_entity(executor, id).await
}

pub async fn list_entities_by_ids(pool: &Database, ids: &[Uuid]) -> Result<Vec<Entity>, AppError> {
    storage::list_entities_by_ids(pool, ids).await
}

pub async fn list_entities(pool: &Database, params: ListEntities) -> Result<EntityList, AppError> {
    storage::list_entities(pool, params).await
}

pub async fn update_entity_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateEntity,
    event_name: &str,
    audit_details: Value,
) -> Result<Entity, AppError> {
    update_entity_with_audit_inner(
        pool,
        id,
        req,
        EntityUpdateAudit {
            events_enabled,
            actor_id,
            expected_tenant_id: None,
            event_name,
            details: audit_details,
        },
        EntityAttributeUpdateMode::Replace,
    )
    .await
}

/// Update an entity only while it still belongs to the tenant against which
/// the caller was authorized. The resolver/service authorization happens
/// before this transaction; re-checking the snapshot under the entity row lock
/// prevents a concurrent move from carrying that authorization into another
/// tenant.
pub(crate) async fn update_entity_with_expected_tenant_and_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Uuid,
    id: Uuid,
    expected_tenant_id: Option<Uuid>,
    req: UpdateEntity,
    audit_details: Value,
) -> Result<Entity, AppError> {
    update_entity_with_audit_inner(
        pool,
        id,
        req,
        EntityUpdateAudit {
            events_enabled,
            actor_id: Some(actor_id),
            expected_tenant_id: Some(expected_tenant_id),
            event_name: "entity.update",
            details: audit_details,
        },
        EntityAttributeUpdateMode::Replace,
    )
    .await
}

/// Update the safe self-service profile surface while merging its attribute
/// patch against the entity row locked by the mutation transaction.
///
/// The caller performs the request/session eligibility check. This function
/// re-checks the target's global-human shape under the row lock so a concurrent
/// administrative change cannot turn the self-service path into an update of a
/// different entity kind or scope.
pub(crate) async fn update_self_profile_with_expected_tenant_and_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Uuid,
    id: Uuid,
    expected_tenant_id: Option<Uuid>,
    req: UpdateEntity,
    audit_details: Value,
) -> Result<Entity, AppError> {
    update_entity_with_audit_inner(
        pool,
        id,
        req,
        EntityUpdateAudit {
            events_enabled,
            actor_id: Some(actor_id),
            expected_tenant_id: Some(expected_tenant_id),
            event_name: "entity.update",
            details: audit_details,
        },
        EntityAttributeUpdateMode::MergeSelfProfile,
    )
    .await
}

struct EntityUpdateAudit<'a> {
    events_enabled: bool,
    actor_id: Option<Uuid>,
    expected_tenant_id: Option<Option<Uuid>>,
    event_name: &'a str,
    details: Value,
}

#[derive(Clone, Copy)]
enum EntityAttributeUpdateMode {
    Replace,
    MergeSelfProfile,
}

#[derive(sqlx::FromRow)]
struct LockedEntityUpdate {
    kind: EntityKind,
    name: String,
    profile_id: Option<Uuid>,
    profile_version_id: Option<Uuid>,
    attributes: Value,
}

async fn update_entity_with_audit_inner(
    pool: &Database,
    id: Uuid,
    mut req: UpdateEntity,
    audit: EntityUpdateAudit<'_>,
    attribute_mode: EntityAttributeUpdateMode,
) -> Result<Entity, AppError> {
    let EntityUpdateAudit {
        events_enabled,
        actor_id,
        expected_tenant_id,
        event_name,
        details: audit_details,
    } = audit;
    let alias = crate::models::alias::validate_alias_update(req.alias.take())?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();

    let external_id =
        crate::models::external_id::validate_external_id_update(req.external_id.take())?;
    let external_id_is_set = external_id.is_some();
    let external_id = external_id.flatten();

    // Preserve validation precedence for administrative updates: malformed
    // replacement attributes must fail before the row lock/config-managed
    // guard. Self-profile patches are merged only after locking the current
    // row, but validate the incoming patch rather than inherited legacy keys.
    let replacement_attributes = match attribute_mode {
        EntityAttributeUpdateMode::Replace => {
            let attributes = req.attributes.clone().map(normalize_attributes);
            if let Some(attributes) = attributes.as_ref() {
                reject_parent_group_attribute(attributes)?;
            }
            attributes
        }
        EntityAttributeUpdateMode::MergeSelfProfile => {
            if let Some(attributes) = req.attributes.as_ref() {
                reject_parent_group_attribute(attributes)?;
            }
            None
        }
    };

    let mut tx = pool.begin().await.map_err(db_err)?;
    let current_tenant_id: Option<Option<Uuid>> = storage::entity_tenant(&mut tx, id).await?;
    let Some(current_tenant_id) = current_tenant_id else {
        return Err(AppError::not_found(format!("entity {id} not found")));
    };
    if expected_tenant_id.is_some_and(|expected| expected != current_tenant_id) {
        return Err(AppError::conflict(
            "entity tenant changed after authorization; retry the update",
        ));
    }
    let mut tenant_ids = [current_tenant_id, req.tenant_id]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    tenant_ids.sort_unstable();
    tenant_ids.dedup();
    for tenant_id in tenant_ids {
        crate::tenants::repo::lock_active_tenant(&mut tx, tenant_id).await?;
    }
    let locked = storage::lock_entity_update(&mut tx, id, current_tenant_id).await?;
    let Some(locked) = locked else {
        if expected_tenant_id.is_some() {
            return Err(AppError::conflict(
                "entity changed after authorization; retry the update",
            ));
        }
        return Err(AppError::not_found(format!("entity {id} not found")));
    };
    let LockedEntityUpdate {
        kind: current_kind,
        name: current_name,
        profile_id: current_profile_id,
        profile_version_id: current_profile_version_id,
        attributes: current_attributes,
    } = locked;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "entities", id).await?;
    if matches!(attribute_mode, EntityAttributeUpdateMode::MergeSelfProfile)
        && (current_kind != EntityKind::Human || current_tenant_id.is_some())
    {
        return Err(AppError::conflict(
            "entity changed after self-profile eligibility check; retry the update",
        ));
    }

    if matches!(attribute_mode, EntityAttributeUpdateMode::MergeSelfProfile) {
        if let Some(name) = req.name.as_deref().filter(|name| *name != current_name) {
            // Name-only login without a tenant selector fails when more than one
            // live entity has the identifier. Serialize competing self-service
            // choices and refuse to create that ambiguity.
            let name_in_use = storage::name_is_in_use(&mut tx, id, name).await?;
            if name_in_use {
                return Err(AppError::conflict(
                    "name is already in use by another entity; choose a different name",
                ));
            }
        }
    }

    let attributes = match attribute_mode {
        EntityAttributeUpdateMode::Replace => replacement_attributes,
        EntityAttributeUpdateMode::MergeSelfProfile => req
            .attributes
            .clone()
            .map(|attributes| merge_profile_attributes(&current_attributes, attributes))
            .transpose()?,
    };
    if req.kind.is_some()
        || req.profile_id.is_some()
        || req.profile_version_id.is_some()
        || attributes.is_some()
    {
        let profile_changed = req
            .profile_id
            .is_some_and(|profile_id| Some(profile_id) != current_profile_id);
        let proposed_profile_version_id = if profile_changed {
            req.profile_version_id
        } else {
            req.profile_version_id.or(current_profile_version_id)
        };
        let validated_profile_version_id = validate_proposed_entity_profile_in_tx(
            &mut tx,
            ProposedEntityProfile {
                kind: req.kind.as_ref().unwrap_or(&current_kind),
                profile_id: req.profile_id.or(current_profile_id),
                profile_version_id: proposed_profile_version_id,
                attributes: attributes.as_ref().unwrap_or(&current_attributes),
                profile_changed,
            },
        )
        .await?;
        // `profileId` without `profileVersionId` follows create semantics:
        // bind the active/latest version of the new profile. Persist the
        // normalized id, rather than validating one version and leaving the
        // previous profile's id in the row.
        if profile_changed && req.profile_version_id.is_none() {
            req.profile_version_id = validated_profile_version_id;
        }
    }
    let sync_email = req.kind.as_ref().is_some_and(|kind| kind != &current_kind)
        || req
            .attributes
            .as_ref()
            .is_some_and(|attributes| attributes.get("email").is_some());
    let entity = storage::update_entity(
        &mut tx,
        storage::EntityChanges {
            id,
            request: req,
            attributes,
            alias_is_set,
            alias,
            external_id_is_set,
            external_id,
        },
    )
    .await?;

    if sync_email {
        sync_entity_email_from_attrs_in_tx(&mut tx, entity.id, &entity.kind, &entity.attributes)
            .await?;
    }

    // The caller builds `audit_details` before the write, so it cannot know the
    // resulting identifier. Consumers denormalize `external_id` onto their own
    // rows (Magistrala keeps it on every message), so the event has to carry the
    // value the entity now has — not merely the fact that it changed.
    //
    // Only on the generic `entity.update`. This function also serves the status
    // transitions (`entity.enable`/`disable`/`suspend`), which carry empty
    // details by design and cannot change the identifier — restating it there
    // would rewrite existing event payloads for no consumer's benefit.
    let mut details = audit_details;
    if event_name == "entity.update" {
        if let Some(fields) = details.as_object_mut() {
            fields.insert(
                "external_id".to_string(),
                serde_json::json!(entity.external_id),
            );
        }
    }

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: entity.tenant_id,
        target_kind: Some("entity"),
        target_id: Some(id),
        event: event_name,
        outcome: crate::models::enums::AuditOutcome::Allow,
        details,
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(entity)
}

pub async fn update_entity(
    pool: &Database,
    id: Uuid,
    req: UpdateEntity,
) -> Result<Entity, AppError> {
    update_entity_with_audit(
        pool,
        false,
        None,
        id,
        req,
        "entity.update",
        serde_json::json!({}),
    )
    .await
}

pub async fn get_entity_object_groups(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    storage::get_entity_object_groups(pool, entity_id).await
}

pub async fn add_entity_to_object_group(
    pool: &Database,
    entity_id: Uuid,
    group_id: Uuid,
) -> Result<Entity, AppError> {
    add_entity_to_object_group_with_audit(pool, false, None, entity_id, group_id).await
}

pub async fn add_entity_to_object_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    entity_id: Uuid,
    group_id: Uuid,
) -> Result<Entity, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let inserted = add_entity_to_object_group_in_tx(&mut tx, entity_id, group_id).await?;
    let entity = fetch_entity(&mut tx, entity_id).await?;
    if !inserted {
        tx.commit().await.map_err(db_err)?;
        return Ok(entity);
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: entity.tenant_id,
        target_kind: "entity",
        target_id: Some(entity_id),
        event: "entity.object_group.add",
    };
    let details = serde_json::json!({ "group_id": group_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(entity)
}

/// Remove the entity from **one** group, leaving its other memberships (and the
/// grants that flow through them) intact.
pub async fn remove_entity_from_object_group(
    pool: &Database,
    entity_id: Uuid,
    group_id: Uuid,
) -> Result<Entity, AppError> {
    remove_entity_from_object_group_with_audit(pool, false, None, entity_id, group_id).await
}

pub async fn remove_entity_from_object_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    entity_id: Uuid,
    group_id: Uuid,
) -> Result<Entity, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let deleted = delete_entity_object_groups_in_tx(&mut tx, entity_id, Some(group_id)).await?;
    let entity = fetch_entity(&mut tx, entity_id).await?;
    if deleted == 0 {
        tx.commit().await.map_err(db_err)?;
        return Ok(entity);
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: entity.tenant_id,
        target_kind: "entity",
        target_id: Some(entity_id),
        event: "entity.object_group.remove",
    };
    let details = serde_json::json!({ "group_id": group_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(entity)
}

/// Remove the entity from **every** group it belongs to. Distinct from
/// [`remove_entity_from_object_group`] on purpose: with many-to-many membership
/// "clear the group" is ambiguous, so each caller states which it means.
pub async fn clear_entity_object_groups(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Entity, AppError> {
    clear_entity_object_groups_with_audit(pool, false, None, entity_id).await
}

pub async fn clear_entity_object_groups_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    entity_id: Uuid,
) -> Result<Entity, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let deleted = delete_entity_object_groups_in_tx(&mut tx, entity_id, None).await?;
    let entity = fetch_entity(&mut tx, entity_id).await?;
    if deleted == 0 {
        tx.commit().await.map_err(db_err)?;
        return Ok(entity);
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: entity.tenant_id,
        target_kind: "entity",
        target_id: Some(entity_id),
        event: "entity.object_groups.clear",
    };
    let details = serde_json::json!({});
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(entity)
}

pub(crate) async fn add_entity_to_object_group_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Uuid,
) -> Result<bool, AppError> {
    add_entity_to_object_group_in_tx_impl(tx, entity_id, group_id, true).await
}

/// Bootstrap-only counterpart to [`add_entity_to_object_group_in_tx`]. The
/// bootstrap transaction owns semantic reconciliation and stamps the group
/// only after its exact declared membership has been validated, so it must be
/// able to replay an already config-managed link idempotently.
pub(crate) async fn add_config_entity_to_object_group_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Uuid,
) -> Result<bool, AppError> {
    add_entity_to_object_group_in_tx_impl(tx, entity_id, group_id, false).await
}

async fn add_entity_to_object_group_in_tx_impl(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Uuid,
    enforce_api_ownership: bool,
) -> Result<bool, AppError> {
    let entity_tenant_id: Option<Option<Uuid>> = storage::entity_tenant(tx, entity_id).await?;
    let Some(entity_tenant_id) = entity_tenant_id else {
        return Err(AppError::bad_request(
            "entity parent group reference is invalid",
        ));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, entity_tenant_id).await?;

    let (entity_tenant_id, group_tenant_id) =
        storage::lock_entity_group(tx, entity_id, group_id, entity_tenant_id)
            .await?
            .ok_or_else(|| AppError::bad_request("entity parent group reference is invalid"))?;
    let Some(tenant_id) = entity_tenant_id else {
        return Err(AppError::bad_request(
            "platform entity cannot be placed in a group",
        ));
    };
    if group_tenant_id != Some(tenant_id) {
        return Err(AppError::bad_request(
            "entity and parent group must belong to the same tenant",
        ));
    }
    if enforce_api_ownership {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "object_groups", group_id).await?;
    }
    // Additive: membership is a set, so re-adding an existing membership is an
    // idempotent no-op rather than a silent move between groups.
    storage::insert_entity_group(tx, group_id, entity_id, tenant_id).await
}

/// `group_id = Some(..)` removes one membership; `None` removes them all. The
/// two callers name which they mean, so neither can inherit the other's
/// behaviour by accident.
async fn delete_entity_object_groups_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<u64, AppError> {
    let tenant_id: Option<Option<Uuid>> = storage::entity_tenant(tx, entity_id).await?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("entity {entity_id} not found")));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    let locked: Option<Uuid> = storage::lock_entity(tx, entity_id, tenant_id).await?;
    if locked.is_none() {
        return Err(AppError::not_found(format!("entity {entity_id} not found")));
    }
    let mut affected_group_ids: Vec<Uuid> =
        storage::entity_membership_owners(tx, entity_id, group_id).await?;
    affected_group_ids.dedup();
    // The group owns the membership edge. Lock every affected owner before a
    // clear-all, then reject the whole operation if even one is declarative;
    // no API-managed edge is partially removed on conflict.
    for affected_group_id in affected_group_ids {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "object_groups", affected_group_id)
            .await?;
    }
    storage::remove_entity_memberships(tx, entity_id, group_id).await
}

/// Object group membership is a set, and a scalar attribute cannot express one.
/// The attribute write path is gone: membership is mutated only through the
/// explicit `addEntityToObjectGroup` / `removeEntityFromObjectGroup` /
/// `clearEntityObjectGroups` mutations. Rejecting the attribute rather than
/// ignoring it keeps the break loud — a caller that still sends it would
/// otherwise believe it had placed the entity in a group.
fn reject_parent_group_attribute(attrs: &Value) -> Result<(), AppError> {
    if attrs.get("parent_group_id").is_some() {
        return Err(AppError::bad_request(
            "the parent_group_id attribute is no longer supported; \
             use addEntityToObjectGroup / removeEntityFromObjectGroup",
        ));
    }
    Ok(())
}

async fn resolve_entity_profile(
    pool: &Database,
    requested_kind: Option<EntityKind>,
    profile_id: Option<Uuid>,
    requested_profile_version_id: Option<Uuid>,
    attributes: &Value,
) -> Result<(EntityKind, Option<Uuid>, Option<Uuid>), AppError> {
    let Some(profile_id) = profile_id else {
        if requested_profile_version_id.is_some() {
            return Err(AppError::bad_request(
                "profile_version_id requires profile_id",
            ));
        }
        let kind = requested_kind
            .ok_or_else(|| AppError::bad_request("kind is required without profile_id"))?;
        return Ok((kind, None, None));
    };

    let profile = super::profile_repo::get_profile(pool, profile_id).await?;
    if profile.object_kind != "entity" {
        return Err(AppError::bad_request(format!(
            "profile {profile_id} is for object_kind '{}', not 'entity'",
            profile.object_kind
        )));
    }
    if profile.status != "active" {
        return Err(AppError::bad_request(format!(
            "profile {profile_id} is not active"
        )));
    }

    let kind = entity_kind_from_profile(&profile.kind)?;
    if let Some(requested_kind) = requested_kind {
        if requested_kind != kind {
            return Err(AppError::bad_request(format!(
                "profile kind '{}' conflicts with requested entity kind '{}'",
                profile.kind,
                entity_kind_as_str(&requested_kind)
            )));
        }
    }

    let version = match requested_profile_version_id {
        Some(version_id) => {
            let version = super::profile_repo::get_profile_version(pool, version_id).await?;
            if version.profile_id != profile_id {
                return Err(AppError::bad_request(format!(
                    "profile_version_id {version_id} does not belong to profile_id {profile_id}"
                )));
            }
            version
        }
        None => super::profile_repo::get_active_profile_version(pool, profile_id)
            .await?
            .ok_or_else(|| {
                AppError::bad_request(format!("profile {profile_id} has no active version"))
            })?,
    };

    schema::validate_json_schema(&version.json_schema, attributes)?;
    Ok((kind, Some(profile_id), Some(version.id)))
}

struct ProposedEntityProfile<'a> {
    kind: &'a EntityKind,
    profile_id: Option<Uuid>,
    profile_version_id: Option<Uuid>,
    attributes: &'a Value,
    profile_changed: bool,
}

/// Validate the state the UPDATE will actually persist, after the entity row
/// is locked and on the same transaction. In particular, a request that
/// changes a profile and attributes together must be checked against the new
/// profile version, not the entity's pre-update version. The share locks keep
/// that profile metadata stable until the entity write commits.
async fn validate_proposed_entity_profile_in_tx(
    tx: &mut DbTransaction<'_>,
    proposed: ProposedEntityProfile<'_>,
) -> Result<Option<Uuid>, AppError> {
    let Some(profile_id) = proposed.profile_id else {
        if proposed.profile_version_id.is_some() {
            return Err(AppError::bad_request(
                "profile_version_id requires profile_id",
            ));
        }
        return Ok(None);
    };

    let profile: Option<(String, String, String)> = storage::lock_profile(tx, profile_id).await?;
    let Some((object_kind, profile_kind, profile_status)) = profile else {
        return Err(AppError::not_found(format!(
            "profile {profile_id} not found"
        )));
    };
    if object_kind != "entity" {
        return Err(AppError::bad_request(format!(
            "profile {profile_id} is for object_kind '{object_kind}', not 'entity'"
        )));
    }
    if proposed.profile_changed && profile_status != "active" {
        return Err(AppError::bad_request(format!(
            "profile {profile_id} is not active"
        )));
    }
    let expected_kind = entity_kind_from_profile(&profile_kind)?;
    if proposed.kind != &expected_kind {
        return Err(AppError::bad_request(format!(
            "profile kind '{}' conflicts with requested entity kind '{}'",
            profile_kind,
            entity_kind_as_str(proposed.kind)
        )));
    }

    let profile_version_id = match proposed.profile_version_id {
        Some(profile_version_id) => profile_version_id,
        None if proposed.profile_changed => storage::lock_latest_profile_version(tx, profile_id)
            .await?
            .ok_or_else(|| {
                AppError::bad_request(format!("profile {profile_id} has no active version"))
            })?,
        None => return Ok(None),
    };
    let version: Option<(Uuid, Value)> =
        storage::lock_profile_version(tx, profile_version_id).await?;
    let Some((version_profile_id, json_schema)) = version else {
        return Err(AppError::not_found(format!(
            "profile version {profile_version_id} not found"
        )));
    };
    if version_profile_id != profile_id {
        return Err(AppError::bad_request(format!(
            "profile_version_id {profile_version_id} does not belong to profile_id {profile_id}"
        )));
    }
    schema::validate_json_schema(&json_schema, proposed.attributes)?;
    Ok(Some(profile_version_id))
}

fn normalize_attributes(attributes: Value) -> Value {
    if attributes == Value::Null {
        serde_json::json!({})
    } else {
        attributes
    }
}

fn merge_profile_attributes(existing: &Value, update: Value) -> Result<Value, AppError> {
    let Value::Object(update) = update else {
        return Err(AppError::bad_request(
            "self profile attributes must be a JSON object",
        ));
    };
    let mut merged = match existing {
        Value::Object(existing) => existing.clone(),
        Value::Null => serde_json::Map::new(),
        _ => {
            return Err(AppError::bad_request(
                "existing human profile attributes must be a JSON object",
            ))
        }
    };
    for (key, value) in update {
        if value.is_null() {
            merged.remove(&key);
        } else {
            merged.insert(key, value);
        }
    }
    Ok(Value::Object(merged))
}

pub(crate) async fn sync_entity_email_from_attrs_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    kind: &EntityKind,
    attributes: &Value,
) -> Result<(), AppError> {
    let Some(email) = (kind == &EntityKind::Human)
        .then(|| normalized_email_attr(attributes))
        .flatten()
    else {
        deactivate_entity_email_in_tx(tx, entity_id).await?;
        return Ok(());
    };

    storage::sync_entity_email(tx, entity_id, email).await
}

async fn deactivate_entity_email_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<(), AppError> {
    storage::deactivate_entity_email_in_tx(tx, entity_id).await
}

fn normalized_email_attr(attributes: &Value) -> Option<String> {
    let email = attributes
        .get("email")?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || email.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(email)
}

fn entity_kind_from_profile(kind: &str) -> Result<EntityKind, AppError> {
    match kind {
        "human" => Ok(EntityKind::Human),
        "device" => Ok(EntityKind::Device),
        "service" => Ok(EntityKind::Service),
        "workload" => Ok(EntityKind::Workload),
        "application" => Ok(EntityKind::Application),
        other => Err(AppError::bad_request(format!(
            "profile kind '{other}' is not a valid entity kind"
        ))),
    }
}

fn entity_kind_as_str(kind: &EntityKind) -> &'static str {
    match kind {
        EntityKind::Human => "human",
        EntityKind::Device => "device",
        EntityKind::Service => "service",
        EntityKind::Workload => "workload",
        EntityKind::Application => "application",
    }
}

/// The exact set of active session ids `delete_entity` is about to revoke —
/// mirrors that function's `UPDATE sessions` `WHERE` clause precisely, so
/// callers can invalidate `atom:v1:session:*` cache entries for them *before*
/// the delete runs (afterward, `revoked_at IS NULL` no longer matches these
/// rows). See `src/cache/mod.rs`'s consistency model.
pub async fn entity_active_session_ids(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    storage::entity_active_session_ids(pool, entity_id).await
}

/// The exact set of active access-token credential ids `delete_entity` is
/// about to revoke — restricted to the one credential kind this codebase
/// caches under `CacheCategory::Credential` (certificates are tracked via the
/// CRL instead, not this cache). Callers invalidate `atom:v1:credential:*`
/// entries for these *before* the delete runs. See `src/cache/mod.rs`'s
/// consistency model.
pub async fn entity_active_access_token_ids(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    storage::entity_active_access_token_ids(pool, entity_id).await
}

/// Locks the entity row and, in the *same* transaction, enumerates the exact
/// session and access-token credential ids a subsequent delete is about to
/// revoke — *before* the entity is touched. Callers establish the cache
/// barrier on these ids (plus the entity's own `entity_status` key) before
/// calling [`deactivate_and_finish_entity_deletion_in_tx`]: starting the
/// barrier only after the status flip would leave a window where a
/// concurrent request can still take a full cache hit on the pre-delete
/// entity/session/credential entries and keep running past the point the
/// delete commits.
///
/// The `SELECT ... FOR UPDATE` below takes the same exclusive row lock on the
/// entity that `create_session`/`create_access_token` take (via
/// `lock_active_entity`) before inserting. So a session or access token
/// created concurrently for this entity either committed before this lock was
/// acquired (and is therefore visible to the enumeration below, which runs
/// after it, in the same transaction) or is blocked until this transaction
/// commits (and then fails, since the entity is no longer active by then).
/// Enumerating via a plain pre-transaction pool query — the previous shape of
/// this code — could miss a session/credential created in that window,
/// leaving its cache entry uninvalidated indefinitely. See
/// `src/cache/mod.rs`'s consistency model.
pub async fn lock_entity_and_collect_revocation_ids_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<(Vec<Uuid>, Vec<Uuid>), AppError> {
    lock_entity_and_collect_revocation_ids_in_tx_inner(tx, id, None).await
}

/// Locked deletion preflight for an already-authorized entity snapshot. See
/// [`update_entity_with_expected_tenant_and_audit`]: this closes the same
/// authorization-to-mutation race for deletion without acquiring another pool
/// connection while this transaction is open.
pub(crate) async fn lock_entity_and_collect_revocation_ids_for_tenant_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<(Vec<Uuid>, Vec<Uuid>), AppError> {
    lock_entity_and_collect_revocation_ids_in_tx_inner(tx, id, Some(expected_tenant_id)).await
}

async fn lock_entity_and_collect_revocation_ids_in_tx_inner(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    expected_tenant_id: Option<Option<Uuid>>,
) -> Result<(Vec<Uuid>, Vec<Uuid>), AppError> {
    // Discover ownership without locking, then take the canonical tenant ->
    // entity order. The locked ownership check below is the serialization
    // point with bootstrap's final `managed_by='config'` stamp.
    let tenant_id: Option<Option<Uuid>> = storage::entity_tenant_including_deleted(tx, id).await?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("entity {id} not found")));
    };
    if expected_tenant_id.is_some_and(|expected| expected != tenant_id) {
        return Err(AppError::conflict(
            "entity tenant changed after authorization; retry the deletion",
        ));
    }
    if expected_tenant_id.is_some() {
        // The authorized API path may mutate only inside an active tenant.
        // Taking this lifecycle-aware lock in the mutation transaction also
        // serializes the delete against a concurrent freeze/disable/delete.
        crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    } else {
        // Internal cleanup/test callers retain the lifecycle-neutral behavior
        // they had before the authorized service entry point was introduced.
        crate::tenants::repo::lock_tenant_rows_in_order(tx, &[tenant_id]).await?;
    }
    crate::managed_by::ensure_not_config_managed_in_tx(tx, "entities", id).await?;
    let locked = storage::lock_entity(tx, id, tenant_id).await?;
    if locked.is_none() {
        if expected_tenant_id.is_some() {
            return Err(AppError::conflict(
                "entity changed after authorization; retry the deletion",
            ));
        }
        return Err(AppError::not_found(format!("entity {id} not found")));
    }

    storage::entity_revocation_ids(tx, id).await
}

/// Finishes the entity soft-delete started by
/// [`lock_entity_and_collect_revocation_ids_in_tx`] in the same transaction:
/// flips the entity to inactive/tombstoned, revokes active credentials (all
/// kinds) and sessions, and tombstones the email. Does not commit — the
/// caller commits after this succeeds, once the cache barrier established on
/// the enumerated ids covers the whole transaction.
///
/// Returns the entity's `tenant_id`, captured here (before the tombstone)
/// rather than left for the caller to re-derive post-commit: `get_entity`
/// filters `deleted_at IS NULL`, so a re-read after this commits always
/// misses the row and silently drops the tenant from the delete's audit
/// trail.
pub async fn deactivate_and_finish_entity_deletion_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    deleted_by: Option<Uuid>,
    id: Uuid,
) -> Result<(Option<Uuid>, Value), AppError> {
    let (tenant_id, revoked) = storage::deactivate_entity(tx, id, actor_id, deleted_by).await?;
    let revoked_certificates: Vec<(Uuid, Option<Uuid>)> = revoked
        .into_iter()
        .filter(|(_, kind, _)| kind == "certificate")
        .map(|(id, _, issuer_id)| (id, issuer_id))
        .collect();
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "entity",
        target_id: Some(id),
        event: "entity.delete",
    };
    let details = serde_json::json!({
        "certificate_revocations": {
            "count": revoked_certificates.len(),
            "credential_ids": revoked_certificates
                .iter()
                .map(|(credential_id, _)| credential_id)
                .collect::<Vec<_>>(),
            "issuer_ids": revoked_certificates
                .iter()
                .filter_map(|(_, issuer_id)| *issuer_id)
                .collect::<Vec<_>>(),
            "reason": "entity_deleted",
        }
    });
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok((tenant_id, details))
}

pub async fn delete_entity(
    pool: &Database,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_entity_with_audit(pool, false, None, id, deleted_by).await
}

/// Soft-delete an entity: mark it inactive, set the tombstone, and immediately
/// cut off access by revoking its credentials and active sessions. Physical
/// removal is deferred to the purge cron. Hard delete (the old behavior) relied
/// on FK cascade for the credential/session cleanup, so the revocations are now
/// explicit.
///
/// Used directly only when no cache is configured; the cache-aware path
/// (`identity::service::delete_entity`) calls
/// [`lock_entity_and_collect_revocation_ids_in_tx`] and
/// [`deactivate_and_finish_entity_deletion_in_tx`] itself so it can establish
/// the cache barrier between them.
pub async fn delete_entity_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_entity_with_audit_inner(pool, events_enabled, actor_id, id, deleted_by, None).await
}

pub(crate) async fn delete_entity_with_expected_tenant_and_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
    expected_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    delete_entity_with_audit_inner(
        pool,
        events_enabled,
        actor_id,
        id,
        deleted_by,
        Some(expected_tenant_id),
    )
    .await
}

async fn delete_entity_with_audit_inner(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
    expected_tenant_id: Option<Option<Uuid>>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_entity_and_collect_revocation_ids_in_tx_inner(&mut tx, id, expected_tenant_id).await?;
    let (tenant_id, details) = deactivate_and_finish_entity_deletion_in_tx(
        &mut tx,
        events_enabled,
        actor_id,
        deleted_by,
        id,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;
    // The audit_logs row is deliberately written after commit (fire-and-forget,
    // never blocks an already-valid delete) — see `audit::commit_with_audit`'s
    // doc comment. The outbox row, by contrast, went in atomically with the
    // mutation above via `observe_in_tx`. `tenant_id` is captured inside the
    // transaction above (before the tombstone) rather than re-read here — a
    // post-commit `get_entity` would always miss the now-deleted row.
    crate::audit::write(
        pool,
        false,
        crate::audit::AuditEvent {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: Some("entity"),
            target_id: Some(id),
            event: "entity.delete",
            outcome: crate::models::enums::AuditOutcome::Allow,
            details,
        },
    )
    .await;
    Ok(())
}

pub async fn restore_entity_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let _ = restored_by;
    let mut tx = pool.begin().await.map_err(db_err)?;

    let expected_tenant_id: Option<Option<Uuid>> =
        storage::deleted_entity_tenant(&mut tx, id).await?;
    let Some(expected_tenant_id) = expected_tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted entity {id} to restore"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "entities", id).await?;

    let tenant_info: Option<(Option<Uuid>, bool, DateTime<Utc>)> =
        storage::entity_restore_snapshot(&mut tx, id, expected_tenant_id).await?;
    let (tenant_id, _is_tenant_deleted, entity_deleted_at) = match tenant_info {
        None => {
            return Err(AppError::not_found(format!(
                "no soft-deleted entity {id} to restore"
            )))
        }
        Some((_, true, _)) => {
            return Err(AppError::conflict(
                "the entity's tenant is soft-deleted; restore the tenant first",
            ))
        }
        Some((t_id, false, deleted_at)) => (t_id, false, deleted_at),
    };

    storage::restore_entity(&mut tx, id, entity_deleted_at).await?;
    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("entity"),
        target_id: Some(id),
        event: "entity.restore",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(())
}

pub async fn restore_entity(
    pool: &Database,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    restore_entity_with_audit(pool, false, None, id, restored_by).await
}

pub async fn purge_entity_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant_id: Option<Option<Uuid>> =
        storage::entity_tenant_including_deleted(&mut tx, id).await?;
    let Some(expected_tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!(
            "no soft-deleted entity {id} to purge"
        )));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[expected_tenant_id]).await?;
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "entities", id).await?;

    let (tenant_id, credential_ids) = storage::purge_entity(&mut tx, id).await?;
    let mut doomed = credential_ids;
    doomed.push(id);
    crate::authz::repo::purge_authz_references_for_ids(&mut tx, &doomed).await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("entity"),
        target_id: Some(id),
        event: "entity.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(tenant_id)
}

pub async fn purge_entity(pool: &Database, id: Uuid) -> Result<Option<Uuid>, AppError> {
    purge_entity_with_audit(pool, false, None, id).await
}

// ─── Sessions ────────────────────────────────────────────────────────────────

fn checked_session_expiration(expiry_secs: u64) -> Result<DateTime<Utc>, AppError> {
    let seconds = i64::try_from(expiry_secs).map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "JWT_EXPIRY_SECS is too large to represent as a duration"
        ))
    })?;
    let duration = Duration::try_seconds(seconds).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "JWT_EXPIRY_SECS is too large to represent as a duration"
        ))
    })?;
    Utc::now().checked_add_signed(duration).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "JWT_EXPIRY_SECS is too large to represent as a session expiration"
        ))
    })
}

pub async fn create_session(
    pool: &Database,
    entity_id: Uuid,
    expiry_secs: u64,
) -> Result<Session, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    if lock_active_entity(&mut tx, entity_id).await?.is_none() {
        return Err(AppError::not_found(format!(
            "active entity {entity_id} not found"
        )));
    }
    let session = create_session_in_tx(&mut tx, entity_id, expiry_secs).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(session)
}

pub(crate) async fn create_session_in_tx(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    expiry_secs: u64,
) -> Result<Session, AppError> {
    let id = Uuid::new_v4();
    let expires_at = checked_session_expiration(expiry_secs)?;

    storage::insert_session(tx, id, entity_id, expires_at).await
}

pub(crate) async fn refresh_session_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    entity_id: Uuid,
    expiry_secs: u64,
) -> Result<Session, AppError> {
    let expires_at = checked_session_expiration(expiry_secs)?;

    // GREATEST, not an unconditional overwrite: with refresh tokens enabled,
    // `expires_at` is the long family deadline, and the deprecated
    // `refreshSession` mutation only knows `jwt_expiry_secs` — a plain `SET`
    // would truncate the family and kill future refresh exchanges.
    storage::extend_session(tx, id, entity_id, expires_at).await
}

pub async fn get_session(pool: &Database, id: Uuid) -> Result<Session, AppError> {
    storage::get_session(pool, id).await
}

/// The caller owns the commit, so a logout can bind the session revocation and
/// its `auth.logout` event into one transaction.
pub async fn revoke_session_in_tx(tx: &mut DbTransaction<'_>, id: Uuid) -> Result<(), AppError> {
    storage::revoke_session_in_tx(tx, id).await
}

// ─── Groups ──────────────────────────────────────────────────────────────────

pub async fn create_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateGroup,
) -> Result<Group, AppError> {
    let CreateGroup {
        id,
        name,
        tenant_id,
        group_type,
        description,
        attributes,
    } = req;
    let id = id.unwrap_or_else(Uuid::new_v4);
    let attrs = normalize_attributes(attributes);
    let group_type = group_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::bad_request("groupType is required: use object or principal"))?;
    let mut tx = pool.begin().await.map_err(db_err)?;
    crate::tenants::repo::lock_optional_active_tenant(&mut tx, tenant_id).await?;
    if !matches!(group_type, "principal" | "object") {
        return Err(AppError::bad_request(
            "groupType must be either 'object' or 'principal'",
        ));
    }
    let group = storage::insert_group(
        &mut tx,
        storage::NewGroup {
            id,
            name,
            tenant_id,
            group_type,
            description,
            attributes: attrs,
        },
    )
    .await?;
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: group.tenant_id,
        target_kind: "group",
        target_id: Some(group.id),
        event: "group.create",
    };
    let details = serde_json::json!({ "group_type": group.group_type });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(group)
}

pub async fn create_group(pool: &Database, req: CreateGroup) -> Result<Group, AppError> {
    create_group_with_audit(pool, false, None, req).await
}

pub async fn get_group(pool: &Database, id: Uuid) -> Result<Group, AppError> {
    fetch_group(pool, id).await
}

/// Executor-generic `get_group`, so a mutation can read the row it just wrote
/// from inside its own transaction instead of re-reading it after the commit.
async fn fetch_group<'e, E>(executor: E, id: Uuid) -> Result<Group, AppError>
where
    E: crate::db::IntoTarget<'e>,
{
    storage::fetch_group(executor, id).await
}

pub async fn list_groups_by_ids(pool: &Database, ids: &[Uuid]) -> Result<Vec<Group>, AppError> {
    storage::list_groups_by_ids(pool, ids).await
}

pub async fn list_groups(pool: &Database, params: ListGroups) -> Result<GroupList, AppError> {
    storage::list_groups(pool, params).await
}

/// Reads every physical row behind the `groups` view before taking locks. A
/// legacy database can contain the same UUID in both group tables, so every
/// owning tenant participates in the canonical tenant-first order.
async fn group_tenant_ids_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<Vec<Option<Uuid>>, AppError> {
    storage::group_tenant_ids(tx, id).await
}

/// Locks and checks every physical group row after its tenant rows have been
/// acquired. Object-before-principal matches the existing hierarchy mutation
/// compatibility path and makes duplicate legacy UUIDs deterministic.
async fn ensure_group_not_config_managed_in_tx(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
) -> Result<(), AppError> {
    let group_types: Vec<String> = storage::physical_group_types(tx, id).await?;
    if group_types.is_empty() {
        return Err(AppError::not_found(format!("group {id} not found")));
    }
    for group_type in group_types {
        let table = match group_type.as_str() {
            "object" => "object_groups",
            "principal" => "principal_groups",
            _ => {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "unknown physical group type {group_type}"
                )))
            }
        };
        crate::managed_by::ensure_not_config_managed_in_tx(tx, table, id).await?;
    }
    Ok(())
}

/// Body of [`update_group`]; caller contract per
/// `authz::repo::create_role_assignment_in_tx`. When the update changes
/// `status`, the resolver must already hold this group's closure lock via
/// `authz::repo::lock_group_closures_and_collect_grants_keys` on this `tx`.
pub(crate) async fn update_group_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    mut req: UpdateGroup,
    event_name: &str,
    audit_details: Value,
) -> Result<Group, AppError> {
    let attributes = req.attributes.take().map(normalize_attributes);
    let tenant_ids = group_tenant_ids_in_tx(tx, id).await?;
    if tenant_ids.is_empty() {
        return Err(AppError::not_found(format!("group {id} not found")));
    }
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids).await?;
    for tenant_id in tenant_ids.into_iter().flatten() {
        crate::tenants::repo::lock_active_tenant(tx, tenant_id).await?;
    }
    ensure_group_not_config_managed_in_tx(tx, id).await?;
    let live: bool = storage::group_is_live(tx, id).await?;
    if !live {
        return Err(AppError::not_found(format!("group {id} not found")));
    }
    let group = storage::update_group(
        tx,
        storage::GroupChanges {
            id,
            request: req,
            attributes,
        },
    )
    .await?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: group.tenant_id,
        target_kind: "group",
        target_id: Some(id),
        event: event_name,
    };
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &audit_details).await?;
    Ok(group)
}

pub async fn update_group(pool: &Database, id: Uuid, req: UpdateGroup) -> Result<Group, AppError> {
    update_group_with_audit(
        pool,
        false,
        None,
        id,
        req,
        "group.update",
        serde_json::json!({}),
    )
    .await
}

pub async fn update_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateGroup,
    event_name: &str,
    audit_details: Value,
) -> Result<Group, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let group = update_group_in_tx(
        &mut tx,
        events_enabled,
        actor_id,
        id,
        req,
        event_name,
        audit_details.clone(),
    )
    .await?;
    tx.commit().await.map_err(db_err)?;
    // `update_group_in_tx` already enqueued the outbox row via `observe_in_tx`
    // before returning — this is the post-commit stdout observability log
    // `commit_with_observation` would otherwise provide; calling that helper
    // instead would enqueue the outbox row a second time.
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: group.tenant_id,
            target_kind: "group",
            target_id: Some(id),
            event: event_name,
        },
        &audit_details,
    );
    Ok(group)
}

pub async fn set_group_parent(
    pool: &Database,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Group, AppError> {
    set_group_parent_with_audit(pool, false, None, child_id, parent_id).await
}

pub async fn set_group_parent_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Group, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let group =
        set_group_parent_in_tx(&mut tx, events_enabled, actor_id, child_id, parent_id).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id: group.tenant_id,
            target_kind: "group",
            target_id: Some(child_id),
            event: "group.parent.set",
        },
        &serde_json::json!({ "parent_id": parent_id }),
    );
    Ok(group)
}

/// Body of [`set_group_parent`] (minus its post-commit `get_group` read).
/// Preparation is defensive and always happens here: cache-aware callers run
/// the same helper once before `cache.begin()`, then safely reacquire these
/// transaction-owned locks here. Reparenting only changes what `child_id` and
/// its descendants inherit from above, never hierarchy rows below it, so the
/// child closure is exactly what this mutation can affect.
pub(crate) async fn set_group_parent_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Group, AppError> {
    // Always prepare here as well as in the cache-aware transport. Internal and
    // cache-disabled callers must use the same tenant(s) -> hierarchy advisory
    // -> group-row order, and an invalid cross-tenant request must pre-lock both
    // ownership sets before it reaches the advisory lock.
    crate::authz::repo::prepare_group_hierarchy_mutation_in_tx(tx, child_id, Some(parent_id))
        .await?;

    if child_id == parent_id {
        return Err(AppError::bad_request("group cannot be its own parent"));
    }

    let (child_tenant_id, child_group_type) = storage::hierarchy_group(tx, child_id).await?;
    let (parent_tenant_id, parent_group_type) = storage::hierarchy_group(tx, parent_id).await?;
    if child_tenant_id != parent_tenant_id {
        return Err(AppError::bad_request(
            "parent and child groups must belong to the same tenant",
        ));
    }
    if child_group_type != parent_group_type {
        return Err(AppError::bad_request(
            "parent and child groups must have the same group type",
        ));
    }
    let hierarchy_table = if child_group_type == "principal" {
        "principal_group_hierarchy"
    } else {
        "object_group_hierarchy"
    };
    let group_table = if child_group_type == "principal" {
        "principal_groups"
    } else {
        "object_groups"
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, child_tenant_id).await?;
    let locked_ids = storage::lock_hierarchy_groups(tx, group_table, child_id, parent_id).await?;
    if locked_ids.len() != 2 {
        return Err(AppError::bad_request("parent or child group was deleted"));
    }
    crate::managed_by::ensure_not_config_managed_in_tx(tx, group_table, child_id).await?;

    // A legacy deployment may contain the same UUID in both physical group
    // tables. The compatibility path below mirrors an object hierarchy write
    // into the principal hierarchy when both endpoints exist there, so that
    // second child is also an owner whose config marker must be honored.
    let mirrored_principal = if child_group_type == "object" {
        let principal_ids =
            storage::lock_hierarchy_groups(tx, "principal_groups", child_id, parent_id).await?;
        if principal_ids.len() == 2 {
            crate::managed_by::ensure_not_config_managed_in_tx(tx, "principal_groups", child_id)
                .await?;
            true
        } else {
            false
        }
    } else {
        false
    };

    let creates_cycle =
        storage::hierarchy_creates_cycle(tx, hierarchy_table, parent_id, child_id).await?;
    if creates_cycle {
        return Err(AppError::bad_request("group hierarchy cycle detected"));
    }

    storage::set_hierarchy_parent(tx, hierarchy_table, parent_id, child_id, child_tenant_id)
        .await?;
    if mirrored_principal {
        storage::set_hierarchy_parent(
            tx,
            "principal_group_hierarchy",
            parent_id,
            child_id,
            child_tenant_id,
        )
        .await?;
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: child_tenant_id,
        target_kind: "group",
        target_id: Some(child_id),
        event: "group.parent.set",
    };
    let details = serde_json::json!({ "parent_id": parent_id });
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    fetch_group(tx, child_id).await
}

pub async fn remove_group_parent(pool: &Database, child_id: Uuid) -> Result<(), AppError> {
    remove_group_parent_with_audit(pool, false, None, child_id).await
}

pub async fn remove_group_parent_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    child_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = remove_group_parent_in_tx(&mut tx, events_enabled, actor_id, child_id).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "group",
            target_id: Some(child_id),
            event: "group.parent.remove",
        },
        &serde_json::json!({}),
    );
    Ok(())
}

/// Body of [`remove_group_parent`]; caller contract per
/// [`set_group_parent_in_tx`]. Returns the group's `tenant_id` for the
/// caller's post-commit observability log.
pub(crate) async fn remove_group_parent_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    child_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    crate::authz::repo::prepare_group_hierarchy_mutation_in_tx(tx, child_id, None).await?;

    let tenant_id: Option<Option<Uuid>> = storage::live_group_tenant(tx, child_id).await?;
    let Some(tenant_id) = tenant_id else {
        return Err(AppError::not_found(format!("group {child_id} not found")));
    };
    crate::tenants::repo::lock_optional_active_tenant(tx, tenant_id).await?;
    let object_locked: Option<Uuid> = storage::lock_object_group(tx, child_id).await?;
    let principal_locked: Option<Uuid> = storage::lock_principal_group(tx, child_id).await?;
    if object_locked.is_none() && principal_locked.is_none() {
        return Err(AppError::not_found(format!("group {child_id} not found")));
    }
    if object_locked.is_some() {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "object_groups", child_id).await?;
    }
    if principal_locked.is_some() {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "principal_groups", child_id)
            .await?;
    }
    storage::remove_parent(tx, child_id).await?;
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "group",
        target_id: Some(child_id),
        event: "group.parent.remove",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant_id)
}

pub async fn list_child_groups(
    pool: &Database,
    parent_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<GroupList, AppError> {
    storage::list_child_groups(pool, parent_id, limit, offset).await
}

pub async fn delete_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant_id = delete_group_in_tx(&mut tx, events_enabled, actor_id, id, deleted_by).await?;
    tx.commit().await.map_err(db_err)?;
    crate::audit::log_observe_allow(
        &crate::audit::AuditMeta {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: "group",
            target_id: Some(id),
            event: "group.delete",
        },
        &serde_json::json!({}),
    );
    Ok(())
}

/// Body of [`delete_group`]; caller contract per
/// `authz::repo::create_role_assignment_in_tx`. The resolver must already
/// hold this group's closure lock via
/// `authz::repo::lock_group_closures_and_collect_grants_keys` on this `tx` —
/// a soft delete only sets `deleted_at`, leaving `group_hierarchy` untouched,
/// so the closure is unaffected by this mutation's own effect. Returns the
/// group's `tenant_id` for the caller's post-commit observability log — a
/// re-read after this commits would always miss the now-deleted row.
pub(crate) async fn delete_group_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let tenant_ids = group_tenant_ids_in_tx(tx, id).await?;
    let Some(tenant_id) = tenant_ids.first().copied() else {
        return Err(AppError::not_found(format!("group {id} not found")));
    };
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids).await?;
    ensure_group_not_config_managed_in_tx(tx, id).await?;
    let live: bool = storage::group_is_live(tx, id).await?;
    if !live {
        return Err(AppError::not_found(format!("group {id} not found")));
    }

    let result: Option<Uuid> = storage::delete_group(tx, id, deleted_by).await?;
    if result.is_none() {
        return Err(AppError::not_found(format!("group {id} not found")));
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "group",
        target_id: Some(id),
        event: "group.delete",
    };
    let details = serde_json::json!({});
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &details).await?;
    Ok(tenant_id)
}

pub async fn delete_group(
    pool: &Database,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<(), AppError> {
    delete_group_with_audit(pool, false, None, id, deleted_by).await
}

pub async fn restore_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    restore_group_in_tx(&mut tx, events_enabled, actor_id, id, restored_by).await?;
    tx.commit().await.map_err(db_err)?;
    // The audit_logs row is deliberately written after commit (fire-and-forget,
    // never blocks an already-valid restore) — see `audit::commit_with_audit`'s
    // doc comment. The outbox row, by contrast, went in atomically with the
    // mutation inside `restore_group_in_tx` via `observe_in_tx`.
    let tenant_id = get_group(pool, id).await.ok().and_then(|g| g.tenant_id);
    crate::audit::write(
        pool,
        false,
        crate::audit::AuditEvent {
            actor_entity_id: actor_id,
            tenant_id,
            target_kind: Some("group"),
            target_id: Some(id),
            event: "group.restore",
            outcome: crate::models::enums::AuditOutcome::Allow,
            details: serde_json::json!({}),
        },
    )
    .await;
    Ok(())
}

/// Body of [`restore_group`]; caller contract per
/// `authz::repo::create_role_assignment_in_tx`. The resolver must already
/// hold this group's closure lock via
/// `authz::repo::lock_group_closures_and_collect_grants_keys` on this `tx`.
pub(crate) async fn restore_group_in_tx(
    tx: &mut DbTransaction<'_>,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    let _ = restored_by;
    let tenant_ids = group_tenant_ids_in_tx(tx, id).await?;
    if tenant_ids.is_empty() {
        return Err(AppError::not_found(format!(
            "no soft-deleted group {id} to restore"
        )));
    }
    crate::tenants::repo::lock_tenant_rows_in_order(tx, &tenant_ids).await?;
    ensure_group_not_config_managed_in_tx(tx, id).await?;
    let tenant_info: Option<(Option<Uuid>, bool)> = storage::group_restore_snapshot(tx, id).await?;
    let (tenant_id, _is_tenant_deleted) = match tenant_info {
        None => {
            return Err(AppError::not_found(format!(
                "no soft-deleted group {id} to restore"
            )))
        }
        Some((_, true)) => {
            return Err(AppError::conflict(
                "the group's tenant is soft-deleted; restore the tenant first",
            ))
        }
        Some((t_id, false)) => (t_id, false),
    };

    storage::restore_group(tx, id).await?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "group",
        target_id: Some(id),
        event: "group.restore",
    };
    crate::audit::observe_in_tx(tx, events_enabled, &meta, &serde_json::json!({})).await?;
    Ok(())
}

pub async fn restore_group(
    pool: &Database,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<(), AppError> {
    restore_group_with_audit(pool, false, None, id, restored_by).await
}

pub async fn purge_group_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant_ids = group_tenant_ids_in_tx(&mut tx, id).await?;
    if tenant_ids.is_empty() {
        return Err(AppError::not_found(format!(
            "no soft-deleted group {id} to purge"
        )));
    }
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &tenant_ids).await?;
    ensure_group_not_config_managed_in_tx(&mut tx, id).await?;

    let purged_tenant_id: Option<Option<Uuid>> = storage::purge_group(&mut tx, id).await?;
    let tenant_id = purged_tenant_id
        .ok_or_else(|| AppError::not_found(format!("no soft-deleted group {id} to purge")))?;

    crate::authz::repo::purge_authz_references_for_ids(&mut tx, &[id]).await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: Some("group"),
        target_id: Some(id),
        event: "group.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(tenant_id)
}

pub async fn purge_group(pool: &Database, id: Uuid) -> Result<Option<Uuid>, AppError> {
    purge_group_with_audit(pool, false, None, id).await
}

pub async fn add_group_member(
    pool: &Database,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    add_group_member_with_audit(pool, false, None, group_id, entity_id).await
}

pub async fn add_group_member_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let (inserted, group_tenant_id) = add_group_member_in_tx(&mut tx, group_id, entity_id).await?;
    if !inserted {
        tx.commit().await.map_err(db_err)?;
        return Ok(());
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: group_tenant_id,
        target_kind: "group",
        target_id: Some(group_id),
        event: "group_member.add",
    };
    let details = serde_json::json!({ "entity_id": entity_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(())
}

pub(crate) async fn add_group_member_in_tx(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(bool, Option<Uuid>), AppError> {
    add_group_member_in_tx_impl(tx, group_id, entity_id, true).await
}

/// Bootstrap-only replay of a declarative principal-group membership. Runtime
/// callers use [`add_group_member_in_tx`] and cannot change a config-owned
/// member set.
pub(crate) async fn add_config_group_member_in_tx(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(bool, Option<Uuid>), AppError> {
    add_group_member_in_tx_impl(tx, group_id, entity_id, false).await
}

async fn add_group_member_in_tx_impl(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    entity_id: Uuid,
    enforce_api_ownership: bool,
) -> Result<(bool, Option<Uuid>), AppError> {
    let group_tenant_id: Option<Option<Uuid>> =
        storage::active_principal_group_tenant(tx, group_id).await?;
    let entity_tenant_id: Option<Option<Uuid>> =
        storage::active_member_tenant(tx, entity_id).await?;
    let (Some(group_tenant_id), Some(entity_tenant_id)) = (group_tenant_id, entity_tenant_id)
    else {
        return Err(AppError::bad_request(
            "group membership requires a live active group and entity",
        ));
    };
    let mut tenant_ids = [group_tenant_id, entity_tenant_id]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    tenant_ids.sort_unstable();
    tenant_ids.dedup();
    for tenant_id in tenant_ids {
        crate::tenants::repo::lock_active_tenant(tx, tenant_id).await?;
    }
    let group_locked: Option<Uuid> =
        storage::lock_active_member_group(tx, group_id, group_tenant_id).await?;
    let entity_locked: Option<Uuid> =
        storage::lock_active_member(tx, entity_id, entity_tenant_id).await?;
    if group_locked.is_none() || entity_locked.is_none() {
        return Err(AppError::bad_request(
            "group membership target changed during validation",
        ));
    }
    if enforce_api_ownership {
        crate::managed_by::ensure_not_config_managed_in_tx(tx, "principal_groups", group_id)
            .await?;
    }
    // On this transaction's connection: reaching into the pool for a second one
    // while holding a transaction deadlocks a saturated pool.
    crate::guardrails::validate_group_member(tx, group_id, entity_id).await?;
    let inserted = storage::insert_member(tx, group_id, entity_id).await?;
    // Adding an entity that is already a member is a successful no-op, not a
    // state change — publishing `group_member.add` for it would tell consumers
    // membership changed when nothing did.
    Ok((inserted > 0, group_tenant_id))
}

/// Takes the group's `principal_groups` row lock before deleting, matching
/// [`add_group_member`]. `authz::repo::lock_group_closures_and_collect_member_ids`
/// documents this lock as the reason a group-subject mutation may enumerate
/// members under its own closure lock and trust the result: without it a
/// removal is not serialized against that enumeration. Unlike `add_group_member`
/// this deliberately does not require the group to be active or live — a
/// membership must stay removable from a suspended or soft-deleted group.
pub async fn remove_group_member(
    pool: &Database,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    remove_group_member_with_audit(pool, false, None, group_id, entity_id).await
}

pub async fn remove_group_member_with_audit(
    pool: &Database,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    // Removal stays idempotent: a missing group or a missing membership row is
    // not an error. But only an actual deletion is a domain event — publishing
    // `group_member.remove` for a no-op would lie to downstream consumers.
    //
    // Deliberately no `deleted_at IS NULL` filter, unlike `add_group_member`
    // — a membership must stay removable from a suspended or soft-deleted
    // group. Takes the group's row lock, matching `add_group_member`'s —
    // `authz::repo::lock_group_closures_and_collect_member_ids` documents
    // this lock as the reason a group-subject mutation may enumerate members
    // under its own closure lock and trust the result.
    let tenant_id: Option<Option<Uuid>> =
        storage::principal_group_tenant(&mut tx, group_id).await?;
    let Some(tenant_id) = tenant_id else {
        return Ok(());
    };
    crate::tenants::repo::lock_tenant_rows_in_order(&mut tx, &[tenant_id]).await?;
    let locked: Option<Uuid> = storage::lock_member_group(&mut tx, group_id, tenant_id).await?;
    if locked.is_none() {
        return Ok(());
    }
    crate::managed_by::ensure_not_config_managed_in_tx(&mut tx, "principal_groups", group_id)
        .await?;
    let deleted = storage::remove_member(&mut tx, group_id, entity_id).await?;
    if deleted == 0 {
        return Ok(());
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id,
        target_kind: "group",
        target_id: Some(group_id),
        event: "group_member.remove",
    };
    let details = serde_json::json!({ "entity_id": entity_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(())
}

pub async fn list_group_members(pool: &Database, group_id: Uuid) -> Result<Vec<Entity>, AppError> {
    storage::list_group_members(pool, group_id).await
}

pub async fn get_entity_groups(pool: &Database, entity_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    storage::get_entity_groups(pool, entity_id).await
}

// ─── Ownerships ──────────────────────────────────────────────────────────────

pub async fn create_ownership(
    pool: &Database,
    owner_id: Uuid,
    owned_id: Uuid,
    relation: String,
) -> Result<Ownership, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let entity_rows: Vec<(Uuid, Option<Uuid>)> =
        storage::ownership_entities(&mut tx, owner_id, owned_id).await?;
    let expected_entities = if owner_id == owned_id { 1 } else { 2 };
    if entity_rows.len() != expected_entities {
        return Err(AppError::bad_request(
            "ownership requires live active entities",
        ));
    }
    let mut tenant_ids = entity_rows
        .iter()
        .filter_map(|(_, tenant_id)| *tenant_id)
        .collect::<Vec<_>>();
    tenant_ids.sort_unstable();
    tenant_ids.dedup();
    for tenant_id in tenant_ids {
        crate::tenants::repo::lock_active_tenant(&mut tx, tenant_id).await?;
    }
    let mut entity_ids = vec![owner_id, owned_id];
    entity_ids.sort_unstable();
    entity_ids.dedup();
    let locked: Vec<Uuid> = storage::lock_ownership_entities(&mut tx, &entity_ids).await?;
    if locked.len() != entity_ids.len() {
        return Err(AppError::bad_request(
            "ownership target changed during validation",
        ));
    }
    let ownership = storage::upsert_ownership(&mut tx, owner_id, owned_id, relation).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(ownership)
}

pub async fn list_owned(pool: &Database, owner_id: Uuid) -> Result<Vec<Entity>, AppError> {
    storage::list_owned(pool, owner_id).await
}

pub async fn delete_ownership(
    pool: &Database,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<(), AppError> {
    storage::delete_ownership(pool, owner_id, owned_id).await
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

pub(crate) async fn invalidate_email_tokens_in_tx(
    tx: &mut DbTransaction<'_>,
    email_id: Uuid,
) -> Result<(), AppError> {
    storage::invalidate_email_tokens_in_tx(tx, email_id).await
}

pub async fn credential_tenant_id(
    pool: &Database,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    storage::credential_tenant_id(pool, entity_id, credential_id).await
}
