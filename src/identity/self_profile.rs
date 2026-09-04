use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::AuthContext,
    error::AppError,
    models::{
        entity::{Entity, UpdateEntity},
        enums::EntityKind,
    },
};

/// Result of attempting the narrow authenticated self-profile path.
///
/// `NotApplicable` returns ownership of the update so the caller can route it
/// through the normal administrative entity authorization path unchanged.
pub(crate) enum SelfProfileUpdate {
    Updated(Entity),
    NotApplicable(UpdateEntity),
}

const SELF_PROFILE_ATTRIBUTE_KEYS: [&str; 4] = ["first_name", "last_name", "email", "picture"];

fn profile_attributes_only(attributes: &Value) -> bool {
    let Value::Object(attributes) = attributes else {
        return false;
    };
    attributes
        .keys()
        .all(|key| SELF_PROFILE_ATTRIBUTE_KEYS.contains(&key.as_str()))
}

fn profile_fields_only(req: &UpdateEntity) -> bool {
    req.kind.is_none()
        && req.alias.is_none()
        && req.external_id.is_none()
        && req.tenant_id.is_none()
        && req.profile_id.is_none()
        && req.profile_version_id.is_none()
        && req.status.is_none()
        && req
            .attributes
            .as_ref()
            .is_none_or(profile_attributes_only)
}

/// Attempt the authenticated human self-profile path used by `updateEntity`.
///
/// Human identities are global (`tenant_id = NULL`) even when they administer
/// or participate in tenant workspaces. Requiring platform `manage` to change
/// their own display/account fields therefore makes ordinary tenant users
/// unable to edit their profile. A real session may update only the deliberately
/// small profile surface below; every other mutation falls back to the normal
/// ceiling-aware entity authorization path.
///
/// This is intentionally *not* available to API/access-token authentication:
/// `session_id` must be present and scoped credentials are rejected. The
/// administrative fields (`kind`, tenant/profile binding, status, external id,
/// alias) can never use this path.
pub(crate) async fn try_update(
    pool: &PgPool,
    cache: Option<&crate::cache::CacheClient>,
    events_enabled: bool,
    auth: &AuthContext,
    id: Uuid,
    req: UpdateEntity,
    audit_details: Value,
) -> Result<SelfProfileUpdate, AppError> {
    if id != auth.entity_id || auth.session_id.is_none() || auth.scoped || !profile_fields_only(&req)
    {
        return Ok(SelfProfileUpdate::NotApplicable(req));
    }

    let existing = super::repo::get_entity(pool, id).await?;
    if existing.kind != EntityKind::Human || existing.tenant_id.is_some() {
        return Ok(SelfProfileUpdate::NotApplicable(req));
    }

    let mutate = || {
        super::repo::update_entity_with_expected_tenant_and_audit(
            pool,
            events_enabled,
            auth.entity_id,
            id,
            existing.tenant_id,
            req,
            audit_details,
        )
    };
    let Some(cache) = cache else {
        return mutate().await.map(SelfProfileUpdate::Updated);
    };

    // Keep the same invalidation envelope as the normal entity update path.
    // Name/attributes may participate in authentication lookup or ABAC context,
    // and keeping both paths identical prevents cache behavior from drifting.
    let entity_status_keys = [crate::cache::keys::entity_status(id)];
    let grants_keys = [crate::cache::keys::grants(id)];
    let groups = [
        (
            crate::cache::CacheCategory::EntityStatus,
            entity_status_keys.as_slice(),
        ),
        (crate::cache::CacheCategory::Grants, grants_keys.as_slice()),
    ];
    let leases = crate::cache::invalidate::begin_all(cache, &groups).await?;
    let result = mutate().await;
    crate::cache::invalidate::end_all(cache, leases).await;
    result.map(SelfProfileUpdate::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn update(attributes: Option<Value>) -> UpdateEntity {
        UpdateEntity {
            name: Some("alice".into()),
            kind: None,
            alias: None,
            external_id: None,
            tenant_id: None,
            profile_id: None,
            profile_version_id: None,
            status: None,
            attributes,
        }
    }

    #[test]
    fn self_profile_field_filter_allows_only_account_attributes() {
        assert!(profile_fields_only(&update(Some(json!({
            "first_name": "Alice",
            "last_name": "Example",
            "email": "alice@example.test",
            "picture": "https://example.test/alice.png"
        })))))
        ;

        assert!(!profile_fields_only(&update(Some(json!({
            "department": "platform-admin"
        })))))
        ;

        let mut unsafe_update = update(None);
        unsafe_update.status = Some(crate::models::enums::EntityStatus::Suspended);
        assert!(!profile_fields_only(&unsafe_update));
    }
}
