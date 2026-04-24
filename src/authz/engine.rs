use serde_json::Value;
use sqlx::PgPool;

use crate::{
    error::AppError,
    models::{
        enums::{Effect, EntityStatus, GrantKind, ScopeKind},
        policy::{AuthzRequest, AuthzResponse, PolicyBinding},
    },
};

use super::repo;

pub async fn evaluate(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzResponse, AppError> {
    use sqlx::Row;

    let entity_row = sqlx::query(
        "SELECT attributes, status FROM entities WHERE id = $1",
    )
    .bind(req.subject_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    let entity_row = match entity_row {
        Some(r) => r,
        None => {
            return Ok(AuthzResponse {
                allowed: false,
                reason: "subject not found".to_string(),
            });
        }
    };

    let entity_status: EntityStatus = entity_row.try_get("status").map_err(AppError::Database)?;
    if entity_status != EntityStatus::Active {
        return Ok(AuthzResponse {
            allowed: false,
            reason: "subject is not active".to_string(),
        });
    }
    let entity_attrs: Value = entity_row.try_get("attributes").map_err(AppError::Database)?;

    let resource_row = sqlx::query(
        "SELECT kind, attributes FROM resources WHERE id = $1",
    )
    .bind(req.resource_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    let resource_row = match resource_row {
        Some(r) => r,
        None => {
            return Ok(AuthzResponse {
                allowed: false,
                reason: "resource not found".to_string(),
            });
        }
    };

    let resource_kind: String = resource_row.try_get("kind").map_err(AppError::Database)?;
    let resource_attrs: Value = resource_row.try_get("attributes").map_err(AppError::Database)?;

    let cap_id = repo::find_capability_by_name(pool, &req.action, &resource_kind).await?;
    let cap_id = match cap_id {
        Some(id) => id,
        None => {
            return Ok(AuthzResponse {
                allowed: false,
                reason: format!("unknown action '{}'", req.action),
            });
        }
    };

    let eval_ctx = build_context(&entity_attrs, &resource_attrs, &req.context);
    let bindings = repo::load_bindings_for_entity(pool, req.subject_id).await?;

    // Collect all role IDs referenced by bindings and batch-load their capabilities.
    // This eliminates the N+1 that would occur from per-binding role lookups.
    let role_ids: Vec<_> = bindings
        .iter()
        .filter(|b| b.grant_kind == GrantKind::Role)
        .map(|b| b.grant_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let role_caps = repo::capability_ids_for_roles(pool, &role_ids).await?;

    let resource_id_str = req.resource_id.to_string();
    let mut has_allow = false;

    for binding in &bindings {
        if !scope_matches(binding, &resource_id_str, &resource_kind) {
            continue;
        }

        let grant_matches = match binding.grant_kind {
            GrantKind::Capability => binding.grant_id == cap_id,
            GrantKind::Role => role_caps
                .get(&binding.grant_id)
                .map(|caps| caps.contains(&cap_id))
                .unwrap_or(false),
        };

        if !grant_matches {
            continue;
        }

        if !conditions_match(&binding.conditions, &eval_ctx) {
            continue;
        }

        match binding.effect {
            Effect::Deny => {
                return Ok(AuthzResponse {
                    allowed: false,
                    reason: format!("explicitly denied by policy {}", binding.id),
                });
            }
            Effect::Allow => {
                has_allow = true;
            }
        }
    }

    if has_allow {
        Ok(AuthzResponse {
            allowed: true,
            reason: "allowed".to_string(),
        })
    } else {
        Ok(AuthzResponse {
            allowed: false,
            reason: "no matching allow policy".to_string(),
        })
    }
}

fn scope_matches(binding: &PolicyBinding, resource_id: &str, resource_kind: &str) -> bool {
    match binding.scope_kind {
        ScopeKind::All => true,
        ScopeKind::Resource => binding
            .scope_ref
            .as_deref()
            .map(|r| r == resource_id)
            .unwrap_or(false),
        ScopeKind::ResourceKind => binding
            .scope_ref
            .as_deref()
            .map(|k| k == resource_kind)
            .unwrap_or(false),
    }
}

fn build_context(entity_attrs: &Value, resource_attrs: &Value, extra: &Value) -> Value {
    serde_json::json!({
        "entity": { "attributes": entity_attrs },
        "resource": { "attributes": resource_attrs },
        "context": extra,
    })
}

/// Evaluate flat-map ABAC conditions against the evaluation context.
/// Keys are dot-paths; all entries must match (AND logic).
fn conditions_match(conditions: &Value, ctx: &Value) -> bool {
    let map = match conditions.as_object() {
        Some(m) => m,
        None => return true,
    };

    if map.is_empty() {
        return true;
    }

    for (path, expected) in map {
        if resolve_path(ctx, path) != Some(expected) {
            return false;
        }
    }

    true
}

fn resolve_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        enums::{Effect, GrantKind, ScopeKind, SubjectKind},
        policy::PolicyBinding,
    };
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    fn make_binding(
        scope_kind: ScopeKind,
        scope_ref: Option<&str>,
        grant_kind: GrantKind,
        effect: Effect,
    ) -> PolicyBinding {
        PolicyBinding {
            id: Uuid::new_v4(),
            subject_kind: SubjectKind::Entity,
            subject_id: Uuid::new_v4(),
            grant_kind,
            grant_id: Uuid::new_v4(),
            scope_kind,
            scope_ref: scope_ref.map(|s| s.to_string()),
            effect,
            conditions: json!({}),
            created_at: Utc::now(),
        }
    }

    // ─── resolve_path ─────────────────────────────────────────────────────────

    #[test]
    fn resolve_path_single_segment() {
        let root = json!({"foo": "bar"});
        assert_eq!(resolve_path(&root, "foo"), Some(&json!("bar")));
    }

    #[test]
    fn resolve_path_missing_segment_returns_none() {
        let root = json!({"foo": "bar"});
        assert_eq!(resolve_path(&root, "missing"), None);
    }

    #[test]
    fn resolve_path_nested() {
        let root = json!({"a": {"b": {"c": 42}}});
        assert_eq!(resolve_path(&root, "a.b.c"), Some(&json!(42)));
        assert_eq!(resolve_path(&root, "a.b.x"), None);
    }

    // ─── conditions_match ─────────────────────────────────────────────────────

    #[test]
    fn conditions_empty_always_passes() {
        let ctx = json!({"entity": {}, "resource": {}, "context": {}});
        assert!(conditions_match(&json!({}), &ctx));
    }

    #[test]
    fn conditions_single_match() {
        let conditions = json!({"entity.attributes.env": "prod"});
        let ctx = json!({
            "entity": {"attributes": {"env": "prod"}},
            "resource": {"attributes": {}},
            "context": {}
        });
        assert!(conditions_match(&conditions, &ctx));
    }

    #[test]
    fn conditions_single_mismatch() {
        let conditions = json!({"entity.attributes.env": "prod"});
        let ctx = json!({
            "entity": {"attributes": {"env": "staging"}},
            "resource": {"attributes": {}},
            "context": {}
        });
        assert!(!conditions_match(&conditions, &ctx));
    }

    #[test]
    fn conditions_all_must_match() {
        let conditions = json!({
            "entity.attributes.env": "prod",
            "context.ip_trusted": "true"
        });
        let ctx_partial = json!({
            "entity": {"attributes": {"env": "prod"}},
            "context": {"ip_trusted": "false"}
        });
        assert!(!conditions_match(&conditions, &ctx_partial));

        let ctx_full = json!({
            "entity": {"attributes": {"env": "prod"}},
            "context": {"ip_trusted": "true"}
        });
        assert!(conditions_match(&conditions, &ctx_full));
    }

    #[test]
    fn conditions_missing_key_fails() {
        let conditions = json!({"entity.attributes.missing": "value"});
        let ctx = json!({"entity": {"attributes": {}}});
        assert!(!conditions_match(&conditions, &ctx));
    }

    // ─── scope_matches ────────────────────────────────────────────────────────

    #[test]
    fn scope_all_matches_everything() {
        let b = make_binding(ScopeKind::All, None, GrantKind::Capability, Effect::Allow);
        assert!(scope_matches(&b, "any-uuid", "any-kind"));
    }

    #[test]
    fn scope_resource_kind_matches_correct_kind() {
        let b = make_binding(
            ScopeKind::ResourceKind,
            Some("channel"),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, "some-uuid", "channel"));
        assert!(!scope_matches(&b, "some-uuid", "device"));
    }

    #[test]
    fn scope_specific_resource_matches_by_id() {
        let res_id = Uuid::new_v4().to_string();
        let b = make_binding(
            ScopeKind::Resource,
            Some(&res_id),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, &res_id, "any-kind"));
        assert!(!scope_matches(&b, "other-uuid", "any-kind"));
    }

    #[test]
    fn scope_resource_none_scope_ref_never_matches() {
        let b = make_binding(ScopeKind::Resource, None, GrantKind::Capability, Effect::Allow);
        assert!(!scope_matches(&b, "any-id", "any-kind"));
    }
}
