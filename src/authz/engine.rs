use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::{
    error::AppError,
    models::policy::{AuthzRequest, AuthzResponse},
};

use super::repo;

/// Evaluate an authorization request.
///
/// Algorithm:
/// 1. Load entity and resource (for ABAC context)
/// 2. Find the capability matching the requested action
/// 3. Load all policy bindings for the entity (direct + via group membership)
/// 4. For each binding, check:
///    a. Does the grant cover the requested capability?
///    b. Does the scope cover the requested resource?
///    c. Do ABAC conditions match?
/// 5. DENY overrides ALLOW; default is DENY
pub async fn evaluate(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzResponse, AppError> {
    // Load entity for ABAC context
    let entity_row = sqlx::query(
        "SELECT id, kind, tenant_id, attributes, status FROM entities WHERE id = $1",
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

    let entity_status: String = entity_row.try_get("status").map_err(AppError::Database)?;
    if entity_status != "active" {
        return Ok(AuthzResponse {
            allowed: false,
            reason: "subject is not active".to_string(),
        });
    }
    let entity_attrs: serde_json::Value = entity_row.try_get("attributes").map_err(AppError::Database)?;

    // Load resource for ABAC context
    let resource_row = sqlx::query(
        "SELECT id, kind, tenant_id, attributes FROM resources WHERE id = $1",
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
    let resource_attrs: serde_json::Value = resource_row.try_get("attributes").map_err(AppError::Database)?;

    // Find capability matching the action name
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

    // Build ABAC evaluation context
    let eval_ctx = build_context(&entity_attrs, &resource_attrs, &req.context);

    // Load all applicable policy bindings
    let bindings = repo::load_bindings_for_entity(pool, req.subject_id).await?;

    let resource_id_str = req.resource_id.to_string();

    let mut has_allow = false;

    for binding in &bindings {
        if !scope_matches(binding, &resource_id_str, &resource_kind) {
            continue;
        }

        let grant_matches = match binding.grant_kind.as_str() {
            "capability" => binding.grant_id == cap_id,
            "role" => {
                let role_caps = repo::capability_ids_for_role(pool, binding.grant_id).await?;
                role_caps.contains(&cap_id)
            }
            _ => false,
        };

        if !grant_matches {
            continue;
        }

        if !conditions_match(&binding.conditions, &eval_ctx) {
            continue;
        }

        match binding.effect.as_str() {
            "deny" => {
                return Ok(AuthzResponse {
                    allowed: false,
                    reason: format!("explicitly denied by policy {}", binding.id),
                });
            }
            "allow" => {
                has_allow = true;
            }
            _ => {}
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

fn scope_matches(
    binding: &crate::models::policy::PolicyBinding,
    resource_id: &str,
    resource_kind: &str,
) -> bool {
    match binding.scope_kind.as_str() {
        "all" => true,
        "resource" => binding
            .scope_ref
            .as_deref()
            .map(|r| r == resource_id)
            .unwrap_or(false),
        "resource_kind" => binding
            .scope_ref
            .as_deref()
            .map(|k| k == resource_kind)
            .unwrap_or(false),
        _ => false,
    }
}

fn build_context(entity_attrs: &Value, resource_attrs: &Value, extra: &Value) -> Value {
    serde_json::json!({
        "entity": { "attributes": entity_attrs },
        "resource": { "attributes": resource_attrs },
        "context": extra,
    })
}

/// Evaluate flat-map conditions against the evaluation context.
///
/// Condition keys are dot-paths into the context object.
/// All conditions must match (AND logic).
///
/// Example conditions JSON:
/// `{"entity.attributes.department": "engineering", "resource.attributes.env": "prod"}`
fn conditions_match(conditions: &Value, ctx: &Value) -> bool {
    let map = match conditions.as_object() {
        Some(m) => m,
        None => return true,
    };

    if map.is_empty() {
        return true;
    }

    for (path, expected) in map {
        let actual = resolve_path(ctx, path);
        if actual != Some(expected) {
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
