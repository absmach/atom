use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    authz::conditions::conditions_match,
    error::AppError,
    models::{
        access::{
            AuthzExplainResponse, EvaluatedBinding, ExplainCapability, ExplainSubject,
            ResourceSummary,
        },
        enums::{Effect, EntityKind, EntityStatus, GrantKind, ScopeKind, TenantStatus},
        policy::{AuthzRequest, AuthzResponse, PolicyBinding},
    },
};
use serde_json::json;

use super::repo;

struct EntityEvalContext {
    id: Uuid,
    kind: EntityKind,
    tenant_id: Option<Uuid>,
    status: EntityStatus,
    attributes: Value,
}

struct TenantEvalContext {
    id: Uuid,
    status: TenantStatus,
    attributes: Value,
}

/// Generic protected object resolved from `resources`, `tenants`, or any
/// other table that backs an `object_kind`.
///
/// - `coarse_kind` is the value of the canonical `object_kind` enum
///   (e.g., `"resource"`, `"tenant"`, `"entity"`). Used by `scope_kind = object_kind`.
/// - `kind` is the sub-kind for objects that have one (e.g., `"channel"` for
///   resources). Tenants have no sub-kind, so `kind` mirrors `coarse_kind`.
///   Used by capability lookup and by `scope_kind = object_type`.
/// - `id` is what `scope_kind = object` policies match against (as text).
pub(crate) struct ProtectedObject {
    pub id: Uuid,
    pub coarse_kind: String,
    pub kind: String,
    pub name: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub attributes: Value,
}

/// Resolve the protected object identified by an authz request.
/// Returns `Ok(None)` if the object does not exist; returns
/// `BadRequest` if the request supplies neither `resource_id` nor
/// `(object_kind, object_id)`, supplies `object_kind = "platform"`, or supplies
/// an unsupported `object_kind`.
pub(crate) async fn resolve_object(
    pool: &PgPool,
    req: &AuthzRequest,
) -> Result<Option<ProtectedObject>, AppError> {
    use sqlx::Row;

    if req.object_kind.as_deref() == Some("platform") {
        if req.object_id.is_some() {
            return Err(AppError::bad_request(
                "object_id is not supported when object_kind is platform",
            ));
        }
        return Ok(Some(ProtectedObject {
            id: Uuid::nil(),
            coarse_kind: "platform".to_string(),
            kind: "platform".to_string(),
            name: Some("platform".to_string()),
            tenant_id: None,
            attributes: Value::Object(Default::default()),
        }));
    }

    // Explicit (object_kind, object_id) wins when present.
    if req.object_kind.is_some() || req.object_id.is_some() {
        let kind = req.object_kind.as_deref().ok_or_else(|| {
            AppError::bad_request("object_kind is required when object_id is provided")
        })?;
        let id = req.object_id.ok_or_else(|| {
            AppError::bad_request("object_id is required when object_kind is provided")
        })?;
        return match kind {
            "resource" => load_resource(pool, id).await,
            "tenant" => {
                // M3: load the tenant regardless of status so the engine can
                // deny with a state-aware reason ("tenant is frozen" etc.)
                // rather than a generic "not found".
                let row = sqlx::query("SELECT id, name, attributes FROM tenants WHERE id = $1")
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .map_err(AppError::Database)?;
                Ok(row.map(|r| ProtectedObject {
                    id,
                    coarse_kind: "tenant".to_string(),
                    kind: "tenant".to_string(),
                    name: r.try_get::<String, _>("name").ok(),
                    tenant_id: Some(id),
                    attributes: r
                        .try_get::<Value, _>("attributes")
                        .unwrap_or(Value::Object(Default::default())),
                }))
            }
            "entity" => load_entity_as_object(pool, id).await,
            "group" => load_group_as_object(pool, id).await,
            other => Err(AppError::bad_request(format!(
                "unsupported object_kind '{other}' (supported: platform, resource, tenant, entity, group)"
            ))),
        };
    }

    let resource_id = req.resource_id.ok_or_else(|| {
        AppError::bad_request("authz check requires either resource_id or (object_kind, object_id)")
    })?;
    load_resource(pool, resource_id).await
}

/// Resolve an entity used as a protected object (AZ-17). The entity's row
/// supplies the sub-kind (`human` / `device` / `service` / `workload` /
/// `application`), which combined with the coarse `entity` kind yields the
/// namespaced `object_type` (e.g., `entity:device`).
async fn load_entity_as_object(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ProtectedObject>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT id, kind, name, tenant_id, attributes FROM entities WHERE id = $1 AND status <> 'inactive'",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(row.map(|r| ProtectedObject {
        id,
        coarse_kind: "entity".to_string(),
        kind: r
            .try_get::<String, _>("kind")
            .unwrap_or_else(|_| String::new()),
        name: r.try_get::<String, _>("name").ok(),
        tenant_id: r.try_get::<Option<Uuid>, _>("tenant_id").unwrap_or(None),
        attributes: r
            .try_get::<Value, _>("attributes")
            .unwrap_or(Value::Object(Default::default())),
    }))
}

async fn load_resource(pool: &PgPool, id: Uuid) -> Result<Option<ProtectedObject>, AppError> {
    use sqlx::Row;
    let row =
        sqlx::query("SELECT id, kind, name, tenant_id, attributes FROM resources WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)?;
    Ok(row.map(|r| ProtectedObject {
        id,
        coarse_kind: "resource".to_string(),
        kind: r
            .try_get::<String, _>("kind")
            .unwrap_or_else(|_| String::new()),
        name: r.try_get::<Option<String>, _>("name").unwrap_or(None),
        tenant_id: r.try_get::<Option<Uuid>, _>("tenant_id").unwrap_or(None),
        attributes: r
            .try_get::<Value, _>("attributes")
            .unwrap_or(Value::Object(Default::default())),
    }))
}

async fn load_group_as_object(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ProtectedObject>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT id, name, tenant_id, attributes FROM groups WHERE id = $1 AND status <> 'inactive'",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(row.map(|r| ProtectedObject {
        id,
        coarse_kind: "group".to_string(),
        kind: "group".to_string(),
        name: r.try_get::<String, _>("name").ok(),
        tenant_id: r.try_get::<Option<Uuid>, _>("tenant_id").unwrap_or(None),
        attributes: r
            .try_get::<Value, _>("attributes")
            .unwrap_or(Value::Object(Default::default())),
    }))
}

pub async fn evaluate(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzResponse, AppError> {
    use sqlx::Row;

    let entity_row =
        sqlx::query("SELECT id, kind, tenant_id, attributes, status FROM entities WHERE id = $1")
            .bind(req.subject_id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)?;

    let entity_row = match entity_row {
        Some(r) => r,
        None => return Ok(AuthzResponse::deny("subject not found")),
    };

    let entity_status: EntityStatus = entity_row.try_get("status").map_err(AppError::Database)?;
    if entity_status != EntityStatus::Active {
        return Ok(AuthzResponse::deny("subject is not active"));
    }
    let entity_ctx = EntityEvalContext {
        id: entity_row.try_get("id").map_err(AppError::Database)?,
        kind: entity_row.try_get("kind").map_err(AppError::Database)?,
        tenant_id: entity_row
            .try_get("tenant_id")
            .map_err(AppError::Database)?,
        status: entity_status,
        attributes: entity_row
            .try_get("attributes")
            .map_err(AppError::Database)?,
    };

    let object = match resolve_object(pool, req).await? {
        Some(obj) => obj,
        None => return Ok(AuthzResponse::deny(object_not_found_reason(req))),
    };

    // M3: deny when the object's owning tenant is not active. Skips for
    // platform/global objects (tenant_id = None).
    if let Some(deny) = check_tenant_lifecycle(pool, &object).await? {
        return Ok(deny);
    }

    let cap_id = repo::find_capability_by_name(pool, &req.action, &object.kind).await?;
    let cap_id = match cap_id {
        Some(id) => id,
        None => {
            return Ok(AuthzResponse::deny(format!(
                "unknown action '{}'",
                req.action
            )))
        }
    };

    let tenant_ctx = load_tenant_context(pool, object.tenant_id).await?;
    let eval_ctx = build_context(&entity_ctx, &object, tenant_ctx.as_ref(), &req.context);
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

    let object_id_str = object.id.to_string();
    let object_tenant_id_str = object.tenant_id.map(|t| t.to_string());
    let mut has_allow = false;

    for binding in &bindings {
        if !scope_matches(
            binding,
            &object_id_str,
            &object.coarse_kind,
            &object.kind,
            object_tenant_id_str.as_deref(),
        ) {
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
                return Ok(AuthzResponse::deny(format!(
                    "explicitly denied by policy {}",
                    binding.id
                )));
            }
            Effect::Allow => {
                has_allow = true;
            }
        }
    }

    if has_allow {
        Ok(AuthzResponse::allow())
    } else {
        Ok(AuthzResponse::deny("no matching allow policy"))
    }
}

pub async fn explain(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzExplainResponse, AppError> {
    use sqlx::Row;

    let entity_row = sqlx::query(
        "SELECT id, name, kind, tenant_id, status, attributes FROM entities WHERE id = $1",
    )
    .bind(req.subject_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    let entity_row = match entity_row {
        Some(row) => row,
        None => {
            return Ok(AuthzExplainResponse {
                allowed: false,
                reason: "subject not found".to_string(),
                subject: None,
                resource: None,
                capability: None,
                matched_binding: None,
                evaluated_bindings: Vec::new(),
            });
        }
    };

    let subject = ExplainSubject {
        id: entity_row.try_get("id").map_err(AppError::Database)?,
        name: entity_row.try_get("name").map_err(AppError::Database)?,
        kind: entity_row.try_get("kind").map_err(AppError::Database)?,
        status: entity_row.try_get("status").map_err(AppError::Database)?,
    };
    let entity_ctx = EntityEvalContext {
        id: subject.id,
        kind: subject.kind.clone(),
        tenant_id: entity_row
            .try_get("tenant_id")
            .map_err(AppError::Database)?,
        status: subject.status.clone(),
        attributes: entity_row
            .try_get("attributes")
            .map_err(AppError::Database)?,
    };

    if subject.status != EntityStatus::Active {
        return Ok(AuthzExplainResponse {
            allowed: false,
            reason: "subject is not active".to_string(),
            subject: Some(subject),
            resource: None,
            capability: None,
            matched_binding: None,
            evaluated_bindings: Vec::new(),
        });
    }

    let object = match resolve_object(pool, req).await? {
        Some(obj) => obj,
        None => {
            return Ok(AuthzExplainResponse {
                allowed: false,
                reason: object_not_found_reason(req),
                subject: Some(subject),
                resource: None,
                capability: None,
                matched_binding: None,
                evaluated_bindings: Vec::new(),
            });
        }
    };

    let resource = ResourceSummary {
        id: object.id,
        kind: object.kind.clone(),
        name: object.name.clone(),
        tenant_id: object.tenant_id,
    };
    let tenant_ctx = load_tenant_context(pool, object.tenant_id).await?;

    // M3: tenant-lifecycle short-circuit, surfaced through explain so callers
    // see "tenant is frozen" rather than a confusing scope_mismatch loop.
    if let Some(deny) = check_tenant_lifecycle(pool, &object).await? {
        return Ok(AuthzExplainResponse {
            allowed: false,
            reason: deny.reason,
            subject: Some(subject),
            resource: Some(resource),
            capability: None,
            matched_binding: None,
            evaluated_bindings: Vec::new(),
        });
    }

    let cap_row = sqlx::query(
        r#"SELECT id, name, resource_kind FROM capabilities
           WHERE name = $1 AND (resource_kind IS NULL OR resource_kind = $2)
           ORDER BY resource_kind NULLS LAST
           LIMIT 1"#,
    )
    .bind(&req.action)
    .bind(&resource.kind)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    let cap_row = match cap_row {
        Some(row) => row,
        None => {
            return Ok(AuthzExplainResponse {
                allowed: false,
                reason: format!("unknown action '{}'", req.action),
                subject: Some(subject),
                resource: Some(resource),
                capability: None,
                matched_binding: None,
                evaluated_bindings: Vec::new(),
            });
        }
    };
    let capability = ExplainCapability {
        id: cap_row.try_get("id").map_err(AppError::Database)?,
        name: cap_row.try_get("name").map_err(AppError::Database)?,
        resource_kind: cap_row
            .try_get("resource_kind")
            .map_err(AppError::Database)?,
    };

    let rows = sqlx::query(
        r#"SELECT pb.id, pb.tenant_id, pb.subject_kind, pb.subject_id, pb.grant_kind, pb.grant_id,
                  pb.scope_kind, pb.scope_ref, pb.effect, pb.conditions, pb.created_at,
                  role.name AS role_name,
                  CASE
                    WHEN pb.subject_kind = 'entity' THEN 'direct'
                    ELSE 'group:' || g.name
                  END AS via
           FROM policy_bindings pb
           LEFT JOIN groups g ON pb.subject_kind = 'group' AND g.id = pb.subject_id AND g.status = 'active'
           LEFT JOIN roles role ON pb.grant_kind = 'role' AND role.id = pb.grant_id
           WHERE
             (pb.subject_kind = 'entity' AND pb.subject_id = $1)
             OR
             (pb.subject_kind = 'group' AND pb.subject_id IN (
               SELECT gm.group_id
               FROM group_members gm
               JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
               WHERE gm.entity_id = $1
             ))
           ORDER BY pb.created_at ASC"#,
    )
    .bind(req.subject_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;

    let bindings = rows
        .iter()
        .map(|row| {
            Ok((
                PolicyBinding {
                    id: row.try_get("id").map_err(AppError::Database)?,
                    tenant_id: row.try_get("tenant_id").map_err(AppError::Database)?,
                    subject_kind: row.try_get("subject_kind").map_err(AppError::Database)?,
                    subject_id: row.try_get("subject_id").map_err(AppError::Database)?,
                    grant_kind: row.try_get("grant_kind").map_err(AppError::Database)?,
                    grant_id: row.try_get("grant_id").map_err(AppError::Database)?,
                    scope_kind: row.try_get("scope_kind").map_err(AppError::Database)?,
                    scope_ref: row.try_get("scope_ref").map_err(AppError::Database)?,
                    effect: row.try_get("effect").map_err(AppError::Database)?,
                    conditions: row.try_get("conditions").map_err(AppError::Database)?,
                    created_at: row.try_get("created_at").map_err(AppError::Database)?,
                },
                row.try_get::<Option<String>, _>("role_name")
                    .map_err(AppError::Database)?,
                row.try_get::<String, _>("via")
                    .map_err(AppError::Database)?,
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    let role_ids: Vec<_> = bindings
        .iter()
        .filter(|(binding, _, _)| binding.grant_kind == GrantKind::Role)
        .map(|(binding, _, _)| binding.grant_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let role_caps = repo::capability_ids_for_roles(pool, &role_ids).await?;

    let eval_ctx = build_context(&entity_ctx, &object, tenant_ctx.as_ref(), &req.context);
    let object_id_str = object.id.to_string();
    let object_tenant_id_str = object.tenant_id.map(|t| t.to_string());
    let mut evaluated = Vec::new();
    let mut allow_match = None;

    for (binding, role_name, via) in bindings {
        let mut result = "skipped".to_string();
        let mut skip_reason = None;
        if !scope_matches(
            &binding,
            &object_id_str,
            &object.coarse_kind,
            &resource.kind,
            object_tenant_id_str.as_deref(),
        ) {
            skip_reason = Some("scope_mismatch".to_string());
        } else {
            let grant_matches = match binding.grant_kind {
                GrantKind::Capability => binding.grant_id == capability.id,
                GrantKind::Role => role_caps
                    .get(&binding.grant_id)
                    .map(|caps| caps.contains(&capability.id))
                    .unwrap_or(false),
            };
            if !grant_matches {
                skip_reason = Some("grant_mismatch".to_string());
            } else if !conditions_match(&binding.conditions, &eval_ctx) {
                skip_reason = Some("conditions_mismatch".to_string());
            } else {
                result = "matched".to_string();
            }
        }

        let evaluated_binding = EvaluatedBinding {
            id: binding.id,
            effect: binding.effect.clone(),
            grant_kind: binding.grant_kind.clone(),
            grant_id: binding.grant_id,
            role_name,
            scope_kind: binding.scope_kind,
            scope_ref: binding.scope_ref,
            conditions: binding.conditions,
            via,
            result,
            skip_reason,
        };

        if evaluated_binding.result == "matched" {
            match evaluated_binding.effect {
                Effect::Deny => {
                    let reason = format!("explicitly denied by policy {}", evaluated_binding.id);
                    evaluated.push(evaluated_binding.clone());
                    return Ok(AuthzExplainResponse {
                        allowed: false,
                        reason,
                        subject: Some(subject),
                        resource: Some(resource),
                        capability: Some(capability),
                        matched_binding: Some(evaluated_binding),
                        evaluated_bindings: evaluated,
                    });
                }
                Effect::Allow => {
                    allow_match = Some(evaluated_binding.clone());
                }
            }
        }
        evaluated.push(evaluated_binding);
    }

    if let Some(matched_binding) = allow_match {
        Ok(AuthzExplainResponse {
            allowed: true,
            reason: "allowed".to_string(),
            subject: Some(subject),
            resource: Some(resource),
            capability: Some(capability),
            matched_binding: Some(matched_binding),
            evaluated_bindings: evaluated,
        })
    } else {
        Ok(AuthzExplainResponse {
            allowed: false,
            reason: "no matching allow policy".to_string(),
            subject: Some(subject),
            resource: Some(resource),
            capability: Some(capability),
            matched_binding: None,
            evaluated_bindings: evaluated,
        })
    }
}

/// M3 / TEN-14 / AZ-16 / AUD-8: deny the request when the object's owning
/// tenant is not `active`. Returns `Ok(None)` for platform/global objects and
/// for active tenants. The deny carries `tenant_id` + `tenant_status` in
/// `details` so audit can record the lifecycle reason.
async fn check_tenant_lifecycle(
    pool: &PgPool,
    object: &ProtectedObject,
) -> Result<Option<AuthzResponse>, AppError> {
    use sqlx::Row;

    let Some(tenant_id) = object.tenant_id else {
        return Ok(None);
    };

    let row = sqlx::query("SELECT status FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let status: TenantStatus = row.try_get("status").map_err(AppError::Database)?;
    let state = match status {
        TenantStatus::Active => return Ok(None),
        TenantStatus::Inactive => "inactive",
        TenantStatus::Frozen => "frozen",
        TenantStatus::Deleted => "deleted",
    };

    Ok(Some(AuthzResponse::deny_with_details(
        format!("tenant is {state}"),
        json!({
            "tenant_id": tenant_id,
            "tenant_status": state,
        }),
    )))
}

async fn load_tenant_context(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
) -> Result<Option<TenantEvalContext>, AppError> {
    use sqlx::Row;

    let Some(tenant_id) = tenant_id else {
        return Ok(None);
    };

    let row = sqlx::query("SELECT id, status, attributes FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database)?;

    row.map(|row| {
        Ok(TenantEvalContext {
            id: row.try_get("id").map_err(AppError::Database)?,
            status: row.try_get("status").map_err(AppError::Database)?,
            attributes: row.try_get("attributes").map_err(AppError::Database)?,
        })
    })
    .transpose()
}

fn object_not_found_reason(req: &AuthzRequest) -> String {
    match req.object_kind.as_deref() {
        Some("tenant") => "tenant not found".to_string(),
        Some("entity") => "entity not found".to_string(),
        Some(kind) => format!("{kind} not found"),
        None => "resource not found".to_string(),
    }
}

/// Match a policy binding's scope against the protected object.
///
/// - `Platform`: matches every object (super-admin / inheritance lands in M4).
/// - `Tenant`: requires the object to live inside the referenced tenant. Full
///   tenant-inheritance evaluation lands in M3/M4. For M1 we already return a
///   correct local match (object's tenant_id equals scope_ref UUID); platform
///   inheritance into tenants is M4.
/// - `ObjectKind`: scope_ref equals the coarse object kind (e.g., `"resource"`).
/// - `ObjectType`: scope_ref is namespaced (`"<coarse>:<sub>"`) and must match
///   both halves.
/// - `Object`: scope_ref equals the object's UUID as text.
fn scope_matches(
    binding: &PolicyBinding,
    object_id: &str,
    coarse_kind: &str,
    sub_kind: &str,
    object_tenant_id: Option<&str>,
) -> bool {
    if let Some(policy_tenant_id) = binding.tenant_id {
        if object_tenant_id.and_then(|id| id.parse::<Uuid>().ok()) != Some(policy_tenant_id) {
            return false;
        }
    }

    match binding.scope_kind {
        ScopeKind::Platform => true,
        ScopeKind::Tenant => match (binding.scope_ref.as_deref(), object_tenant_id) {
            (Some(scope_ref), Some(tenant)) => scope_ref == tenant,
            _ => false,
        },
        ScopeKind::ObjectKind => binding
            .scope_ref
            .as_deref()
            .map(|k| k == coarse_kind)
            .unwrap_or(false),
        ScopeKind::ObjectType => binding
            .scope_ref
            .as_deref()
            .and_then(|s| s.split_once(':'))
            .map(|(prefix, sub)| prefix == coarse_kind && sub == sub_kind)
            .unwrap_or(false),
        ScopeKind::Object => binding
            .scope_ref
            .as_deref()
            .map(|r| r == object_id)
            .unwrap_or(false),
    }
}

fn build_context(
    entity: &EntityEvalContext,
    object: &ProtectedObject,
    tenant: Option<&TenantEvalContext>,
    extra: &Value,
) -> Value {
    let object_type = namespaced_object_type(object);
    let tenant_value = tenant
        .map(|tenant| {
            json!({
                "id": tenant.id,
                "status": tenant.status,
                "attributes": tenant.attributes,
            })
        })
        .unwrap_or(Value::Null);

    serde_json::json!({
        "entity": {
            "id": entity.id,
            "kind": entity.kind,
            "tenant_id": entity.tenant_id,
            "status": entity.status,
            "attributes": entity.attributes,
        },
        "resource": {
            "id": object.id,
            "kind": object.kind,
            "tenant_id": object.tenant_id,
            "attributes": object.attributes,
        },
        "object": {
            "id": object.id,
            "kind": object.coarse_kind,
            "type": object_type,
            "tenant_id": object.tenant_id,
            "attributes": object.attributes,
        },
        "tenant": tenant_value,
        "context": extra,
    })
}

fn namespaced_object_type(object: &ProtectedObject) -> Value {
    match object.coarse_kind.as_str() {
        "entity" | "resource" => Value::String(format!("{}:{}", object.coarse_kind, object.kind)),
        "group" | "tenant" | "role" | "policy" | "credential" | "audit_log" => Value::Null,
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::conditions::resolve_path;
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
            tenant_id: None,
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

    #[test]
    fn build_context_includes_entity_object_resource_tenant_and_request_fields() {
        let tenant_id = Uuid::new_v4();
        let entity_id = Uuid::new_v4();
        let object_id = Uuid::new_v4();
        let entity = EntityEvalContext {
            id: entity_id,
            kind: EntityKind::Human,
            tenant_id: None,
            status: EntityStatus::Active,
            attributes: json!({"department": "ops"}),
        };
        let object = ProtectedObject {
            id: object_id,
            coarse_kind: "resource".into(),
            kind: "channel".into(),
            name: Some("telemetry".into()),
            tenant_id: Some(tenant_id),
            attributes: json!({"tags": ["production"]}),
        };
        let tenant = TenantEvalContext {
            id: tenant_id,
            status: TenantStatus::Active,
            attributes: json!({"region": "eu"}),
        };

        let ctx = build_context(
            &entity,
            &object,
            Some(&tenant),
            &json!({"mfa_verified": true}),
        );

        assert_eq!(ctx["entity"]["id"], json!(entity_id));
        assert_eq!(ctx["entity"]["kind"], "human");
        assert_eq!(ctx["object"]["kind"], "resource");
        assert_eq!(ctx["object"]["type"], "resource:channel");
        assert_eq!(ctx["resource"]["kind"], "channel");
        assert_eq!(ctx["tenant"]["id"], json!(tenant_id));
        assert_eq!(ctx["tenant"]["status"], "active");
        assert_eq!(ctx["context"]["mfa_verified"], true);
    }

    // ─── scope_matches ────────────────────────────────────────────────────────

    #[test]
    fn scope_platform_matches_everything() {
        let b = make_binding(
            ScopeKind::Platform,
            None,
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, "any-uuid", "resource", "channel", None));
        assert!(scope_matches(
            &b,
            "any-uuid",
            "tenant",
            "tenant",
            Some("any-tenant")
        ));
    }

    #[test]
    fn scope_object_kind_matches_coarse_only() {
        let b = make_binding(
            ScopeKind::ObjectKind,
            Some("resource"),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, "uuid", "resource", "channel", None));
        assert!(scope_matches(&b, "uuid", "resource", "device_config", None));
        assert!(!scope_matches(&b, "uuid", "tenant", "tenant", None));
    }

    #[test]
    fn scope_object_type_requires_namespaced_match() {
        let b = make_binding(
            ScopeKind::ObjectType,
            Some("resource:channel"),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, "uuid", "resource", "channel", None));
        assert!(!scope_matches(
            &b,
            "uuid",
            "resource",
            "device_config",
            None
        ));
        assert!(!scope_matches(&b, "uuid", "tenant", "channel", None));
    }

    #[test]
    fn scope_object_type_rejects_bare_value() {
        let b = make_binding(
            ScopeKind::ObjectType,
            Some("channel"),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(!scope_matches(&b, "uuid", "resource", "channel", None));
    }

    #[test]
    fn scope_object_matches_specific_id() {
        let res_id = Uuid::new_v4().to_string();
        let b = make_binding(
            ScopeKind::Object,
            Some(&res_id),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, &res_id, "resource", "channel", None));
        assert!(!scope_matches(
            &b,
            "other-uuid",
            "resource",
            "channel",
            None
        ));
    }

    #[test]
    fn scope_object_with_none_scope_ref_never_matches() {
        let b = make_binding(
            ScopeKind::Object,
            None,
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(!scope_matches(&b, "any-id", "resource", "channel", None));
    }

    #[test]
    fn scope_tenant_matches_when_tenant_ids_equal() {
        let tenant_id = Uuid::new_v4().to_string();
        let b = make_binding(
            ScopeKind::Tenant,
            Some(&tenant_id),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(
            &b,
            "any-uuid",
            "resource",
            "channel",
            Some(&tenant_id)
        ));
        let other_tenant = Uuid::new_v4().to_string();
        assert!(!scope_matches(
            &b,
            "any-uuid",
            "resource",
            "channel",
            Some(&other_tenant)
        ));
        assert!(!scope_matches(&b, "any-uuid", "resource", "channel", None));
    }

    #[test]
    fn tenant_owned_binding_is_bound_to_policy_tenant() {
        let tenant_id = Uuid::new_v4();
        let other_tenant_id = Uuid::new_v4().to_string();
        let mut b = make_binding(
            ScopeKind::ObjectKind,
            Some("resource"),
            GrantKind::Capability,
            Effect::Allow,
        );
        b.tenant_id = Some(tenant_id);

        assert!(scope_matches(
            &b,
            "uuid",
            "resource",
            "channel",
            Some(&tenant_id.to_string())
        ));
        assert!(!scope_matches(
            &b,
            "uuid",
            "resource",
            "channel",
            Some(&other_tenant_id)
        ));
        assert!(!scope_matches(&b, "uuid", "resource", "channel", None));
    }

    // ─── ObjectKind enum sanity ───────────────────────────────────────────────

    #[test]
    fn object_kind_serialises_to_canonical_strings() {
        use crate::models::enums::ObjectKind;
        assert_eq!(ObjectKind::Entity.as_str(), "entity");
        assert_eq!(ObjectKind::AuditLog.as_str(), "audit_log");
        // round-trip
        let v = serde_json::to_value(ObjectKind::AuditLog).unwrap();
        assert_eq!(v, serde_json::json!("audit_log"));
        let parsed: ObjectKind = serde_json::from_value(serde_json::json!("entity")).unwrap();
        assert_eq!(parsed, ObjectKind::Entity);
    }

    #[test]
    fn scope_kind_serde_round_trip() {
        for (variant, canonical) in [
            (ScopeKind::Platform, "platform"),
            (ScopeKind::Tenant, "tenant"),
            (ScopeKind::ObjectKind, "object_kind"),
            (ScopeKind::ObjectType, "object_type"),
            (ScopeKind::Object, "object"),
        ] {
            let v = serde_json::to_value(&variant).unwrap();
            assert_eq!(v, serde_json::json!(canonical));
            let parsed: ScopeKind = serde_json::from_value(v).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    // ─── object_not_found_reason ──────────────────────────────────────────────

    #[test]
    fn not_found_reason_for_legacy_resource_request() {
        let req = AuthzRequest {
            subject_id: Uuid::new_v4(),
            action: "read".into(),
            resource_id: Some(Uuid::new_v4()),
            object_kind: None,
            object_id: None,
            context: json!({}),
        };
        assert_eq!(object_not_found_reason(&req), "resource not found");
    }

    #[test]
    fn not_found_reason_for_tenant_object() {
        let req = AuthzRequest {
            subject_id: Uuid::new_v4(),
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("tenant".into()),
            object_id: Some(Uuid::new_v4()),
            context: json!({}),
        };
        assert_eq!(object_not_found_reason(&req), "tenant not found");
    }
}

#[cfg(test)]
mod db_tests {
    //! DB-gated authorization tests. Each is `#[ignore]` because it
    //! needs a live Postgres reachable via `DATABASE_URL`.
    use super::*;
    use crate::models::{
        enums::{Effect, GrantKind, ScopeKind, SubjectKind, TenantStatus},
        policy::CreatePolicyBinding,
        tenant::CreateTenant,
    };
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn pool() -> PgPool {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let pool = PgPool::connect(&url).await.expect("connect");
        sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
            .await
            .expect("load migrations")
            .run(&pool)
            .await
            .expect("migrate");
        pool
    }

    fn admin_id() -> Uuid {
        "00000000-0000-0000-0000-000000000001".parse().unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn admin_can_manage_tenant_via_object_kind() {
        let pool = pool().await;
        let t = crate::tenants::repo::create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: format!("authz-{}", Uuid::new_v4()),
                route: None,
                tags: vec![],
                attributes: serde_json::Value::Null,
            },
            None,
        )
        .await
        .expect("create tenant");

        let req = AuthzRequest {
            subject_id: admin_id(),
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("tenant".into()),
            object_id: Some(t.id),
            context: json!({}),
        };
        let resp = evaluate(&pool, &req).await.expect("evaluate");
        assert!(resp.allowed, "admin should be allowed: {}", resp.reason);

        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore]
    async fn non_holder_denied_for_tenant() {
        let pool = pool().await;
        let entity_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')",
        )
        .bind(entity_id)
        .bind(format!("nonadmin-{entity_id}"))
        .execute(&pool)
        .await
        .expect("insert entity");

        let t = crate::tenants::repo::create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: format!("authz-deny-{}", Uuid::new_v4()),
                route: None,
                tags: vec![],
                attributes: serde_json::Value::Null,
            },
            None,
        )
        .await
        .expect("create tenant");

        let req = AuthzRequest {
            subject_id: entity_id,
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("tenant".into()),
            object_id: Some(t.id),
            context: json!({}),
        };
        let resp = evaluate(&pool, &req).await.expect("evaluate");
        assert!(!resp.allowed);

        let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
            .bind(entity_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore]
    async fn legacy_resource_id_check_still_works() {
        let pool = pool().await;
        let entity_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')",
        )
        .bind(entity_id)
        .bind(format!("legacy-{entity_id}"))
        .execute(&pool)
        .await
        .expect("insert entity");

        let resource_id = Uuid::new_v4();
        sqlx::query("INSERT INTO resources (id, kind) VALUES ($1, 'channel')")
            .bind(resource_id)
            .execute(&pool)
            .await
            .expect("insert resource");

        let read_cap: Uuid =
            sqlx::query_scalar("SELECT id FROM capabilities WHERE name = 'read' LIMIT 1")
                .fetch_one(&pool)
                .await
                .expect("read cap");

        crate::authz::repo::create_policy(
            &pool,
            CreatePolicyBinding {
                tenant_id: None,
                subject_kind: SubjectKind::Entity,
                subject_id: entity_id,
                grant_kind: GrantKind::Capability,
                grant_id: read_cap,
                scope_kind: ScopeKind::Object,
                scope_ref: Some(resource_id.to_string()),
                effect: Effect::Allow,
                conditions: json!({}),
            },
        )
        .await
        .expect("policy");

        let req = AuthzRequest {
            subject_id: entity_id,
            action: "read".into(),
            resource_id: Some(resource_id),
            object_kind: None,
            object_id: None,
            context: json!({}),
        };
        let resp = evaluate(&pool, &req).await.expect("evaluate");
        assert!(resp.allowed, "legacy form must still work: {}", resp.reason);

        let _ = sqlx::query("DELETE FROM resources WHERE id = $1")
            .bind(resource_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM entities WHERE id = $1")
            .bind(entity_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore]
    async fn deleted_tenant_denies_with_lifecycle_reason() {
        // M3: deleted tenants now resolve as a state-aware deny.
        let pool = pool().await;
        let t = crate::tenants::repo::create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: format!("authz-deleted-{}", Uuid::new_v4()),
                route: None,
                tags: vec![],
                attributes: serde_json::Value::Null,
            },
            None,
        )
        .await
        .expect("create tenant");
        crate::tenants::repo::change_tenant_status(&pool, t.id, TenantStatus::Deleted, None)
            .await
            .expect("delete tenant");

        let req = AuthzRequest {
            subject_id: admin_id(),
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("tenant".into()),
            object_id: Some(t.id),
            context: json!({}),
        };
        let resp = evaluate(&pool, &req).await.expect("evaluate");
        assert!(!resp.allowed);
        assert_eq!(resp.reason, "tenant is deleted");
        let details = resp.details.expect("M3 must surface lifecycle details");
        assert_eq!(details["tenant_status"], "deleted");
        assert_eq!(
            details["tenant_id"],
            serde_json::Value::String(t.id.to_string())
        );

        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await;
    }
}
