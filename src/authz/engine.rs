use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{
        access::{
            AuthzExplainResponse, EvaluatedBinding, ExplainCapability, ExplainSubject,
            ResourceSummary,
        },
        enums::{Effect, EntityStatus, GrantKind, ScopeKind},
        policy::{AuthzRequest, AuthzResponse, PolicyBinding},
    },
};

use super::repo;

/// Generic protected object resolved from either `resources` or `tenants`.
/// `kind` participates in scope/capability matching; `id` is what
/// `scope_kind = resource` policies match against (as text).
pub(crate) struct ProtectedObject {
    pub id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub attributes: Value,
}

/// Resolve the protected object identified by an authz request.
/// Returns `Ok(None)` if the object does not exist; returns
/// `BadRequest` if the request supplies neither `resource_id` nor
/// `(object_kind, object_id)`, or supplies an unsupported `object_kind`.
pub(crate) async fn resolve_object(
    pool: &PgPool,
    req: &AuthzRequest,
) -> Result<Option<ProtectedObject>, AppError> {
    use sqlx::Row;

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
                let row = sqlx::query(
                    "SELECT id, name, attributes FROM tenants WHERE id = $1 AND status <> 'deleted'",
                )
                .bind(id)
                .fetch_optional(pool)
                .await
                .map_err(AppError::Database)?;
                Ok(row.map(|r| ProtectedObject {
                    id,
                    kind: "tenant".to_string(),
                    name: r.try_get::<String, _>("name").ok(),
                    tenant_id: Some(id),
                    attributes: r
                        .try_get::<Value, _>("attributes")
                        .unwrap_or(Value::Object(Default::default())),
                }))
            }
            other => Err(AppError::bad_request(format!(
                "unsupported object_kind '{other}' (supported: resource, tenant)"
            ))),
        };
    }

    let resource_id = req.resource_id.ok_or_else(|| {
        AppError::bad_request("authz check requires either resource_id or (object_kind, object_id)")
    })?;
    load_resource(pool, resource_id).await
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

pub async fn evaluate(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzResponse, AppError> {
    use sqlx::Row;

    let entity_row = sqlx::query("SELECT attributes, status FROM entities WHERE id = $1")
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
    let entity_attrs: Value = entity_row
        .try_get("attributes")
        .map_err(AppError::Database)?;

    let object = match resolve_object(pool, req).await? {
        Some(obj) => obj,
        None => {
            return Ok(AuthzResponse {
                allowed: false,
                reason: object_not_found_reason(req),
            });
        }
    };

    let cap_id = repo::find_capability_by_name(pool, &req.action, &object.kind).await?;
    let cap_id = match cap_id {
        Some(id) => id,
        None => {
            return Ok(AuthzResponse {
                allowed: false,
                reason: format!("unknown action '{}'", req.action),
            });
        }
    };

    let eval_ctx = build_context(&entity_attrs, &object.attributes, &req.context);
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
    let mut has_allow = false;

    for binding in &bindings {
        if !scope_matches(binding, &object_id_str, &object.kind) {
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

pub async fn explain(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzExplainResponse, AppError> {
    use sqlx::Row;

    let entity_row =
        sqlx::query("SELECT id, name, kind, status, attributes FROM entities WHERE id = $1")
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
    let entity_attrs: Value = entity_row
        .try_get("attributes")
        .map_err(AppError::Database)?;

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
    let resource_attrs: Value = object.attributes.clone();

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
        r#"SELECT pb.id, pb.subject_kind, pb.subject_id, pb.grant_kind, pb.grant_id,
                  pb.scope_kind, pb.scope_ref, pb.effect, pb.conditions, pb.created_at,
                  role.name AS role_name,
                  CASE
                    WHEN pb.subject_kind = 'entity' THEN 'direct'
                    ELSE 'group:' || g.name
                  END AS via
           FROM policy_bindings pb
           LEFT JOIN groups g ON pb.subject_kind = 'group' AND g.id = pb.subject_id
           LEFT JOIN roles role ON pb.grant_kind = 'role' AND role.id = pb.grant_id
           WHERE
             (pb.subject_kind = 'entity' AND pb.subject_id = $1)
             OR
             (pb.subject_kind = 'group' AND pb.subject_id IN (
               SELECT group_id FROM group_members WHERE entity_id = $1
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

    let eval_ctx = build_context(&entity_attrs, &resource_attrs, &req.context);
    let object_id_str = object.id.to_string();
    let mut evaluated = Vec::new();
    let mut allow_match = None;

    for (binding, role_name, via) in bindings {
        let mut result = "skipped".to_string();
        let mut skip_reason = None;
        if !scope_matches(&binding, &object_id_str, &resource.kind) {
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

fn object_not_found_reason(req: &AuthzRequest) -> String {
    match req.object_kind.as_deref() {
        Some("tenant") => "tenant not found".to_string(),
        Some(kind) => format!("{kind} not found"),
        None => "resource not found".to_string(),
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
        let b = make_binding(
            ScopeKind::Resource,
            None,
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(!scope_matches(&b, "any-id", "any-kind"));
    }

    // ─── tenant scope matching ────────────────────────────────────────────────

    #[test]
    fn scope_resource_kind_matches_tenant_kind() {
        let b = make_binding(
            ScopeKind::ResourceKind,
            Some("tenant"),
            GrantKind::Capability,
            Effect::Allow,
        );
        let tenant_id = Uuid::new_v4().to_string();
        assert!(scope_matches(&b, &tenant_id, "tenant"));
        assert!(!scope_matches(&b, &tenant_id, "channel"));
    }

    #[test]
    fn scope_resource_matches_tenant_uuid() {
        let tenant_id = Uuid::new_v4().to_string();
        let b = make_binding(
            ScopeKind::Resource,
            Some(&tenant_id),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches(&b, &tenant_id, "tenant"));
        let other = Uuid::new_v4().to_string();
        assert!(!scope_matches(&b, &other, "tenant"));
    }

    #[test]
    fn scope_all_covers_tenant_objects() {
        let b = make_binding(ScopeKind::All, None, GrantKind::Capability, Effect::Allow);
        assert!(scope_matches(&b, &Uuid::new_v4().to_string(), "tenant"));
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
        sqlx::migrate!("./migrations")
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
                subject_kind: SubjectKind::Entity,
                subject_id: entity_id,
                grant_kind: GrantKind::Capability,
                grant_id: read_cap,
                scope_kind: ScopeKind::Resource,
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
    async fn deleted_tenant_resolves_as_not_found() {
        let pool = pool().await;
        let t = crate::tenants::repo::create_tenant(
            &pool,
            CreateTenant {
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
        assert_eq!(resp.reason, "tenant not found");

        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await;
    }
}
