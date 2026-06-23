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
        policy::{AuthzRequest, AuthzResponse},
    },
};
use serde_json::json;

#[cfg(test)]
use crate::models::policy::PolicyBinding;

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
    pub parent_group_id: Option<Uuid>,
    pub ancestor_group_ids: Vec<Uuid>,
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
            parent_group_id: None,
            ancestor_group_ids: Vec::new(),
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
                Ok(repo::load_authz_tenant(pool, id)
                    .await?
                    .map(tenant_object_from_record))
            }
            "entity" => load_entity_as_object(pool, id).await,
            "group" => load_group_as_object(pool, id).await,
            "credential" => load_credential_as_object(pool, id).await,
            other => Err(AppError::bad_request(format!(
                "unsupported object_kind '{other}' (supported: platform, resource, tenant, entity, group, credential)"
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
    load_protected_object(
        pool,
        "entity",
        repo::load_authz_entity_object(pool, id).await?,
    )
    .await
}

async fn load_resource(pool: &PgPool, id: Uuid) -> Result<Option<ProtectedObject>, AppError> {
    load_protected_object(pool, "resource", repo::load_authz_resource(pool, id).await?).await
}

async fn load_group_as_object(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ProtectedObject>, AppError> {
    load_protected_object(
        pool,
        "group",
        repo::load_authz_group_object(pool, id).await?,
    )
    .await
}

async fn load_credential_as_object(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ProtectedObject>, AppError> {
    load_protected_object(
        pool,
        "credential",
        repo::load_authz_credential_object(pool, id).await?,
    )
    .await
}

async fn load_protected_object(
    pool: &PgPool,
    coarse_kind: &str,
    record: Option<repo::AuthzObjectRecord>,
) -> Result<Option<ProtectedObject>, AppError> {
    let Some(record) = record else {
        return Ok(None);
    };
    let ancestor_group_ids = match record.parent_group_id {
        Some(parent_group_id) => repo::group_ancestor_ids(pool, parent_group_id).await?,
        None => Vec::new(),
    };
    Ok(Some(protected_object_from_record(
        coarse_kind,
        record,
        ancestor_group_ids,
    )))
}

fn protected_object_from_record(
    coarse_kind: &str,
    record: repo::AuthzObjectRecord,
    ancestor_group_ids: Vec<Uuid>,
) -> ProtectedObject {
    ProtectedObject {
        id: record.id,
        coarse_kind: coarse_kind.to_string(),
        kind: record.kind,
        name: record.name,
        tenant_id: record.tenant_id,
        attributes: record.attributes,
        parent_group_id: record.parent_group_id,
        ancestor_group_ids,
    }
}

fn tenant_object_from_record(tenant: repo::AuthzTenantRecord) -> ProtectedObject {
    ProtectedObject {
        id: tenant.id,
        coarse_kind: "tenant".to_string(),
        kind: "tenant".to_string(),
        name: Some(tenant.name),
        tenant_id: Some(tenant.id),
        attributes: tenant.attributes,
        parent_group_id: None,
        ancestor_group_ids: Vec::new(),
    }
}

/// Everything `evaluate` and `explain` need once the request has been resolved
/// far enough to run the grant-match loop. Built once by [`load_decision_context`]
/// so the two readers cannot diverge on how they load policy.
struct ReadyContext {
    subject: ExplainSubject,
    resource: ResourceSummary,
    object: ProtectedObject,
    capability: ExplainCapability,
    capability_ids: std::collections::HashSet<Uuid>,
    grants: Vec<repo::EffectiveGrant>,
    eval_ctx: Value,
}

/// A request that short-circuited before the grant loop (subject/object/action
/// problems, or the tenant-lifecycle deny). `response` is the full PDP response
/// — it carries the tenant-lifecycle audit `details` — and `subject`/`resource`
/// are whatever was resolved before the stop, for `explain` to surface.
struct DeniedContext {
    response: AuthzResponse,
    subject: Option<ExplainSubject>,
    resource: Option<ResourceSummary>,
}

enum DecisionContext {
    Ready(Box<ReadyContext>),
    Denied(DeniedContext),
}

fn denied(
    response: AuthzResponse,
    subject: Option<ExplainSubject>,
    resource: Option<ResourceSummary>,
) -> DecisionContext {
    DecisionContext::Denied(DeniedContext {
        response,
        subject,
        resource,
    })
}

/// Shared context loader for `evaluate` and `explain`: resolves the subject, the
/// protected object, the tenant lifecycle, the applicable actions, the single
/// canonical grant expansion, and the ABAC context — exactly once, with one set
/// of queries. Either short-circuits with [`DecisionContext::Denied`] (carrying
/// the full PDP response so audit details survive) or returns a `Ready` context
/// for the shared `match_grant` loop. Centralising this is what stops `explain`
/// from drifting from the real decision (it previously inlined its own subject
/// and action SQL).
async fn load_decision_context(
    pool: &PgPool,
    req: &AuthzRequest,
) -> Result<DecisionContext, AppError> {
    let Some(entity) = repo::load_authz_subject(pool, req.subject_id).await? else {
        return Ok(denied(AuthzResponse::deny("subject not found"), None, None));
    };

    let subject = ExplainSubject {
        id: entity.id,
        name: entity.name,
        kind: entity.kind,
        status: entity.status,
    };
    let entity_ctx = EntityEvalContext {
        id: subject.id,
        kind: subject.kind.clone(),
        tenant_id: entity.tenant_id,
        status: subject.status.clone(),
        attributes: entity.attributes,
    };

    if subject.status != EntityStatus::Active {
        return Ok(denied(
            AuthzResponse::deny("subject is not active"),
            Some(subject),
            None,
        ));
    }

    let object = match resolve_object(pool, req).await? {
        Some(obj) => obj,
        None => {
            return Ok(denied(
                AuthzResponse::deny(object_not_found_reason(req)),
                Some(subject),
                None,
            ));
        }
    };

    let resource = ResourceSummary {
        id: object.id,
        kind: object.kind.clone(),
        name: object.name.clone(),
        tenant_id: object.tenant_id,
    };

    // M3: load the object's owning tenant once. The same row drives the
    // lifecycle short-circuit (kept ahead of action resolution so "tenant is
    // frozen" wins over "unknown action") and the ABAC context built below. The
    // lifecycle deny carries audit `details`, surfaced through the full response.
    let tenant_ctx = match load_tenant(pool, object.tenant_id).await? {
        TenantLoad::Inactive(deny) => return Ok(denied(deny, Some(subject), Some(resource))),
        TenantLoad::None => None,
        TenantLoad::Active(ctx) => Some(ctx),
    };

    let cap_ids =
        repo::find_capability_ids_by_name(pool, &req.action, &object.coarse_kind, &object.kind)
            .await?;
    if cap_ids.is_empty() {
        return Ok(denied(
            AuthzResponse::deny(format!("unknown action '{}'", req.action)),
            Some(subject),
            Some(resource),
        ));
    }
    // The lookup filters on `c.name = req.action`, so every applicable action is
    // the requested one; the first id (ordered by id) represents it for explain.
    let capability = ExplainCapability {
        id: cap_ids[0],
        name: req.action.clone(),
    };
    let capability_ids = cap_ids
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();

    let eval_ctx = build_context(&entity_ctx, &object, tenant_ctx.as_ref(), &req.context);

    // Single canonical grant expansion: direct policies and role-linked blocks,
    // group membership already resolved recursively, each grant carrying its own
    // scope/effect/conditions. One match loop replaces the direct/role split.
    let grants = repo::effective_grants_for_subject(pool, req.subject_id).await?;

    Ok(DecisionContext::Ready(Box::new(ReadyContext {
        subject,
        resource,
        object,
        capability,
        capability_ids,
        grants,
        eval_ctx,
    })))
}

/// Build the scope-match target from a resolved object. The owned id/tenant
/// strings must outlive the returned borrow, so they are passed in by the caller.
fn scope_target<'a>(
    object: &'a ProtectedObject,
    object_id_str: &'a str,
    object_tenant_id_str: Option<&'a str>,
) -> ScopeMatchObject<'a> {
    ScopeMatchObject {
        object_id: object_id_str,
        coarse_kind: &object.coarse_kind,
        sub_kind: &object.kind,
        tenant_id: object_tenant_id_str,
        parent_group_id: object.parent_group_id,
        ancestor_group_ids: &object.ancestor_group_ids,
    }
}

pub async fn evaluate(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzResponse, AppError> {
    let ctx = match load_decision_context(pool, req).await? {
        DecisionContext::Denied(denied) => return Ok(denied.response),
        DecisionContext::Ready(ctx) => ctx,
    };

    let object_id_str = ctx.object.id.to_string();
    let object_tenant_id_str = ctx.object.tenant_id.map(|t| t.to_string());
    let target = scope_target(&ctx.object, &object_id_str, object_tenant_id_str.as_deref());

    let mut has_allow = false;
    for grant in &ctx.grants {
        if match_grant(grant, &target, &ctx.capability_ids, &ctx.eval_ctx).is_some() {
            continue;
        }
        match grant.effect {
            Effect::Deny => return Ok(AuthzResponse::deny(deny_reason(grant))),
            Effect::Allow => has_allow = true,
        }
    }

    if has_allow {
        Ok(AuthzResponse::allow())
    } else {
        Ok(AuthzResponse::deny("no matching allow policy"))
    }
}

/// Whether the subject is allowed any of `actions` on the object, evaluated
/// through the PDP. Used where one capability implies another for object
/// access — e.g. `manage` implies `read`, so an object read resolver allows a
/// caller who can `read` *or* `manage` the object — without falling back to the
/// coarse control-plane gate.
pub async fn allows_any(
    pool: &PgPool,
    subject_id: Uuid,
    object_kind: &str,
    object_id: Uuid,
    actions: &[&str],
) -> Result<bool, AppError> {
    for action in actions {
        let resp = evaluate(
            pool,
            &AuthzRequest {
                subject_id,
                action: (*action).to_string(),
                resource_id: None,
                object_kind: Some(object_kind.to_string()),
                object_id: Some(object_id),
                context: Value::Null,
            },
        )
        .await?;
        if resp.allowed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Match a canonical grant against the request: assignment tenant boundary →
/// block scope (group-aware) → action → conditions. Returns `None` when the
/// grant matches, or `Some(skip_reason)` naming the first failed check. The PDP
/// decision and `explain` both go through this, so they cannot disagree. Effect
/// is applied by the caller so deny can short-circuit.
fn match_grant(
    grant: &repo::EffectiveGrant,
    target: &ScopeMatchObject<'_>,
    cap_id_set: &std::collections::HashSet<Uuid>,
    eval_ctx: &serde_json::Value,
) -> Option<&'static str> {
    let tenant_ok = grant.tenant_boundary.is_none_or(|boundary| {
        target.tenant_id.and_then(|id| id.parse::<Uuid>().ok()) == Some(boundary)
    });
    if !tenant_ok || !scope_values_match(&grant.scope_kind, grant.scope_ref.as_deref(), target) {
        return Some("scope_mismatch");
    }
    if !cap_id_set.contains(&grant.capability_id) {
        return Some("grant_mismatch");
    }
    if !conditions_match(&grant.conditions, eval_ctx) {
        return Some("conditions_mismatch");
    }
    None
}

fn deny_reason(grant: &repo::EffectiveGrant) -> String {
    match &grant.role_name {
        Some(role) => format!("explicitly denied by role '{role}' block"),
        None => "explicitly denied by direct policy".to_string(),
    }
}

pub async fn explain(pool: &PgPool, req: &AuthzRequest) -> Result<AuthzExplainResponse, AppError> {
    let ctx = match load_decision_context(pool, req).await? {
        DecisionContext::Denied(denied) => {
            return Ok(AuthzExplainResponse {
                allowed: false,
                reason: denied.response.reason,
                subject: denied.subject,
                resource: denied.resource,
                capability: None,
                matched_binding: None,
                evaluated_bindings: Vec::new(),
            });
        }
        DecisionContext::Ready(ctx) => ctx,
    };
    let ReadyContext {
        subject,
        resource,
        object,
        capability,
        capability_ids,
        grants,
        eval_ctx,
    } = *ctx;

    let object_id_str = object.id.to_string();
    let object_tenant_id_str = object.tenant_id.map(|t| t.to_string());
    let target = scope_target(&object, &object_id_str, object_tenant_id_str.as_deref());
    let mut evaluated = Vec::new();
    let mut allow_match = None;

    for grant in &grants {
        let (result, skip_reason) = match match_grant(grant, &target, &capability_ids, &eval_ctx) {
            None => ("matched".to_string(), None),
            Some(reason) => ("skipped".to_string(), Some(reason.to_string())),
        };
        let evaluated_binding = EvaluatedBinding {
            id: grant.assignment_id,
            block_id: grant.block_id,
            effect: grant.effect.clone(),
            grant_kind: if grant.role_id.is_some() {
                GrantKind::Role
            } else {
                GrantKind::Capability
            },
            grant_id: grant.role_id.unwrap_or(grant.capability_id),
            role_name: grant.role_name.clone(),
            role_path: grant.role_name.clone(),
            scope_kind: grant.scope_kind.clone(),
            scope_ref: grant.scope_ref.clone(),
            conditions: grant.conditions.clone(),
            via: grant.via.clone(),
            result,
            skip_reason,
        };

        if evaluated_binding.result == "matched" {
            match grant.effect {
                Effect::Deny => {
                    let reason = deny_reason(grant);
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

/// Outcome of loading the object's owning tenant once per check.
enum TenantLoad {
    /// No owning tenant (platform/global object) or the tenant row is missing —
    /// no lifecycle gate and no tenant ABAC context.
    None,
    /// M3 / TEN-14 / AZ-16 / AUD-8: the tenant is not `active`. Carries the deny,
    /// whose `details` hold `tenant_id` + `tenant_status` for audit.
    Inactive(AuthzResponse),
    /// Active tenant context for the ABAC build.
    Active(TenantEvalContext),
}

/// Load the object's owning tenant a single time, serving both the lifecycle
/// short-circuit and the ABAC context (previously two separate queries of the
/// same row).
async fn load_tenant(pool: &PgPool, tenant_id: Option<Uuid>) -> Result<TenantLoad, AppError> {
    let Some(tenant_id) = tenant_id else {
        return Ok(TenantLoad::None);
    };

    Ok(tenant_load_from_record(
        repo::load_authz_tenant(pool, tenant_id).await?,
    ))
}

fn tenant_load_from_record(tenant: Option<repo::AuthzTenantRecord>) -> TenantLoad {
    let Some(tenant) = tenant else {
        return TenantLoad::None;
    };

    let state = match tenant.status {
        TenantStatus::Active => {
            return TenantLoad::Active(TenantEvalContext {
                id: tenant.id,
                status: tenant.status,
                attributes: tenant.attributes,
            });
        }
        TenantStatus::Inactive => "inactive",
        TenantStatus::Frozen => "frozen",
        TenantStatus::Deleted => "deleted",
    };

    TenantLoad::Inactive(AuthzResponse::deny_with_details(
        format!("tenant is {state}"),
        json!({
            "tenant_id": tenant.id,
            "tenant_status": state,
        }),
    ))
}

fn object_not_found_reason(req: &AuthzRequest) -> String {
    match req.object_kind.as_deref() {
        Some("tenant") => "tenant not found".to_string(),
        Some("entity") => "entity not found".to_string(),
        Some("credential") => "credential not found".to_string(),
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
#[cfg(test)]
fn scope_matches(
    binding: &PolicyBinding,
    object_id: &str,
    coarse_kind: &str,
    sub_kind: &str,
    object_tenant_id: Option<&str>,
) -> bool {
    scope_matches_with_groups(
        binding,
        object_id,
        coarse_kind,
        sub_kind,
        object_tenant_id,
        None,
        &[],
    )
}

/// Test-only convenience wrapper that applies the direct-policy tenant boundary
/// then `scope_values_match`. Production code goes through `match_grant`, which
/// applies the same boundary against `EffectiveGrant::tenant_boundary`.
#[cfg(test)]
fn scope_matches_with_groups(
    binding: &PolicyBinding,
    object_id: &str,
    coarse_kind: &str,
    sub_kind: &str,
    object_tenant_id: Option<&str>,
    parent_group_id: Option<Uuid>,
    ancestor_group_ids: &[Uuid],
) -> bool {
    if let Some(policy_tenant_id) = binding.tenant_id {
        if object_tenant_id.and_then(|id| id.parse::<Uuid>().ok()) != Some(policy_tenant_id) {
            return false;
        }
    }

    let target = ScopeMatchObject {
        object_id,
        coarse_kind,
        sub_kind,
        tenant_id: object_tenant_id,
        parent_group_id,
        ancestor_group_ids,
    };
    scope_values_match(&binding.scope_kind, binding.scope_ref.as_deref(), &target)
}

struct ScopeMatchObject<'a> {
    object_id: &'a str,
    coarse_kind: &'a str,
    sub_kind: &'a str,
    tenant_id: Option<&'a str>,
    parent_group_id: Option<Uuid>,
    ancestor_group_ids: &'a [Uuid],
}

fn scope_values_match(
    scope_kind: &ScopeKind,
    scope_ref: Option<&str>,
    target: &ScopeMatchObject<'_>,
) -> bool {
    match scope_kind {
        ScopeKind::Platform => true,
        ScopeKind::Tenant => match (scope_ref, target.tenant_id) {
            (Some(scope_ref), Some(tenant)) => scope_ref == tenant,
            _ => false,
        },
        ScopeKind::ObjectKind => scope_ref.map(|k| k == target.coarse_kind).unwrap_or(false),
        ScopeKind::ObjectType => scope_ref
            .and_then(|s| s.split_once(':'))
            .map(|(prefix, sub)| prefix == target.coarse_kind && sub == target.sub_kind)
            .unwrap_or(false),
        ScopeKind::Object => scope_ref.map(|r| r == target.object_id).unwrap_or(false),
        ScopeKind::GroupObjectType => group_object_scope_matches(
            scope_ref,
            target.coarse_kind,
            target.sub_kind,
            target.parent_group_id,
            &[],
        ),
        ScopeKind::GroupTreeObjectType => group_object_scope_matches(
            scope_ref,
            target.coarse_kind,
            target.sub_kind,
            None,
            target.ancestor_group_ids,
        ),
        ScopeKind::GroupChildKind => {
            group_kind_scope_matches(scope_ref, target.coarse_kind, target.parent_group_id, &[])
        }
        ScopeKind::GroupDescendantKind => group_kind_scope_matches(
            scope_ref,
            target.coarse_kind,
            target.parent_group_id,
            target.ancestor_group_ids,
        ),
    }
}

fn group_object_scope_matches(
    scope_ref: Option<&str>,
    coarse_kind: &str,
    sub_kind: &str,
    parent_group_id: Option<Uuid>,
    ancestor_group_ids: &[Uuid],
) -> bool {
    let Some((group_id, object_type)) = parse_group_scope_ref(scope_ref) else {
        return false;
    };
    let Some((prefix, sub)) = object_type.split_once(':') else {
        return false;
    };
    prefix == coarse_kind
        && sub == sub_kind
        && group_scope_contains(parent_group_id, ancestor_group_ids, group_id)
}

fn group_kind_scope_matches(
    scope_ref: Option<&str>,
    coarse_kind: &str,
    parent_group_id: Option<Uuid>,
    ancestor_group_ids: &[Uuid],
) -> bool {
    let Some((group_id, kind)) = parse_group_scope_ref(scope_ref) else {
        return false;
    };
    kind == "group"
        && coarse_kind == "group"
        && group_scope_contains(parent_group_id, ancestor_group_ids, group_id)
}

fn group_scope_contains(
    parent_group_id: Option<Uuid>,
    ancestor_group_ids: &[Uuid],
    group_id: Uuid,
) -> bool {
    parent_group_id == Some(group_id) || ancestor_group_ids.contains(&group_id)
}

fn parse_group_scope_ref(scope_ref: Option<&str>) -> Option<(Uuid, &str)> {
    let (group_id, rest) = scope_ref?.split_once(':')?;
    Some((group_id.parse().ok()?, rest))
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
            "parent_group_id": object.parent_group_id,
            "ancestor_group_ids": object.ancestor_group_ids,
        },
        "object": {
            "id": object.id,
            "kind": object.coarse_kind,
            "type": object_type,
            "tenant_id": object.tenant_id,
            "attributes": object.attributes,
            "parent_group_id": object.parent_group_id,
            "ancestor_group_ids": object.ancestor_group_ids,
        },
        "tenant": tenant_value,
        "context": extra,
    })
}

fn namespaced_object_type(object: &ProtectedObject) -> Value {
    match object.coarse_kind.as_str() {
        "entity" | "resource" => Value::String(format!("{}:{}", object.coarse_kind, object.kind)),
        "group" | "tenant" | "role" | "policy" | "credential" | "audit_log" | "signing_key" => {
            Value::Null
        }
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
            parent_group_id: None,
            ancestor_group_ids: Vec::new(),
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

    #[test]
    fn protected_object_mapping_preserves_repo_record_and_ancestors() {
        let object_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let parent_group_id = Uuid::new_v4();
        let ancestor_group_id = Uuid::new_v4();
        let object = protected_object_from_record(
            "resource",
            repo::AuthzObjectRecord {
                id: object_id,
                kind: "channel".into(),
                name: Some("telemetry".into()),
                tenant_id: Some(tenant_id),
                attributes: json!({"region": "eu"}),
                parent_group_id: Some(parent_group_id),
            },
            vec![ancestor_group_id],
        );

        assert_eq!(object.id, object_id);
        assert_eq!(object.coarse_kind, "resource");
        assert_eq!(object.kind, "channel");
        assert_eq!(object.name.as_deref(), Some("telemetry"));
        assert_eq!(object.tenant_id, Some(tenant_id));
        assert_eq!(object.attributes, json!({"region": "eu"}));
        assert_eq!(object.parent_group_id, Some(parent_group_id));
        assert_eq!(object.ancestor_group_ids, vec![ancestor_group_id]);
    }

    #[test]
    fn tenant_record_mapping_preserves_lifecycle_decision() {
        let tenant_id = Uuid::new_v4();
        let active = tenant_load_from_record(Some(repo::AuthzTenantRecord {
            id: tenant_id,
            name: "active".into(),
            status: TenantStatus::Active,
            attributes: json!({"region": "eu"}),
        }));
        match active {
            TenantLoad::Active(context) => {
                assert_eq!(context.id, tenant_id);
                assert_eq!(context.status, TenantStatus::Active);
                assert_eq!(context.attributes, json!({"region": "eu"}));
            }
            TenantLoad::None | TenantLoad::Inactive(_) => {
                panic!("active tenant must produce an active context")
            }
        }

        let frozen = tenant_load_from_record(Some(repo::AuthzTenantRecord {
            id: tenant_id,
            name: "frozen".into(),
            status: TenantStatus::Frozen,
            attributes: json!({}),
        }));
        match frozen {
            TenantLoad::Inactive(response) => {
                assert!(!response.allowed);
                assert_eq!(response.reason, "tenant is frozen");
                assert_eq!(
                    response.details,
                    Some(json!({
                        "tenant_id": tenant_id,
                        "tenant_status": "frozen",
                    }))
                );
            }
            TenantLoad::None | TenantLoad::Active(_) => {
                panic!("frozen tenant must produce a lifecycle deny")
            }
        }

        assert!(matches!(tenant_load_from_record(None), TenantLoad::None));
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
    fn scope_object_type_matches_mg_service_resources() {
        for resource_kind in ["rule", "report", "alarm"] {
            let scope_ref = format!("resource:{resource_kind}");
            let binding = make_binding(
                ScopeKind::ObjectType,
                Some(&scope_ref),
                GrantKind::Capability,
                Effect::Allow,
            );

            assert!(
                scope_matches(&binding, "uuid", "resource", resource_kind, None),
                "{scope_ref} should match {resource_kind} resources"
            );
            assert!(
                !scope_matches(&binding, "uuid", "resource", "channel", None),
                "{scope_ref} should not match channel resources"
            );
        }
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
    fn group_object_type_matches_direct_parent_group() {
        let group_id = Uuid::new_v4();
        let b = make_binding(
            ScopeKind::GroupObjectType,
            Some(&format!("{group_id}:entity:device")),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches_with_groups(
            &b,
            "client-id",
            "entity",
            "device",
            None,
            Some(group_id),
            &[],
        ));
        assert!(!scope_matches_with_groups(
            &b,
            "client-id",
            "entity",
            "device",
            None,
            None,
            &[group_id],
        ));
    }

    #[test]
    fn group_tree_object_type_matches_ancestor_group() {
        let group_id = Uuid::new_v4();
        let child_group_id = Uuid::new_v4();
        let grandchild_group_id = Uuid::new_v4();
        let b = make_binding(
            ScopeKind::GroupTreeObjectType,
            Some(&format!("{group_id}:resource:channel")),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(!scope_matches_with_groups(
            &b,
            "channel-id",
            "resource",
            "channel",
            None,
            Some(group_id),
            &[],
        ));
        assert!(scope_matches_with_groups(
            &b,
            "channel-id",
            "resource",
            "channel",
            None,
            Some(child_group_id),
            &[group_id],
        ));
        assert!(scope_matches_with_groups(
            &b,
            "channel-id",
            "resource",
            "channel",
            None,
            Some(grandchild_group_id),
            &[child_group_id, group_id],
        ));
    }

    #[test]
    fn group_descendant_kind_matches_nested_group_object() {
        let group_id = Uuid::new_v4();
        let child_group_id = Uuid::new_v4();
        let b = make_binding(
            ScopeKind::GroupDescendantKind,
            Some(&format!("{group_id}:group")),
            GrantKind::Capability,
            Effect::Allow,
        );
        assert!(scope_matches_with_groups(
            &b,
            "group-id",
            "group",
            "group",
            None,
            Some(child_group_id),
            &[group_id],
        ));
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
    fn scope_tenant_covers_tenant_owned_entities_and_resources() {
        let tenant_id = Uuid::new_v4().to_string();
        let b = make_binding(
            ScopeKind::Tenant,
            Some(&tenant_id),
            GrantKind::Role,
            Effect::Allow,
        );

        assert!(scope_matches(
            &b,
            "client-id",
            "entity",
            "device",
            Some(&tenant_id)
        ));
        assert!(scope_matches(
            &b,
            "channel-id",
            "resource",
            "channel",
            Some(&tenant_id)
        ));
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
            (ScopeKind::GroupObjectType, "group_object_type"),
            (ScopeKind::GroupTreeObjectType, "group_tree_object_type"),
            (ScopeKind::GroupChildKind, "group_child_kind"),
            (ScopeKind::GroupDescendantKind, "group_descendant_kind"),
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

    /// The PDP matches a grant's scope against an object in Rust
    /// (`scope_values_match`); authorized listing matches the same scope in SQL
    /// (`grant_scope_matches`, migration 001). They must agree exactly, or the
    /// canonical-expansion unification would silently let listing and the PDP
    /// diverge. This pins the two implementations together over every scope kind.
    #[tokio::test]
    #[ignore]
    async fn rust_and_sql_scope_matching_agree() {
        let pool = pool().await;
        let tenant = Uuid::new_v4();
        let object = Uuid::new_v4();
        let other = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let ancestor = Uuid::new_v4();

        struct Case {
            kind: ScopeKind,
            text: &'static str,
            scope_ref: Option<String>,
            coarse: &'static str,
            sub: &'static str,
            object_tenant: Option<Uuid>,
            parent_group: Option<Uuid>,
            ancestors: Vec<Uuid>,
            expected: bool,
        }

        let cases = vec![
            Case {
                kind: ScopeKind::Platform,
                text: "platform",
                scope_ref: None,
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::Tenant,
                text: "tenant",
                scope_ref: Some(tenant.to_string()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::Tenant,
                text: "tenant",
                scope_ref: Some(other.to_string()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::Tenant,
                text: "tenant",
                scope_ref: Some(tenant.to_string()),
                coarse: "entity",
                sub: "human",
                object_tenant: None,
                parent_group: None,
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::ObjectKind,
                text: "object_kind",
                scope_ref: Some("entity".into()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::ObjectKind,
                text: "object_kind",
                scope_ref: Some("resource".into()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::ObjectType,
                text: "object_type",
                scope_ref: Some("entity:human".into()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::ObjectType,
                text: "object_type",
                scope_ref: Some("entity:human".into()),
                coarse: "entity",
                sub: "device",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::Object,
                text: "object",
                scope_ref: Some(object.to_string()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::Object,
                text: "object",
                scope_ref: Some(other.to_string()),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::GroupObjectType,
                text: "group_object_type",
                scope_ref: Some(format!("{parent}:entity:human")),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::GroupObjectType,
                text: "group_object_type",
                scope_ref: Some(format!("{parent}:entity:human")),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: None,
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::GroupTreeObjectType,
                text: "group_tree_object_type",
                scope_ref: Some(format!("{ancestor}:entity:human")),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![ancestor],
                expected: true,
            },
            Case {
                kind: ScopeKind::GroupTreeObjectType,
                text: "group_tree_object_type",
                scope_ref: Some(format!("{parent}:entity:human")),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::GroupChildKind,
                text: "group_child_kind",
                scope_ref: Some(format!("{parent}:group")),
                coarse: "group",
                sub: "group",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::GroupChildKind,
                text: "group_child_kind",
                scope_ref: Some(format!("{parent}:group")),
                coarse: "entity",
                sub: "human",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![],
                expected: false,
            },
            Case {
                kind: ScopeKind::GroupDescendantKind,
                text: "group_descendant_kind",
                scope_ref: Some(format!("{parent}:group")),
                coarse: "group",
                sub: "group",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![],
                expected: true,
            },
            Case {
                kind: ScopeKind::GroupDescendantKind,
                text: "group_descendant_kind",
                scope_ref: Some(format!("{ancestor}:group")),
                coarse: "group",
                sub: "group",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![ancestor],
                expected: true,
            },
            Case {
                kind: ScopeKind::GroupDescendantKind,
                text: "group_descendant_kind",
                scope_ref: Some(format!("{other}:group")),
                coarse: "group",
                sub: "group",
                object_tenant: Some(tenant),
                parent_group: Some(parent),
                ancestors: vec![ancestor],
                expected: false,
            },
        ];

        let object_str = object.to_string();
        for case in cases {
            let tenant_str = case.object_tenant.map(|t| t.to_string());
            let target = ScopeMatchObject {
                object_id: &object_str,
                coarse_kind: case.coarse,
                sub_kind: case.sub,
                tenant_id: tenant_str.as_deref(),
                parent_group_id: case.parent_group,
                ancestor_group_ids: &case.ancestors,
            };
            let rust = scope_values_match(&case.kind, case.scope_ref.as_deref(), &target);

            let sql: bool =
                sqlx::query_scalar("SELECT grant_scope_matches($1, $2, $3, $4, $5, $6, $7, $8)")
                    .bind(case.text)
                    .bind(case.scope_ref.as_deref())
                    .bind(case.coarse)
                    .bind(case.sub)
                    .bind(object)
                    .bind(case.object_tenant)
                    .bind(case.parent_group)
                    .bind(&case.ancestors)
                    .fetch_one(&pool)
                    .await
                    .expect("grant_scope_matches");

            assert_eq!(
                rust, sql,
                "Rust/SQL scope match disagree for {} ref={:?}",
                case.text, case.scope_ref
            );
            assert_eq!(
                rust, case.expected,
                "unexpected match result for {} ref={:?}",
                case.text, case.scope_ref
            );
        }
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
                alias: None,
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
                alias: None,
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
            sqlx::query_scalar("SELECT id FROM actions WHERE name = 'read' LIMIT 1")
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
    async fn repository_loaders_resolve_group_and_credential_objects() {
        let pool = pool().await;
        let entity_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO entities (id, kind, name, status, attributes)
             VALUES ($1, 'human', $2, 'active', $3)",
        )
        .bind(entity_id)
        .bind(format!("loader-subject-{entity_id}"))
        .bind(json!({"department": "ops"}))
        .execute(&pool)
        .await
        .expect("insert entity");

        let grandparent_group_id = Uuid::new_v4();
        let parent_group_id = Uuid::new_v4();
        let child_group_id = Uuid::new_v4();
        for (group_id, name) in [
            (grandparent_group_id, "loader-grandparent"),
            (parent_group_id, "loader-parent"),
            (child_group_id, "loader-child"),
        ] {
            sqlx::query(
                "INSERT INTO object_groups (id, name, status, attributes)
                 VALUES ($1, $2, 'active', $3)",
            )
            .bind(group_id)
            .bind(format!("{name}-{group_id}"))
            .bind(json!({"source": "db-test"}))
            .execute(&pool)
            .await
            .expect("insert object group");
        }
        for (parent_id, child_id) in [
            (grandparent_group_id, parent_group_id),
            (parent_group_id, child_group_id),
        ] {
            sqlx::query(
                "INSERT INTO object_group_hierarchy (parent_id, child_id)
                 VALUES ($1, $2)",
            )
            .bind(parent_id)
            .bind(child_id)
            .execute(&pool)
            .await
            .expect("insert group hierarchy");
        }

        let group = resolve_object(
            &pool,
            &AuthzRequest {
                subject_id: entity_id,
                action: "read".into(),
                resource_id: None,
                object_kind: Some("group".into()),
                object_id: Some(child_group_id),
                context: json!({}),
            },
        )
        .await
        .expect("resolve group")
        .expect("group exists");
        assert_eq!(group.kind, "group");
        assert_eq!(group.parent_group_id, Some(parent_group_id));
        assert_eq!(group.ancestor_group_ids, vec![grandparent_group_id]);

        let credential_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO credentials (id, entity_id, kind, identifier, metadata)
             VALUES ($1, $2, 'api_key', $3, $4)",
        )
        .bind(credential_id)
        .bind(entity_id)
        .bind(format!("loader-key-{credential_id}"))
        .bind(json!({"environment": "test"}))
        .execute(&pool)
        .await
        .expect("insert credential");

        let credential = resolve_object(
            &pool,
            &AuthzRequest {
                subject_id: entity_id,
                action: "revoke".into(),
                resource_id: None,
                object_kind: Some("credential".into()),
                object_id: Some(credential_id),
                context: json!({}),
            },
        )
        .await
        .expect("resolve credential")
        .expect("credential exists");
        assert_eq!(credential.kind, "api_key");
        assert_eq!(credential.attributes, json!({"environment": "test"}));
        assert_eq!(credential.parent_group_id, None);
        assert!(credential.ancestor_group_ids.is_empty());
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
                alias: None,
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
