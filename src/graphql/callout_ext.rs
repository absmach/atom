//! async-graphql extension that fires per-op callouts before executing.
//!
//! Registered once in `schema.rs`. In `parse_query` we walk the parsed
//! document, resolve variables against the request's `Variables`, and record
//! one pending callout per top-level field that has a matching entry in
//! `CalloutService`. In `execute` we run the callout chain sequentially; a
//! single DENY short-circuits the whole request with a GraphQL error carrying
//! the callout's reason and the endpoint id that denied.
//!
//! We can't run callouts inside `resolve` because `ExtensionContext` in
//! async-graphql 7.2 does not expose the request's `Variables` to that hook.
//! `parse_query` receives them explicitly, so this is where argument
//! resolution happens.
//!
//! Ordering: the extension runs *after* `graphql_handler` puts `AuthContext`
//! into request data, so `actor` is populated. It runs *before* any resolver
//! body, so scope gates / PDP / repo mutations only execute on ALLOW.

use std::sync::{Arc, Mutex};

use async_graphql::{
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextExecute, NextParseQuery},
    parser::types::{DocumentOperations, ExecutableDocument, Field, Selection, SelectionSet},
    Name, Response, ServerError, ServerResult, Variables,
};
use async_graphql_value::ConstValue;
use serde_json::Value as JsonValue;

use uuid::Uuid;

use crate::{
    audit,
    auth::AuthContext,
    callout::{envelope::Actor, CalloutOutcome, Surface},
    identity::repo as identity_repo,
    models::enums::AuditOutcome,
    state::AppState,
};

/// Factory registered on the schema builder. Reused across requests.
pub struct CalloutExtensionFactory;

impl ExtensionFactory for CalloutExtensionFactory {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(CalloutExtension {
            pending: Mutex::new(PendingByOperation::default()),
        })
    }
}

#[derive(Default)]
struct PendingByOperation {
    /// Callouts to run when a specific named operation executes.
    named: std::collections::HashMap<String, Vec<Pending>>,
    /// Callouts to run for the single anonymous operation.
    anonymous: Vec<Pending>,
}

struct Pending {
    resolver: String,
    args: JsonValue,
}

struct CalloutExtension {
    pending: Mutex<PendingByOperation>,
}

#[async_trait::async_trait]
impl Extension for CalloutExtension {
    async fn parse_query(
        &self,
        ctx: &ExtensionContext<'_>,
        query: &str,
        variables: &Variables,
        next: NextParseQuery<'_>,
    ) -> ServerResult<ExecutableDocument> {
        let doc = next.run(ctx, query, variables).await?;
        let Some(state) = ctx.data_opt::<AppState>() else {
            return Ok(doc);
        };
        let mut pending = self.pending.lock().expect("callout pending mutex");
        match &doc.operations {
            DocumentOperations::Single(op) => {
                collect_pending(
                    state,
                    &op.node.selection_set.node,
                    variables,
                    &mut pending.anonymous,
                );
            }
            DocumentOperations::Multiple(map) => {
                for (name, op) in map {
                    let mut list = Vec::new();
                    collect_pending(state, &op.node.selection_set.node, variables, &mut list);
                    if !list.is_empty() {
                        pending.named.insert(name.to_string(), list);
                    }
                }
            }
        }
        Ok(doc)
    }

    async fn execute(
        &self,
        ctx: &ExtensionContext<'_>,
        operation_name: Option<&str>,
        next: NextExecute<'_>,
    ) -> Response {
        let Some(state) = ctx.data_opt::<AppState>() else {
            return next.run(ctx, operation_name).await;
        };
        let pending = self
            .pending
            .lock()
            .expect("callout pending mutex")
            .take_for(operation_name);
        if pending.is_empty() {
            return next.run(ctx, operation_name).await;
        }
        let auth = ctx.data_opt::<AuthContext>().cloned().unwrap_or_default();
        for mut p in pending {
            enrich_args(state, &p.resolver, &mut p.args).await;
            let actor = Actor::from_auth(&auth);
            let outcome = state
                .callouts
                .check(Surface::GraphQL, &p.resolver, actor, p.args)
                .await;
            match outcome {
                CalloutOutcome::Allow | CalloutOutcome::NotConfigured => continue,
                CalloutOutcome::Deny {
                    reason,
                    endpoint_id,
                } => {
                    audit_callout_deny(state, &auth, &p.resolver, &endpoint_id, &reason);
                    let message = format!("callout denied ({endpoint_id}): {reason}");
                    return Response::from_errors(vec![ServerError::new(message, None)]);
                }
            }
        }
        next.run(ctx, operation_name).await
    }
}

impl PendingByOperation {
    fn take_for(&mut self, operation_name: Option<&str>) -> Vec<Pending> {
        match operation_name {
            Some(name) => self.named.remove(name).unwrap_or_default(),
            None => std::mem::take(&mut self.anonymous),
        }
    }
}

fn collect_pending(
    state: &AppState,
    sel: &SelectionSet,
    variables: &Variables,
    out: &mut Vec<Pending>,
) {
    for item in &sel.items {
        if let Selection::Field(field) = &item.node {
            let name = field.node.name.node.as_str();
            if state.callouts.graphql_op(name).is_none() {
                continue;
            }
            out.push(Pending {
                resolver: name.to_string(),
                args: field_args_to_json(&field.node, variables),
            });
        }
        // Fragments are unusual on top-level fields; the resolver-name based
        // gate model doesn't extend naturally to them. We ignore them here —
        // the alternative would be to resolve them and re-walk, which
        // complicates the model without matching a real use case.
    }
}

fn field_args_to_json(field: &Field, variables: &Variables) -> JsonValue {
    let mut out = serde_json::Map::new();
    for (name, value) in &field.arguments {
        let const_val = value
            .node
            .clone()
            .into_const_with::<()>(|var| resolve_variable(variables, &var).ok_or(()))
            .unwrap_or(ConstValue::Null);
        let json = const_val.into_json().unwrap_or(JsonValue::Null);
        out.insert(name.node.to_string(), json);
    }
    JsonValue::Object(out)
}

fn resolve_variable(variables: &Variables, name: &Name) -> Option<ConstValue> {
    variables.get(name).cloned()
}

/// Enrich `args` with fields the callout policy may want to see but which are
/// not present in the raw GraphQL arguments. For `deleteEntity`, add the
/// target entity's `kind` so policy can gate on device/human/service without a
/// round-trip to the Atom API.
///
/// Best-effort: any lookup failure (missing row, DB error) leaves `args` as-is
/// and lets the callout run without the enriched fields. The subsequent
/// resolver will surface the real error to the caller.
async fn enrich_args(state: &AppState, resolver: &str, args: &mut JsonValue) {
    if resolver != "deleteEntity" {
        return;
    }
    let Some(id_str) = args.get("id").and_then(JsonValue::as_str) else {
        return;
    };
    let Ok(id) = Uuid::parse_str(id_str) else {
        return;
    };
    if let Ok(entity) = identity_repo::get_entity(&state.pool, id).await {
        if let Some(map) = args.as_object_mut() {
            if let Ok(kind) = serde_json::to_value(&entity.kind) {
                map.insert("kind".into(), kind);
            }
        }
    }
}

fn audit_callout_deny(
    state: &AppState,
    auth: &AuthContext,
    operation: &str,
    endpoint: &str,
    reason: &str,
) {
    let pool = state.pool.clone();
    let actor_id = (!auth.entity_id.is_nil()).then_some(auth.entity_id);
    let tenant_id = auth.tenant_id;
    let events_enabled = state.config.events.enabled();
    let operation = operation.to_string();
    let endpoint = endpoint.to_string();
    let reason = reason.to_string();
    tokio::spawn(async move {
        audit::write(
            &pool,
            events_enabled,
            audit::AuditEvent {
                actor_entity_id: actor_id,
                tenant_id,
                target_kind: Some("callout"),
                target_id: None,
                event: "callout.deny",
                outcome: AuditOutcome::Deny,
                details: serde_json::json!({
                    "operation": operation,
                    "surface": "graphql",
                    "endpoint": endpoint,
                    "reason": reason,
                }),
            },
        )
        .await;
    });
}
