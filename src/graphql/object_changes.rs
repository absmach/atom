use super::auth::{gql_error, require_auth};
use crate::{
    object_changes::{
        self, ObjectChangeInput, ObjectKind, ObjectLeaseGuardInput, ObjectLeaseInput,
    },
    state::AppState,
};
use async_graphql::{Context, ErrorExtensions, Object, Result, ID};
use serde_json::Value;
#[derive(Default)]
pub struct ObjectChangesMutation;
fn error(err: crate::error::AppError) -> async_graphql::Error {
    let message = err.to_string();
    let code = [
        "REVISION_CONFLICT",
        "LEASE_LOST",
        "LEASE_HELD",
        "IDEMPOTENCY_CONFLICT",
        "CONFIG_MANAGED",
    ]
    .into_iter()
    .find(|c| message.contains(c))
    .unwrap_or("OBJECT_CHANGE_FAILED");
    gql_error(err).extend_with(|_, extensions| extensions.set("code", code))
}
#[Object]
impl ObjectChangesMutation {
    async fn commit_object_changes(
        &self,
        ctx: &Context<'_>,
        request_id: ID,
        changes: Vec<ObjectChangeInput>,
        guards: Option<Vec<ObjectLeaseGuardInput>>,
    ) -> Result<Value> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = object_changes::uuid(&request_id).map_err(error)?;
        let result =
            object_changes::commit(state, &auth, id, changes, guards.unwrap_or_default()).await;
        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id: None,
                    target_kind: "transaction",
                    target_id: Some(id),
                    event: "object_changes.commit",
                },
                &serde_json::json!({}),
                err,
            )
            .await;
        }
        result.map_err(error)
    }
    async fn acquire_object_lease(
        &self,
        ctx: &Context<'_>,
        input: ObjectLeaseInput,
    ) -> Result<Value> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let target = input.object_id.clone();
        let kind = input.object_kind;
        let result = object_changes::acquire(state, &auth, input).await;
        observe_lease_error(
            state,
            auth.entity_id,
            kind,
            &target,
            "object_lease.acquire",
            &result,
        )
        .await;
        result.map_err(error)
    }
    async fn renew_object_lease(
        &self,
        ctx: &Context<'_>,
        guard: ObjectLeaseGuardInput,
        ttl_seconds: i32,
    ) -> Result<Value> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let target = guard.object_id.clone();
        let kind = guard.object_kind;
        let result = object_changes::finish_lease(state, &auth, guard, Some(ttl_seconds)).await;
        observe_lease_error(
            state,
            auth.entity_id,
            kind,
            &target,
            "object_lease.renew",
            &result,
        )
        .await;
        result.map_err(error)
    }
    async fn release_object_lease(
        &self,
        ctx: &Context<'_>,
        guard: ObjectLeaseGuardInput,
    ) -> Result<Value> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let target = guard.object_id.clone();
        let kind = guard.object_kind;
        let result = object_changes::finish_lease(state, &auth, guard, None).await;
        observe_lease_error(
            state,
            auth.entity_id,
            kind,
            &target,
            "object_lease.release",
            &result,
        )
        .await;
        result.map_err(error)
    }
}

#[derive(Default)]
pub struct ObjectChangesQuery;
#[Object]
impl ObjectChangesQuery {
    async fn validate_object_lease(
        &self,
        ctx: &Context<'_>,
        guard: ObjectLeaseGuardInput,
    ) -> Result<bool> {
        let auth = require_auth(ctx)?;
        object_changes::validate_lease(ctx.data::<AppState>()?, &auth, guard)
            .await
            .map_err(error)
    }

    /// Capability probe for clients that require transactional object metadata.
    async fn object_coordination_version(&self, ctx: &Context<'_>) -> Result<i32> {
        require_auth(ctx)?;
        Ok(1)
    }
}

async fn observe_lease_error(
    state: &AppState,
    actor: uuid::Uuid,
    kind: ObjectKind,
    target: &ID,
    event: &'static str,
    result: &std::result::Result<Value, crate::error::AppError>,
) {
    if let Err(err) = result {
        crate::audit::observe_error(
            &state.pool,
            state.config.events.enabled(),
            &crate::audit::AuditMeta {
                actor_entity_id: Some(actor),
                tenant_id: None,
                target_kind: match kind {
                    ObjectKind::Entity => "entity",
                    ObjectKind::Resource => "resource",
                },
                target_id: object_changes::uuid(target).ok(),
                event,
            },
            &serde_json::json!({}),
            err,
        )
        .await;
    }
}
