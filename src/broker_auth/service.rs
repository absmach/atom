//! The `fluxmq.auth.v1.AuthService` implementation.
//!
//! ## Denials are answers, not errors
//!
//! Every rejection this service can reach — bad password, unknown entity,
//! unparseable topic, policy deny, rate limit — returns a *successful* RPC
//! carrying `authenticated: false` / `authorized: false`. Only a genuine
//! infrastructure failure returns a gRPC error.
//!
//! That is not stylistic. A broker wraps this callout in a circuit breaker; a
//! run of RPC errors trips it, and a tripped breaker rejects **every** client
//! connection, not just the one that misbehaved. A single device retrying with
//! a stale password must not be able to take the broker's whole auth path down.
//! Rate limiting is on that list for the same reason: it is the one failure a
//! bad client can trigger at will.

use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    audit,
    authz::{engine, repo},
    certs,
    config::BrokerTopicRef,
    error::AppError,
    identity::service as identity_service,
    models::{alias::AliasObjectClass, enums::AuditOutcome, policy::AuthzRequest},
    state::AppState,
};

use super::topic::TopicMatch;

// Generated from the vendored proto/broker/v1/auth.proto. The module path is
// the proto package, which is also the gRPC wire path a broker dials.
pub mod proto {
    tonic::include_proto!("fluxmq.auth.v1");
}

pub use proto::auth_service_server::AuthServiceServer as BrokerAuthServiceServer;
use proto::{auth_service_server::AuthService, Action, AuthnReq, AuthnRes, AuthzReq, AuthzRes};

/// MQTT v5 reason codes, reused so a broker can forward something meaningful in
/// its CONNACK/SUBACK rather than a bare boolean.
const REASON_SUCCESS: u32 = 0x00;
const REASON_BAD_CREDENTIALS: u32 = 0x86;
const REASON_NOT_AUTHORIZED: u32 = 0x87;

/// The object kind every broker topic addresses. Topics name channels, which
/// are `resources` in Atom's model.
const OBJECT_KIND: &str = "resource";

pub struct BrokerAuth {
    state: AppState,
}

impl BrokerAuth {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

/// Whether a failure is a decision about the request rather than a fault in
/// Atom. See the module docs: only the latter may surface as a gRPC error.
fn is_decision(err: &AppError) -> bool {
    matches!(
        err,
        AppError::NotFound(_)
            | AppError::BadRequest(_)
            | AppError::Unauthorized(_)
            | AppError::Forbidden
            | AppError::Conflict(_)
            | AppError::RateLimited { .. }
    )
}

fn authn_denied(reason: impl Into<String>) -> AuthnRes {
    AuthnRes {
        authenticated: false,
        id: String::new(),
        reason_code: REASON_BAD_CREDENTIALS,
        reason: reason.into(),
    }
}

fn authz_denied(reason: impl Into<String>) -> AuthzRes {
    AuthzRes {
        authorized: false,
        reason_code: REASON_NOT_AUTHORIZED,
        reason: reason.into(),
    }
}

#[tonic::async_trait]
impl AuthService for BrokerAuth {
    /// Resolve broker credentials to an Atom entity.
    ///
    /// The caller is trusted at the transport (the gRPC listener's mTLS client
    /// CA); there is no bearer token on this path, because a broker's callout
    /// client has nowhere to put one.
    async fn authenticate(&self, request: Request<AuthnReq>) -> Result<Response<AuthnRes>, Status> {
        let req = request.into_inner();

        // Short-circuit before the database and, importantly, before the login
        // rate limiter: a flood of anonymous connects would otherwise spend
        // Atom's throttle budget and start returning errors that trip the
        // broker's circuit breaker.
        if req.username.is_empty() || req.password.is_empty() {
            return Ok(Response::new(authn_denied("missing credentials")));
        }

        // No tenant selector: the identifier is resolved across tenants and the
        // entity's own tenant comes back with it. That is what lets this work
        // with no configuration in a multi-tenant deployment.
        let result = identity_service::authenticate_credential_in_tenant(
            &self.state.pool,
            &self.state.config,
            &req.username,
            &req.password,
            None,
            self.state.config.broker_auth.credential_kind,
        )
        .await;

        match result {
            Ok(authenticated) => {
                tracing::debug!(
                    client_id = %req.client_id,
                    entity_id = %authenticated.entity_id,
                    "broker authenticate: allow"
                );
                Ok(Response::new(AuthnRes {
                    authenticated: true,
                    id: authenticated.entity_id.to_string(),
                    reason_code: REASON_SUCCESS,
                    reason: String::new(),
                }))
            }
            Err(err) if is_decision(&err) => {
                tracing::debug!(
                    client_id = %req.client_id,
                    error = %err,
                    "broker authenticate: deny"
                );
                Ok(Response::new(authn_denied(err.to_string())))
            }
            Err(err) => {
                tracing::error!(client_id = %req.client_id, error = %err, "broker authenticate: failed");
                Err(Status::from(err))
            }
        }
    }

    /// Decide one publish or subscribe against the topic's object.
    async fn authorize(&self, request: Request<AuthzReq>) -> Result<Response<AuthzRes>, Status> {
        let req = request.into_inner();

        let Some(action) = action_name(req.action) else {
            return Ok(Response::new(authz_denied("unsupported action")));
        };

        // `external_id` is whatever Authenticate returned. If the broker did not
        // authenticate this client it passes the protocol-level client id, which
        // is not an Atom subject — deny rather than guess.
        let Ok(subject_id) = Uuid::parse_str(&req.external_id) else {
            return Ok(Response::new(authz_denied("subject is not an Atom entity")));
        };

        let Some(matched) = self
            .state
            .config
            .broker_auth
            .topic_templates
            .match_topic(&req.topic)
        else {
            return Ok(Response::new(authz_denied(
                "topic does not address one object",
            )));
        };

        let object_id = match self.resolve_object(subject_id, &matched).await {
            Ok(object_id) => object_id,
            Err(err) if is_decision(&err) => {
                tracing::debug!(
                    subject_id = %subject_id, topic = %req.topic, error = %err,
                    "broker authorize: deny (unresolved object)"
                );
                return Ok(Response::new(authz_denied(err.to_string())));
            }
            Err(err) => {
                tracing::error!(subject_id = %subject_id, topic = %req.topic, error = %err,
                    "broker authorize: failed");
                return Err(Status::from(err));
            }
        };

        let authz_req = AuthzRequest {
            subject_id,
            action: action.to_string(),
            resource_id: None,
            object_kind: Some(OBJECT_KIND.to_string()),
            object_id: Some(object_id),
            context: serde_json::json!({
                "topic": req.topic,
                "subtopic": matched.subtopic,
                "connection": action,
            }),
        };

        // No ceiling: the broker is not acting under a scoped access token, and
        // the subject's own grants are the whole authority here.
        let decision = match engine::evaluate_with_ceiling(&self.state.pool, &authz_req, None).await
        {
            Ok(decision) => decision,
            Err(err) if is_decision(&err) => {
                return Ok(Response::new(authz_denied(err.to_string())))
            }
            Err(err) => {
                tracing::error!(subject_id = %subject_id, topic = %req.topic, error = %err,
                    "broker authorize: evaluation failed");
                return Err(Status::from(err));
            }
        };

        let tenant_id = matched
            .tenant
            .as_deref()
            .and_then(|tenant| Uuid::parse_str(tenant).ok());
        audit::write_hot_path(
            &self.state.pool,
            self.state.config.audit_policy,
            self.state.config.events.enabled(),
            audit::HotPathAuditKind::AuthzCheck,
            audit::AuditEvent {
                actor_entity_id: Some(subject_id),
                tenant_id,
                target_kind: Some(OBJECT_KIND),
                target_id: Some(object_id),
                event: "authz.check",
                outcome: if decision.allowed {
                    AuditOutcome::Allow
                } else {
                    AuditOutcome::Deny
                },
                details: serde_json::json!({
                    "subject_id": subject_id,
                    "action": action,
                    "object_id": object_id,
                    "topic": req.topic,
                    "transport": "grpc:broker",
                }),
            },
        )
        .await;

        Ok(Response::new(if decision.allowed {
            AuthzRes {
                authorized: true,
                reason_code: REASON_SUCCESS,
                reason: String::new(),
            }
        } else {
            authz_denied(decision.reason)
        }))
    }
}

impl BrokerAuth {
    /// Turn the bound topic segments into an object UUID.
    ///
    /// When the template carries no `{tenant}`, the subject's own tenant is the
    /// resolution scope — which is why the zero-configuration case needs no
    /// tenant in the topic at all.
    async fn resolve_object(
        &self,
        subject_id: Uuid,
        matched: &TopicMatch,
    ) -> Result<Uuid, AppError> {
        match self.state.config.broker_auth.topic_ref {
            BrokerTopicRef::Uuid => Uuid::parse_str(&matched.resource)
                .map_err(|_| AppError::bad_request("topic object segment is not a UUID")),
            BrokerTopicRef::Alias => {
                let (tenant_id, tenant_alias, global) = match matched.tenant.as_deref() {
                    // A `{tenant}` segment scopes resolution on its own; it is
                    // not checked against the subject's tenant. Cross-tenant
                    // grants are legitimate, so that call belongs to the PDP,
                    // not to a hardcoded equality test here.
                    Some(alias) => (None, Some(alias), false),
                    None => {
                        match certs::repo::entity_tenant_id(&self.state.pool, subject_id).await? {
                            Some(tenant_id) => (Some(tenant_id), None, false),
                            // A tenantless subject addresses tenantless objects.
                            None => (None, None, true),
                        }
                    }
                };

                let resolved = repo::resolve_alias(
                    &self.state.pool,
                    tenant_id,
                    tenant_alias,
                    global,
                    AliasObjectClass::Resource,
                    &matched.resource,
                )
                .await?;
                Ok(resolved.object_id)
            }
        }
    }
}

fn action_name(action: i32) -> Option<&'static str> {
    match Action::try_from(action) {
        Ok(Action::Publish) => Some("publish"),
        Ok(Action::Subscribe) => Some("subscribe"),
        Ok(Action::None) | Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_map_to_atom_capability_names() {
        assert_eq!(action_name(Action::Publish as i32), Some("publish"));
        assert_eq!(action_name(Action::Subscribe as i32), Some("subscribe"));
    }

    #[test]
    fn unset_and_unknown_actions_are_rejected() {
        assert_eq!(action_name(Action::None as i32), None);
        assert_eq!(action_name(99), None);
    }

    #[test]
    fn request_shaped_failures_are_decisions_not_faults() {
        assert!(is_decision(&AppError::not_found("no such resource")));
        assert!(is_decision(&AppError::unauthorized("invalid credentials")));
        assert!(is_decision(&AppError::Forbidden));
        assert!(is_decision(&AppError::bad_request("bad topic")));
        // A client can trigger this at will; letting it surface as an RPC error
        // would let one bad device trip the broker's circuit breaker.
        assert!(is_decision(&AppError::RateLimited {
            message: "slow down".into(),
            retry_after_secs: 1,
        }));
    }

    #[test]
    fn infrastructure_failures_are_faults() {
        assert!(!is_decision(&AppError::Internal(anyhow::anyhow!("boom"))));
        assert!(!is_decision(&AppError::Database(sqlx::Error::PoolClosed)));
    }

    #[test]
    fn denial_responses_carry_the_not_authorized_reason_code() {
        assert_eq!(authz_denied("nope").reason_code, REASON_NOT_AUTHORIZED);
        assert!(!authz_denied("nope").authorized);
        assert_eq!(authn_denied("nope").reason_code, REASON_BAD_CREDENTIALS);
        assert!(!authn_denied("nope").authenticated);
        assert!(authn_denied("nope").id.is_empty());
    }
}
