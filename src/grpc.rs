use std::net::SocketAddr;

use tokio::net::TcpListener;
use tonic::{
    metadata::MetadataMap,
    transport::{server::TcpIncoming, Server},
    Request, Response, Status,
};
use uuid::Uuid;

use crate::{
    audit,
    auth::{authenticate_token, require_any_capability, scope_for_tenant, AuthContext, Scope},
    authz::{access, engine, repo},
    certs,
    identity::service as identity_service,
    models::{alias::AliasObjectClass, enums::AuditOutcome, policy::AuthzRequest},
    state::{AppState, GrpcRuntimeStatus},
};

// Generated code from proto/atom.proto
pub mod proto {
    tonic::include_proto!("atom.v1");
}

use proto::{
    alias_service_server::{AliasService, AliasServiceServer},
    auth_service_server::{AuthService, AuthServiceServer},
    authz_service_server::{AuthzService, AuthzServiceServer},
    certificate_service_server::{CertificateService, CertificateServiceServer},
    AuthenticateCredentialRequest, AuthenticateCredentialResponse, AuthenticateRequest,
    AuthenticateResponse, CheckRequest, CheckResponse, ResolveAliasRequest, ResolveAliasResponse,
    ResolveCertificateRequest, ResolveCertificateResponse, RevokeEntityCertificatesRequest,
    RevokeEntityCertificatesResponse,
};

// ─── AuthzService ─────────────────────────────────────────────────────────────

struct AtomAuthz {
    state: AppState,
}

#[tonic::async_trait]
impl AuthzService for AtomAuthz {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let auth = auth_context_from_metadata(&self.state, request.metadata()).await?;
        let req = request.into_inner();

        let subject_id = Uuid::parse_str(&req.subject_id)
            .map_err(|_| Status::invalid_argument("invalid subject_id: expected UUID"))?;

        let resource_id = if req.resource_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&req.resource_id)
                    .map_err(|_| Status::invalid_argument("invalid resource_id: expected UUID"))?,
            )
        };

        let object_kind = if req.object_kind.is_empty() {
            None
        } else {
            Some(req.object_kind)
        };
        let object_id = if req.object_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&req.object_id)
                    .map_err(|_| Status::invalid_argument("invalid object_id: expected UUID"))?,
            )
        };

        let context = if req.context.is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::to_value(&req.context).unwrap_or_default()
        };

        let authz_req = AuthzRequest {
            subject_id,
            action: req.action,
            resource_id,
            object_kind,
            object_id,
            context,
        };

        let tenant_id = access::authz_request_tenant_id(&self.state.pool, &authz_req)
            .await
            .map_err(Status::from)?;
        access::require_authz_check_access(
            &self.state.pool,
            &auth,
            authz_req.subject_id,
            tenant_id,
        )
        .await
        .map_err(Status::from)?;

        let resp = engine::evaluate(&self.state.pool, &authz_req)
            .await
            .map_err(Status::from)?;
        audit::write(
            &self.state.pool,
            Some(auth.entity_id),
            tenant_id,
            "authz.check",
            if resp.allowed {
                AuditOutcome::Allow
            } else {
                AuditOutcome::Deny
            },
            serde_json::json!({
                "subject_id": authz_req.subject_id,
                "action": authz_req.action,
                "resource_id": authz_req.resource_id,
                "object_kind": authz_req.object_kind,
                "object_id": authz_req.object_id,
                "reason": resp.reason,
                "transport": "grpc",
            }),
        )
        .await;

        Ok(Response::new(CheckResponse {
            allowed: resp.allowed,
            reason: resp.reason,
        }))
    }
}

// ─── AuthService ──────────────────────────────────────────────────────────────

async fn auth_context_from_metadata(
    state: &AppState,
    metadata: &MetadataMap,
) -> Result<AuthContext, Status> {
    let header = metadata
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization metadata"))?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| Status::unauthenticated("expected Bearer token"))?;
    authenticate_token(state, token).await.map_err(Status::from)
}

struct AtomAuth {
    state: AppState,
}

#[tonic::async_trait]
impl AuthService for AtomAuth {
    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        let token = request.into_inner().token;

        let ctx = authenticate_token(&self.state, &token)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(AuthenticateResponse {
            entity_id: ctx.entity_id.to_string(),
            tenant_id: ctx.tenant_id.map(|t| t.to_string()).unwrap_or_default(),
            session_id: ctx.session_id.map(|s| s.to_string()).unwrap_or_default(),
        }))
    }

    async fn authenticate_credential(
        &self,
        request: Request<AuthenticateCredentialRequest>,
    ) -> Result<Response<AuthenticateCredentialResponse>, Status> {
        let auth = auth_context_from_metadata(&self.state, request.metadata()).await?;
        let req = request.into_inner();

        let kind = req.kind.trim();
        if !(kind.is_empty() || kind.eq_ignore_ascii_case("password")) {
            return Err(Status::invalid_argument(
                "unsupported credential kind: expected password",
            ));
        }

        let requested_tenant_id =
            parse_optional_uuid(&req.tenant_id, "tenant_id").map_err(Status::from)?;
        let tenant_alias = (!req.tenant_alias.trim().is_empty()).then_some(req.tenant_alias.trim());
        let tenant_id = identity_service::resolve_credential_auth_tenant(
            &self.state.pool,
            requested_tenant_id,
            tenant_alias,
        )
        .await
        .map_err(Status::from)?;

        require_credential_auth_access(&self.state.pool, auth.entity_id, tenant_id).await?;

        let result = identity_service::authenticate_password_credential_in_tenant(
            &self.state.pool,
            &self.state.config,
            &req.identifier,
            &req.secret,
            tenant_id,
        )
        .await;

        let outcome = if result.is_ok() {
            AuditOutcome::Allow
        } else {
            AuditOutcome::Deny
        };
        let entity_id = result.as_ref().ok().map(|auth| auth.entity_id);
        let credential_id = result.as_ref().ok().map(|auth| auth.credential_id);
        audit::write(
            &self.state.pool,
            Some(auth.entity_id),
            tenant_id,
            "auth.credential_authenticate",
            outcome,
            serde_json::json!({
                "caller_entity_id": auth.entity_id,
                "entity_id": entity_id,
                "credential_id": credential_id,
                "credential_kind": "password",
                "identifier": req.identifier,
                "transport": "grpc",
            }),
        )
        .await;

        let authenticated = result.map_err(Status::from)?;
        Ok(Response::new(AuthenticateCredentialResponse {
            entity_id: authenticated.entity_id.to_string(),
            tenant_id: authenticated
                .tenant_id
                .map(|tenant_id| tenant_id.to_string())
                .unwrap_or_default(),
            credential_id: authenticated.credential_id.to_string(),
        }))
    }
}

async fn require_credential_auth_access(
    pool: &sqlx::PgPool,
    caller_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<(), Status> {
    match tenant_id {
        Some(tenant_id) => require_any_capability(
            pool,
            caller_id,
            &[
                ("authz.check", Scope::Tenant(tenant_id)),
                ("authz.check", Scope::Platform),
            ],
        )
        .await
        .map_err(Status::from),
        None => require_any_capability(pool, caller_id, &[("authz.check", Scope::Platform)])
            .await
            .map_err(Status::from),
    }
}

// ─── CertificateService ──────────────────────────────────────────────────────

struct AtomCertificates {
    state: AppState,
}

#[tonic::async_trait]
impl CertificateService for AtomCertificates {
    async fn resolve_certificate(
        &self,
        request: Request<ResolveCertificateRequest>,
    ) -> Result<Response<ResolveCertificateResponse>, Status> {
        let auth = auth_context_from_metadata(&self.state, request.metadata()).await?;
        let req = request.into_inner();
        let identity = certs::service::resolve_certificate_identity(
            &self.state.pool,
            &req.serial_number,
            (!req.fingerprint_sha256.is_empty()).then_some(req.fingerprint_sha256.as_str()),
        )
        .await
        .map_err(Status::from)?;
        require_any_capability(
            &self.state.pool,
            auth.entity_id,
            &[
                ("authz.check", scope_for_tenant(identity.tenant_id)),
                ("authz.check", Scope::Platform),
            ],
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(ResolveCertificateResponse {
            entity_id: identity.entity_id.to_string(),
            tenant_id: identity
                .tenant_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            credential_id: identity.credential_id.to_string(),
            expires_at: identity.expires_at.to_rfc3339(),
        }))
    }

    async fn revoke_entity_certificates(
        &self,
        request: Request<RevokeEntityCertificatesRequest>,
    ) -> Result<Response<RevokeEntityCertificatesResponse>, Status> {
        let auth = auth_context_from_metadata(&self.state, request.metadata()).await?;
        let req = request.into_inner();
        let entity_id = Uuid::parse_str(&req.entity_id)
            .map_err(|_| Status::invalid_argument("invalid entity_id: expected UUID"))?;
        let tenant_id = certs::repo::entity_tenant_id(&self.state.pool, entity_id)
            .await
            .map_err(Status::from)?;
        require_any_capability(
            &self.state.pool,
            auth.entity_id,
            &[
                ("manage", Scope::Object(entity_id)),
                ("manage", scope_for_tenant(tenant_id)),
            ],
        )
        .await
        .map_err(Status::from)?;
        let revoked = certs::service::revoke_entity_certificates(
            &self.state.pool,
            entity_id,
            (!req.reason.is_empty()).then_some(req.reason),
        )
        .await
        .map_err(Status::from)?;
        audit::write(
            &self.state.pool,
            Some(auth.entity_id),
            tenant_id,
            "certificate.revoke_entity",
            AuditOutcome::Allow,
            serde_json::json!({"entity_id": entity_id, "count": revoked, "transport": "grpc"}),
        )
        .await;

        Ok(Response::new(RevokeEntityCertificatesResponse {
            revoked: revoked as u64,
        }))
    }
}

// ─── AliasService ──────────────────────────────────────────────────────────────

struct AtomAlias {
    state: AppState,
}

#[tonic::async_trait]
impl AliasService for AtomAlias {
    async fn resolve_alias(
        &self,
        request: Request<ResolveAliasRequest>,
    ) -> Result<Response<ResolveAliasResponse>, Status> {
        // Authenticate the caller; resolution itself is capability-neutral — the
        // subsequent AuthzService.Check by UUID is the authorization gate.
        let _auth = auth_context_from_metadata(&self.state, request.metadata()).await?;
        let req = request.into_inner();

        let tenant_id = if req.tenant_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&req.tenant_id)
                    .map_err(|_| Status::invalid_argument("invalid tenant_id: expected UUID"))?,
            )
        };
        let tenant_alias = (!req.tenant_alias.is_empty()).then_some(req.tenant_alias.as_str());

        let class = parse_alias_object_class(&req.object_kind).ok_or_else(|| {
            Status::invalid_argument("invalid object_kind: expected 'entity' or 'resource'")
        })?;

        let resolved = repo::resolve_alias(
            &self.state.pool,
            tenant_id,
            tenant_alias,
            req.global,
            class,
            &req.object_alias,
        )
        .await
        .map_err(Status::from)?;

        Ok(Response::new(ResolveAliasResponse {
            tenant_id: resolved
                .tenant_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            object_id: resolved.object_id.to_string(),
        }))
    }
}

fn parse_alias_object_class(value: &str) -> Option<AliasObjectClass> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("entity") {
        Some(AliasObjectClass::Entity)
    } else if value.eq_ignore_ascii_case("resource") {
        Some(AliasObjectClass::Resource)
    } else {
        None
    }
}

fn parse_optional_uuid(value: &str, field: &str) -> Result<Option<Uuid>, crate::error::AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    Uuid::parse_str(value)
        .map(Some)
        .map_err(|_| crate::error::AppError::bad_request(format!("invalid {field}: expected UUID")))
}

// ─── Server ───────────────────────────────────────────────────────────────────

pub async fn bind_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

pub async fn serve(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!("grpc listening on {addr}");
    let incoming = match TcpIncoming::from_listener(listener, true, None) {
        Ok(incoming) => incoming,
        Err(err) => {
            let message = format!("gRPC listener setup failed on {addr}: {err}");
            state
                .set_grpc_status(GrpcRuntimeStatus::error(addr.to_string(), message.clone()))
                .await;
            anyhow::bail!(message);
        }
    };

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AuthzServiceServer<AtomAuthz>>()
        .await;
    health_reporter
        .set_serving::<AuthServiceServer<AtomAuth>>()
        .await;
    health_reporter
        .set_serving::<CertificateServiceServer<AtomCertificates>>()
        .await;
    health_reporter
        .set_serving::<AliasServiceServer<AtomAlias>>()
        .await;

    state
        .set_grpc_status(GrpcRuntimeStatus::serving(addr.to_string()))
        .await;

    let result = Server::builder()
        .add_service(health_service)
        .add_service(AuthzServiceServer::new(AtomAuthz {
            state: state.clone(),
        }))
        .add_service(AuthServiceServer::new(AtomAuth {
            state: state.clone(),
        }))
        .add_service(CertificateServiceServer::new(AtomCertificates {
            state: state.clone(),
        }))
        .add_service(AliasServiceServer::new(AtomAlias {
            state: state.clone(),
        }))
        .serve_with_incoming_shutdown(incoming, crate::shutdown::shutdown_signal())
        .await;

    match result {
        Ok(()) => {
            state
                .set_grpc_status(GrpcRuntimeStatus::error(
                    addr.to_string(),
                    format!("gRPC server stopped on {addr}"),
                ))
                .await;
            Ok(())
        }
        Err(err) => {
            let message = format!("gRPC server exited on {addr}: {err}");
            state
                .set_grpc_status(GrpcRuntimeStatus::error(addr.to_string(), message))
                .await;
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        keys::{ActiveKeys, LoadedKey},
    };
    use sqlx::postgres::PgPoolOptions;
    use tokio::time::{sleep, Duration};
    use tonic_health::pb::{
        health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
    };

    #[tokio::test]
    async fn bind_listener_fails_when_address_is_in_use() {
        let first = bind_listener("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("first listener");
        let addr = first.local_addr().expect("local addr");

        let err = bind_listener(addr).await.expect_err("address in use");

        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn grpc_health_service_reports_serving() {
        let listener = bind_listener("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("listener");
        let addr = listener.local_addr().expect("local addr");
        let state = test_state();
        let grpc_state = state.clone();
        tokio::spawn(async move {
            let _ = serve(listener, grpc_state).await;
        });

        let mut client = health_client(addr).await;
        let response = client
            .check(HealthCheckRequest {
                service: String::new(),
            })
            .await
            .expect("health response")
            .into_inner();

        assert_eq!(response.status, ServingStatus::Serving as i32);
        assert_eq!(
            state.grpc_status().await.state,
            crate::state::GrpcRuntimeState::Serving
        );
    }

    #[test]
    fn alias_object_kind_rejects_unknown_values() {
        assert_eq!(
            parse_alias_object_class("entity"),
            Some(AliasObjectClass::Entity)
        );
        assert_eq!(
            parse_alias_object_class(" RESOURCE "),
            Some(AliasObjectClass::Resource)
        );
        assert_eq!(parse_alias_object_class("entitiy"), None);
    }

    async fn health_client(addr: SocketAddr) -> HealthClient<tonic::transport::Channel> {
        let endpoint = format!("http://{addr}");
        for _ in 0..20 {
            if let Ok(channel) = tonic::transport::Channel::from_shared(endpoint.clone())
                .expect("health endpoint")
                .connect()
                .await
            {
                return HealthClient::new(channel);
            }
            sleep(Duration::from_millis(25)).await;
        }
        let channel = tonic::transport::Channel::from_shared(endpoint)
            .expect("health endpoint")
            .connect()
            .await
            .expect("connect health client");
        HealthClient::new(channel)
    }

    fn test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("create lazy test pool");
        let primary = LoadedKey {
            kid: "test".into(),
            public_key_pem: String::new(),
            private_key_pem: String::new(),
            x_b64: String::new(),
            y_b64: String::new(),
        };
        AppState::new(
            pool,
            Config::for_tests(),
            ActiveKeys {
                primary,
                standby: None,
            },
            None,
        )
    }
}
