use std::net::SocketAddr;

use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

use crate::{
    auth::authenticate_token, authz::engine, models::policy::AuthzRequest, state::AppState,
};

// Generated code from proto/atom.proto
pub mod proto {
    tonic::include_proto!("atom.v1");
}

use proto::{
    auth_service_server::{AuthService, AuthServiceServer},
    authz_service_server::{AuthzService, AuthzServiceServer},
    AuthenticateRequest, AuthenticateResponse, CheckRequest, CheckResponse,
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

        let resp = engine::evaluate(&self.state.pool, &authz_req)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(CheckResponse {
            allowed: resp.allowed,
            reason: resp.reason,
        }))
    }
}

// ─── AuthService ──────────────────────────────────────────────────────────────

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
}

// ─── Server ───────────────────────────────────────────────────────────────────

pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    tracing::info!("grpc listening on {addr}");

    Server::builder()
        .add_service(AuthzServiceServer::new(AtomAuthz {
            state: state.clone(),
        }))
        .add_service(AuthServiceServer::new(AtomAuth { state }))
        .serve(addr)
        .await?;

    Ok(())
}
