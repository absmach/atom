use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{require_any_capability, scope_for_tenant, AuthContext, Scope},
    error::AppError,
    models::policy::AuthzRequest,
};

pub async fn authz_request_tenant_id(
    pool: &PgPool,
    req: &AuthzRequest,
) -> Result<Option<Uuid>, AppError> {
    if req.object_kind.as_deref() == Some("platform") {
        return Ok(None);
    }

    if let Some(resource_id) = req.resource_id {
        return Ok(crate::protected_objects::lookup(pool, resource_id)
            .await?
            .filter(|object| object.object_kind == "resource")
            .and_then(|object| object.tenant_id));
    }

    match (req.object_kind.as_deref(), req.object_id) {
        (Some(kind), Some(id)) => Ok(crate::protected_objects::lookup(pool, id)
            .await?
            .filter(|object| object.object_kind == kind)
            .and_then(|object| object.tenant_id)),
        _ => Ok(None),
    }
}

pub async fn require_authz_check_access(
    pool: &PgPool,
    auth: &AuthContext,
    subject_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    if auth.entity_id == subject_id {
        return Ok(());
    }

    let scope = scope_for_tenant(tenant_id);
    require_any_capability(
        pool,
        auth,
        &[("authz.check", scope), ("authz.check", Scope::Platform)],
    )
    .await
}
