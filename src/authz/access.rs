use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{require_any_capability, scope_for_tenant, AuthContext, Scope},
    error::{db_err, AppError},
    models::policy::AuthzRequest,
};

pub async fn authz_request_tenant_id(
    pool: &PgPool,
    req: &AuthzRequest,
) -> Result<Option<Uuid>, AppError> {
    if req.object_kind.as_deref() == Some("tenant") {
        return Ok(req.object_id);
    }

    if let Some(resource_id) = req.resource_id {
        return sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT tenant_id FROM resources WHERE id = $1",
        )
        .bind(resource_id)
        .fetch_optional(pool)
        .await
        .map(|value| value.flatten())
        .map_err(db_err);
    }

    match (req.object_kind.as_deref(), req.object_id) {
        (Some("resource"), Some(id)) => {
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM resources WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await
                .map(|value| value.flatten())
                .map_err(db_err)
        }
        (Some("entity"), Some(id)) => {
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT tenant_id FROM entities WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await
                .map(|value| value.flatten())
                .map_err(db_err)
        }
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
        &[
            ("authz.check", scope),
            ("policy.manage", scope),
            ("manage", scope),
            ("authz.check", Scope::Platform),
            ("policy.manage", Scope::Platform),
            ("manage", Scope::Platform),
        ],
    )
    .await
}
