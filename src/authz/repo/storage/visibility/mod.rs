//! Native storage contract for authorization visibility.
mod postgres;
mod sqlite;
use super::super::*;

pub(in crate::authz::repo) async fn load_credential_ceiling(
    pool: &Database,
    credential_id: Uuid,
) -> Result<CredentialCeiling, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_credential_ceiling(pool, credential_id).await,
        Database::Sqlite(db) => sqlite::load_credential_ceiling(&db.pool, credential_id).await,
    }
}

pub(in crate::authz::repo) async fn audit_logs(
    pool: &Database,
    params: crate::models::access::AuditQuery,
    allowed_tenant_ids: Option<Vec<Uuid>>,
) -> Result<AuditLogResponse, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::audit_logs(pool, params, allowed_tenant_ids).await,
        Database::Sqlite(db) => sqlite::audit_logs(&db.pool, params, allowed_tenant_ids).await,
    }
}

pub(in crate::authz::repo) async fn orphan_policies(
    pool: &Database,
    params: AdminPageQuery,
) -> Result<OrphanPoliciesResponse, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::orphan_policies(pool, params).await,
        Database::Sqlite(db) => sqlite::orphan_policies(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn expiring_credentials(
    pool: &Database,
    params: ExpiringCredentialsQuery,
) -> Result<ExpiringCredentialsResponse, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::expiring_credentials(pool, params).await,
        Database::Sqlite(db) => sqlite::expiring_credentials(&db.pool, params).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_subject(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<AuthzSubjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_subject(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::load_authz_subject(&db.pool, entity_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_tenant(
    pool: &Database,
    tenant_id: Uuid,
) -> Result<Option<AuthzTenantRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_tenant(pool, tenant_id).await,
        Database::Sqlite(db) => sqlite::load_authz_tenant(&db.pool, tenant_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_resource(
    pool: &Database,
    resource_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_resource(pool, resource_id).await,
        Database::Sqlite(db) => sqlite::load_authz_resource(&db.pool, resource_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_entity_object(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_entity_object(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::load_authz_entity_object(&db.pool, entity_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_group_object(
    pool: &Database,
    group_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_group_object(pool, group_id).await,
        Database::Sqlite(db) => sqlite::load_authz_group_object(&db.pool, group_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_credential_object(
    pool: &Database,
    credential_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::load_authz_credential_object(pool, credential_id).await
        }
        Database::Sqlite(db) => sqlite::load_authz_credential_object(&db.pool, credential_id).await,
    }
}

pub(in crate::authz::repo) async fn group_ancestor_ids(
    pool: &Database,
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::group_ancestor_ids(pool, group_ids).await,
        Database::Sqlite(db) => sqlite::group_ancestor_ids(&db.pool, group_ids).await,
    }
}

pub(in crate::authz::repo) async fn effective_grants_for_subject(
    pool: &Database,
    entity_id: Uuid,
) -> Result<Vec<EffectiveGrant>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::effective_grants_for_subject(pool, entity_id).await,
        Database::Sqlite(db) => sqlite::effective_grants_for_subject(&db.pool, entity_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_role_object(
    pool: &Database,
    role_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_role_object(pool, role_id).await,
        Database::Sqlite(db) => sqlite::load_authz_role_object(&db.pool, role_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_policy_object(
    pool: &Database,
    policy_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => postgres::load_authz_policy_object(pool, policy_id).await,
        Database::Sqlite(db) => sqlite::load_authz_policy_object(&db.pool, policy_id).await,
    }
}

pub(in crate::authz::repo) async fn load_authz_api_endpoint_object(
    pool: &Database,
    endpoint_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::load_authz_api_endpoint_object(pool, endpoint_id).await
        }
        Database::Sqlite(db) => sqlite::load_authz_api_endpoint_object(&db.pool, endpoint_id).await,
    }
}

pub(in crate::authz::repo) async fn authorized_entity_ids(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::authorized_entity_ids(pool, params, ceiling_credential_id).await
        }
        Database::Sqlite(db) => {
            sqlite::authorized_entity_ids(&db.pool, params, ceiling_credential_id).await
        }
    }
}

pub(in crate::authz::repo) async fn authorized_group_ids(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::authorized_group_ids(pool, params, ceiling_credential_id).await
        }
        Database::Sqlite(db) => {
            sqlite::authorized_group_ids(&db.pool, params, ceiling_credential_id).await
        }
    }
}

pub(in crate::authz::repo) async fn authorized_resource_rows(
    pool: &Database,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
    projection: AuthorizedResourceProjection,
) -> Result<Vec<AuthorizedPageRow>, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::authorized_resource_rows(pool, params, ceiling_credential_id, projection)
                .await
        }
        Database::Sqlite(db) => {
            sqlite::authorized_resource_rows(&db.pool, params, ceiling_credential_id, projection)
                .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::authz::repo) async fn authorize_flat_candidate_query(
    pool: &Database,
    subject_id: Uuid,
    ceiling_id: Option<Uuid>,
    object_kind: &str,
    actions: &[&str],
    filters: Value,
    candidate: FlatCandidate,
    limit: i64,
    offset: i64,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    match pool {
        Database::Postgres(pool) => {
            postgres::authorize_flat_candidate_query(
                pool,
                subject_id,
                ceiling_id,
                object_kind,
                actions,
                filters,
                candidate,
                limit,
                offset,
            )
            .await
        }
        Database::Sqlite(db) => {
            sqlite::authorize_flat_candidate_query(
                &db.pool,
                subject_id,
                ceiling_id,
                object_kind,
                actions,
                filters,
                candidate,
                limit,
                offset,
            )
            .await
        }
    }
}

pub(in crate::authz::repo) async fn selected_endpoints(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<ApiEndpoint>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::selected_endpoints(pool, ids).await,
        Database::Sqlite(db) => sqlite::selected_endpoints(&db.pool, ids).await,
    }
}

pub(in crate::authz::repo) async fn selected_roles(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<Role>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::selected_roles(pool, ids).await,
        Database::Sqlite(db) => sqlite::selected_roles(&db.pool, ids).await,
    }
}

pub(in crate::authz::repo) async fn selected_role_assignments(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<RoleAssignment>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::selected_role_assignments(pool, ids).await,
        Database::Sqlite(db) => sqlite::selected_role_assignments(&db.pool, ids).await,
    }
}

pub(in crate::authz::repo) async fn selected_direct_policies(
    pool: &Database,
    ids: &[Uuid],
) -> Result<Vec<DirectPolicy>, sqlx::Error> {
    match pool {
        Database::Postgres(pool) => postgres::selected_direct_policies(pool, ids).await,
        Database::Sqlite(db) => sqlite::selected_direct_policies(&db.pool, ids).await,
    }
}
