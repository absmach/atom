use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    error::{db_err, restore_conflict, AppError},
    identity::service::{hash_secret, verify_secret},
    models::{
        entity::{Entity, EntityList},
        enums::{SortDir, SubjectKind, TenantOrderField, TenantStatus},
        policy::CreateRoleAssignment,
        tenant::{
            CreateTenant, CreateTenantInvitation, ListTenantInvitations, ListTenants, Tenant,
            TenantInvitation, TenantInvitationList, TenantList, UpdateTenant,
        },
    },
};

const TENANT_COLS: &str =
    "id, name, alias, status, tags, attributes, created_by, updated_by, deleted_at, deleted_by, created_at, updated_at, managed_by";
const INVITATION_COLS: &str =
    "ti.id, ti.tenant_id, ti.invitee_user_id, e.name AS invitee_name, ti.invitee_email, ti.invited_by,
     ti.role_id, r.name AS role_name, ti.accepted_at, ti.rejected_at,
     ti.revoked_at, ti.created_at, ti.updated_at";

fn tenant_order_by(order: TenantOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (TenantOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (TenantOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (TenantOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC, id ASC",
        (TenantOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (TenantOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (TenantOrderField::Name, SortDir::Desc) => "lower(name) DESC, id ASC",
        (TenantOrderField::Alias, SortDir::Asc) => "lower(alias) ASC, id ASC",
        (TenantOrderField::Alias, SortDir::Desc) => "lower(alias) DESC NULLS LAST, id ASC",
        (TenantOrderField::Status, SortDir::Asc) => "status ASC, id ASC",
        (TenantOrderField::Status, SortDir::Desc) => "status DESC, id ASC",
    }
}

fn tenant_order_by_alias(order: TenantOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (TenantOrderField::CreatedAt, SortDir::Asc) => "t.created_at ASC, t.id ASC",
        (TenantOrderField::CreatedAt, SortDir::Desc) => "t.created_at DESC, t.id ASC",
        (TenantOrderField::UpdatedAt, SortDir::Asc) => "t.updated_at ASC, t.id ASC",
        (TenantOrderField::UpdatedAt, SortDir::Desc) => "t.updated_at DESC NULLS LAST, t.id ASC",
        (TenantOrderField::Name, SortDir::Asc) => "lower(t.name) ASC, t.id ASC",
        (TenantOrderField::Name, SortDir::Desc) => "lower(t.name) DESC, t.id ASC",
        (TenantOrderField::Alias, SortDir::Asc) => "lower(t.alias) ASC, t.id ASC",
        (TenantOrderField::Alias, SortDir::Desc) => "lower(t.alias) DESC NULLS LAST, t.id ASC",
        (TenantOrderField::Status, SortDir::Asc) => "t.status ASC, t.id ASC",
        (TenantOrderField::Status, SortDir::Desc) => "t.status DESC, t.id ASC",
    }
}

pub struct CreatedInvitation {
    pub invitation: TenantInvitation,
    pub token: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PurgedTenant {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAdminBootstrap {
    pub tenant_id: Uuid,
    pub creator_id: Uuid,
    pub role_name: &'static str,
    pub capabilities: [&'static str; 9],
    pub scope_ref: String,
}

#[derive(Debug, Clone)]
pub struct TenantRoleAssignmentSummary {
    pub role_id: Uuid,
    pub role_name: String,
    /// Actions present in the role definition. This is metadata, not an
    /// authorization decision: block effects, conditions, and object scopes are
    /// intentionally not flattened into an inaccurate effective-access claim.
    pub actions: Vec<String>,
    pub assignment_paths: Vec<String>,
}

pub fn tenant_admin_bootstrap(tenant_id: Uuid, creator_id: Uuid) -> TenantAdminBootstrap {
    TenantAdminBootstrap {
        tenant_id,
        creator_id,
        role_name: "tenant-admin",
        capabilities: [
            "manage",
            "read",
            "write",
            "delete",
            "publish",
            "subscribe",
            "execute",
            "policy.manage",
            "role.manage",
        ],
        scope_ref: tenant_id.to_string(),
    }
}

pub async fn lock_active_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<(), AppError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id
           FROM tenants
           WHERE id = $1 AND status = 'active' AND deleted_at IS NULL
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::not_found(format!(
            "active tenant {tenant_id} not found"
        )));
    }
    Ok(())
}

pub async fn lock_optional_active_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(tenant_id) = tenant_id {
        lock_active_tenant(tx, tenant_id).await?;
    }
    Ok(())
}

pub async fn create_tenant_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant = create_tenant_in_tx(&mut tx, req, created_by).await?;
    if let Some(creator_id) = created_by {
        bootstrap_tenant_admin(&mut tx, tenant_admin_bootstrap(tenant.id, creator_id)).await?;
    }
    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(tenant.id),
        target_kind: "tenant",
        target_id: Some(tenant.id),
        event: "tenant.create",
    };
    let details = serde_json::json!({
        "name": tenant.name,
        "alias": tenant.alias,
    });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

pub async fn create_tenant(
    pool: &PgPool,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    create_tenant_with_audit(pool, false, None, req, created_by).await
}

async fn create_tenant_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let alias = crate::models::alias::validate_alias_opt(req.alias)?;
    let attrs = if req.attributes.is_null() {
        serde_json::json!({})
    } else {
        req.attributes
    };
    sqlx::query_as::<_, Tenant>(&format!(
        r#"INSERT INTO tenants (id, name, alias, tags, attributes, created_by, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $6)
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(req.name)
    .bind(alias)
    .bind(&req.tags)
    .bind(attrs)
    .bind(created_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)
}

async fn bootstrap_tenant_admin(
    tx: &mut Transaction<'_, Postgres>,
    plan: TenantAdminBootstrap,
) -> Result<(), AppError> {
    use sqlx::Row;

    let role_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO roles (id, name, tenant_id, description)
           VALUES ($1, $2, $3, 'Default tenant administration role')"#,
    )
    .bind(role_id)
    .bind(plan.role_name)
    .bind(plan.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    let permission_block_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO permission_blocks (tenant_id, scope_mode, effect, conditions)
           VALUES ($1, 'tenant', 'allow', '{}'::jsonb)
           RETURNING id"#,
    )
    .bind(plan.tenant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
           SELECT $1, c.id
           FROM actions c
           WHERE c.name = ANY($2::text[])
           ON CONFLICT DO NOTHING"#,
    )
    .bind(permission_block_id)
    .bind(plan.capabilities.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        r#"INSERT INTO role_permission_blocks (role_id, permission_block_id)
           VALUES ($1, $2)"#,
    )
    .bind(role_id)
    .bind(permission_block_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    let missing_names: Vec<String> = sqlx::query_scalar(
        r#"SELECT required.name
           FROM unnest($1::text[]) AS required(name)
           WHERE NOT EXISTS (
               SELECT 1 FROM permission_block_actions pba
               JOIN actions c ON c.id = pba.action_id
               WHERE pba.permission_block_id = $2 AND c.name = required.name
           )
           ORDER BY required.name"#,
    )
    .bind(plan.capabilities.as_slice())
    .bind(permission_block_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)?;
    if !missing_names.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "tenant-admin bootstrap missing seeded capabilities: {}",
            missing_names.join(", ")
        )));
    }

    sqlx::query(
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           VALUES ($1, 'entity', $2, $3)"#,
    )
    .bind(plan.tenant_id)
    .bind(plan.creator_id)
    .bind(role_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    let creator = sqlx::query("SELECT kind FROM entities WHERE id = $1")
        .bind(plan.creator_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;

    if creator
        .and_then(|row| row.try_get::<String, _>("kind").ok())
        .as_deref()
        == Some("human")
    {
        sqlx::query(
            r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
               VALUES ($1, $2, 'active')
               ON CONFLICT (tenant_id, entity_id) DO NOTHING"#,
        )
        .bind(plan.tenant_id)
        .bind(plan.creator_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }

    Ok(())
}

pub async fn get_tenant(pool: &PgPool, id: Uuid) -> Result<Tenant, AppError> {
    sqlx::query_as::<_, Tenant>(&format!(
        "SELECT {TENANT_COLS} FROM tenants WHERE id = $1 AND deleted_at IS NULL"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })
}

pub async fn list_tenants(pool: &PgPool, params: ListTenants) -> Result<TenantList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let id = params.id;
    let name = params.name;
    let alias = params.alias;
    let status = params.status;
    let deleted = params.deleted.as_str();
    let q = search_pattern(params.q);
    let order_by = tenant_order_by(params.order, params.dir);

    let items = sqlx::query_as::<_, Tenant>(&format!(
        r#"SELECT {TENANT_COLS} FROM tenants
           WHERE ($1::uuid IS NULL OR id = $1)
             AND ($2::text IS NULL OR name = $2)
             AND ($3::text IS NULL OR lower(alias) = lower($3))
             AND ($4::text IS NULL OR status = $4)
             AND ($5::text IS NULL OR name ILIKE $5 OR alias ILIKE $5 OR array_to_string(tags, ',') ILIKE $5 OR attributes::text ILIKE $5)
             AND ($8::text = 'all'
                  OR ($8::text = 'live' AND deleted_at IS NULL)
                  OR ($8::text = 'deleted' AND deleted_at IS NOT NULL))
             ORDER BY {order_by}
           LIMIT $6 OFFSET $7"#,
    ))
    .bind(id)
    .bind(name.clone())
    .bind(alias.clone())
    .bind(status.clone())
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .bind(deleted)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM tenants
           WHERE ($1::uuid IS NULL OR id = $1)
             AND ($2::text IS NULL OR name = $2)
             AND ($3::text IS NULL OR lower(alias) = lower($3))
             AND ($4::text IS NULL OR status = $4)
             AND ($5::text IS NULL OR name ILIKE $5 OR alias ILIKE $5 OR array_to_string(tags, ',') ILIKE $5 OR attributes::text ILIKE $5)
             AND ($6::text = 'all'
                  OR ($6::text = 'live' AND deleted_at IS NULL)
                  OR ($6::text = 'deleted' AND deleted_at IS NOT NULL))"#,
    )
    .bind(id)
    .bind(name)
    .bind(alias)
    .bind(status)
    .bind(q)
    .bind(deleted)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(TenantList { items, total })
}

/// Ceiling-aware tenant visibility listing for request-path callers. The
/// scoped-token ceiling is derived from the caller's `AuthContext`
/// (`ceiling_credential_for`), never passed by hand — same rule as
/// `engine::evaluate` and `authz::repo::authorized_object_ids`.
pub async fn list_tenants_for_entity(
    pool: &PgPool,
    auth: &crate::auth::AuthContext,
    entity_id: Uuid,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    let ceiling_credential_id = auth.ceiling_credential_for(entity_id);
    list_tenants_for_entity_with_ceiling(pool, entity_id, ceiling_credential_id, params).await
}

/// Low-level visibility listing taking an explicit ceiling credential. For
/// tests; production code must call [`list_tenants_for_entity`].
pub async fn list_tenants_for_entity_with_ceiling(
    pool: &PgPool,
    entity_id: Uuid,
    ceiling_credential_id: Option<Uuid>,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let name = params.name;
    let alias = params.alias;
    let status = params.status;
    let deleted = params.deleted.as_str();
    let q = search_pattern(params.q);
    let access_actions = ["read", "manage"];
    let order_by = tenant_order_by_alias(params.order, params.dir);

    // Visibility filter over the one canonical grant expansion
    // (`subject_effective_grants`), consistent with the PDP and the
    // entity/resource/group authorized listers. A tenant is visible when, for
    // SOME requested action (read or manage), the caller holds an unconditional
    // allow whose scope matches the tenant object — at platform, tenant=t,
    // object_kind='tenant', object_type='tenant:tenant', or object=t — that is
    // not overridden by a deny for that same action. Scope matching uses the
    // shared `grant_scope_matches` predicate; recursive group membership and
    // role-linked blocks (carrying their real effect/conditions) are resolved
    // inside the canonical expansion. Deny-override is per-action (a manage deny
    // must not hide a read-visible tenant) and the assignment tenant boundary is
    // honoured.
    // The scoped-token ceiling joins the same shape as the object listings
    // (shared `ceiling_cte`, unconditional entries only — no request context
    // here, matching the coarse gates), applied per action inside the
    // visibility filter so the caller sees `owner visibility ∩ ceiling`.
    let ctes: String = r#"WITH grants AS (
            SELECT * FROM subject_effective_grants($1)
        ),
        access_caps AS (
            SELECT id FROM actions WHERE name = ANY($6::text[])
        ),
        __CEILING_CTE__"#
        .replace("__CEILING_CTE__", &crate::authz::repo::ceiling_cte("$10"));
    // A grant covers tenant object `t` when it grants the action `c.id`, its
    // assignment boundary admits `t`, and its scope matches the tenant under the
    // shared predicate. A tenant has no parent/ancestor groups and is its own
    // tenant boundary, so the group-scope arms never match (as before).
    let scope_match = r#"g.capability_id = c.id
              AND (g.tenant_boundary IS NULL OR g.tenant_boundary = t.id)
              AND grant_scope_matches(g.scope_kind, g.scope_ref, 'tenant', 'tenant',
                                      t.id, t.id, '{}'::uuid[], '{}'::uuid[])"#;
    let auth_filter = format!(
        r#"AND EXISTS (
            SELECT 1 FROM access_caps c
            WHERE EXISTS (
                SELECT 1 FROM grants g
                WHERE g.effect = 'allow' AND g.conditions = '{{}}'::jsonb
                  AND {scope_match}
            )
            AND NOT EXISTS (
                SELECT 1 FROM grants g
                WHERE g.effect = 'deny'
                  AND {scope_match}
            )
            AND ($10::uuid IS NULL OR EXISTS (
                SELECT 1 FROM ceiling cl
                WHERE cl.action_id = c.id
                  AND (cl.tenant_id IS NULL OR cl.tenant_id = t.id)
                  AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'tenant', 'tenant',
                                          t.id, t.id, '{{}}'::uuid[], '{{}}'::uuid[])
            ))
        )"#
    );
    // Lifecycle predicate mirrors the PDP, which denies any read on a tenant that
    // is not active (`engine::load_tenant`: inactive/frozen/deleted → deny). A
    // scoped (non-platform) subject must therefore never see a non-active tenant
    // in a listing, regardless of the `status`/`deleted` filter params — that is
    // the platform-admin `list_tenants` path's job, not this one. Keyed on
    // `status` (a soft delete also sets `status = 'deleted'`) plus an explicit
    // tombstone guard so it does not depend on that coupling.
    let base_filter = r#"t.status = 'active'
             AND t.deleted_at IS NULL
             AND ($2::text IS NULL OR t.name = $2)
             AND ($3::text IS NULL OR lower(t.alias) = lower($3))
             AND ($4::text IS NULL OR t.status = $4)
             AND ($5::text IS NULL OR t.name ILIKE $5 OR t.alias ILIKE $5 OR array_to_string(t.tags, ',') ILIKE $5 OR t.attributes::text ILIKE $5)
             AND ($9::text = 'all'
                  OR ($9::text = 'live' AND t.deleted_at IS NULL)
                  OR ($9::text = 'deleted' AND t.deleted_at IS NOT NULL))"#;

    let items = sqlx::query_as::<_, Tenant>(&format!(
        "{ctes} SELECT {TENANT_COLS} FROM tenants t \
         WHERE {base_filter} {auth_filter} ORDER BY {order_by} LIMIT $7 OFFSET $8"
    ))
    .bind(entity_id)
    .bind(name.clone())
    .bind(alias.clone())
    .bind(status.clone())
    .bind(q.clone())
    .bind(access_actions.as_slice())
    .bind(limit)
    .bind(offset)
    .bind(deleted)
    .bind(ceiling_credential_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(&format!(
        "{ctes} SELECT COUNT(*) FROM tenants t WHERE {base_filter} {auth_filter}"
    ))
    .bind(entity_id)
    .bind(name)
    .bind(alias)
    .bind(status)
    .bind(q)
    .bind(access_actions.as_slice())
    .bind(0_i64)
    .bind(0_i64)
    .bind(deleted)
    .bind(ceiling_credential_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(TenantList { items, total })
}

pub async fn update_tenant_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    req: UpdateTenant,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    crate::managed_by::ensure_not_config_managed(pool, "tenants", id).await?;
    let alias = crate::models::alias::validate_alias_update(req.alias)?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant = sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET name       = COALESCE($2, name),
               alias      = CASE WHEN $3 THEN $4 ELSE alias END,
               tags       = COALESCE($5, tags),
               attributes = COALESCE($6, attributes),
               updated_by = $7,
               updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(req.name)
    .bind(alias_is_set)
    .bind(alias)
    .bind(req.tags)
    .bind(req.attributes)
    .bind(updated_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: "tenant.update",
    };
    let details = serde_json::json!({});
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

pub async fn update_tenant(
    pool: &PgPool,
    id: Uuid,
    req: UpdateTenant,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    update_tenant_with_audit(pool, false, None, id, req, updated_by).await
}

/// The exact set of active session ids `soft_delete_tenant` is about to
/// revoke — mirrors that function's `UPDATE sessions` `WHERE` clause
/// precisely, so callers can invalidate `atom:v1:session:*` cache entries for
/// them *before* the delete runs (afterward, `revoked_at IS NULL` no longer
/// matches these rows). See `src/cache/mod.rs`'s consistency model.
pub async fn tenant_active_session_ids(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM sessions
           WHERE revoked_at IS NULL
             AND entity_id IN (SELECT id FROM entities WHERE tenant_id = $1)"#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// Soft-delete a tenant: mark `status = deleted`, stamp the tombstone, and
/// immediately revoke every active credential and session of entities in the
/// tenant. Physical removal (and the entity cascade) is deferred to the purge
/// cron.
pub async fn soft_delete_tenant(
    pool: &PgPool,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    soft_delete_tenant_with_audit(pool, false, None, id, deleted_by).await
}

pub async fn soft_delete_tenant_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    crate::managed_by::ensure_not_config_managed(pool, "tenants", id).await?;
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant = sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET status = 'deleted', deleted_at = now(), deleted_by = $2,
               updated_by = $2, updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(deleted_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })?;

    let revocation_actor_id = actor_id.or(deleted_by);
    let revoked_certificates: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        r#"WITH revoked AS (
               UPDATE credentials c
               SET status = 'revoked',
                   metadata = c.metadata || jsonb_build_object(
                       'revoked_at', now(),
                       'revocation_reason', 'tenant_deleted',
                       'revoked_by_entity_id', $2::uuid
                   )
               FROM entities e
               WHERE c.entity_id = e.id
                 AND e.tenant_id = $1
                 AND c.status = 'active'
               RETURNING c.id, c.kind, c.issuer_id
           )
           SELECT id, issuer_id FROM revoked WHERE kind = 'certificate'"#,
    )
    .bind(id)
    .bind(revocation_actor_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        "UPDATE sessions SET revoked_at = now()
         WHERE revoked_at IS NULL
           AND entity_id IN (SELECT id FROM entities WHERE tenant_id = $1)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: "tenant.delete",
    };
    let details = serde_json::json!({
        "certificate_revocations": {
            "count": revoked_certificates.len(),
            "credential_ids": revoked_certificates
                .iter()
                .map(|(credential_id, _)| credential_id)
                .collect::<Vec<_>>(),
            "issuer_ids": revoked_certificates
                .iter()
                .filter_map(|(_, issuer_id)| *issuer_id)
                .collect::<Vec<_>>(),
            "reason": "tenant_deleted",
        }
    });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

/// Reverse a tenant soft delete within the retention window. Reactivates the
/// tenant and clears its tombstone; its children (entities, groups, roles,
/// resources) were never individually tombstoned by `soft_delete_tenant` — they
/// were hidden only via the tenant's `deleted_at` — so they become visible again
/// automatically.
///
/// To make the restored tenant operational, the non-certificate child
/// credentials (passwords, API keys) that *this* delete revoked — identified by
/// the `tenant_deleted` revocation marker — are reactivated, so members can log
/// in with their existing secrets. Certificates stay revoked (their revocation
/// is published via the CRL and cannot be safely undone — re-issue is required),
/// and sessions stay revoked, so a fresh login is required. Credentials revoked
/// earlier for other reasons (e.g. an individually soft-deleted child) are left
/// untouched.
///
/// Fails with a conflict if the tenant name/alias was re-taken by a live tenant
/// during the retention window.
/// The exact set of credential ids `restore_tenant` is about to reactivate —
/// mirrors that function's `UPDATE credentials` `WHERE` clause precisely, so
/// callers can invalidate `atom:v1:credential:*` cache entries for them
/// *before* running the restore (see `src/cache/mod.rs`'s consistency
/// model). A stale cached "revoked" credential is a false-deny (fails
/// closed, not a security hole) but is still worth fixing: unlike a tenant
/// or entity status flip, which a later-checked fresh field can catch
/// regardless of earlier stale fields, `verify_api_key_snapshot` checks the
/// credential's own status first — a stale value there is never overridden
/// by anything checked afterward.
pub async fn tenant_restore_reactivated_credential_ids(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT c.id
           FROM credentials c
           JOIN entities e ON c.entity_id = e.id
           WHERE e.tenant_id = $1
             AND e.deleted_at IS NULL
             AND c.status = 'revoked'
             AND c.kind <> 'certificate'
             AND c.metadata->>'revocation_reason' = 'tenant_deleted'"#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn restore_tenant_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    crate::managed_by::ensure_not_config_managed(pool, "tenants", id).await?;
    let mut tx = pool.begin().await.map_err(db_err)?;

    let tenant = sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET status = 'active', deleted_at = NULL, deleted_by = NULL,
               updated_by = $2, updated_at = now()
           WHERE id = $1 AND deleted_at IS NOT NULL
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(restored_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::not_found(format!("no soft-deleted tenant {id} to restore"))
        }
        other => restore_conflict(other),
    })?;

    sqlx::query(
        r#"UPDATE credentials c
           SET status = 'active',
               metadata = c.metadata - 'revoked_at' - 'revocation_reason'
           FROM entities e
           WHERE c.entity_id = e.id
             AND e.tenant_id = $1
             AND e.deleted_at IS NULL
             AND c.status = 'revoked'
             AND c.kind <> 'certificate'
             AND c.metadata->>'revocation_reason' = 'tenant_deleted'"#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: Some("tenant"),
        target_id: Some(id),
        event: "tenant.restore",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({}),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(tenant)
}

pub async fn restore_tenant(
    pool: &PgPool,
    id: Uuid,
    restored_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    restore_tenant_with_audit(pool, false, None, id, restored_by).await
}

pub(crate) async fn tenant_purge_object_ids(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    if tenant_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(
        r#"SELECT id FROM unnest($1::uuid[]) AS t(id)
           UNION ALL SELECT id FROM entities WHERE tenant_id = ANY($1)
           UNION ALL SELECT c.id FROM credentials c
                     JOIN entities e ON e.id = c.entity_id
                     WHERE e.tenant_id = ANY($1)
           UNION ALL SELECT id FROM object_groups WHERE tenant_id = ANY($1)
           UNION ALL SELECT id FROM principal_groups WHERE tenant_id = ANY($1)
           UNION ALL SELECT id FROM roles WHERE tenant_id = ANY($1)
           UNION ALL SELECT id FROM resources WHERE tenant_id = ANY($1)"#,
    )
    .bind(tenant_ids)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_err)
}

pub(crate) async fn purge_tenant_pki_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_ids: &[Uuid],
) -> Result<(), AppError> {
    if tenant_ids.is_empty() {
        return Ok(());
    }

    // Rate-limit rows are deliberately independent of subject FKs. Remove
    // both tenant and child-entity scopes while those entities are still
    // available to identify, before the tenant cascade runs.
    sqlx::query(
        r#"DELETE FROM pki_enrollment_rate_windows
           WHERE (scope_kind = 'tenant' AND scope_id = ANY($1))
              OR (scope_kind = 'entity' AND scope_id IN (
                    SELECT id FROM entities WHERE tenant_id = ANY($1)
                 ))"#,
    )
    .bind(tenant_ids)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    // Credentials restrict authority deletion, and authorities belong to the
    // tenant being purged. Remove them in dependency order before the tenant.
    sqlx::query(
        r#"DELETE FROM credentials
           WHERE issuer_id IN (
               SELECT id FROM pki_authorities WHERE tenant_id = ANY($1)
           )"#,
    )
    .bind(tenant_ids)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    sqlx::query("DELETE FROM pki_authorities WHERE tenant_id = ANY($1)")
        .bind(tenant_ids)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;

    Ok(())
}

pub async fn purge_tenant_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
) -> Result<PurgedTenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    let doomed = tenant_purge_object_ids(&mut tx, &[id]).await?;
    purge_tenant_pki_in_tx(&mut tx, &[id]).await?;

    let purged = sqlx::query_as::<_, (Uuid, String)>(
        "DELETE FROM tenants
         WHERE id = $1 AND deleted_at IS NOT NULL
         RETURNING id, name",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some((id, name)) = purged else {
        return Err(AppError::not_found(format!(
            "no soft-deleted tenant {id} to purge"
        )));
    };

    crate::authz::repo::purge_authz_references_for_ids(&mut tx, &doomed).await?;

    let event = crate::audit::AuditEvent {
        actor_entity_id: actor_id,
        tenant_id: None,
        target_kind: Some("tenant"),
        target_id: Some(id),
        event: "tenant.purge",
        outcome: crate::models::enums::AuditOutcome::Allow,
        details: serde_json::json!({
            "tenant_name": name,
        }),
    };
    crate::audit::commit_with_audit(pool, tx, events_enabled, &event).await?;
    Ok(PurgedTenant { id, name })
}

pub async fn purge_tenant(pool: &PgPool, id: Uuid) -> Result<PurgedTenant, AppError> {
    purge_tenant_with_audit(pool, false, None, id).await
}

/// `actor_id` is both the audited actor and the row's `updated_by` — they are
/// the same principal, so this takes it once.
pub async fn change_tenant_status_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    id: Uuid,
    status: TenantStatus,
    event_name: &str,
) -> Result<Tenant, AppError> {
    if status == TenantStatus::Deleted {
        return Err(AppError::bad_request(
            "use delete tenant to apply the soft-delete lifecycle",
        ));
    }
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant = sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET status = $2, updated_by = $3, updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(&status)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })?;

    if status != TenantStatus::Active {
        sqlx::query(
            "UPDATE sessions SET revoked_at = now()
             WHERE revoked_at IS NULL
               AND entity_id IN (SELECT id FROM entities WHERE tenant_id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(id),
        target_kind: "tenant",
        target_id: Some(id),
        event: event_name,
    };
    let details = serde_json::json!({ "status": tenant.status });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(tenant)
}

pub async fn change_tenant_status(
    pool: &PgPool,
    id: Uuid,
    status: TenantStatus,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    change_tenant_status_with_audit(pool, false, updated_by, id, status, "tenant.status.update")
        .await
}

fn search_pattern(q: Option<String>) -> Option<String> {
    q.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

pub async fn create_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invited_by: Uuid,
    req: CreateTenantInvitation,
    expiry_secs: u64,
) -> Result<CreatedInvitation, AppError> {
    let invitee_email = req
        .invitee_email
        .as_deref()
        .map(normalize_email)
        .transpose()?;
    let invitee_user_id = match (req.invitee_user_id, invitee_email.as_deref()) {
        (Some(user_id), _) => Some(user_id),
        (None, Some(email)) => entity_id_by_email(pool, email).await?,
        (None, None) => {
            return Err(AppError::bad_request(
                "invitee_user_id or invitee_email is required",
            ))
        }
    };
    let email = match invitee_email {
        Some(email) => Some(email),
        None => match invitee_user_id {
            Some(user_id) => email_by_entity_id(pool, user_id).await?,
            None => None,
        },
    };

    let (token_id, token_secret, token) = new_secret_token("atomi");
    let token_hash = hash_secret(token_secret.as_bytes())?;
    let expires_at = Utc::now() + Duration::seconds(expiry_secs as i64);

    let invitation = sqlx::query_as::<_, TenantInvitation>(&format!(
        r#"WITH updated AS (
               UPDATE tenant_invitations
               SET invitee_user_id = COALESCE($2, invitee_user_id),
                   invitee_email = COALESCE($3, invitee_email),
                   invited_by = $4,
                   role_id = $5,
                   secret_hash = $6,
                   expires_at = $7,
                   rejected_at = NULL,
                   revoked_at = NULL,
                   accepted_at = NULL,
                   accepted_by = NULL,
                   updated_at = now()
               WHERE tenant_id = $1
                 AND (($2::uuid IS NOT NULL AND invitee_user_id = $2)
                      OR ($3::text IS NOT NULL AND lower(invitee_email) = lower($3)))
               RETURNING *
           ),
           inserted AS (
               INSERT INTO tenant_invitations
                   (id, tenant_id, invitee_user_id, invitee_email, invited_by, role_id,
                    secret_hash, expires_at, rejected_at, revoked_at, updated_at)
               SELECT $8, $1, $2, $3, $4, $5, $6, $7, NULL, NULL, now()
               WHERE NOT EXISTS (SELECT 1 FROM updated)
               RETURNING *
           )
           SELECT {INVITATION_COLS}
           FROM (
               SELECT * FROM updated
               UNION ALL
               SELECT * FROM inserted
           ) ti
           LEFT JOIN roles r ON r.id = ti.role_id
           LEFT JOIN entities e ON e.id = ti.invitee_user_id AND e.deleted_at IS NULL
           LIMIT 1"#
    ))
    .bind(tenant_id)
    .bind(invitee_user_id)
    .bind(email.clone())
    .bind(invited_by)
    .bind(req.role_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(token_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(CreatedInvitation {
        invitation,
        token: email.as_ref().map(|_| token),
        email,
    })
}

pub async fn list_tenant_invitations(
    pool: &PgPool,
    tenant_id: Uuid,
    params: ListTenantInvitations,
) -> Result<TenantInvitationList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, TenantInvitation>(
        r#"SELECT ti.id, ti.tenant_id, ti.invitee_user_id, e.name AS invitee_name, ti.invitee_email, ti.invited_by,
                  ti.role_id, r.name AS role_name, ti.accepted_at, ti.rejected_at,
                  ti.revoked_at, ti.created_at, ti.updated_at
           FROM tenant_invitations ti
           LEFT JOIN roles r ON r.id = ti.role_id
           LEFT JOIN entities e ON e.id = ti.invitee_user_id AND e.deleted_at IS NULL
           WHERE ti.tenant_id = $1
           ORDER BY ti.created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    Ok(TenantInvitationList { items, total })
}

pub async fn list_user_invitations(
    pool: &PgPool,
    invitee_user_id: Uuid,
    params: ListTenantInvitations,
) -> Result<TenantInvitationList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, TenantInvitation>(
        r#"SELECT ti.id, ti.tenant_id, ti.invitee_user_id, e.name AS invitee_name, ti.invitee_email, ti.invited_by,
                  ti.role_id, r.name AS role_name, ti.accepted_at, ti.rejected_at,
                  ti.revoked_at, ti.created_at, ti.updated_at
           FROM tenant_invitations ti
           LEFT JOIN roles r ON r.id = ti.role_id
           LEFT JOIN entities e ON e.id = ti.invitee_user_id AND e.deleted_at IS NULL
           WHERE ti.invitee_user_id = $1
              OR EXISTS (
                  SELECT 1 FROM entity_emails ee
                  WHERE ee.entity_id = $1 AND lower(ee.email) = lower(ti.invitee_email)
                    AND ee.deleted_at IS NULL
              )
           ORDER BY ti.created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(invitee_user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM tenant_invitations ti
               WHERE ti.invitee_user_id = $1
                  OR EXISTS (
                      SELECT 1 FROM entity_emails ee
                      WHERE ee.entity_id = $1 AND lower(ee.email) = lower(ti.invitee_email)
                        AND ee.deleted_at IS NULL
                  )"#,
    )
    .bind(invitee_user_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(TenantInvitationList { items, total })
}

pub async fn list_tenant_members(
    pool: &PgPool,
    tenant_id: Uuid,
    q: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<EntityList, AppError> {
    let limit = limit.clamp(1, 100);
    let offset = offset.max(0);
    let q = search_pattern(q);

    let items = sqlx::query_as::<_, Entity>(
        r#"SELECT e.id, e.kind, e.name, e.alias, e.external_id, e.tenant_id, e.profile_id,
                  e.profile_version_id, e.status, e.attributes, e.deleted_at, e.deleted_by,
                  e.created_at, e.updated_at
           FROM tenant_memberships tm
           JOIN entities e ON e.id = tm.entity_id
           WHERE tm.tenant_id = $1
             AND tm.status = 'active'
             AND e.deleted_at IS NULL
             AND e.kind = 'human'
             AND ($2::text IS NULL OR e.name ILIKE $2 OR e.attributes::text ILIKE $2)
           ORDER BY e.created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(tenant_id)
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM tenant_memberships tm
           JOIN entities e ON e.id = tm.entity_id
           WHERE tm.tenant_id = $1
             AND tm.status = 'active'
             AND e.deleted_at IS NULL
             AND e.kind = 'human'
             AND ($2::text IS NULL OR e.name ILIKE $2 OR e.attributes::text ILIKE $2)"#,
    )
    .bind(tenant_id)
    .bind(q)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub async fn list_tenant_assignable_entities(
    pool: &PgPool,
    tenant_id: Uuid,
    q: String,
    limit: i64,
    offset: i64,
) -> Result<EntityList, AppError> {
    let limit = limit.clamp(1, 20);
    let offset = offset.max(0);
    let q = search_pattern(Some(q));

    let items = sqlx::query_as::<_, Entity>(
        r#"SELECT e.id, e.kind, e.name, e.alias, e.external_id, e.tenant_id, e.profile_id,
                  e.profile_version_id, e.status, e.attributes, e.deleted_at, e.deleted_by,
                  e.created_at, e.updated_at
           FROM entities e
           WHERE e.kind = 'human'
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND ($2::text IS NULL OR e.name ILIKE $2 OR e.attributes::text ILIKE $2)
             AND NOT EXISTS (
                 SELECT 1
                 FROM tenant_memberships tm
                 WHERE tm.tenant_id = $1
                   AND tm.entity_id = e.id
                   AND tm.status = 'active'
             )
           ORDER BY e.created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(tenant_id)
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM entities e
           WHERE e.kind = 'human'
             AND e.status = 'active'
             AND e.deleted_at IS NULL
             AND ($2::text IS NULL OR e.name ILIKE $2 OR e.attributes::text ILIKE $2)
             AND NOT EXISTS (
                 SELECT 1
                 FROM tenant_memberships tm
                 WHERE tm.tenant_id = $1
                   AND tm.entity_id = e.id
                   AND tm.status = 'active'
             )"#,
    )
    .bind(tenant_id)
    .bind(q)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub async fn remove_tenant_member(
    pool: &PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    remove_tenant_member_with_audit(pool, false, None, tenant_id, entity_id).await
}

pub async fn remove_tenant_member_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;

    sqlx::query(
        r#"DELETE FROM principal_group_members gm
           USING principal_groups g
           WHERE gm.group_id = g.id
             AND g.tenant_id = $1
             AND gm.entity_id = $2"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        r#"DELETE FROM role_assignments
           WHERE tenant_id = $1
             AND subject_kind = 'entity'
             AND subject_id = $2"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let result = sqlx::query(
        r#"DELETE FROM tenant_memberships
           WHERE tenant_id = $1
             AND entity_id = $2"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    if result.rows_affected() == 0 {
        return Err(AppError::not_found("tenant member not found"));
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(tenant_id),
        target_kind: "tenant",
        target_id: Some(tenant_id),
        event: "tenant_member.remove",
    };
    let details = serde_json::json!({ "entity_id": entity_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(())
}

pub async fn add_tenant_member(
    pool: &PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    add_tenant_member_with_audit(pool, false, None, tenant_id, entity_id, role_id).await
}

pub async fn add_tenant_member_with_audit(
    pool: &PgPool,
    events_enabled: bool,
    actor_id: Option<Uuid>,
    tenant_id: Uuid,
    entity_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    lock_active_tenant(&mut tx, tenant_id).await?;
    crate::authz::repo::lock_live_entity_subject_in_tx(&mut tx, Some(tenant_id), entity_id).await?;

    // The `WHERE` on the conflict branch keeps `rows_affected` honest: without
    // it a `DO UPDATE` reports one row even when it rewrote 'active' as
    // 'active', and re-adding an existing member would look like a change.
    let membership_changed = sqlx::query(
        r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
           VALUES ($1, $2, 'active')
           ON CONFLICT (tenant_id, entity_id)
           DO UPDATE SET status = 'active'
           WHERE tenant_memberships.status IS DISTINCT FROM 'active'"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?
    .rows_affected()
        > 0;

    let mut role_assigned = false;
    if let Some(role_id) = role_id {
        role_assigned = crate::authz::repo::create_role_assignment_if_missing_in_tx(
            &mut tx,
            &CreateRoleAssignment {
                tenant_id: Some(tenant_id),
                subject_kind: SubjectKind::Entity,
                subject_id: entity_id,
                role_id,
            },
        )
        .await?;
    }

    // Re-adding an already-active member with no new role assignment changed
    // nothing; publishing `tenant_member.add` for it would be a false positive.
    if !membership_changed && !role_assigned {
        tx.commit().await.map_err(db_err)?;
        return Ok(());
    }

    let meta = crate::audit::AuditMeta {
        actor_entity_id: actor_id,
        tenant_id: Some(tenant_id),
        target_kind: "tenant",
        target_id: Some(tenant_id),
        event: "tenant_member.add",
    };
    let details = serde_json::json!({ "entity_id": entity_id, "role_id": role_id });
    crate::audit::commit_with_observation(tx, events_enabled, &meta, &details).await?;
    Ok(())
}

pub async fn list_tenant_role_assignments(
    pool: &PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<TenantRoleAssignmentSummary>, AppError> {
    let rows = sqlx::query(
        r#"WITH RECURSIVE subject_groups(group_id, path) AS (
             SELECT gm.group_id, g.name
             FROM group_members gm
             JOIN groups g ON g.id = gm.group_id AND g.status = 'active' AND g.deleted_at IS NULL
             WHERE gm.entity_id = $2
             UNION ALL
             SELECT gh.parent_id, parent.name || ' -> ' || sg.path
             FROM group_hierarchy gh
             JOIN subject_groups sg ON sg.group_id = gh.child_id
             JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active' AND parent.deleted_at IS NULL
           ), assignments AS (
             SELECT ra.role_id, 'direct'::text AS assignment_path
             FROM role_assignments ra
             WHERE ra.subject_kind = 'entity'
               AND ra.subject_id = $2
               AND (ra.tenant_id = $1 OR ra.tenant_id IS NULL)
             UNION ALL
             SELECT ra.role_id, 'group:' || sg.path
             FROM role_assignments ra
             JOIN subject_groups sg ON sg.group_id = ra.subject_id
             WHERE ra.subject_kind = 'group'
               AND (ra.tenant_id = $1 OR ra.tenant_id IS NULL)
           )
           SELECT r.id AS role_id,
                  r.name AS role_name,
                  COALESCE(
                    ARRAY_AGG(DISTINCT a.name ORDER BY a.name)
                      FILTER (WHERE a.name IS NOT NULL),
                    ARRAY[]::text[]
                  ) AS actions,
                  ARRAY_AGG(
                    DISTINCT assignments.assignment_path
                    ORDER BY assignments.assignment_path
                  ) AS assignment_paths
           FROM assignments
           JOIN roles r ON r.id = assignments.role_id AND r.deleted_at IS NULL
           LEFT JOIN role_permission_blocks rpb ON rpb.role_id = r.id
           LEFT JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
           LEFT JOIN actions a ON a.id = pba.action_id
           WHERE r.tenant_id = $1 OR r.tenant_id IS NULL
           GROUP BY r.id, r.name
           ORDER BY r.name, r.id"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(|row| {
            Ok(TenantRoleAssignmentSummary {
                role_id: row.try_get("role_id").map_err(db_err)?,
                role_name: row.try_get("role_name").map_err(db_err)?,
                actions: row.try_get("actions").map_err(db_err)?,
                assignment_paths: row.try_get("assignment_paths").map_err(db_err)?,
            })
        })
        .collect()
}

pub async fn accept_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let role_id = accept_invitation_row(&mut tx, tenant_id, invitee_user_id).await?;
    grant_invitation_role(&mut tx, tenant_id, invitee_user_id, role_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn accept_invitation_token(
    pool: &PgPool,
    token: &str,
    actor_id: Uuid,
) -> Result<Uuid, AppError> {
    let (token_id, token_secret) = parse_secret_token(token, "atomi")
        .ok_or_else(|| AppError::bad_request("invalid invitation token"))?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = sqlx::query(
        r#"SELECT id, tenant_id, invitee_user_id, invitee_email, role_id,
                  secret_hash, expires_at, accepted_at, rejected_at, revoked_at
           FROM tenant_invitations
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(token_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found("invitation not found"),
        other => AppError::Database(other),
    })?;

    let secret_hash: Option<String> = row.try_get("secret_hash").map_err(db_err)?;
    let Some(secret_hash) = secret_hash else {
        return Err(AppError::bad_request("invalid invitation token"));
    };
    if !verify_secret(token_secret.as_bytes(), &secret_hash) {
        return Err(AppError::bad_request("invalid invitation token"));
    }
    ensure_invitation_pending(&row)?;

    let tenant_id: Uuid = row.try_get("tenant_id").map_err(db_err)?;
    let invitee_user_id: Option<Uuid> = row.try_get("invitee_user_id").unwrap_or(None);
    if let Some(invitee_user_id) = invitee_user_id {
        if invitee_user_id != actor_id {
            return Err(invitation_wrong_user());
        }
    } else if let Some(email) = row
        .try_get::<Option<String>, _>("invitee_email")
        .unwrap_or(None)
    {
        if !entity_has_email(&mut tx, actor_id, &email).await? {
            return Err(invitation_wrong_user());
        }
    }

    let invitation_id: Uuid = row.try_get("id").map_err(db_err)?;
    let role_id: Option<Uuid> = sqlx::query_scalar(
        r#"UPDATE tenant_invitations
           SET invitee_user_id = $2,
               accepted_by = $2,
               accepted_at = now(),
               rejected_at = NULL,
               revoked_at = NULL,
               updated_at = now()
           WHERE id = $1
           RETURNING role_id"#,
    )
    .bind(invitation_id)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    grant_invitation_role(&mut tx, tenant_id, actor_id, role_id).await?;
    tx.commit().await.map_err(db_err)?;
    Ok(tenant_id)
}

async fn accept_invitation_row(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let row = invitation_row_for_invitee(tx, tenant_id, invitee_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;
    let invitation_id: Uuid = row.try_get("id").map_err(db_err)?;

    sqlx::query_scalar::<_, Option<Uuid>>(
        r#"UPDATE tenant_invitations
           SET invitee_user_id = $2,
               accepted_by = $2,
               accepted_at = now(),
               rejected_at = NULL,
               revoked_at = NULL,
               updated_at = now()
           WHERE id = $1
           RETURNING role_id"#,
    )
    .bind(invitation_id)
    .bind(invitee_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)
}

async fn grant_invitation_role(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    lock_active_tenant(tx, tenant_id).await?;
    crate::authz::repo::lock_live_entity_subject_in_tx(tx, Some(tenant_id), invitee_user_id)
        .await?;
    sqlx::query(
        r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
           VALUES ($1, $2, 'active')
           ON CONFLICT (tenant_id, entity_id)
           DO UPDATE SET status = 'active'"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    let Some(role_id) = role_id else {
        return Ok(());
    };

    crate::authz::repo::create_role_assignment_if_missing_in_tx(
        tx,
        &CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: invitee_user_id,
            role_id,
        },
    )
    .await?;
    Ok(())
}

pub async fn reject_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = invitation_row_for_invitee(&mut tx, tenant_id, invitee_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;
    let invitation_id: Uuid = row.try_get("id").map_err(db_err)?;

    sqlx::query(
        r#"UPDATE tenant_invitations
           SET rejected_at = now(), updated_at = now()
           WHERE id = $1"#,
    )
    .bind(invitation_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn revoke_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = invitation_row_for_invitee(&mut tx, tenant_id, invitee_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;
    let invitation_id: Uuid = row.try_get("id").map_err(db_err)?;

    sqlx::query(
        r#"UPDATE tenant_invitations
           SET revoked_at = now(), updated_at = now()
           WHERE id = $1"#,
    )
    .bind(invitation_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn revoke_invitation_by_id(
    pool: &PgPool,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let row = invitation_row_by_id(&mut tx, tenant_id, invitation_id)
        .await?
        .ok_or_else(|| AppError::not_found("tenant invitation not found"))?;
    ensure_invitation_pending(&row)?;

    sqlx::query(
        r#"UPDATE tenant_invitations
           SET revoked_at = now(), updated_at = now()
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(invitation_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

async fn invitation_row_for_invitee(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<PgRow>, AppError> {
    sqlx::query(
        r#"SELECT ti.id, ti.tenant_id, ti.invitee_user_id, ti.invitee_email,
                  ti.role_id, ti.secret_hash, ti.expires_at, ti.accepted_at,
                  ti.rejected_at, ti.revoked_at
           FROM tenant_invitations ti
           WHERE ti.tenant_id = $1
             AND (ti.invitee_user_id = $2
                  OR EXISTS (
                      SELECT 1 FROM entity_emails ee
                      WHERE ee.entity_id = $2 AND lower(ee.email) = lower(ti.invitee_email)
                        AND ee.deleted_at IS NULL
                  ))
           ORDER BY ti.created_at DESC
           LIMIT 1
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)
}

async fn invitation_row_by_id(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<Option<PgRow>, AppError> {
    sqlx::query(
        r#"SELECT id, tenant_id, invitee_user_id, invitee_email, role_id,
                  secret_hash, expires_at, accepted_at, rejected_at, revoked_at
           FROM tenant_invitations
           WHERE tenant_id = $1 AND id = $2
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .bind(invitation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)
}

fn ensure_invitation_pending(row: &PgRow) -> Result<(), AppError> {
    let accepted_at: Option<DateTime<Utc>> = row.try_get("accepted_at").map_err(db_err)?;
    if accepted_at.is_some() {
        return Err(AppError::bad_request("invitation already accepted"));
    }

    let rejected_at: Option<DateTime<Utc>> = row.try_get("rejected_at").map_err(db_err)?;
    if rejected_at.is_some() {
        return Err(AppError::bad_request("invitation already rejected"));
    }

    let revoked_at: Option<DateTime<Utc>> = row.try_get("revoked_at").map_err(db_err)?;
    if revoked_at.is_some() {
        return Err(AppError::bad_request("invitation already revoked"));
    }

    let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at").map_err(db_err)?;
    if expires_at.is_some_and(|expires_at| expires_at < Utc::now()) {
        return Err(AppError::bad_request("invitation expired"));
    }

    Ok(())
}

fn invitation_wrong_user() -> AppError {
    AppError::bad_request("invitation does not belong to this user")
}

async fn entity_id_by_email(pool: &PgPool, email: &str) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT entity_id
           FROM entity_emails
           WHERE lower(email) = lower($1) AND deleted_at IS NULL"#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

async fn email_by_entity_id(pool: &PgPool, entity_id: Uuid) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT email FROM entity_emails WHERE entity_id = $1 AND deleted_at IS NULL",
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

async fn entity_has_email(
    tx: &mut Transaction<'_, Postgres>,
    entity_id: Uuid,
    email: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1 FROM entity_emails
               WHERE entity_id = $1 AND lower(email) = lower($2) AND deleted_at IS NULL
           )"#,
    )
    .bind(entity_id)
    .bind(email)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)
}

fn new_secret_token(prefix: &str) -> (Uuid, String, String) {
    let id = Uuid::new_v4();
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);
    let token = format!("{prefix}_{}_{}", hex::encode(id.as_bytes()), secret);
    (id, secret, token)
}

fn parse_secret_token(token: &str, prefix: &str) -> Option<(Uuid, String)> {
    let rest = token.strip_prefix(&format!("{prefix}_"))?;
    if rest.len() != 32 + 1 + 64 {
        return None;
    }
    let (id_hex, tail) = rest.split_at(32);
    let secret = tail.strip_prefix('_')?;
    let id_bytes = hex::decode(id_hex).ok()?;
    let id: [u8; 16] = id_bytes.try_into().ok()?;
    if hex::decode(secret).ok()?.len() != 32 {
        return None;
    }
    Some((Uuid::from_bytes(id), secret.to_string()))
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    let normalized = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(AppError::bad_request("invalid email"));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(AppError::bad_request("invalid email"));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    //! DB-gated tests. Each is `#[ignore]` because it needs a live
    //! Postgres reachable via `DATABASE_URL`. Run with:
    //!
    //!     DATABASE_URL=postgres://... cargo test tenants:: -- --ignored
    use super::*;
    use crate::models::tenant::{CreateTenant, ListTenants, UpdateTenant};
    use serde_json::{json, Value};
    use sqlx::PgPool;

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

    async fn cleanup(pool: &PgPool, ids: &[Uuid]) {
        for id in ids {
            let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }
    }

    fn unique_name(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4())
    }

    #[test]
    fn tenant_admin_bootstrap_plan_matches_m5_contract() {
        let tenant_id = Uuid::new_v4();
        let creator_id = Uuid::new_v4();
        let plan = tenant_admin_bootstrap(tenant_id, creator_id);

        assert_eq!(plan.tenant_id, tenant_id);
        assert_eq!(plan.creator_id, creator_id);
        assert_eq!(plan.role_name, "tenant-admin");
        assert_eq!(plan.scope_ref, tenant_id.to_string());
        assert_eq!(
            plan.capabilities,
            [
                "manage",
                "read",
                "write",
                "delete",
                "publish",
                "subscribe",
                "execute",
                "policy.manage",
                "role.manage"
            ]
        );
        assert!(!plan.capabilities.contains(&"tenant.manage"));
    }

    #[tokio::test]
    #[ignore]
    async fn create_and_get_roundtrips() {
        let pool = pool().await;
        let req = CreateTenant {
            id: None,
            name: unique_name("acme"),
            alias: Some(unique_name("acme-alias")),
            tags: vec!["pilot".into()],
            attributes: json!({"region": "eu"}),
        };
        let created = create_tenant(&pool, req, None).await.expect("create");
        assert_eq!(created.status, TenantStatus::Active);
        assert_eq!(created.tags, vec!["pilot".to_string()]);
        let fetched = get_tenant(&pool, created.id).await.expect("get");
        assert_eq!(fetched.id, created.id);
        cleanup(&pool, &[created.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn list_filters_by_status() {
        let pool = pool().await;
        let a = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("list-a"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create a");
        let b = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("list-b"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create b");
        change_tenant_status(&pool, b.id, TenantStatus::Inactive, None)
            .await
            .expect("disable b");

        let active = list_tenants(
            &pool,
            ListTenants {
                id: None,
                q: None,
                name: None,
                alias: None,
                status: Some(TenantStatus::Active),
                deleted: crate::models::enums::DeletedFilter::Live,
                limit: 100,
                offset: 0,
                order: Default::default(),
                dir: Default::default(),
            },
        )
        .await
        .expect("list active");
        assert!(active.items.iter().any(|t| t.id == a.id));
        assert!(!active.items.iter().any(|t| t.id == b.id));
        cleanup(&pool, &[a.id, b.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn update_replaces_only_provided_fields() {
        let pool = pool().await;
        let t = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("upd"),
                alias: Some("orig-alias".into()),
                tags: vec!["x".into()],
                attributes: json!({"k": "v"}),
            },
            None,
        )
        .await
        .expect("create");
        let upd = update_tenant(
            &pool,
            t.id,
            UpdateTenant {
                name: Some("renamed".into()),
                alias: None,
                tags: None,
                attributes: None,
            },
            None,
        )
        .await
        .expect("update");
        assert_eq!(upd.name, "renamed");
        assert_eq!(upd.alias.as_deref(), Some("orig-alias"));
        assert_eq!(upd.tags, vec!["x".to_string()]);
        cleanup(&pool, &[t.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn status_transitions_cover_non_delete_variants() {
        let pool = pool().await;
        let t = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("status"),
                alias: None,
                tags: vec![],
                attributes: Value::Null,
            },
            None,
        )
        .await
        .expect("create");
        for next in [
            TenantStatus::Inactive,
            TenantStatus::Frozen,
            TenantStatus::Active,
        ] {
            let updated = change_tenant_status(&pool, t.id, next.clone(), None)
                .await
                .expect("change status");
            assert_eq!(updated.status, next);
        }
        assert!(
            change_tenant_status(&pool, t.id, TenantStatus::Deleted, None)
                .await
                .is_err()
        );
        cleanup(&pool, &[t.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn entity_with_unknown_tenant_id_is_rejected_by_fk() {
        let pool = pool().await;
        let bogus = Uuid::new_v4();
        let res = sqlx::query(
            "INSERT INTO entities (id, kind, name, tenant_id)
             VALUES (gen_random_uuid(), 'service', 'fk-test', $1)",
        )
        .bind(bogus)
        .execute(&pool)
        .await;
        let err = res.expect_err("FK should reject unknown tenant_id");
        let msg = format!("{err}");
        assert!(
            msg.contains("foreign key") || msg.contains("entities_tenant_id_fkey"),
            "unexpected error: {msg}"
        );
    }
}
