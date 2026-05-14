use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    error::{db_err, AppError},
    identity::service::{hash_secret, verify_secret},
    models::{
        entity::{Entity, EntityList},
        enums::TenantStatus,
        tenant::{
            CreateTenant, CreateTenantInvitation, ListTenantInvitations, ListTenants, Tenant,
            TenantInvitation, TenantInvitationList, TenantList, UpdateTenant,
        },
    },
};

const TENANT_COLS: &str =
    "id, name, route, status, tags, attributes, created_by, updated_by, created_at, updated_at";
const INVITATION_COLS: &str =
    "ti.id, ti.tenant_id, ti.invitee_user_id, ti.invitee_email, ti.invited_by,
     ti.role_id, r.name AS role_name, ti.accepted_at, ti.rejected_at,
     ti.revoked_at, ti.created_at, ti.updated_at";

pub struct CreatedInvitation {
    pub invitation: TenantInvitation,
    pub token: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAdminBootstrap {
    pub tenant_id: Uuid,
    pub creator_id: Uuid,
    pub role_name: &'static str,
    pub capabilities: [&'static str; 5],
    pub scope_ref: String,
}

#[derive(Debug, Clone)]
pub struct TenantRoleAction {
    pub role_id: Uuid,
    pub role_name: String,
    pub actions: Vec<String>,
    pub access_type: String,
}

pub fn tenant_admin_bootstrap(tenant_id: Uuid, creator_id: Uuid) -> TenantAdminBootstrap {
    TenantAdminBootstrap {
        tenant_id,
        creator_id,
        role_name: "tenant-admin",
        capabilities: [
            "manage",
            "audit.read",
            "credential.manage",
            "policy.manage",
            "role.manage",
        ],
        scope_ref: tenant_id.to_string(),
    }
}

pub async fn create_tenant(
    pool: &PgPool,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    let tenant = create_tenant_in_tx(&mut tx, req, created_by).await?;
    if let Some(creator_id) = created_by {
        bootstrap_tenant_admin(&mut tx, tenant_admin_bootstrap(tenant.id, creator_id)).await?;
    }
    tx.commit().await.map_err(db_err)?;
    Ok(tenant)
}

async fn create_tenant_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    req: CreateTenant,
    created_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let attrs = if req.attributes.is_null() {
        serde_json::json!({})
    } else {
        req.attributes
    };
    sqlx::query_as::<_, Tenant>(&format!(
        r#"INSERT INTO tenants (id, name, route, tags, attributes, created_by, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $6)
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(req.name)
    .bind(req.route)
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
        r#"INSERT INTO roles (id, name, tenant_id, description, scope_kind, scope_ref)
           VALUES ($1, $2, $3, 'Default tenant administration role', 'tenant', $3::text)"#,
    )
    .bind(role_id)
    .bind(plan.role_name)
    .bind(plan.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        r#"INSERT INTO role_capabilities (role_id, capability_id)
           SELECT $1, c.id
           FROM capabilities c
           WHERE c.name = ANY($2::text[])
             AND c.resource_kind IS NULL
           ON CONFLICT DO NOTHING"#,
    )
    .bind(role_id)
    .bind(plan.capabilities.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    let linked_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM role_capabilities WHERE role_id = $1")
            .bind(role_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db_err)?;
    if linked_count != plan.capabilities.len() as i64 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "tenant-admin bootstrap missing seeded capabilities"
        )));
    }

    sqlx::query(
        r#"INSERT INTO policy_bindings
             (tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions)
           VALUES ($1, 'entity', $2, 'role', $3, 'tenant', $4, 'allow', '{}')"#,
    )
    .bind(plan.tenant_id)
    .bind(plan.creator_id)
    .bind(role_id)
    .bind(plan.scope_ref)
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
    sqlx::query_as::<_, Tenant>(&format!("SELECT {TENANT_COLS} FROM tenants WHERE id = $1"))
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
    let name = params.name;
    let route = params.route;
    let status = params.status;
    let q = search_pattern(params.q);

    let items = sqlx::query_as::<_, Tenant>(&format!(
        r#"SELECT {TENANT_COLS} FROM tenants
           WHERE ($1::text IS NULL OR name = $1)
             AND ($2::text IS NULL OR route = $2)
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR name ILIKE $4 OR route ILIKE $4 OR array_to_string(tags, ',') ILIKE $4 OR attributes::text ILIKE $4)
           ORDER BY created_at DESC
           LIMIT $5 OFFSET $6"#,
    ))
    .bind(name.clone())
    .bind(route.clone())
    .bind(status.clone())
    .bind(q.clone())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM tenants
           WHERE ($1::text IS NULL OR name = $1)
             AND ($2::text IS NULL OR route = $2)
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR name ILIKE $4 OR route ILIKE $4 OR array_to_string(tags, ',') ILIKE $4 OR attributes::text ILIKE $4)"#,
    )
    .bind(name)
    .bind(route)
    .bind(status)
    .bind(q)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(TenantList { items, total })
}

pub async fn list_tenants_for_entity(
    pool: &PgPool,
    entity_id: Uuid,
    params: ListTenants,
) -> Result<TenantList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let name = params.name;
    let route = params.route;
    let status = params.status;
    let q = search_pattern(params.q);
    let access_actions = ["list", "read", "manage"];

    let items = sqlx::query_as::<_, Tenant>(&format!(
        r#"SELECT {TENANT_COLS} FROM tenants t
           WHERE ($2::text IS NULL OR t.name = $2)
             AND ($3::text IS NULL OR t.route = $3)
             AND ($4::text IS NULL OR t.status = $4)
             AND ($5::text IS NULL OR t.name ILIKE $5 OR t.route ILIKE $5 OR array_to_string(t.tags, ',') ILIKE $5 OR t.attributes::text ILIKE $5)
             AND EXISTS (
                 SELECT 1
                 FROM policy_bindings pb
                 WHERE (
                     (pb.subject_kind = 'entity' AND pb.subject_id = $1)
                     OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                         SELECT group_id FROM group_members WHERE entity_id = $1
                     ))
                 )
                 AND pb.effect = 'allow'
                 AND (
                     pb.scope_kind = 'platform'
                     OR (pb.scope_kind = 'tenant' AND pb.scope_ref = t.id::text)
                 )
                 AND (
                     (pb.grant_kind = 'capability' AND pb.grant_id IN (
                         SELECT id FROM capabilities
                         WHERE name = ANY($6::text[]) AND resource_kind IS NULL
                     ))
                     OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                         SELECT rc.role_id
                         FROM role_capabilities rc
                         JOIN capabilities c ON c.id = rc.capability_id
                         WHERE c.name = ANY($6::text[]) AND c.resource_kind IS NULL
                     ))
                 )
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM policy_bindings pb
                 WHERE (
                     (pb.subject_kind = 'entity' AND pb.subject_id = $1)
                     OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                         SELECT group_id FROM group_members WHERE entity_id = $1
                     ))
                 )
                 AND pb.effect = 'deny'
                 AND (
                     pb.scope_kind = 'platform'
                     OR (pb.scope_kind = 'tenant' AND pb.scope_ref = t.id::text)
                 )
                 AND (
                     (pb.grant_kind = 'capability' AND pb.grant_id IN (
                         SELECT id FROM capabilities
                         WHERE name = ANY($6::text[]) AND resource_kind IS NULL
                     ))
                     OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                         SELECT rc.role_id
                         FROM role_capabilities rc
                         JOIN capabilities c ON c.id = rc.capability_id
                         WHERE c.name = ANY($6::text[]) AND c.resource_kind IS NULL
                     ))
                 )
             )
           ORDER BY t.created_at DESC
           LIMIT $7 OFFSET $8"#,
    ))
    .bind(entity_id)
    .bind(name.clone())
    .bind(route.clone())
    .bind(status.clone())
    .bind(q.clone())
    .bind(access_actions.as_slice())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM tenants t
           WHERE ($2::text IS NULL OR t.name = $2)
             AND ($3::text IS NULL OR t.route = $3)
             AND ($4::text IS NULL OR t.status = $4)
             AND ($5::text IS NULL OR t.name ILIKE $5 OR t.route ILIKE $5 OR array_to_string(t.tags, ',') ILIKE $5 OR t.attributes::text ILIKE $5)
             AND EXISTS (
                 SELECT 1
                 FROM policy_bindings pb
                 WHERE (
                     (pb.subject_kind = 'entity' AND pb.subject_id = $1)
                     OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                         SELECT group_id FROM group_members WHERE entity_id = $1
                     ))
                 )
                 AND pb.effect = 'allow'
                 AND (
                     pb.scope_kind = 'platform'
                     OR (pb.scope_kind = 'tenant' AND pb.scope_ref = t.id::text)
                 )
                 AND (
                     (pb.grant_kind = 'capability' AND pb.grant_id IN (
                         SELECT id FROM capabilities
                         WHERE name = ANY($6::text[]) AND resource_kind IS NULL
                     ))
                     OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                         SELECT rc.role_id
                         FROM role_capabilities rc
                         JOIN capabilities c ON c.id = rc.capability_id
                         WHERE c.name = ANY($6::text[]) AND c.resource_kind IS NULL
                     ))
                 )
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM policy_bindings pb
                 WHERE (
                     (pb.subject_kind = 'entity' AND pb.subject_id = $1)
                     OR (pb.subject_kind = 'group' AND pb.subject_id IN (
                         SELECT group_id FROM group_members WHERE entity_id = $1
                     ))
                 )
                 AND pb.effect = 'deny'
                 AND (
                     pb.scope_kind = 'platform'
                     OR (pb.scope_kind = 'tenant' AND pb.scope_ref = t.id::text)
                 )
                 AND (
                     (pb.grant_kind = 'capability' AND pb.grant_id IN (
                         SELECT id FROM capabilities
                         WHERE name = ANY($6::text[]) AND resource_kind IS NULL
                     ))
                     OR (pb.grant_kind = 'role' AND pb.grant_id IN (
                         SELECT rc.role_id
                         FROM role_capabilities rc
                         JOIN capabilities c ON c.id = rc.capability_id
                         WHERE c.name = ANY($6::text[]) AND c.resource_kind IS NULL
                     ))
                 )
             )"#,
    )
    .bind(entity_id)
    .bind(name)
    .bind(route)
    .bind(status)
    .bind(q)
    .bind(access_actions.as_slice())
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(TenantList { items, total })
}

pub async fn update_tenant(
    pool: &PgPool,
    id: Uuid,
    req: UpdateTenant,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET name       = COALESCE($2, name),
               route      = COALESCE($3, route),
               tags       = COALESCE($4, tags),
               attributes = COALESCE($5, attributes),
               updated_by = $6,
               updated_at = now()
           WHERE id = $1
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(req.name)
    .bind(req.route)
    .bind(req.tags)
    .bind(req.attributes)
    .bind(updated_by)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })
}

/// Sets `status` to a new value. `Deleted` is the soft-delete state.
/// The row is retained so historical references (audit logs, attributes,
/// etc.) remain resolvable.
pub async fn change_tenant_status(
    pool: &PgPool,
    id: Uuid,
    status: TenantStatus,
    updated_by: Option<Uuid>,
) -> Result<Tenant, AppError> {
    sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET status = $2, updated_by = $3, updated_at = now()
           WHERE id = $1
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(status)
    .bind(updated_by)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("tenant {id} not found")),
        other => AppError::Database(other),
    })
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
        r#"SELECT ti.id, ti.tenant_id, ti.invitee_user_id, ti.invitee_email, ti.invited_by,
                  ti.role_id, r.name AS role_name, ti.accepted_at, ti.rejected_at,
                  ti.revoked_at, ti.created_at, ti.updated_at
           FROM tenant_invitations ti
           LEFT JOIN roles r ON r.id = ti.role_id
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
        r#"SELECT ti.id, ti.tenant_id, ti.invitee_user_id, ti.invitee_email, ti.invited_by,
                  ti.role_id, r.name AS role_name, ti.accepted_at, ti.rejected_at,
                  ti.revoked_at, ti.created_at, ti.updated_at
           FROM tenant_invitations ti
           LEFT JOIN roles r ON r.id = ti.role_id
           WHERE ti.invitee_user_id = $1
              OR EXISTS (
                  SELECT 1 FROM entity_emails ee
                  WHERE ee.entity_id = $1 AND lower(ee.email) = lower(ti.invitee_email)
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
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.profile_id, e.profile_version_id,
                  e.status, e.attributes, e.created_at, e.updated_at
           FROM tenant_memberships tm
           JOIN entities e ON e.id = tm.entity_id
           WHERE tm.tenant_id = $1
             AND tm.status = 'active'
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

pub async fn list_tenant_role_actions(
    pool: &PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<TenantRoleAction>, AppError> {
    let rows = sqlx::query(
        r#"WITH bindings AS (
             SELECT pb.*, 'direct'::text AS access_type
             FROM policy_bindings pb
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $2
             UNION ALL
             SELECT pb.*, 'group'::text AS access_type
             FROM policy_bindings pb
             JOIN group_members gm ON gm.group_id = pb.subject_id
             WHERE pb.subject_kind = 'group' AND gm.entity_id = $2
           )
           SELECT r.id AS role_id,
                  r.name AS role_name,
                  ARRAY_AGG(DISTINCT c.name ORDER BY c.name) AS actions,
                  MIN(bindings.access_type) AS access_type
           FROM bindings
           JOIN roles r ON bindings.grant_kind = 'role' AND r.id = bindings.grant_id
           JOIN role_capabilities rc ON rc.role_id = r.id
           JOIN capabilities c ON c.id = rc.capability_id
           WHERE bindings.effect = 'allow'
             AND (r.tenant_id = $1 OR r.tenant_id IS NULL)
             AND (
                 bindings.scope_kind = 'platform'
                 OR (bindings.scope_kind = 'tenant' AND bindings.scope_ref = $1::text)
             )
           GROUP BY r.id, r.name"#,
    )
    .bind(tenant_id)
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(|row| {
            Ok(TenantRoleAction {
                role_id: row.try_get("role_id").map_err(db_err)?,
                role_name: row.try_get("role_name").map_err(db_err)?,
                actions: row.try_get("actions").map_err(db_err)?,
                access_type: row.try_get("access_type").map_err(db_err)?,
            })
        })
        .collect()
}

pub async fn accept_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    let role_id: Option<Uuid> = accept_invitation_row(pool, tenant_id, invitee_user_id).await?;
    grant_invitation_role(pool, tenant_id, invitee_user_id, role_id).await
}

pub async fn accept_invitation_token(
    pool: &PgPool,
    token: &str,
    actor_id: Uuid,
) -> Result<Uuid, AppError> {
    let (token_id, token_secret) = parse_secret_token(token, "atomi")
        .ok_or_else(|| AppError::bad_request("invalid invitation token"))?;

    let row = sqlx::query(
        r#"SELECT id, tenant_id, invitee_user_id, invitee_email, role_id,
                  secret_hash, expires_at, accepted_at, rejected_at, revoked_at
           FROM tenant_invitations
           WHERE id = $1"#,
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::bad_request("invalid invitation token"),
        other => AppError::Database(other),
    })?;

    let secret_hash: String = row.try_get("secret_hash").map_err(db_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;
    let accepted_at: Option<DateTime<Utc>> = row.try_get("accepted_at").unwrap_or(None);
    let rejected_at: Option<DateTime<Utc>> = row.try_get("rejected_at").unwrap_or(None);
    let revoked_at: Option<DateTime<Utc>> = row.try_get("revoked_at").unwrap_or(None);
    if accepted_at.is_some()
        || rejected_at.is_some()
        || revoked_at.is_some()
        || expires_at < Utc::now()
    {
        return Err(AppError::bad_request("invitation token expired"));
    }
    if !verify_secret(token_secret.as_bytes(), &secret_hash) {
        return Err(AppError::bad_request("invalid invitation token"));
    }

    let tenant_id: Uuid = row.try_get("tenant_id").map_err(db_err)?;
    let invitee_user_id: Option<Uuid> = row.try_get("invitee_user_id").unwrap_or(None);
    if let Some(invitee_user_id) = invitee_user_id {
        if invitee_user_id != actor_id {
            return Err(AppError::Forbidden);
        }
    } else if let Some(email) = row
        .try_get::<Option<String>, _>("invitee_email")
        .unwrap_or(None)
    {
        if !entity_has_email(pool, actor_id, &email).await? {
            return Err(AppError::Forbidden);
        }
    }

    let role_id: Option<Uuid> = row.try_get("role_id").unwrap_or(None);
    let updated_role_id: Option<Uuid> = sqlx::query_scalar(
        r#"UPDATE tenant_invitations
           SET invitee_user_id = $2,
               accepted_by = $2,
               accepted_at = now(),
               rejected_at = NULL,
               revoked_at = NULL,
               updated_at = now()
           WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL
           RETURNING role_id"#,
    )
    .bind(token_id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .flatten()
    .or(role_id);

    grant_invitation_role(pool, tenant_id, actor_id, updated_role_id).await?;
    Ok(tenant_id)
}

async fn accept_invitation_row(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"UPDATE tenant_invitations ti
           SET invitee_user_id = $2,
               accepted_by = $2,
               accepted_at = now(),
               rejected_at = NULL,
               revoked_at = NULL,
               updated_at = now()
           WHERE ti.tenant_id = $1
             AND ti.revoked_at IS NULL
             AND (ti.invitee_user_id = $2
                  OR EXISTS (
                      SELECT 1 FROM entity_emails ee
                      WHERE ee.entity_id = $2 AND lower(ee.email) = lower(ti.invitee_email)
                  ))
           RETURNING role_id"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
    .map(Option::flatten)
}

async fn grant_invitation_role(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
    role_id: Option<Uuid>,
) -> Result<(), AppError> {
    use crate::models::enums::{Effect, GrantKind, ScopeKind, SubjectKind};

    sqlx::query(
        r#"INSERT INTO tenant_memberships (tenant_id, entity_id, status)
           VALUES ($1, $2, 'active')
           ON CONFLICT (tenant_id, entity_id)
           DO UPDATE SET status = 'active'"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let Some(role_id) = role_id else {
        return Ok(());
    };

    sqlx::query(
        r#"INSERT INTO policy_bindings
             (tenant_id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref, effect, conditions)
           SELECT $1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb
           WHERE NOT EXISTS (
               SELECT 1 FROM policy_bindings
               WHERE tenant_id = $1
                 AND subject_kind = $2
                 AND subject_id = $3
                 AND grant_kind = $4
                 AND grant_id = $5
                 AND scope_kind = $6
                 AND scope_ref = $7
                 AND effect = $8
           )"#,
    )
    .bind(tenant_id)
    .bind(SubjectKind::Entity)
    .bind(invitee_user_id)
    .bind(GrantKind::Role)
    .bind(role_id)
    .bind(ScopeKind::Tenant)
    .bind(tenant_id.to_string())
    .bind(Effect::Allow)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn reject_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE tenant_invitations
           SET rejected_at = now(), updated_at = now()
           WHERE tenant_id = $1
             AND (invitee_user_id = $2
                  OR EXISTS (
                      SELECT 1 FROM entity_emails ee
                      WHERE ee.entity_id = $2 AND lower(ee.email) = lower(tenant_invitations.invitee_email)
                  ))"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn revoke_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    invitee_user_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE tenant_invitations
           SET revoked_at = now(), updated_at = now()
           WHERE tenant_id = $1 AND invitee_user_id = $2"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn revoke_invitation_by_id(
    pool: &PgPool,
    tenant_id: Uuid,
    invitation_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE tenant_invitations
           SET revoked_at = now(), updated_at = now()
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(invitation_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn entity_id_by_email(pool: &PgPool, email: &str) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT entity_id
           FROM entity_emails
           WHERE lower(email) = lower($1)"#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

async fn email_by_entity_id(pool: &PgPool, entity_id: Uuid) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT email FROM entity_emails WHERE entity_id = $1")
        .bind(entity_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

async fn entity_has_email(pool: &PgPool, entity_id: Uuid, email: &str) -> Result<bool, AppError> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1 FROM entity_emails
               WHERE entity_id = $1 AND lower(email) = lower($2)
           )"#,
    )
    .bind(entity_id)
    .bind(email)
    .fetch_one(pool)
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
                "audit.read",
                "credential.manage",
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
            route: Some(unique_name("acme-route")),
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
                route: None,
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
                route: None,
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
                q: None,
                name: None,
                route: None,
                status: Some(TenantStatus::Active),
                limit: 100,
                offset: 0,
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
                route: Some("orig-route".into()),
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
                route: None,
                tags: None,
                attributes: None,
            },
            None,
        )
        .await
        .expect("update");
        assert_eq!(upd.name, "renamed");
        assert_eq!(upd.route.as_deref(), Some("orig-route"));
        assert_eq!(upd.tags, vec!["x".to_string()]);
        cleanup(&pool, &[t.id]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn status_transitions_cover_all_variants() {
        let pool = pool().await;
        let t = create_tenant(
            &pool,
            CreateTenant {
                id: None,
                name: unique_name("status"),
                route: None,
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
            TenantStatus::Deleted,
        ] {
            let updated = change_tenant_status(&pool, t.id, next.clone(), None)
                .await
                .expect("change status");
            assert_eq!(updated.status, next);
        }
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
