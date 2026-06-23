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
    "id, name, alias, status, tags, attributes, created_by, updated_by, created_at, updated_at";
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
    pub capabilities: [&'static str; 9],
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
    let alias = params.alias;
    let status = params.status;
    let q = search_pattern(params.q);

    let items = sqlx::query_as::<_, Tenant>(&format!(
        r#"SELECT {TENANT_COLS} FROM tenants
           WHERE ($1::text IS NULL OR name = $1)
             AND ($2::text IS NULL OR lower(alias) = lower($2))
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR name ILIKE $4 OR alias ILIKE $4 OR array_to_string(tags, ',') ILIKE $4 OR attributes::text ILIKE $4)
           ORDER BY created_at DESC
           LIMIT $5 OFFSET $6"#,
    ))
    .bind(name.clone())
    .bind(alias.clone())
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
             AND ($2::text IS NULL OR lower(alias) = lower($2))
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR name ILIKE $4 OR alias ILIKE $4 OR array_to_string(tags, ',') ILIKE $4 OR attributes::text ILIKE $4)"#,
    )
    .bind(name)
    .bind(alias)
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
    let alias = params.alias;
    let status = params.status;
    let q = search_pattern(params.q);
    let access_actions = ["read", "manage"];

    // Visibility filter over the single canonical grant model, consistent with
    // the PDP. A tenant is visible when, for SOME requested action (read or
    // manage), the caller holds an unconditional allow that matches the tenant
    // object — at platform, tenant=t, object_kind='tenant', object_type=
    // 'tenant:tenant', or object=t scope — via a direct policy or a role-linked
    // block carrying its real effect, and that same action is not denied.
    // Deny-override is per-action (a manage deny does not hide a read-visible
    // tenant); group membership is resolved recursively; the assignment tenant
    // boundary is honoured.
    const CTES: &str = r#"WITH RECURSIVE subject_groups(group_id) AS (
            SELECT gm.group_id
            FROM group_members gm
            JOIN groups g ON g.id = gm.group_id AND g.status = 'active' AND g.group_type = 'principal'
            WHERE gm.entity_id = $1
            UNION ALL
            SELECT gh.parent_id
            FROM group_hierarchy gh
            JOIN subject_groups sg ON sg.group_id = gh.child_id
            JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active' AND parent.group_type = 'principal'
        ),
        role_grants AS (
            SELECT rpb.role_id AS root_role_id,
                   pb.scope_mode AS scope_kind,
                   CASE pb.scope_mode
                     WHEN 'platform' THEN NULL
                     WHEN 'tenant' THEN pb.tenant_id::text
                     WHEN 'object_kind' THEN pb.object_kind
                     WHEN 'object_type' THEN pb.object_type
                     WHEN 'object' THEN pb.object_id::text
                     ELSE NULL
                   END AS scope_ref,
                   pba.action_id AS capability_id,
                   pb.effect,
                   pb.conditions
            FROM role_permission_blocks rpb
            JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
            JOIN permission_block_actions pba ON pba.permission_block_id = rpb.permission_block_id
        )"#;
    // Scopes the PDP matches for a tenant object `t`: platform, tenant=t,
    // object_kind='tenant', object_type='tenant:tenant', and object=t.
    const SCOPE_MATCH: &str = "(%P%.scope_kind = 'platform'
        OR (%P%.scope_kind = 'tenant' AND %P%.scope_ref = t.id::text)
        OR (%P%.scope_kind = 'object_kind' AND %P%.scope_ref = 'tenant')
        OR (%P%.scope_kind = 'object_type' AND %P%.scope_ref = 'tenant:tenant')
        OR (%P%.scope_kind = 'object' AND %P%.scope_ref = t.id::text))";
    let edge_scope = SCOPE_MATCH.replace("%P%", "pb");
    let role_scope = SCOPE_MATCH.replace("%P%", "rg");
    let subject_match = r#"((pb.subject_kind = 'entity' AND pb.subject_id = $1)
            OR (pb.subject_kind = 'group' AND pb.subject_id IN (SELECT group_id FROM subject_groups)))
          AND (pb.tenant_id IS NULL OR pb.tenant_id = t.id)"#;
    // Per-action allow/deny, correlated to action `a` so deny-override applies
    // within an action only: a `manage` deny must not hide a tenant the caller
    // can `read`. The tenant is visible when SOME requested action has an
    // unconditional allow not overridden by a deny.
    let allow_for_action = format!(
        r#"EXISTS (
            SELECT 1 FROM effective_access_edges() pb
            WHERE {subject_match}
              AND (
                (pb.grant_kind = 'capability' AND pb.effect = 'allow' AND pb.conditions = '{{}}'::jsonb
                  AND pb.grant_id = a.id AND {edge_scope})
                OR (pb.grant_kind = 'role' AND EXISTS (
                  SELECT 1 FROM role_grants rg
                  WHERE rg.root_role_id = pb.grant_id AND rg.effect = 'allow' AND rg.conditions = '{{}}'::jsonb
                    AND rg.capability_id = a.id AND {role_scope}))
              )
        )"#
    );
    let deny_for_action = format!(
        r#"EXISTS (
            SELECT 1 FROM effective_access_edges() pb
            WHERE {subject_match}
              AND (
                (pb.grant_kind = 'capability' AND pb.effect = 'deny'
                  AND pb.grant_id = a.id AND {edge_scope})
                OR (pb.grant_kind = 'role' AND EXISTS (
                  SELECT 1 FROM role_grants rg
                  WHERE rg.root_role_id = pb.grant_id AND rg.effect = 'deny'
                    AND rg.capability_id = a.id AND {role_scope}))
              )
        )"#
    );
    let auth_filter = format!(
        r#"AND EXISTS (
            SELECT 1 FROM actions a
            WHERE a.name = ANY($6::text[])
              AND {allow_for_action}
              AND NOT {deny_for_action}
        )"#
    );
    let base_filter = r#"($2::text IS NULL OR t.name = $2)
             AND ($3::text IS NULL OR lower(t.alias) = lower($3))
             AND ($4::text IS NULL OR t.status = $4)
             AND ($5::text IS NULL OR t.name ILIKE $5 OR t.alias ILIKE $5 OR array_to_string(t.tags, ',') ILIKE $5 OR t.attributes::text ILIKE $5)"#;

    let items = sqlx::query_as::<_, Tenant>(&format!(
        "{CTES} SELECT {TENANT_COLS} FROM tenants t \
         WHERE {base_filter} {auth_filter} ORDER BY t.created_at DESC LIMIT $7 OFFSET $8"
    ))
    .bind(entity_id)
    .bind(name.clone())
    .bind(alias.clone())
    .bind(status.clone())
    .bind(q.clone())
    .bind(access_actions.as_slice())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(&format!(
        "{CTES} SELECT COUNT(*) FROM tenants t WHERE {base_filter} {auth_filter}"
    ))
    .bind(entity_id)
    .bind(name)
    .bind(alias)
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
    let alias = crate::models::alias::validate_alias_update(req.alias)?;
    let alias_is_set = alias.is_some();
    let alias = alias.flatten();
    sqlx::query_as::<_, Tenant>(&format!(
        r#"UPDATE tenants
           SET name       = COALESCE($2, name),
               alias      = CASE WHEN $3 THEN $4 ELSE alias END,
               tags       = COALESCE($5, tags),
               attributes = COALESCE($6, attributes),
               updated_by = $7,
               updated_at = now()
           WHERE id = $1
           RETURNING {TENANT_COLS}"#,
    ))
    .bind(id)
    .bind(req.name)
    .bind(alias_is_set)
    .bind(alias)
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
        r#"SELECT e.id, e.kind, e.name, e.alias, e.tenant_id, e.profile_id, e.profile_version_id,
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
        r#"SELECT e.id, e.kind, e.name, e.alias, e.tenant_id, e.profile_id, e.profile_version_id,
                  e.status, e.attributes, e.created_at, e.updated_at
           FROM entities e
           WHERE e.kind = 'human'
             AND e.status = 'active'
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

    tx.commit().await.map_err(db_err)?;
    Ok(())
}

pub async fn list_tenant_role_actions(
    pool: &PgPool,
    tenant_id: Uuid,
    entity_id: Uuid,
) -> Result<Vec<TenantRoleAction>, AppError> {
    let rows = sqlx::query(
        r#"WITH bindings AS (
             SELECT pb.*, 'direct'::text AS access_type
             FROM effective_access_edges() pb
             WHERE pb.subject_kind = 'entity' AND pb.subject_id = $2
             UNION ALL
             SELECT pb.*, 'group'::text AS access_type
             FROM effective_access_edges() pb
             JOIN group_members gm ON gm.group_id = pb.subject_id
             WHERE pb.subject_kind = 'group' AND gm.entity_id = $2
           )
           SELECT r.id AS role_id,
                  r.name AS role_name,
                  ARRAY_AGG(DISTINCT c.name ORDER BY c.name) AS actions,
                  MIN(bindings.access_type) AS access_type
           FROM bindings
           JOIN roles r ON bindings.grant_kind = 'role' AND r.id = bindings.grant_id
           JOIN effective_role_actions() rc ON rc.role_id = r.id
           JOIN actions c ON c.id = rc.capability_id
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
        r#"INSERT INTO role_assignments
             (tenant_id, subject_kind, subject_id, role_id)
           SELECT $1, 'entity', $2, $3
           WHERE NOT EXISTS (
               SELECT 1 FROM role_assignments
               WHERE tenant_id = $1
                 AND subject_kind = 'entity'
                 AND subject_id = $2
                 AND role_id = $3
           )"#,
    )
    .bind(tenant_id)
    .bind(invitee_user_id)
    .bind(role_id)
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
                q: None,
                name: None,
                alias: None,
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
    async fn status_transitions_cover_all_variants() {
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
