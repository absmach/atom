use super::*;
use sqlx::Row;

pub(super) async fn load_credential_ceiling(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
) -> Result<CredentialCeiling, AppError> {
    let rows = sqlx::query(
        r#"SELECT l.id        AS limit_id,
                  s.scope_kind AS scope_kind,
                  s.scope_ref  AS scope_ref,
                  l.tenant_id  AS tenant_id,
                  l.conditions AS conditions,
                  la.action_id AS action_id
           FROM credential_permission_limits l
           JOIN credential_permission_limit_scopes s ON s.limit_id = l.id
           JOIN credential_permission_limit_actions la ON la.limit_id = l.id
           WHERE l.credential_id = $1"#,
    )
    .bind(credential_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let entries = rows
        .into_iter()
        .map(|row| {
            let limit_id: Uuid = row.try_get("limit_id").map_err(db_err)?;
            Ok(EffectiveGrant {
                assignment_id: limit_id,
                block_id: limit_id,
                role_id: None,
                role_name: None,
                via: "access_token_ceiling".to_string(),
                // Honor the row's tenant restriction the same way an assignment
                // tenant boundary does. `object_kind`/`object_type` ceilings can
                // carry a `tenant_id` that the scope_ref alone does not encode; a
                // NULL tenant_id (platform/object modes, or a tenant-agnostic kind)
                // leaves the entry unrestricted, matching `match_grant`.
                tenant_boundary: row.try_get("tenant_id").map_err(db_err)?,
                scope_kind: row.try_get("scope_kind").map_err(db_err)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                capability_id: row.try_get("action_id").map_err(db_err)?,
                effect: Effect::Allow,
                conditions: row.try_get("conditions").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    Ok(CredentialCeiling { entries })
}

pub(super) async fn audit_logs(
    pool: &sqlx::PgPool,
    params: crate::models::access::AuditQuery,
    allowed_tenant_ids: Option<Vec<Uuid>>,
) -> Result<AuditLogResponse, AppError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let items = sqlx::query_as::<_, AuditLogItem>(
        r#"SELECT id, actor_entity_id, tenant_id, target_kind, target_id, event, outcome, details, created_at
           FROM audit_logs
           WHERE ($1::uuid IS NULL OR actor_entity_id = $1)
             AND ($2::text IS NULL OR event = $2)
             AND ($3::text IS NULL OR outcome = $3)
             AND ($4::timestamptz IS NULL OR created_at >= $4)
             AND ($5::timestamptz IS NULL OR created_at < $5)
             AND ($6::uuid IS NULL OR tenant_id = $6)
             AND ($7::uuid[] IS NULL OR tenant_id = ANY($7))
             AND ($8::text IS NULL OR target_kind = $8)
             AND ($9::uuid IS NULL OR target_id = $9)
           ORDER BY created_at DESC
           LIMIT $10 OFFSET $11"#,
    )
    .bind(params.actor_entity_id)
    .bind(params.event.clone())
    .bind(params.outcome.clone())
    .bind(params.from)
    .bind(params.to)
    .bind(params.tenant_id)
    .bind(allowed_tenant_ids.as_deref())
    .bind(params.target_kind.clone())
    .bind(params.target_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM audit_logs
           WHERE ($1::uuid IS NULL OR actor_entity_id = $1)
             AND ($2::text IS NULL OR event = $2)
             AND ($3::text IS NULL OR outcome = $3)
             AND ($4::timestamptz IS NULL OR created_at >= $4)
             AND ($5::timestamptz IS NULL OR created_at < $5)
             AND ($6::uuid IS NULL OR tenant_id = $6)
             AND ($7::uuid[] IS NULL OR tenant_id = ANY($7))
             AND ($8::text IS NULL OR target_kind = $8)
             AND ($9::uuid IS NULL OR target_id = $9)"#,
    )
    .bind(params.actor_entity_id)
    .bind(params.event)
    .bind(params.outcome)
    .bind(params.from)
    .bind(params.to)
    .bind(params.tenant_id)
    .bind(allowed_tenant_ids.as_deref())
    .bind(params.target_kind)
    .bind(params.target_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(AuditLogResponse { items, total })
}

pub(super) async fn orphan_policies(
    pool: &sqlx::PgPool,
    params: AdminPageQuery,
) -> Result<OrphanPoliciesResponse, AppError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let rows = sqlx::query(
        r#"WITH orphaned AS (
             SELECT ra.id,
                    ra.tenant_id,
                    'role_assignment'::text AS source_kind,
                    ra.subject_kind,
                    ra.subject_id,
                    ra.role_id,
                    NULL::uuid AS permission_block_id,
                    ra.created_at,
                    CASE
                      WHEN (ra.subject_kind = 'entity' AND e.id IS NULL)
                        OR (ra.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN r.id IS NULL
                      THEN 'role_not_found'
                    END AS orphan_reason
             FROM role_assignments ra
             LEFT JOIN entities e ON ra.subject_kind = 'entity' AND ra.subject_id = e.id
             LEFT JOIN principal_groups g ON ra.subject_kind = 'group' AND ra.subject_id = g.id
             LEFT JOIN roles r ON ra.role_id = r.id
             UNION ALL
             SELECT dp.id,
                    dp.tenant_id,
                    'direct_policy'::text AS source_kind,
                    dp.subject_kind,
                    dp.subject_id,
                    NULL::uuid AS role_id,
                    dp.permission_block_id,
                    dp.created_at,
                    CASE
                      WHEN (dp.subject_kind = 'entity' AND e.id IS NULL)
                        OR (dp.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN pb.id IS NULL
                      THEN 'permission_block_not_found'
                    END AS orphan_reason
             FROM direct_policies dp
             LEFT JOIN entities e ON dp.subject_kind = 'entity' AND dp.subject_id = e.id
             LEFT JOIN principal_groups g ON dp.subject_kind = 'group' AND dp.subject_id = g.id
             LEFT JOIN permission_blocks pb ON dp.permission_block_id = pb.id
           )
           SELECT * FROM orphaned
           WHERE orphan_reason IS NOT NULL
           ORDER BY created_at DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"WITH orphaned AS (
             SELECT CASE
                      WHEN (ra.subject_kind = 'entity' AND e.id IS NULL)
                        OR (ra.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN r.id IS NULL
                      THEN 'role_not_found'
                    END AS orphan_reason
             FROM role_assignments ra
             LEFT JOIN entities e ON ra.subject_kind = 'entity' AND ra.subject_id = e.id
             LEFT JOIN principal_groups g ON ra.subject_kind = 'group' AND ra.subject_id = g.id
             LEFT JOIN roles r ON ra.role_id = r.id
             UNION ALL
             SELECT CASE
                      WHEN (dp.subject_kind = 'entity' AND e.id IS NULL)
                        OR (dp.subject_kind = 'group' AND g.id IS NULL)
                      THEN 'subject_not_found'
                      WHEN pb.id IS NULL
                      THEN 'permission_block_not_found'
                    END AS orphan_reason
             FROM direct_policies dp
             LEFT JOIN entities e ON dp.subject_kind = 'entity' AND dp.subject_id = e.id
             LEFT JOIN principal_groups g ON dp.subject_kind = 'group' AND dp.subject_id = g.id
             LEFT JOIN permission_blocks pb ON dp.permission_block_id = pb.id
           )
           SELECT COUNT(*) FROM orphaned WHERE orphan_reason IS NOT NULL"#,
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(OrphanPolicyItem {
                id: row.try_get("id").map_err(db_err)?,
                tenant_id: row.try_get("tenant_id").map_err(db_err)?,
                source_kind: row.try_get("source_kind").map_err(db_err)?,
                subject_kind: row.try_get("subject_kind").map_err(db_err)?,
                subject_id: row.try_get("subject_id").map_err(db_err)?,
                role_id: row.try_get("role_id").map_err(db_err)?,
                permission_block_id: row.try_get("permission_block_id").map_err(db_err)?,
                created_at: row.try_get("created_at").map_err(db_err)?,
                orphan_reason: row.try_get("orphan_reason").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(OrphanPoliciesResponse { items, total })
}

pub(super) async fn expiring_credentials(
    pool: &sqlx::PgPool,
    params: ExpiringCredentialsQuery,
) -> Result<ExpiringCredentialsResponse, AppError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let days = params.days.max(0);
    let rows = sqlx::query(
        r#"SELECT c.id, c.entity_id, e.name AS entity_name, e.kind AS entity_kind,
                  c.kind, c.status, c.expires_at, c.created_at
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.status = 'active'
             AND c.expires_at IS NOT NULL
             AND c.expires_at <= now() + ($1::text || ' days')::interval
             AND ($2::uuid IS NULL OR c.entity_id = $2)
             AND ($3::text IS NULL OR c.kind = $3)
           ORDER BY c.expires_at ASC
           LIMIT $4 OFFSET $5"#,
    )
    .bind(days.to_string())
    .bind(params.entity_id)
    .bind(params.kind)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM credentials c
           WHERE c.status = 'active'
             AND c.expires_at IS NOT NULL
             AND c.expires_at <= now() + ($1::text || ' days')::interval
             AND ($2::uuid IS NULL OR c.entity_id = $2)
             AND ($3::text IS NULL OR c.kind = $3)"#,
    )
    .bind(days.to_string())
    .bind(params.entity_id)
    .bind(params.kind)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let now = Utc::now();
    let items = rows
        .into_iter()
        .map(|row| {
            let expires_at = row.try_get("expires_at").map_err(db_err)?;
            Ok(ExpiringCredentialItem {
                id: row.try_get("id").map_err(db_err)?,
                entity_id: row.try_get("entity_id").map_err(db_err)?,
                entity_name: row.try_get("entity_name").map_err(db_err)?,
                entity_kind: row.try_get("entity_kind").map_err(db_err)?,
                kind: row.try_get::<CredentialKind, _>("kind").map_err(db_err)?,
                status: row.try_get("status").map_err(db_err)?,
                expires_at,
                days_remaining: (expires_at - now).num_days(),
                created_at: row.try_get("created_at").map_err(db_err)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(ExpiringCredentialsResponse { items, total })
}

pub(super) async fn load_authz_subject(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Option<AuthzSubjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzSubjectRecord>(
        r#"SELECT id, name, kind, tenant_id, status, attributes
           FROM entities
           WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_tenant(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
) -> Result<Option<AuthzTenantRecord>, AppError> {
    sqlx::query_as::<_, AuthzTenantRecord>(
        r#"SELECT id, name, status, deleted_at, attributes
           FROM tenants
           WHERE id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_resource(
    pool: &sqlx::PgPool,
    resource_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT r.id, r.kind, r.name, r.tenant_id, r.attributes,
                  COALESCE((SELECT array_agg(grp.group_id)
                            FROM group_resource_parents grp
                            WHERE grp.resource_id = r.id), '{}'::uuid[]) AS parent_group_ids
           FROM resources r
           WHERE r.id = $1 AND r.deleted_at IS NULL"#,
    )
    .bind(resource_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_entity_object(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT e.id, e.kind, e.name, e.tenant_id, e.attributes,
                  COALESCE((SELECT array_agg(gep.group_id)
                            FROM group_entity_parents gep
                            WHERE gep.entity_id = e.id), '{}'::uuid[]) AS parent_group_ids
           FROM entities e
           WHERE e.id = $1 AND e.deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_group_object(
    pool: &sqlx::PgPool,
    group_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    // The group hierarchy stays a tree (`PRIMARY KEY (child_id)`), so this is 0
    // or 1 parent — carried as an array only so every protected object presents
    // the same shape to the scope predicate.
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT g.id, 'group'::text AS kind, g.name, g.tenant_id, g.attributes,
                  CASE WHEN gh.parent_id IS NULL THEN '{}'::uuid[] ELSE ARRAY[gh.parent_id] END
                      AS parent_group_ids
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE g.id = $1 AND g.deleted_at IS NULL"#,
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_credential_object(
    pool: &sqlx::PgPool,
    credential_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT c.id, c.kind, c.identifier AS name, e.tenant_id,
                  c.metadata AS attributes, '{}'::uuid[] AS parent_group_ids
           FROM credentials c
           JOIN entities e ON e.id = c.entity_id
           WHERE c.id = $1"#,
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn group_ancestor_ids(
    pool: &sqlx::PgPool,
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    if group_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(
        r#"WITH RECURSIVE ancestors(id) AS (
               SELECT parent_id FROM group_hierarchy WHERE child_id = ANY($1::uuid[])
               UNION
               SELECT gh.parent_id
               FROM group_hierarchy gh
               JOIN ancestors a ON gh.child_id = a.id
           )
           SELECT DISTINCT id FROM ancestors"#,
    )
    .bind(group_ids)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn effective_grants_for_subject(
    pool: &sqlx::PgPool,
    entity_id: Uuid,
) -> Result<Vec<EffectiveGrant>, AppError> {
    // Canonical grant expansion lives in the `subject_effective_grants` SQL
    // function, shared by this PDP path and every authorized
    // listing reader so scope/effect/conditions semantics cannot drift.
    let rows = sqlx::query(
        r#"SELECT assignment_id, block_id, role_id, role_name, via, tenant_boundary,
                  scope_kind, scope_ref, capability_id, effect, conditions
           FROM subject_effective_grants($1)"#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.into_iter()
        .map(|row| {
            let scope_kind_text: String = row.try_get("scope_kind").map_err(db_err)?;
            Ok(EffectiveGrant {
                assignment_id: row.try_get("assignment_id").map_err(db_err)?,
                block_id: row.try_get("block_id").map_err(db_err)?,
                role_id: row.try_get("role_id").map_err(db_err)?,
                role_name: row.try_get("role_name").map_err(db_err)?,
                via: row.try_get("via").map_err(db_err)?,
                tenant_boundary: row.try_get("tenant_boundary").map_err(db_err)?,
                scope_kind: parse_scope_kind_text(&scope_kind_text)?,
                scope_ref: row.try_get("scope_ref").map_err(db_err)?,
                capability_id: row.try_get("capability_id").map_err(db_err)?,
                effect: row.try_get("effect").map_err(db_err)?,
                conditions: row.try_get("conditions").map_err(db_err)?,
            })
        })
        .collect()
}

pub(super) async fn load_authz_role_object(
    pool: &sqlx::PgPool,
    role_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT r.id, 'role'::text AS kind, r.name, r.tenant_id,
                  '{}'::jsonb AS attributes, '{}'::uuid[] AS parent_group_ids
           FROM roles r
           JOIN protected_object_ids registry
             ON registry.id = r.id
            AND registry.object_kind = 'role'
            AND registry.source_table = 'roles'
           WHERE r.id = $1 AND r.deleted_at IS NULL"#,
    )
    .bind(role_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_policy_object(
    pool: &sqlx::PgPool,
    policy_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT registry.id, 'policy'::text AS kind, NULL::text AS name,
                  policy.tenant_id, '{}'::jsonb AS attributes,
                  '{}'::uuid[] AS parent_group_ids
           FROM protected_object_ids registry
           JOIN LATERAL (
               SELECT tenant_id
               FROM direct_policies
               WHERE registry.source_table = 'direct_policies' AND id = registry.id
               UNION ALL
               SELECT tenant_id
               FROM role_assignments
               WHERE registry.source_table = 'role_assignments' AND id = registry.id
           ) policy ON TRUE
           WHERE registry.id = $1 AND registry.object_kind = 'policy'"#,
    )
    .bind(policy_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn load_authz_api_endpoint_object(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
) -> Result<Option<AuthzObjectRecord>, AppError> {
    sqlx::query_as::<_, AuthzObjectRecord>(
        r#"SELECT endpoint.id, 'api_endpoint'::text AS kind, endpoint.name,
                  endpoint.tenant_id, '{}'::jsonb AS attributes,
                  '{}'::uuid[] AS parent_group_ids
           FROM api_endpoints endpoint
           JOIN protected_object_ids registry
             ON registry.id = endpoint.id
            AND registry.object_kind = 'api_endpoint'
            AND registry.source_table = 'api_endpoints'
           WHERE endpoint.id = $1"#,
    )
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn authorized_entity_ids(
    pool: &sqlx::PgPool,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let id = search_pattern(params.id);
    let q = search_pattern(params.q);
    let external_id = crate::models::external_id::normalize_external_id(params.external_id);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = authorized_entity_order_by(params.entity_order, params.dir);

    let sql = r#"WITH RECURSIVE target_groups(id) AS (
                   SELECT $8::uuid WHERE $8::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $9::boolean
               ),
               grants AS (
                   SELECT * FROM subject_effective_grants($1)
               ),
               __CEILING_CTE__,
               caps AS (
                   SELECT a.id AS capability_id, aa.object_type
                   FROM actions a
                   JOIN action_applicability aa ON aa.action_id = a.id
                   WHERE a.name = $2 AND aa.object_kind = 'entity'
               ),
               candidates AS (
                   SELECT e.id, e.kind::text AS sub_kind, e.tenant_id, e.created_at, e.updated_at,
                          e.name, e.status::text AS status,
                          COALESCE((SELECT array_agg(gep.group_id)
                                    FROM group_entity_parents gep
                                    WHERE gep.entity_id = e.id), '{}'::uuid[]) AS parent_group_ids
                   FROM entities e
                   WHERE e.deleted_at IS NULL
                     AND (e.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = e.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL))
                     AND ($3::uuid IS NULL OR e.tenant_id = $3)
                     AND ($4::text IS NULL OR e.kind::text = $4 OR 'entity:' || e.kind::text = $4)
                     AND ($5::text IS NULL OR e.name ILIKE $5 OR e.attributes::text ILIKE $5)
                     AND ($6::uuid IS NULL OR e.profile_id = $6)
                     AND ($7::text IS NULL OR e.status::text = $7)
                     AND ($8::uuid IS NULL OR EXISTS (
                             SELECT 1 FROM group_entity_parents gep
                             WHERE gep.entity_id = e.id
                               AND gep.group_id IN (SELECT id FROM target_groups)))
                     AND ($13::jsonb IS NULL OR e.attributes @> $13::jsonb)
                     AND ($14::text IS NULL OR e.external_id = $14)
                     AND ($15::text IS NULL OR e.id::text ILIKE $15)
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = ANY(c.parent_group_ids)
                   UNION
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               candidate_ancestor_ids AS (
                   SELECT object_id, array_agg(ancestor_id) AS ancestors
                   FROM candidate_ancestors
                   GROUP BY object_id
               ),
               authorized AS (
                   SELECT c.id, c.created_at, c.updated_at, c.name, c.sub_kind, c.status
                   FROM candidates c
                   LEFT JOIN candidate_ancestor_ids ca ON ca.object_id = c.id
                   WHERE EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'allow' AND g.conditions = '{}'::jsonb
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'entity', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'deny'
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'entity', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND ($12::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling cl
                       WHERE (cl.tenant_id IS NULL OR cl.tenant_id = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = cl.action_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'entity:' || c.sub_kind)
                         )
                         AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'entity', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   ))
               )
               SELECT id, COUNT(*) OVER() AS total
               FROM authorized
               ORDER BY __ORDER_BY__
               LIMIT $10 OFFSET $11"#
        .replace("__ORDER_BY__", order_by)
        .replace("__CEILING_CTE__", &crate::authz::sql::postgres::ceiling_cte("$12"));

    let rows = sqlx::query_as::<_, AuthorizedPageRow>(&sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.object_type)
        .bind(q)
        .bind(params.profile_id)
        .bind(params.entity_status.map(|status| match status {
            crate::models::enums::EntityStatus::Active => "active".to_string(),
            crate::models::enums::EntityStatus::Inactive => "inactive".to_string(),
            crate::models::enums::EntityStatus::Suspended => "suspended".to_string(),
        }))
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(limit)
        .bind(offset)
        .bind(ceiling_credential_id)
        .bind(attributes_contains)
        .bind(external_id)
        .bind(id)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    rows_to_authorized_object_ids(rows)
}

pub(super) async fn authorized_group_ids(
    pool: &sqlx::PgPool,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let status = params.entity_status.map(|status| match status {
        crate::models::enums::EntityStatus::Active => "active".to_string(),
        crate::models::enums::EntityStatus::Inactive => "inactive".to_string(),
        crate::models::enums::EntityStatus::Suspended => "suspended".to_string(),
    });
    let order_by = authorized_group_order_by(params.group_order, params.dir);

    // Scope matching is delegated to the shared `grant_scope_matches` predicate
    // (the same logic the PDP's Rust path mirrors). For groups the relevant
    // scopes are platform/tenant/object_kind/object plus `group_child_kind`/
    // `group_descendant_kind`; the `group_*_objects` scope modes are
    // CHECK-constrained to entity/resource objects, so they never target a group.
    let sql = r#"WITH RECURSIVE target_groups(id) AS (
                   SELECT $6::uuid WHERE $6::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $7::boolean
               ),
               grants AS (
                   SELECT * FROM subject_effective_grants($1)
               ),
               __CEILING_CTE__,
               caps AS (
                   SELECT a.id AS capability_id, aa.object_type
                   FROM actions a
                   JOIN action_applicability aa ON aa.action_id = a.id
                   WHERE a.name = $2 AND aa.object_kind = 'group'
               ),
               candidates AS (
                   SELECT g.id, 'group'::text AS sub_kind, g.tenant_id, g.created_at, g.updated_at,
                          g.name, g.status::text AS status,
                          CASE WHEN gph.parent_id IS NULL THEN '{}'::uuid[]
                               ELSE ARRAY[gph.parent_id] END AS parent_group_ids
                   FROM groups g
                   LEFT JOIN group_hierarchy gph ON gph.child_id = g.id
                   WHERE g.deleted_at IS NULL
                     AND (g.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = g.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL))
                     AND ($3::uuid IS NULL OR g.tenant_id = $3)
                     AND ($4::text IS NULL OR g.group_type = $4)
                     AND ($5::text IS NULL OR g.name ILIKE $5 OR g.description ILIKE $5 OR g.attributes::text ILIKE $5)
                     AND ($8::text IS NULL OR g.status = $8)
                     AND ($6::uuid IS NULL OR gph.parent_id IN (SELECT id FROM target_groups))
                     AND ($12::jsonb IS NULL OR g.attributes @> $12::jsonb)
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = ANY(c.parent_group_ids)
                   UNION
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               candidate_ancestor_ids AS (
                   SELECT object_id, array_agg(ancestor_id) AS ancestors
                   FROM candidate_ancestors
                   GROUP BY object_id
               ),
               authorized AS (
                   SELECT c.id, c.created_at, c.updated_at, c.name, c.status
                   FROM candidates c
                   LEFT JOIN candidate_ancestor_ids ca ON ca.object_id = c.id
                   WHERE EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'allow' AND g.conditions = '{}'::jsonb
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'group:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'group', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'deny'
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'group:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'group', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND ($11::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling cl
                       WHERE (cl.tenant_id IS NULL OR cl.tenant_id = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = cl.action_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'group:' || c.sub_kind)
                         )
                         AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'group', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   ))
               )
               SELECT id, COUNT(*) OVER() AS total
               FROM authorized
               ORDER BY __ORDER_BY__
               LIMIT $9 OFFSET $10"#
        .replace("__ORDER_BY__", order_by)
        .replace("__CEILING_CTE__", &crate::authz::sql::postgres::ceiling_cte("$11"));

    let rows = sqlx::query_as::<_, AuthorizedPageRow>(&sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.group_type)
        .bind(q)
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .bind(ceiling_credential_id)
        .bind(attributes_contains)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    rows_to_authorized_object_ids(rows)
}

pub(super) async fn authorized_resource_rows(
    pool: &sqlx::PgPool,
    params: AuthorizedObjectIdsQuery,
    ceiling_credential_id: Option<Uuid>,
    projection: AuthorizedResourceProjection,
) -> Result<Vec<AuthorizedPageRow>, AppError> {
    let limit = match projection {
        AuthorizedResourceProjection::Ids => params.limit.clamp(1, 500),
        AuthorizedResourceProjection::Kinds => 500,
    };
    let offset = params.offset.max(0);
    let q = search_pattern(params.q);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = authorized_resource_order_by(params.resource_order, params.dir);

    let select_clause = match projection {
        AuthorizedResourceProjection::Ids => format!(
            "SELECT id, COUNT(*) OVER() AS total
             FROM authorized
             ORDER BY {order_by}
             LIMIT $9 OFFSET $10"
        ),
        AuthorizedResourceProjection::Kinds => String::from(
            "SELECT DISTINCT sub_kind AS kind
             FROM authorized
             ORDER BY kind
             LIMIT $9 OFFSET $10",
        ),
    };
    let sql = r#"WITH RECURSIVE target_groups(id) AS (
                   SELECT $6::uuid WHERE $6::uuid IS NOT NULL
                   UNION ALL
                   SELECT gh.child_id
                   FROM group_hierarchy gh
                   JOIN target_groups tg ON tg.id = gh.parent_id
                   WHERE $7::boolean
               ),
               grants AS (
                   SELECT * FROM subject_effective_grants($1)
               ),
               __CEILING_CTE__,
               caps AS (
                   SELECT a.id AS capability_id, aa.object_type
                   FROM actions a
                   JOIN action_applicability aa ON aa.action_id = a.id
                   WHERE a.name = $2 AND aa.object_kind = 'resource'
               ),
               candidates AS (
                   SELECT r.id, r.kind AS sub_kind, r.tenant_id, r.created_at, r.updated_at,
                          r.name,
                          COALESCE((SELECT array_agg(grp.group_id)
                                    FROM group_resource_parents grp
                                    WHERE grp.resource_id = r.id), '{}'::uuid[]) AS parent_group_ids
                   FROM resources r
                   WHERE r.deleted_at IS NULL
                     AND (r.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL))
                     AND ($3::uuid IS NULL OR r.tenant_id = $3)
                     AND ($4::text IS NULL OR r.kind = $4 OR 'resource:' || r.kind = $4)
                     AND ($5::text IS NULL OR r.name ILIKE $5 OR r.attributes::text ILIKE $5)
                     AND ($6::uuid IS NULL OR EXISTS (
                             SELECT 1 FROM group_resource_parents grp
                             WHERE grp.resource_id = r.id
                               AND grp.group_id IN (SELECT id FROM target_groups)))
                     AND ($8::jsonb IS NULL OR r.attributes @> $8::jsonb)
               ),
               candidate_ancestors(object_id, ancestor_id) AS (
                   SELECT c.id, gh.parent_id
                   FROM candidates c
                   JOIN group_hierarchy gh ON gh.child_id = ANY(c.parent_group_ids)
                   UNION
                   SELECT ca.object_id, gh.parent_id
                   FROM candidate_ancestors ca
                   JOIN group_hierarchy gh ON gh.child_id = ca.ancestor_id
               ),
               candidate_ancestor_ids AS (
                   SELECT object_id, array_agg(ancestor_id) AS ancestors
                   FROM candidate_ancestors
                   GROUP BY object_id
               ),
               authorized AS (
                   SELECT c.id, c.sub_kind, c.created_at, c.updated_at, c.name
                   FROM candidates c
                   LEFT JOIN candidate_ancestor_ids ca ON ca.object_id = c.id
                   WHERE EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'allow' AND g.conditions = '{}'::jsonb
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'resource', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants g
                       WHERE g.effect = 'deny'
                         AND (g.tenant_boundary IS NULL OR g.tenant_boundary = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = g.capability_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                         )
                         AND grant_scope_matches(g.scope_kind, g.scope_ref, 'resource', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   )
                   AND ($11::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling cl
                       WHERE (cl.tenant_id IS NULL OR cl.tenant_id = c.tenant_id)
                         AND EXISTS (
                             SELECT 1 FROM caps mc
                             WHERE mc.capability_id = cl.action_id
                               AND (mc.object_type IS NULL OR mc.object_type = 'resource:' || c.sub_kind)
                         )
                         AND grant_scope_matches(cl.scope_kind, cl.scope_ref, 'resource', c.sub_kind,
                                                 c.id, c.tenant_id, c.parent_group_ids,
                                                 COALESCE(ca.ancestors, '{}'::uuid[]))
                   ))
               )
               __SELECT__"#
        .replace("__SELECT__", &select_clause)
        .replace("__CEILING_CTE__", &crate::authz::sql::postgres::ceiling_cte("$11"));

    sqlx::query_as::<_, AuthorizedPageRow>(&sql)
        .bind(params.subject_id)
        .bind(params.action)
        .bind(params.tenant_id)
        .bind(params.object_type)
        .bind(q)
        .bind(params.parent_group_id)
        .bind(params.include_descendants)
        .bind(attributes_contains)
        .bind(limit)
        .bind(offset)
        .bind(ceiling_credential_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

fn authorized_entity_order_by(order: EntityOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (EntityOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (EntityOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (EntityOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC NULLS LAST, id ASC",
        (EntityOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (EntityOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::Name, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::Username, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::Username, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::FirstName, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::FirstName, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::LastName, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::LastName, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::Email, SortDir::Asc) => "lower(name) ASC, id ASC",
        (EntityOrderField::Email, SortDir::Desc) => "lower(name) DESC, id ASC",
        (EntityOrderField::Kind, SortDir::Asc) => "sub_kind ASC, id ASC",
        (EntityOrderField::Kind, SortDir::Desc) => "sub_kind DESC, id ASC",
        (EntityOrderField::Status, SortDir::Asc) => "status ASC, id ASC",
        (EntityOrderField::Status, SortDir::Desc) => "status DESC, id ASC",
    }
}

fn authorized_resource_order_by(order: ResourceOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (ResourceOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (ResourceOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC NULLS LAST, id ASC",
        (ResourceOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (ResourceOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (ResourceOrderField::Name, SortDir::Desc) => "lower(name) DESC NULLS LAST, id ASC",
        (ResourceOrderField::Kind, SortDir::Asc) => "sub_kind ASC, id ASC",
        (ResourceOrderField::Kind, SortDir::Desc) => "sub_kind DESC, id ASC",
    }
}

fn authorized_group_order_by(order: GroupOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (GroupOrderField::CreatedAt, SortDir::Asc) => "created_at ASC, id ASC",
        (GroupOrderField::CreatedAt, SortDir::Desc) => "created_at DESC, id ASC",
        (GroupOrderField::UpdatedAt, SortDir::Asc) => "updated_at ASC NULLS LAST, id ASC",
        (GroupOrderField::UpdatedAt, SortDir::Desc) => "updated_at DESC NULLS LAST, id ASC",
        (GroupOrderField::Name, SortDir::Asc) => "lower(name) ASC, id ASC",
        (GroupOrderField::Name, SortDir::Desc) => "lower(name) DESC, id ASC",
        (GroupOrderField::Status, SortDir::Asc) => "status ASC, id ASC",
        (GroupOrderField::Status, SortDir::Desc) => "status DESC, id ASC",
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn authorize_flat_candidate_query(
    pool: &sqlx::PgPool,
    subject_id: Uuid,
    ceiling_id: Option<Uuid>,
    object_kind: &str,
    actions: &[&str],
    filters: Value,
    candidate: FlatCandidate,
    limit: i64,
    offset: i64,
) -> Result<AuthorizedObjectIdsResponse, AppError> {
    let candidate_sql = flat_candidate_sql(candidate);
    let action_names = actions
        .iter()
        .map(|action| (*action).to_string())
        .collect::<Vec<_>>();
    let sql = r#"WITH candidates AS (__CANDIDATES__),
           grants AS (
               SELECT * FROM subject_effective_grants($1)
           ),
           __CEILING__,
           caps AS (
               SELECT a.id
               FROM actions a
               JOIN action_applicability aa ON aa.action_id = a.id
               WHERE a.name = ANY($2::text[])
                 AND aa.object_kind = $3
                 AND aa.object_type IS NULL
           ),
           authorized AS (
               SELECT candidate.id, candidate.ordinality
               FROM candidates candidate
               WHERE candidate.tenant_id IS NULL
                  OR EXISTS (
                       SELECT 1 FROM tenants tenant
                       WHERE tenant.id = candidate.tenant_id
                         AND tenant.status = 'active'
                         AND tenant.deleted_at IS NULL
                  )
               INTERSECT
               SELECT candidate.id, candidate.ordinality
               FROM candidates candidate
               WHERE EXISTS (
                   SELECT 1
                   FROM caps cap
                   WHERE EXISTS (
                       SELECT 1 FROM grants effective_grant
                       WHERE effective_grant.capability_id = cap.id
                         AND effective_grant.effect = 'allow'
                         AND effective_grant.conditions = '{}'::jsonb
                         AND (effective_grant.tenant_boundary IS NULL OR effective_grant.tenant_boundary = candidate.tenant_id)
                         AND grant_scope_matches(
                               effective_grant.scope_kind, effective_grant.scope_ref, $3, $3,
                               candidate.id, candidate.tenant_id,
                               '{}'::uuid[], '{}'::uuid[])
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM grants effective_grant
                       WHERE effective_grant.capability_id = cap.id
                         AND effective_grant.effect = 'deny'
                         AND (effective_grant.tenant_boundary IS NULL OR effective_grant.tenant_boundary = candidate.tenant_id)
                         AND grant_scope_matches(
                               effective_grant.scope_kind, effective_grant.scope_ref, $3, $3,
                               candidate.id, candidate.tenant_id,
                               '{}'::uuid[], '{}'::uuid[])
                   )
                   AND ($4::uuid IS NULL OR EXISTS (
                       SELECT 1 FROM ceiling token_scope
                       WHERE token_scope.action_id = cap.id
                         AND (token_scope.tenant_id IS NULL OR token_scope.tenant_id = candidate.tenant_id)
                         AND grant_scope_matches(
                               token_scope.scope_kind, token_scope.scope_ref, $3, $3,
                               candidate.id, candidate.tenant_id,
                               '{}'::uuid[], '{}'::uuid[])
                   ))
               )
           ),
           totals AS (SELECT count(*)::bigint AS total FROM authorized),
           page AS (
               SELECT id FROM authorized ORDER BY ordinality LIMIT $6 OFFSET $7
           )
           SELECT page.id, totals.total
           FROM totals
           LEFT JOIN LATERAL (SELECT id FROM page) page ON TRUE"#.replace("__CANDIDATES__", candidate_sql).replace("__CEILING__", &crate::authz::sql::postgres::ceiling_cte("$4"));
    let rows = sqlx::query(&sql)
        .bind(subject_id)
        .bind(action_names)
        .bind(object_kind)
        .bind(ceiling_id)
        .bind(filters)
        .bind(limit.clamp(1, 100))
        .bind(offset.max(0))
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
    let total = rows
        .first()
        .map(|row| row.try_get::<i64, _>("total").map_err(db_err))
        .transpose()?
        .unwrap_or(0);
    let ids = rows
        .into_iter()
        .filter_map(|row| row.try_get::<Option<Uuid>, _>("id").ok().flatten())
        .collect();
    Ok(AuthorizedObjectIdsResponse { ids, total })
}

fn flat_candidate_sql(candidate: FlatCandidate) -> &'static str {
    match candidate {
        FlatCandidate::Endpoints => {
            r#"
    SELECT id, tenant_id,
           row_number() OVER (ORDER BY tenant_id NULLS FIRST, key, id) AS ordinality
    FROM api_endpoints
    WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
           OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
      AND (NULLIF($5->>'status', '') IS NULL OR status = ($5->>'status'))"#
        }
        FlatCandidate::Roles => {
            r#"SELECT id, tenant_id,
                  row_number() OVER (ORDER BY name, id) AS ordinality
           FROM roles
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
                  OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL
                  OR name ILIKE ($5->>'q') OR description ILIKE ($5->>'q'))
             AND (
               NULLIF($5->>'derived_kind', '') IS NULL
               OR ($5->>'derived_kind' = 'simple' AND EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
               OR ($5->>'derived_kind' = 'composite' AND FALSE)
               OR ($5->>'derived_kind' = 'empty' AND NOT EXISTS (
                    SELECT 1 FROM role_permission_blocks WHERE role_id = roles.id
                  ))
             )
             AND ($5->>'deleted' = 'all'
                  OR ($5->>'deleted' = 'live' AND deleted_at IS NULL)
                  OR ($5->>'deleted' = 'deleted' AND deleted_at IS NOT NULL))"#
        }
        FlatCandidate::Assignments => {
            r#"SELECT id, tenant_id,
                  row_number() OVER (ORDER BY created_at DESC, id) AS ordinality
           FROM role_assignments
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
                  OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'subject_kind', '') IS NULL
                  OR subject_kind = ($5->>'subject_kind'))
             AND (NULLIF($5->>'subject_id', '')::uuid IS NULL
                  OR subject_id = NULLIF($5->>'subject_id', '')::uuid)
             AND (NULLIF($5->>'role_id', '')::uuid IS NULL
                  OR role_id = NULLIF($5->>'role_id', '')::uuid)
             AND EXISTS (SELECT 1 FROM roles r WHERE r.id = role_assignments.role_id AND r.deleted_at IS NULL)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = role_assignments.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = role_assignments.subject_id AND sg.deleted_at IS NULL))
             )"#
        }
        FlatCandidate::RoleObjects => {
            r#"SELECT id, tenant_id,
               row_number() OVER (ORDER BY name, id) AS ordinality
           FROM roles
           WHERE deleted_at IS NULL
             AND (NULLIF($5->>'tenant_id', '')::uuid IS NULL OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL OR name ILIKE ($5->>'q') OR description ILIKE ($5->>'q'))
             AND (NULLIF($5->>'id', '') IS NULL OR id::text ILIKE ($5->>'id'))"#
        }
        FlatCandidate::PolicyObjects => {
            r#"SELECT id, tenant_id,
               row_number() OVER (ORDER BY created_at DESC, id) AS ordinality
           FROM (
               SELECT id, tenant_id, created_at FROM direct_policies
               UNION ALL
               SELECT id, tenant_id, created_at FROM role_assignments
           ) policies
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL OR id::text ILIKE ($5->>'q'))
             AND (NULLIF($5->>'id', '') IS NULL OR id::text ILIKE ($5->>'id'))"#
        }
        FlatCandidate::EndpointObjects => {
            r#"SELECT id, tenant_id,
               row_number() OVER (ORDER BY tenant_id NULLS FIRST, key, id) AS ordinality
           FROM api_endpoints
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'q', '') IS NULL OR name ILIKE ($5->>'q') OR key ILIKE ($5->>'q'))
             AND (NULLIF($5->>'id', '') IS NULL OR id::text ILIKE ($5->>'id'))"#
        }
        FlatCandidate::DirectPolicies => {
            r#"WITH RECURSIVE object_parent_groups(group_id, object_kind, object_type) AS (
             SELECT oge.group_id, 'entity'::text, 'entity:' || e.kind
             FROM object_group_entities oge
             JOIN entities e ON e.id = oge.entity_id
             WHERE oge.entity_id = NULLIF($5->>'object_id', '')::uuid AND e.deleted_at IS NULL
             UNION ALL
             SELECT ogr.group_id, 'resource'::text, 'resource:' || r.kind
             FROM object_group_resources ogr
             JOIN resources r ON r.id = ogr.resource_id
             WHERE ogr.resource_id = NULLIF($5->>'object_id', '')::uuid AND r.deleted_at IS NULL
             UNION ALL
             SELECT ogh.parent_id, 'group'::text, 'group:object'
             FROM object_group_hierarchy ogh
             JOIN object_groups og ON og.id = ogh.child_id
             WHERE ogh.child_id = NULLIF($5->>'object_id', '')::uuid AND og.deleted_at IS NULL
           ),
           object_ancestor_groups(group_id, object_kind, object_type) AS (
             SELECT ogh.parent_id, opg.object_kind, opg.object_type
             FROM object_parent_groups opg
             JOIN object_group_hierarchy ogh ON ogh.child_id = opg.group_id
             UNION ALL
             SELECT ogh.parent_id, oag.object_kind, oag.object_type
             FROM object_ancestor_groups oag
             JOIN object_group_hierarchy ogh ON ogh.child_id = oag.group_id
           )
           SELECT id, tenant_id,
                  row_number() OVER (ORDER BY created_at DESC, id) AS ordinality
           FROM direct_policies
           WHERE (NULLIF($5->>'tenant_id', '')::uuid IS NULL
                  OR tenant_id = NULLIF($5->>'tenant_id', '')::uuid)
             AND (NULLIF($5->>'subject_kind', '') IS NULL
                  OR subject_kind = ($5->>'subject_kind'))
             AND (NULLIF($5->>'subject_id', '')::uuid IS NULL
                  OR subject_id = NULLIF($5->>'subject_id', '')::uuid)
             AND (NULLIF($5->>'permission_block_id', '')::uuid IS NULL
                  OR permission_block_id = NULLIF($5->>'permission_block_id', '')::uuid)
             AND (
               (subject_kind = 'entity' AND EXISTS (SELECT 1 FROM entities se WHERE se.id = direct_policies.subject_id AND se.deleted_at IS NULL))
               OR (subject_kind = 'group' AND EXISTS (SELECT 1 FROM principal_groups sg WHERE sg.id = direct_policies.subject_id AND sg.deleted_at IS NULL))
             )
             AND (NULLIF($5->>'object_id', '')::uuid IS NULL OR EXISTS (
               SELECT 1 FROM permission_blocks pb
               WHERE pb.id = direct_policies.permission_block_id
                 AND (NULLIF($5->>'object_kind', '') IS NULL OR pb.object_kind IS NULL OR pb.object_kind = NULLIF($5->>'object_kind', ''))
                 AND (NULLIF($5->>'object_type', '') IS NULL OR pb.object_type IS NULL OR pb.object_type = NULLIF($5->>'object_type', ''))
                 AND (
                   (pb.scope_mode = 'object' AND pb.object_id = NULLIF($5->>'object_id', '')::uuid)
                   OR (pb.scope_mode = 'group'
                       AND pb.group_id = NULLIF($5->>'object_id', '')::uuid
                       AND (NULLIF($5->>'object_kind', '') IS NULL OR NULLIF($5->>'object_kind', '') = 'group')
                       AND (NULLIF($5->>'object_type', '') IS NULL OR NULLIF($5->>'object_type', '') = 'group:object')
                       AND EXISTS (
                         SELECT 1 FROM object_groups og
                         WHERE og.id = NULLIF($5->>'object_id', '')::uuid
                           AND og.deleted_at IS NULL))
                   OR (pb.scope_mode = 'group_direct_objects' AND EXISTS (
                         SELECT 1 FROM object_parent_groups opg
                         WHERE opg.group_id = pb.group_id
                           AND opg.object_kind = pb.object_kind
                           AND opg.object_type = pb.object_type))
                   OR (pb.scope_mode = 'group_descendant_objects' AND EXISTS (
                         SELECT 1 FROM object_ancestor_groups oag
                         WHERE oag.group_id = pb.group_id
                           AND oag.object_kind = pb.object_kind
                           AND oag.object_type = pb.object_type))
                   OR (pb.scope_mode = 'group_child_groups'
                       AND (NULLIF($5->>'object_kind', '') IS NULL OR NULLIF($5->>'object_kind', '') = 'group')
                       AND (NULLIF($5->>'object_type', '') IS NULL OR NULLIF($5->>'object_type', '') = 'group:object')
                       AND EXISTS (
                         SELECT 1 FROM object_parent_groups opg
                         WHERE opg.group_id = pb.group_id
                           AND opg.object_kind = 'group'))
                   OR (pb.scope_mode = 'group_descendant_groups'
                       AND (NULLIF($5->>'object_kind', '') IS NULL OR NULLIF($5->>'object_kind', '') = 'group')
                       AND (NULLIF($5->>'object_type', '') IS NULL OR NULLIF($5->>'object_type', '') = 'group:object')
                       AND (
                         EXISTS (
                           SELECT 1 FROM object_parent_groups opg
                           WHERE opg.group_id = pb.group_id
                             AND opg.object_kind = 'group')
                         OR EXISTS (
                           SELECT 1 FROM object_ancestor_groups oag
                           WHERE oag.group_id = pb.group_id
                             AND oag.object_kind = 'group')))
                 )
             ))"#
        }
    }
}

pub(super) async fn selected_endpoints(
    pool: &sqlx::PgPool,
    ids: &[Uuid],
) -> Result<Vec<ApiEndpoint>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT id, tenant_id, key, name, description, method, path,
                      operation_kind, graphql, auth_mode, service_entity_id,
                      variables_mapping, request_schema, response_mapping, status,
                      created_by, updated_by, created_at, updated_at
               FROM api_endpoints
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
    )
    .bind(ids)
    .fetch_all(pool)
    .await
}

pub(super) async fn selected_roles(
    pool: &sqlx::PgPool,
    ids: &[Uuid],
) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT id, name, tenant_id, description, deleted_at, deleted_by,
                      created_at, updated_at, managed_by
               FROM roles
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
    )
    .bind(ids)
    .fetch_all(pool)
    .await
}

pub(super) async fn selected_role_assignments(
    pool: &sqlx::PgPool,
    ids: &[Uuid],
) -> Result<Vec<RoleAssignment>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT id, tenant_id, subject_kind, subject_id, role_id, created_at, managed_by
               FROM role_assignments
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
    )
    .bind(ids)
    .fetch_all(pool)
    .await
}

pub(super) async fn selected_direct_policies(
    pool: &sqlx::PgPool,
    ids: &[Uuid],
) -> Result<Vec<DirectPolicy>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT id, tenant_id, subject_kind, subject_id, permission_block_id,
                      created_at, managed_by
               FROM direct_policies
               WHERE id = ANY($1::uuid[])
               ORDER BY array_position($1::uuid[], id)"#,
    )
    .bind(ids)
    .fetch_all(pool)
    .await
}
