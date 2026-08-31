use anyhow::{bail, Context, Result};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::error::{db_err, AppError};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProtectedObjectIdentity {
    pub id: Uuid,
    pub object_kind: String,
    pub source_table: String,
    pub tenant_id: Option<Uuid>,
    pub object_type: Option<String>,
    pub live: bool,
}

const LOOKUP_SQL: &str = r#"
SELECT registry.id, registry.object_kind, registry.source_table,
       object.tenant_id, object.object_type, object.live
FROM protected_object_ids registry
JOIN LATERAL (
    SELECT e.tenant_id, ('entity:' || e.kind)::text AS object_type,
           e.deleted_at IS NULL AS live
    FROM entities e WHERE registry.source_table = 'entities' AND e.id = registry.id
    UNION ALL
    SELECT r.tenant_id, ('resource:' || r.kind)::text, r.deleted_at IS NULL
    FROM resources r WHERE registry.source_table = 'resources' AND r.id = registry.id
    UNION ALL
    SELECT g.tenant_id, NULL::text, g.deleted_at IS NULL
    FROM principal_groups g WHERE registry.source_table = 'principal_groups' AND g.id = registry.id
    UNION ALL
    SELECT g.tenant_id, NULL::text, g.deleted_at IS NULL
    FROM object_groups g WHERE registry.source_table = 'object_groups' AND g.id = registry.id
    UNION ALL
    SELECT t.id, NULL::text, t.deleted_at IS NULL
    FROM tenants t WHERE registry.source_table = 'tenants' AND t.id = registry.id
    UNION ALL
    SELECT r.tenant_id, NULL::text, r.deleted_at IS NULL
    FROM roles r WHERE registry.source_table = 'roles' AND r.id = registry.id
    UNION ALL
    SELECT e.tenant_id, NULL::text, TRUE
    FROM credentials c JOIN entities e ON e.id = c.entity_id
    WHERE registry.source_table = 'credentials' AND c.id = registry.id
    UNION ALL
    SELECT p.tenant_id, NULL::text, TRUE
    FROM direct_policies p
    WHERE registry.source_table = 'direct_policies' AND p.id = registry.id
    UNION ALL
    SELECT p.tenant_id, NULL::text, TRUE
    FROM role_assignments p
    WHERE registry.source_table = 'role_assignments' AND p.id = registry.id
    UNION ALL
    SELECT a.tenant_id, NULL::text, TRUE
    FROM api_endpoints a
    WHERE registry.source_table = 'api_endpoints' AND a.id = registry.id
) object ON TRUE
WHERE registry.id = $1
"#;

pub async fn lookup(pool: &PgPool, id: Uuid) -> Result<Option<ProtectedObjectIdentity>, AppError> {
    sqlx::query_as::<_, ProtectedObjectIdentity>(LOOKUP_SQL)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

pub async fn lookup_on_connection(
    connection: &mut PgConnection,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError> {
    sqlx::query_as::<_, ProtectedObjectIdentity>(LOOKUP_SQL)
        .bind(id)
        .fetch_optional(connection)
        .await
        .map_err(db_err)
}

/// Read-only startup preflight for databases that have not applied migration
/// 026 yet. The migration repeats this check while holding table locks.
pub async fn preflight_global_protected_object_ids(pool: &PgPool) -> Result<()> {
    let ready: bool = sqlx::query_scalar(
        r#"SELECT to_regclass('public._sqlx_migrations') IS NOT NULL
                  AND to_regclass('public.tenants') IS NOT NULL
                  AND to_regclass('public.entities') IS NOT NULL
                  AND to_regclass('public.resources') IS NOT NULL
                  AND to_regclass('public.principal_groups') IS NOT NULL
                  AND to_regclass('public.object_groups') IS NOT NULL
                  AND to_regclass('public.roles') IS NOT NULL
                  AND to_regclass('public.credentials') IS NOT NULL
                  AND to_regclass('public.direct_policies') IS NOT NULL
                  AND to_regclass('public.role_assignments') IS NOT NULL
                  AND to_regclass('public.api_endpoints') IS NOT NULL
                  AND to_regclass('public.permission_blocks') IS NOT NULL
                  AND to_regclass('public.credential_permission_limits') IS NOT NULL"#,
    )
    .fetch_one(pool)
    .await
    .context("failed to inspect protected-object tables before migration 026")?;
    if !ready {
        return Ok(());
    }

    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 26 AND success)",
    )
    .fetch_one(pool)
    .await
    .context("failed to inspect migration 026 state")?;
    if applied {
        return Ok(());
    }

    let invalid_seed_scopes: Option<String> = sqlx::query_scalar(
        r#"WITH seeded_assignment AS (
               SELECT id
               FROM role_assignments
               WHERE id = '00000000-0000-0000-0000-000000000001'
                 AND tenant_id IS NULL
                 AND subject_kind = 'entity'
                 AND subject_id = '00000000-0000-0000-0000-000000000001'
                 AND role_id = '00000000-0000-0000-0000-000000000002'
           ), invalid AS (
               SELECT 'permission_blocks'::text AS source_table, block.id, block.object_kind
               FROM permission_blocks block
               JOIN seeded_assignment assignment ON assignment.id = block.object_id
               WHERE block.scope_mode = 'object'
                 AND (block.object_kind IS NULL OR block.object_kind NOT IN ('entity', 'policy'))

               UNION ALL

               SELECT 'credential_permission_limits', ceiling.id, ceiling.object_kind
               FROM credential_permission_limits ceiling
               JOIN seeded_assignment assignment ON assignment.id = ceiling.object_id
               WHERE ceiling.scope_mode = 'object'
                 AND (ceiling.object_kind IS NULL OR ceiling.object_kind NOT IN ('entity', 'policy'))
           )
           SELECT string_agg(
                      format('%s[%s, object_kind=%s]', source_table, id,
                             COALESCE(object_kind, 'NULL')),
                      '; ' ORDER BY source_table, id
                  )
           FROM invalid"#,
    )
    .fetch_one(pool)
    .await
    .context("failed to inspect legacy exact-object references")?;
    if let Some(invalid_seed_scopes) = invalid_seed_scopes {
        bail!(
            "v1 upgrade blocked by unclassified exact-object references targeting legacy UUID \
             00000000-0000-0000-0000-000000000001: {invalid_seed_scopes}. Set each reported \
             permission_blocks.object_kind or credential_permission_limits.object_kind to entity \
             or policy and rerun the readiness check"
        );
    }

    let rows = sqlx::query(
        r#"WITH protected_rows(id, source_table, object_kind) AS (
               SELECT id, 'tenants', 'tenant' FROM tenants
               UNION ALL SELECT id, 'entities', 'entity' FROM entities
               UNION ALL SELECT id, 'resources', 'resource' FROM resources
               UNION ALL SELECT id, 'principal_groups', 'group' FROM principal_groups
               UNION ALL SELECT id, 'object_groups', 'group' FROM object_groups
               UNION ALL SELECT id, 'roles', 'role' FROM roles
               UNION ALL SELECT id, 'credentials', 'credential' FROM credentials
               UNION ALL SELECT id, 'direct_policies', 'policy' FROM direct_policies
               UNION ALL
               SELECT CASE
                          WHEN id = '00000000-0000-0000-0000-000000000001'
                           AND tenant_id IS NULL
                           AND subject_kind = 'entity'
                           AND subject_id = '00000000-0000-0000-0000-000000000001'
                           AND role_id = '00000000-0000-0000-0000-000000000002'
                          THEN '00000000-0000-0000-0000-00000000000a'::uuid
                          ELSE id
                      END,
                      'role_assignments', 'policy'
               FROM role_assignments
               UNION ALL SELECT id, 'api_endpoints', 'api_endpoint' FROM api_endpoints
           )
           SELECT id,
                  array_agg(source_table || ':' || object_kind ORDER BY source_table) AS sources
           FROM protected_rows
           GROUP BY id
           HAVING count(*) > 1
           ORDER BY id"#,
    )
    .fetch_all(pool)
    .await
    .context("failed to inspect legacy protected-object UUIDs")?;
    if rows.is_empty() {
        return Ok(());
    }

    let collisions = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.try_get("id")?;
            let sources: Vec<String> = row.try_get("sources")?;
            Ok(format!("{id} => {}", sources.join(", ")))
        })
        .collect::<std::result::Result<Vec<_>, sqlx::Error>>()?
        .join("; ");
    bail!(
        "v1 upgrade blocked by global protected-object UUID collisions: {collisions}. Assign distinct UUIDs to the reported rows and rerun the readiness check"
    )
}
