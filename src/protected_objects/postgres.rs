//! Native postgres protected-object registry lookup.
use super::ProtectedObjectIdentity;
use crate::error::{db_err, AppError};
use uuid::Uuid;

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

// SQLite has no LATERAL. Each source table is probed by the requested id inside
// its own UNION branch, then joined back to the registry row by table name.

pub(super) async fn lookup<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, ProtectedObjectIdentity>(LOOKUP_SQL)
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(db_err)
}
