//! Native sqlite protected-object registry lookup.
use super::ProtectedObjectIdentity;
use crate::error::{db_err, AppError};
use uuid::Uuid;

const LOOKUP_SQL: &str = r#"
SELECT registry.id, registry.object_kind, registry.source_table,
       object.tenant_id, object.object_type, object.live
FROM protected_object_ids registry
JOIN (
    SELECT 'entities' AS source_table, e.id AS id, e.tenant_id AS tenant_id,
           ('entity:' || e.kind) AS object_type, (e.deleted_at IS NULL) AS live
    FROM entities e WHERE e.id = $1
    UNION ALL
    SELECT 'resources', r.id, r.tenant_id, ('resource:' || r.kind), (r.deleted_at IS NULL)
    FROM resources r WHERE r.id = $1
    UNION ALL
    SELECT 'principal_groups', g.id, g.tenant_id, NULL, (g.deleted_at IS NULL)
    FROM principal_groups g WHERE g.id = $1
    UNION ALL
    SELECT 'object_groups', g.id, g.tenant_id, NULL, (g.deleted_at IS NULL)
    FROM object_groups g WHERE g.id = $1
    UNION ALL
    SELECT 'tenants', t.id, t.id, NULL, (t.deleted_at IS NULL)
    FROM tenants t WHERE t.id = $1
    UNION ALL
    SELECT 'roles', r.id, r.tenant_id, NULL, (r.deleted_at IS NULL)
    FROM roles r WHERE r.id = $1
    UNION ALL
    SELECT 'credentials', c.id, e.tenant_id, NULL, 1
    FROM credentials c JOIN entities e ON e.id = c.entity_id WHERE c.id = $1
    UNION ALL
    SELECT 'direct_policies', p.id, p.tenant_id, NULL, 1
    FROM direct_policies p WHERE p.id = $1
    UNION ALL
    SELECT 'role_assignments', p.id, p.tenant_id, NULL, 1
    FROM role_assignments p WHERE p.id = $1
    UNION ALL
    SELECT 'api_endpoints', a.id, a.tenant_id, NULL, 1
    FROM api_endpoints a WHERE a.id = $1
) object ON object.source_table = registry.source_table AND object.id = registry.id
WHERE registry.id = $1
"#;

pub(super) async fn lookup<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query_as::<_, ProtectedObjectIdentity>(LOOKUP_SQL)
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(db_err)
}
