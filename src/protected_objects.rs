use crate::db::Database;
use crate::db::DbExecutor;
use anyhow::Result;
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

// SQLite has no LATERAL. Each source table is probed by the requested id inside
// its own UNION branch, then joined back to the registry row by table name.
const SQLITE_LOOKUP_SQL: &str = r#"
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

fn lookup_query(id: Uuid) -> crate::db::QueryAs<ProtectedObjectIdentity> {
    crate::db::query_as::<ProtectedObjectIdentity>(LOOKUP_SQL)
        .sqlite(SQLITE_LOOKUP_SQL)
        .bind(id)
}

pub async fn lookup(
    pool: &Database,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError> {
    lookup_query(id).fetch_optional(pool).await.map_err(db_err)
}

pub async fn lookup_on_connection(
    connection: &mut impl DbExecutor,
    id: Uuid,
) -> Result<Option<ProtectedObjectIdentity>, AppError> {
    lookup_query(id)
        .fetch_optional(connection)
        .await
        .map_err(db_err)
}
