use anyhow::Result;
use sqlx::{PgConnection, PgPool};
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
