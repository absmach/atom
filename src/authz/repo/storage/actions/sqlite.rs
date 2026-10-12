use super::*;

pub(super) async fn get_capability(
    pool: &sqlx::SqlitePool,
    id: Uuid,
) -> Result<Capability, AppError> {
    sqlx::query_as::<_, Capability>(
        r#"SELECT id, name, description, created_at, updated_at, managed_by FROM actions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("capability {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn capability_applicability(
    pool: &sqlx::SqlitePool,
    capability_id: Uuid,
) -> Result<Vec<CapabilityApplicability>, AppError> {
    sqlx::query_as::<_, CapabilityApplicability>(
        r#"SELECT object_kind, object_type, managed_by
           FROM action_applicability
           WHERE action_id = $1
           ORDER BY object_kind, object_type NULLS FIRST"#,
    )
    .bind(capability_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn list_capability_applicability(
    pool: &sqlx::SqlitePool,
    action_name: Option<String>,
    object_kind: Option<String>,
    object_type: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<CapabilityApplicabilityList, AppError> {
    let limit = limit.clamp(1, 100);
    let offset = offset.max(0);
    let action_name = action_name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let object_kind = object_kind
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let object_type = object_type
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let action_pattern = action_name.as_ref().map(|value| format!("%{value}%"));

    let items = sqlx::query_as::<_, CapabilityApplicabilityEntry>(
        r#"SELECT c.id AS capability_id,
                  c.name AS capability_name,
                  c.description,
                  ca.object_kind,
                  ca.object_type,
                  ca.created_at,
                  ca.managed_by
           FROM action_applicability ca
           JOIN actions c ON c.id = ca.action_id
           WHERE ($3 IS NULL OR c.name LIKE $3)
             AND ($4 IS NULL OR ca.object_kind = $4)
             AND ($5 IS NULL OR ca.object_type = $5)
           ORDER BY c.name, ca.object_kind, ca.object_type NULLS FIRST
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(&action_pattern)
    .bind(&object_kind)
    .bind(&object_type)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM action_applicability ca
           JOIN actions c ON c.id = ca.action_id
           WHERE ($1 IS NULL OR c.name LIKE $1)
             AND ($2 IS NULL OR ca.object_kind = $2)
             AND ($3 IS NULL OR ca.object_type = $3)"#,
    )
    .bind(&action_pattern)
    .bind(&object_kind)
    .bind(&object_type)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(CapabilityApplicabilityList { items, total })
}

pub(super) async fn get_action_assignment_rule(
    pool: &sqlx::SqlitePool,
    id: Uuid,
) -> Result<ActionAssignmentRule, AppError> {
    sqlx::query_as::<_, ActionAssignmentRule>(
        r#"SELECT id, tenant_id, entity_kind, action_name, object_kind, object_type,
                  decision, is_absolute, created_at, managed_by
           FROM action_assignment_rules
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::not_found(format!("action assignment rule {id} not found"))
        }
        other => AppError::Database(other),
    })
}

pub(super) async fn list_action_assignment_rules(
    pool: &sqlx::SqlitePool,
    params: ListActionAssignmentRules,
) -> Result<ActionAssignmentRuleList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let action_name = normalize_optional_text(params.action_name);
    let action_pattern = action_name.as_ref().map(|value| format!("%{value}%"));
    let object_type = normalize_optional_text(params.object_type);

    let items = sqlx::query_as::<_, ActionAssignmentRule>(
        r#"SELECT id, tenant_id, entity_kind, action_name, object_kind, object_type,
                  decision, is_absolute, created_at, managed_by
           FROM action_assignment_rules
           WHERE tenant_id IS NOT DISTINCT FROM $3
             AND ($4 IS NULL OR entity_kind = $4)
             AND ($5 IS NULL OR action_name LIKE $5)
             AND ($6 IS NULL OR object_kind = $6)
             AND ($7 IS NULL OR object_type = $7)
             AND ($8 IS NULL OR decision = $8)
           ORDER BY entity_kind, action_name, object_kind, object_type NULLS FIRST, decision
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(params.tenant_id)
    .bind(&params.entity_kind)
    .bind(&action_pattern)
    .bind(params.object_kind)
    .bind(&object_type)
    .bind(params.decision)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let total = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM action_assignment_rules
           WHERE tenant_id IS NOT DISTINCT FROM $1
             AND ($2 IS NULL OR entity_kind = $2)
             AND ($3 IS NULL OR action_name LIKE $3)
             AND ($4 IS NULL OR object_kind = $4)
             AND ($5 IS NULL OR object_type = $5)
             AND ($6 IS NULL OR decision = $6)"#,
    )
    .bind(params.tenant_id)
    .bind(&params.entity_kind)
    .bind(&action_pattern)
    .bind(params.object_kind)
    .bind(&object_type)
    .bind(params.decision)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(ActionAssignmentRuleList { items, total })
}

pub(super) async fn find_capability_ids_by_name(
    pool: &sqlx::SqlitePool,
    name: &str,
    object_kind: &str,
    object_type: &str,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT c.id
           FROM actions c
           JOIN action_applicability ca ON ca.action_id = c.id
           WHERE c.name = $1
             AND ca.object_kind = $2
             AND (ca.object_type IS NULL OR ca.object_type = $3)
           ORDER BY c.id"#,
    )
    .bind(name)
    .bind(object_kind)
    .bind(format!("{object_kind}:{object_type}"))
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn action_identities(
    conn: &mut sqlx::SqliteConnection,
    unique_capability_ids: &[Uuid],
) -> Result<Vec<ActionIdentity>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT id, name FROM actions WHERE id IN (SELECT unhex(value) FROM json_each($1))"#,
    )
    .bind(crate::db::native::uuid_array_json(unique_capability_ids))
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn inapplicable_actions(
    conn: &mut sqlx::SqliteConnection,
    unique_capability_ids: &[Uuid],
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT c.name
           FROM actions c
           WHERE c.id IN (SELECT unhex(value) FROM json_each($1))
             AND NOT EXISTS (
               SELECT 1
               FROM action_applicability ca
               WHERE ca.action_id = c.id
                 AND ca.object_kind = $2
                 AND ($3 IS NULL OR ca.object_type IS NULL OR ca.object_type = $3)
             )
           ORDER BY c.name"#,
    )
    .bind(crate::db::native::uuid_array_json(unique_capability_ids))
    .bind(object_kind)
    .bind(object_type)
    .fetch_all(&mut *conn)
    .await
}

pub(super) async fn insert_action(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
    name: &str,
    description: &Option<String>,
) -> Result<Capability, sqlx::Error> {
    sqlx::query_as(
        r#"INSERT INTO actions (id, name, description)
           VALUES ($1, $2, $3)
           RETURNING id, name, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn assignment_rule_exists(
    pool: &sqlx::SqlitePool,
    tenant_id: &Option<Uuid>,
    entity_kind: &EntityKind,
    action_name: &str,
    object_kind: &ObjectKind,
    object_type: &Option<String>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
             SELECT 1
             FROM action_assignment_rules
             WHERE tenant_id IS NOT DISTINCT FROM $1
               AND entity_kind = $2
               AND action_name = $3
               AND object_kind = $4
               AND object_type IS NOT DISTINCT FROM $5
           )"#,
    )
    .bind(tenant_id)
    .bind(entity_kind)
    .bind(action_name)
    .bind(object_kind)
    .bind(object_type)
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_assignment_rule(
    conn: &mut sqlx::SqliteConnection,
    tenant_id: &Option<Uuid>,
    entity_kind: &EntityKind,
    action_name: &str,
    object_kind: &ObjectKind,
    object_type: &Option<String>,
    decision: &ActionAssignmentDecision,
    is_absolute: &bool,
) -> Result<ActionAssignmentRule, sqlx::Error> {
    sqlx::query_as(
        r#"INSERT INTO action_assignment_rules
             (tenant_id, entity_kind, action_name, object_kind, object_type, decision, is_absolute)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, tenant_id, entity_kind, action_name, object_kind, object_type,
                     decision, is_absolute, created_at"#,
    )
    .bind(tenant_id)
    .bind(entity_kind)
    .bind(action_name)
    .bind(object_kind)
    .bind(object_type)
    .bind(decision)
    .bind(is_absolute)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn action_exists_by_name(
    conn: &mut sqlx::SqliteConnection,
    action_name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT EXISTS (SELECT 1 FROM actions WHERE name = $1)"#)
        .bind(action_name)
        .fetch_one(&mut *conn)
        .await
}

pub(super) async fn assignment_rule_tenant_optional(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM action_assignment_rules WHERE id = $1"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn remove_assignment_rule(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<ActionAssignmentRule, sqlx::Error> {
    sqlx::query_as(
        r#"DELETE FROM action_assignment_rules
           WHERE id = $1
           RETURNING id, tenant_id, entity_kind, action_name, object_kind, object_type,
                     decision, is_absolute, created_at"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn lock_action_optional(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT id FROM actions WHERE id = $1"#)
        .bind(capability_id)
        .fetch_optional(&mut *conn)
        .await
}

pub(super) async fn applicability_ownership_optional(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<&str>,
) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT managed_by FROM action_applicability
           WHERE action_id = $1
             AND object_kind = $2
             AND object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(capability_id)
    .bind(object_kind)
    .bind(object_type)
    .fetch_optional(&mut *conn)
    .await
}

pub(super) async fn action_exists(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT EXISTS (SELECT 1 FROM actions WHERE id = $1)"#)
        .bind(capability_id)
        .fetch_one(&mut *conn)
        .await
}

pub(super) async fn insert_applicability(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO action_applicability (action_id, object_kind, object_type)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(capability_id)
    .bind(object_kind)
    .bind(object_type)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn applicability_entry(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<CapabilityApplicabilityEntry, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT c.id AS capability_id,
                  c.name AS capability_name,
                  c.description,
                  ca.object_kind,
                  ca.object_type,
                  ca.created_at,
                  ca.managed_by
           FROM action_applicability ca
           JOIN actions c ON c.id = ca.action_id
           WHERE ca.action_id = $1
             AND ca.object_kind = $2
             AND ca.object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(capability_id)
    .bind(object_kind)
    .bind(object_type)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn remove_applicability(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
    object_kind: &str,
    object_type: &Option<String>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"DELETE FROM action_applicability
           WHERE action_id = $1
             AND object_kind = $2
             AND object_type IS NOT DISTINCT FROM $3"#,
    )
    .bind(capability_id)
    .bind(object_kind)
    .bind(object_type)
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) async fn update_action_fields(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
    name: &Option<String>,
    description: &Option<String>,
) -> Result<Capability, sqlx::Error> {
    sqlx::query_as(
        r#"UPDATE actions
           SET name          = COALESCE($2, name),
               description   = COALESCE($3, description),
               updated_at    = now()
           WHERE id = $1
           RETURNING id, name, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn action_has_config_applicability(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM action_applicability
                        WHERE action_id = $1 AND managed_by = 'config')"#,
    )
    .bind(capability_id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn clear_applicability(
    conn: &mut sqlx::SqliteConnection,
    capability_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM action_applicability WHERE action_id = $1"#)
        .bind(capability_id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn action_has_config_links(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1
               FROM permission_block_actions pba
               JOIN permission_blocks pb ON pb.id = pba.permission_block_id
               WHERE pba.action_id = $1 AND pb.managed_by = 'config'
           )"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
}

pub(super) async fn remove_action(
    conn: &mut sqlx::SqliteConnection,
    id: &Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(r#"DELETE FROM actions WHERE id = $1"#)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
}

pub(super) async fn action_by_name_optional(
    pool: &sqlx::SqlitePool,
    action_name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(r#"SELECT id FROM actions WHERE name = $1"#)
        .bind(action_name)
        .fetch_optional(pool)
        .await
}
