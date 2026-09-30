use super::*;

pub(super) async fn fetch_entity<'e, E: sqlx::Executor<'e, Database = sqlx::Sqlite>>(
    executor: E,
    id: Uuid,
) -> Result<Entity, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, alias, external_id, tenant_id, profile_id, profile_version_id,
                  status, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by, revision
           FROM entities
           WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .fetch_one(executor)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn list_entities_by_ids(
    pool: &sqlx::SqlitePool,
    ids: &[Uuid],
) -> Result<Vec<Entity>, AppError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query_as::<_, Entity>(
        r#"SELECT id, kind, name, alias, external_id, tenant_id, profile_id, profile_version_id,
                  status, attributes, deleted_at, deleted_by, created_at, updated_at, managed_by, revision
           FROM entities
           WHERE id IN (SELECT unhex(value) FROM json_each($1)) AND deleted_at IS NULL
           ORDER BY NULLIF(instr($1, lower(hex(id))), 0)"#,
    )
    .bind(crate::db::native::uuid_array_json(ids))
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn entity_active_session_ids(
    pool: &sqlx::SqlitePool,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(r#"SELECT id FROM sessions WHERE entity_id = $1 AND revoked_at IS NULL"#)
        .bind(entity_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)
}

pub(super) async fn entity_active_access_token_ids(
    pool: &sqlx::SqlitePool,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM credentials WHERE entity_id = $1 AND status = 'active' AND kind = $2"#,
    )
    .bind(entity_id)
    .bind(crate::models::enums::CredentialKind::AccessToken)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn get_session(pool: &sqlx::SqlitePool, id: Uuid) -> Result<Session, AppError> {
    sqlx::query_as::<_, Session>(
        r#"SELECT id, entity_id, expires_at, revoked_at, created_at FROM sessions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("session {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn revoke_session_in_tx(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r#"UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found(format!(
            "session {id} not found or already revoked"
        )));
    }
    Ok(())
}

pub(super) async fn add_authenticated_user_membership_in_tx(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO principal_group_members (group_id, entity_id)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(AUTHENTICATED_USERS_GROUP_ID)
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn insert_session(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    entity_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<Session, AppError> {
    sqlx::query_as::<_, Session>(
        r#"INSERT INTO sessions (id, entity_id, expires_at)
           VALUES ($1, $2, $3)
           RETURNING id, entity_id, expires_at, revoked_at, created_at"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(expires_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn extend_session(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    entity_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<Session, AppError> {
    sqlx::query_as::<_, Session>(
        r#"UPDATE sessions
           SET expires_at = max(expires_at, $3)
           WHERE id = $1
             AND entity_id = $2
             AND revoked_at IS NULL
             AND expires_at > now()
           RETURNING id, entity_id, expires_at, revoked_at, created_at"#,
    )
    .bind(id)
    .bind(entity_id)
    .bind(expires_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| AppError::unauthorized("session is not refreshable"))
}

pub(super) async fn active_entity_tenant(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(
        r#"SELECT tenant_id
           FROM entities
           WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_active_entity(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Option<(EntityKind, Option<Uuid>)>, AppError> {
    sqlx::query_as(
        r#"SELECT kind, tenant_id
           FROM entities
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status = 'active'
             AND deleted_at IS NULL"#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn insert_entity(
    conn: &mut sqlx::SqliteConnection,
    entity: NewEntity,
) -> Result<Entity, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"INSERT INTO entities
           (id, kind, name, alias, external_id, tenant_id, profile_id, profile_version_id,
            attributes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id, kind, name, alias, external_id, tenant_id, profile_id,
                     profile_version_id, status, attributes, deleted_at, deleted_by,
                     created_at, updated_at, managed_by, revision"#,
    )
    .bind(entity.id)
    .bind(entity.kind)
    .bind(entity.name)
    .bind(entity.alias)
    .bind(entity.external_id)
    .bind(entity.tenant_id)
    .bind(entity.profile_id)
    .bind(entity.profile_version_id)
    .bind(entity.attributes.to_string())
    .fetch_one(&mut *conn)
    .await
    .map_err(entity_write_conflict)
}

fn entity_order_by(order: EntityOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (EntityOrderField::CreatedAt, SortDir::Asc) => "e.created_at ASC, e.id ASC",
        (EntityOrderField::CreatedAt, SortDir::Desc) => "e.created_at DESC, e.id ASC",
        (EntityOrderField::UpdatedAt, SortDir::Asc) => "e.updated_at ASC NULLS LAST, e.id ASC",
        (EntityOrderField::UpdatedAt, SortDir::Desc) => "e.updated_at DESC NULLS LAST, e.id ASC",
        (EntityOrderField::Name, SortDir::Asc) => "lower(e.name) ASC, e.id ASC",
        (EntityOrderField::Name, SortDir::Desc) => "lower(e.name) DESC, e.id ASC",
        (EntityOrderField::Username, SortDir::Asc) => "lower(e.name) ASC, e.id ASC",
        (EntityOrderField::Username, SortDir::Desc) => "lower(e.name) DESC, e.id ASC",
        (EntityOrderField::FirstName, SortDir::Asc) => {
            "lower(COALESCE(e.attributes->>'first_name', '')) ASC, e.id ASC"
        }
        (EntityOrderField::FirstName, SortDir::Desc) => {
            "lower(COALESCE(e.attributes->>'first_name', '')) DESC, e.id ASC"
        }
        (EntityOrderField::LastName, SortDir::Asc) => {
            "lower(COALESCE(e.attributes->>'last_name', '')) ASC, e.id ASC"
        }
        (EntityOrderField::LastName, SortDir::Desc) => {
            "lower(COALESCE(e.attributes->>'last_name', '')) DESC, e.id ASC"
        }
        (EntityOrderField::Email, SortDir::Asc) => {
            "lower(COALESCE(e.attributes->>'email', '')) ASC, e.id ASC"
        }
        (EntityOrderField::Email, SortDir::Desc) => {
            "lower(COALESCE(e.attributes->>'email', '')) DESC, e.id ASC"
        }
        (EntityOrderField::Kind, SortDir::Asc) => "e.kind ASC, e.id ASC",
        (EntityOrderField::Kind, SortDir::Desc) => "e.kind DESC, e.id ASC",
        (EntityOrderField::Status, SortDir::Asc) => "e.status ASC, e.id ASC",
        (EntityOrderField::Status, SortDir::Desc) => "e.status DESC, e.id ASC",
    }
}

pub(super) async fn list_entities(
    pool: &sqlx::SqlitePool,
    params: ListEntities,
) -> Result<EntityList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let kind = params.kind;
    let profile_id = params.profile_id;
    let tenant_id = params.tenant_id;
    let status = params.status;
    let parent_group_id = params.parent_group_id;
    let include_descendants = params.include_descendants;
    let deleted = params.deleted.as_str();
    let id = search_pattern(params.id);
    let q = search_pattern(params.q);
    let external_id = crate::models::external_id::normalize_external_id(params.external_id);
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = entity_order_by(params.order, params.dir);
    // Native predicate selection exposes exact matches and the live-row
    // predicate to SQLite's planner, so the partial external-id index is
    // usable. Keep every bind slot present in both query variants.
    let (external_id_predicate, external_id_count_predicate) = if external_id.is_some() {
        ("e.external_id = $12", "e.external_id = $10")
    } else {
        ("$12 IS NULL", "$10 IS NULL")
    };
    let (deleted_predicate, deleted_count_predicate) = match params.deleted {
        crate::models::enums::DeletedFilter::Live => (
            "e.deleted_at IS NULL AND $10 = 'live'",
            "e.deleted_at IS NULL AND $8 = 'live'",
        ),
        crate::models::enums::DeletedFilter::Deleted => (
            "e.deleted_at IS NOT NULL AND $10 = 'deleted'",
            "e.deleted_at IS NOT NULL AND $8 = 'deleted'",
        ),
        crate::models::enums::DeletedFilter::All => ("$10 = 'all'", "$8 = 'all'"),
    };

    let items_sql = format!(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $6 WHERE $6 IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $7
           )
           SELECT e.id, e.kind, e.name, e.alias, e.external_id, e.tenant_id, e.profile_id,
                  e.profile_version_id, e.status, e.attributes, e.deleted_at, e.deleted_by,
                  e.created_at, e.updated_at, e.managed_by, e.revision
           FROM entities e
           WHERE ($1 IS NULL OR e.kind = $1)
             AND ($2 IS NULL OR e.profile_id = $2)
             AND ($3 IS NULL OR e.tenant_id = $3)
             AND ($4 IS NULL OR e.status = $4)
             AND ($5 IS NULL OR e.name LIKE $5 OR e.alias LIKE $5 OR atom_text(e.attributes) LIKE $5)
             AND ($6 IS NULL OR EXISTS (
                     SELECT 1 FROM group_entity_parents gep
                     WHERE gep.entity_id = e.id
                       AND gep.group_id IN (SELECT id FROM target_groups)))
             AND ($11 IS NULL OR atom_json_contains(e.attributes, $11))
             AND ({deleted_predicate})
             AND ({external_id_predicate})
             AND ($13 IS NULL OR atom_text(e.id) LIKE $13)
           ORDER BY {order_by}
           LIMIT $8 OFFSET $9"#,
    );
    let items = sqlx::query_as::<_, Entity>(&items_sql)
        .bind(kind.clone())
        .bind(profile_id)
        .bind(tenant_id)
        .bind(status.clone())
        .bind(q.clone())
        .bind(parent_group_id)
        .bind(include_descendants)
        .bind(limit)
        .bind(offset)
        .bind(deleted)
        .bind(attributes_contains.as_ref().map(Value::to_string))
        .bind(external_id.clone())
        .bind(id.clone())
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    let total_sql = format!(
        r#"WITH RECURSIVE target_groups(id) AS (
               SELECT $6 WHERE $6 IS NOT NULL
               UNION ALL
               SELECT gh.child_id
               FROM group_hierarchy gh
               JOIN target_groups tg ON tg.id = gh.parent_id
               WHERE $7
           )
           SELECT COUNT(*)
           FROM entities e
           WHERE ($1 IS NULL OR e.kind = $1)
             AND ($2 IS NULL OR e.profile_id = $2)
             AND ($3 IS NULL OR e.tenant_id = $3)
             AND ($4 IS NULL OR e.status = $4)
             AND ($5 IS NULL OR e.name LIKE $5 OR e.alias LIKE $5 OR atom_text(e.attributes) LIKE $5)
             AND ($6 IS NULL OR EXISTS (
                     SELECT 1 FROM group_entity_parents gep
                     WHERE gep.entity_id = e.id
                       AND gep.group_id IN (SELECT id FROM target_groups)))
             AND ($9 IS NULL OR atom_json_contains(e.attributes, $9))
             AND ({deleted_count_predicate})
             AND ({external_id_count_predicate})
             AND ($11 IS NULL OR atom_text(e.id) LIKE $11)"#,
    );
    let total: i64 = sqlx::query_scalar(&total_sql)
        .bind(kind)
        .bind(profile_id)
        .bind(tenant_id)
        .bind(status)
        .bind(q)
        .bind(parent_group_id)
        .bind(include_descendants)
        .bind(deleted)
        .bind(attributes_contains.map(|v| v.to_string()))
        .bind(external_id)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    Ok(EntityList { items, total })
}

pub(super) async fn entity_tenant(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar("SELECT tenant_id FROM entities WHERE id = $1 AND deleted_at IS NULL")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn lock_entity_update(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    current_tenant_id: Option<Uuid>,
) -> Result<Option<LockedEntityUpdate>, AppError> {
    sqlx::query_as::<_, LockedEntityUpdate>(
        r#"SELECT kind, name, profile_id, profile_version_id, attributes FROM entities
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL"#,
    )
    .bind(id)
    .bind(current_tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn name_is_in_use(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    name: &str,
) -> Result<bool, AppError> {
    let name_in_use: bool = sqlx::query_scalar(
        "SELECT EXISTS (
                    SELECT 1 FROM entities
                    WHERE id <> $1 AND name = $2 AND deleted_at IS NULL
                )",
    )
    .bind(id)
    .bind(name)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?;

    Ok(name_in_use)
}

pub(super) async fn update_entity(
    conn: &mut sqlx::SqliteConnection,
    changes: EntityChanges,
) -> Result<Entity, AppError> {
    let EntityChanges {
        id,
        request: req,
        attributes,
        alias_is_set,
        alias,
        external_id_is_set,
        external_id,
    } = changes;
    // SQLite's revision trigger runs AFTER UPDATE, so RETURNING must receive
    // the increment explicitly. The trigger recognizes this value and does
    // not increment it again.
    sqlx::query_as::<_, Entity>(
        r#"UPDATE entities
           SET name               = COALESCE($2, name),
               kind               = COALESCE($3, kind),
               tenant_id          = COALESCE($4, tenant_id),
               profile_id         = COALESCE($5, profile_id),
               profile_version_id = COALESCE($6, profile_version_id),
               status             = COALESCE($7, status),
               attributes         = COALESCE($8, attributes),
               alias              = CASE WHEN $9 THEN $10 ELSE alias END,
               external_id        = CASE WHEN $11 THEN $12 ELSE external_id END,
               revision = revision + 1,
               updated_at         = now()
           WHERE id = $1 AND deleted_at IS NULL
           RETURNING id, kind, name, alias, external_id, tenant_id, profile_id,
                     profile_version_id, status, attributes, deleted_at, deleted_by,
                     created_at, updated_at, managed_by, revision"#,
    )
    .bind(id)
    .bind(req.name)
    .bind(req.kind)
    .bind(req.tenant_id)
    .bind(req.profile_id)
    .bind(req.profile_version_id)
    .bind(req.status)
    .bind(attributes.map(|v| v.to_string()))
    .bind(alias_is_set)
    .bind(alias)
    .bind(external_id_is_set)
    .bind(external_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("entity {id} not found")),
        other => entity_write_conflict(other),
    })
}

pub(super) async fn lock_entity_group(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    group_id: Uuid,
    entity_tenant_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, Option<Uuid>)>, AppError> {
    sqlx::query_as::<_, (Option<Uuid>, Option<Uuid>)>(
        r#"SELECT e.tenant_id AS entity_tenant_id, g.tenant_id AS group_tenant_id
           FROM entities e
           CROSS JOIN object_groups g
           WHERE e.id = $1 AND g.id = $2
             AND e.tenant_id IS NOT DISTINCT FROM $3
             AND e.deleted_at IS NULL
             AND g.deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .bind(group_id)
    .bind(entity_tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn insert_entity_group(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
    entity_id: Uuid,
    tenant_id: Uuid,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        r#"INSERT INTO object_group_entities (group_id, entity_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (group_id, entity_id) DO NOTHING"#,
    )
    .bind(group_id)
    .bind(entity_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}

pub(super) async fn lock_entity(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM entities
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn entity_membership_owners(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT group_id FROM object_group_entities
           WHERE entity_id = $1 AND ($2 IS NULL OR group_id = $2)
           ORDER BY group_id"#,
    )
    .bind(entity_id)
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn remove_entity_memberships(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    group_id: Option<Uuid>,
) -> Result<u64, AppError> {
    let deleted = sqlx::query(
        r#"DELETE FROM object_group_entities
           WHERE entity_id = $1 AND ($2 IS NULL OR group_id = $2)"#,
    )
    .bind(entity_id)
    .bind(group_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?
    .rows_affected();
    Ok(deleted)
}

pub(super) async fn lock_profile(
    conn: &mut sqlx::SqliteConnection,
    profile_id: Uuid,
) -> Result<Option<(String, String, String)>, AppError> {
    sqlx::query_as(
        r#"SELECT object_kind, kind, status
           FROM profiles
           WHERE id = $1"#,
    )
    .bind(profile_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_latest_profile_version(
    conn: &mut sqlx::SqliteConnection,
    profile_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id
               FROM profile_versions
               WHERE profile_id = $1 AND status = 'active'
               ORDER BY version DESC
               LIMIT 1"#,
    )
    .bind(profile_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_profile_version(
    conn: &mut sqlx::SqliteConnection,
    profile_version_id: Uuid,
) -> Result<Option<(Uuid, Value)>, AppError> {
    sqlx::query_as(
        r#"SELECT profile_id, json_schema
           FROM profile_versions
           WHERE id = $1"#,
    )
    .bind(profile_version_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn deactivate_entity_email_in_tx(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE email_verification_tokens
         SET consumed_at = now()
         WHERE email_id IN (SELECT id FROM entity_emails WHERE entity_id = $1)
           AND consumed_at IS NULL",
    )
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "UPDATE password_reset_tokens
         SET consumed_at = now()
         WHERE email_id IN (SELECT id FROM entity_emails WHERE entity_id = $1)
           AND consumed_at IS NULL",
    )
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "UPDATE entity_emails SET deleted_at = now(), updated_at = now()
         WHERE entity_id = $1 AND deleted_at IS NULL",
    )
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn invalidate_email_tokens_in_tx(
    conn: &mut sqlx::SqliteConnection,
    email_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE email_verification_tokens SET consumed_at = now()
         WHERE email_id = $1 AND consumed_at IS NULL",
    )
    .bind(email_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "UPDATE password_reset_tokens SET consumed_at = now()
         WHERE email_id = $1 AND consumed_at IS NULL",
    )
    .bind(email_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(super) async fn email_for_sync(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
) -> Result<Option<(Uuid, String)>, AppError> {
    sqlx::query_as("SELECT id,email FROM entity_emails WHERE entity_id=$1")
        .bind(entity_id)
        .fetch_optional(conn)
        .await
        .map_err(db_err)
}
pub(super) async fn replace_email(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    email_id: Uuid,
    email: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE entity_emails SET email=$2, verified_at=NULL, deleted_at=NULL, updated_at=now() WHERE id=$1").bind(email_id).bind(email).execute(&mut *conn).await.map_err(entity_write_conflict)?;
    sqlx::query("UPDATE credentials SET identifier=$2 WHERE entity_id=$1 AND kind='password' AND status='active'").bind(entity_id).bind(email).execute(conn).await.map_err(db_err)?;
    Ok(())
}
pub(super) async fn reactivate_email(
    conn: &mut sqlx::SqliteConnection,
    email_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE entity_emails SET deleted_at=NULL, updated_at=now() WHERE id=$1")
        .bind(email_id)
        .execute(conn)
        .await
        .map_err(db_err)?;
    Ok(())
}
pub(super) async fn insert_email(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    email: &str,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO entity_emails (id,entity_id,email) VALUES ($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(entity_id)
        .bind(email)
        .execute(conn)
        .await
        .map_err(entity_write_conflict)?;
    Ok(())
}

pub(super) async fn get_entity_object_groups(
    pool: &sqlx::SqlitePool,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT gep.group_id
           FROM group_entity_parents gep
           JOIN object_groups g ON g.id = gep.group_id AND g.deleted_at IS NULL
           WHERE gep.entity_id = $1
           ORDER BY gep.created_at, gep.group_id"#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn fetch_group<'e, E: sqlx::Executor<'e, Database = sqlx::Sqlite>>(
    executor: E,
    id: Uuid,
) -> Result<Group, AppError> {
    sqlx::query_as::<_, Group>(
        r#"SELECT g.id, g.name, g.tenant_id, g.group_type, g.description, gh.parent_id,
                  g.status, g.attributes, g.deleted_at, g.deleted_by, g.created_at, g.updated_at, g.managed_by
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE g.id = $1 AND g.deleted_at IS NULL"#,
    )
    .bind(id)
    .fetch_one(executor)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::not_found(format!("group {id} not found")),
        other => AppError::Database(other),
    })
}

pub(super) async fn list_groups_by_ids(
    pool: &sqlx::SqlitePool,
    ids: &[Uuid],
) -> Result<Vec<Group>, AppError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query_as::<_, Group>(
        r#"SELECT g.id, g.name, g.tenant_id, g.group_type, g.description, gh.parent_id,
                  g.status, g.attributes, g.deleted_at, g.deleted_by, g.created_at, g.updated_at, g.managed_by
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE g.id IN (SELECT unhex(value) FROM json_each($1)) AND g.deleted_at IS NULL
           ORDER BY NULLIF(instr($1, lower(hex(g.id))), 0)"#,
    )
    .bind(crate::db::native::uuid_array_json(ids))
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn list_groups(
    pool: &sqlx::SqlitePool,
    params: ListGroups,
) -> Result<GroupList, AppError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let status = params.status;
    let q = search_pattern(params.q);
    let parent_id = params.parent_id;
    let deleted = params.deleted.as_str();
    let attributes_contains = params.attributes_contains.filter(|attrs| !attrs.is_null());
    let order_by = group_order_by(params.order, params.dir);

    let items_sql = format!(
        r#"SELECT g.id, g.name, g.tenant_id, g.group_type, g.description, gh.parent_id,
                  g.status, g.attributes, g.deleted_at, g.deleted_by, g.created_at, g.updated_at, g.managed_by
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE ($1 IS NULL OR g.tenant_id = $1)
             AND ($2 IS NULL OR g.status = $2)
             AND ($3 IS NULL OR g.name LIKE $3 OR g.description LIKE $3 OR atom_text(g.attributes) LIKE $3)
             AND ($8 IS NULL OR g.group_type = $8)
             AND (($4 IS NULL AND $5 = FALSE)
                  OR ($5 = TRUE AND gh.parent_id = $4))
             AND ($10 IS NULL OR atom_json_contains(g.attributes, $10))
             AND ($9 = 'all'
                  OR ($9 = 'live' AND g.deleted_at IS NULL)
                  OR ($9 = 'deleted' AND g.deleted_at IS NOT NULL))
           ORDER BY {order_by}
           LIMIT $6 OFFSET $7"#,
    );
    let items = sqlx::query_as::<_, Group>(&items_sql)
        .bind(params.tenant_id)
        .bind(status.clone())
        .bind(q.clone())
        .bind(parent_id)
        .bind(parent_id.is_some())
        .bind(limit)
        .bind(offset)
        .bind(params.group_type.clone())
        .bind(deleted)
        .bind(attributes_contains.clone())
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM groups g
           LEFT JOIN group_hierarchy gh ON gh.child_id = g.id
           WHERE ($1 IS NULL OR g.tenant_id = $1)
             AND ($2 IS NULL OR g.status = $2)
             AND ($3 IS NULL OR g.name LIKE $3 OR g.description LIKE $3 OR atom_text(g.attributes) LIKE $3)
             AND ($6 IS NULL OR g.group_type = $6)
             AND (($4 IS NULL AND $5 = FALSE)
                  OR ($5 = TRUE AND gh.parent_id = $4))
             AND ($8 IS NULL OR atom_json_contains(g.attributes, $8))
             AND ($7 = 'all'
                  OR ($7 = 'live' AND g.deleted_at IS NULL)
                  OR ($7 = 'deleted' AND g.deleted_at IS NOT NULL))"#,
    )
    .bind(params.tenant_id)
    .bind(status)
    .bind(q)
    .bind(parent_id)
    .bind(parent_id.is_some())
    .bind(params.group_type)
    .bind(deleted)
    .bind(attributes_contains)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(GroupList { items, total })
}

pub(super) async fn list_child_groups(
    pool: &sqlx::SqlitePool,
    parent_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<GroupList, AppError> {
    list_groups(
        pool,
        ListGroups {
            q: None,
            tenant_id: None,
            attributes_contains: None,
            group_type: Some("object".to_string()),
            parent_id: Some(parent_id),
            status: None,
            deleted: crate::models::enums::DeletedFilter::Live,
            limit,
            offset,
            order: Default::default(),
            dir: Default::default(),
        },
    )
    .await
}

pub(super) async fn list_group_members(
    pool: &sqlx::SqlitePool,
    group_id: Uuid,
) -> Result<Vec<Entity>, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"SELECT e.id, e.kind, e.name, e.alias, e.external_id, e.tenant_id, e.profile_id,
                  e.profile_version_id, e.status, e.attributes, e.deleted_at, e.deleted_by,
                  e.created_at, e.updated_at, e.managed_by, e.revision
           FROM entities e
           JOIN principal_group_members gm ON gm.entity_id = e.id
           WHERE gm.group_id = $1 AND e.deleted_at IS NULL
           ORDER BY e.name"#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn get_entity_groups(
    pool: &sqlx::SqlitePool,
    entity_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT gm.group_id
           FROM principal_group_members gm
           JOIN principal_groups g ON g.id = gm.group_id AND g.deleted_at IS NULL
           WHERE gm.entity_id = $1"#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn list_owned(
    pool: &sqlx::SqlitePool,
    owner_id: Uuid,
) -> Result<Vec<Entity>, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"SELECT e.id, e.kind, e.name, e.alias, e.external_id, e.tenant_id, e.profile_id,
                  e.profile_version_id, e.status, e.attributes, e.deleted_at, e.deleted_by,
                  e.created_at, e.updated_at, e.managed_by, e.revision
           FROM entities e
           JOIN ownerships o ON o.owned_id = e.id
           WHERE o.owner_id = $1 AND e.deleted_at IS NULL
           ORDER BY e.created_at DESC"#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub(super) async fn delete_ownership(
    pool: &sqlx::SqlitePool,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(r#"DELETE FROM ownerships WHERE owner_id = $1 AND owned_id = $2"#)
        .bind(owner_id)
        .bind(owned_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}

fn group_order_by(order: GroupOrderField, dir: SortDir) -> &'static str {
    match (order, dir) {
        (GroupOrderField::CreatedAt, SortDir::Asc) => "g.created_at ASC, g.id ASC",
        (GroupOrderField::CreatedAt, SortDir::Desc) => "g.created_at DESC, g.id ASC",
        (GroupOrderField::UpdatedAt, SortDir::Asc) => "g.updated_at ASC NULLS LAST, g.id ASC",
        (GroupOrderField::UpdatedAt, SortDir::Desc) => "g.updated_at DESC NULLS LAST, g.id ASC",
        (GroupOrderField::Name, SortDir::Asc) => "lower(g.name) ASC, g.id ASC",
        (GroupOrderField::Name, SortDir::Desc) => "lower(g.name) DESC, g.id ASC",
        (GroupOrderField::Status, SortDir::Asc) => "g.status ASC, g.id ASC",
        (GroupOrderField::Status, SortDir::Desc) => "g.status DESC, g.id ASC",
    }
}

pub(super) async fn entity_tenant_including_deleted(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM entities WHERE id = $1"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn entity_revocation_ids(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<(Vec<Uuid>, Vec<Uuid>), AppError> {
    let session_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM sessions WHERE entity_id = $1 AND revoked_at IS NULL"#,
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    // Restricted to the one credential kind this codebase caches under
    // `CacheCategory::Credential` (certificates are tracked via the CRL
    // instead, not this cache).
    let credential_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM credentials WHERE entity_id = $1 AND status = 'active' AND kind = $2"#,
    )
    .bind(id)
    .bind(crate::models::enums::CredentialKind::AccessToken)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;

    Ok((session_ids, credential_ids))
}

pub(super) async fn deactivate_entity(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    actor_id: Option<Uuid>,
    deleted_by: Option<Uuid>,
) -> Result<(Option<Uuid>, Vec<(Uuid, String, Option<Uuid>)>), AppError> {
    let tenant_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE entities
         SET status = 'inactive', deleted_at = now(), deleted_by = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING tenant_id",
    )
    .bind(id)
    .bind(deleted_by)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?
    .ok_or_else(|| AppError::not_found(format!("entity {id} not found")))?;

    let revoked: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        r#"UPDATE credentials
           SET status = 'revoked',
               metadata = CASE
                   WHEN kind = 'certificate'
                   THEN atom_json_merge(metadata, json_object(
                       'revoked_at', now(),
                       'revocation_reason', 'entity_deleted',
                       'revoked_by_entity_id',atom_text($2)))
                   ELSE metadata
               END
           WHERE entity_id = $1 AND status = 'active'
           RETURNING id, kind, issuer_id"#,
    )
    .bind(id)
    .bind(actor_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)?;
    sqlx::query(
        r#"UPDATE sessions SET revoked_at = now() WHERE entity_id = $1 AND revoked_at IS NULL"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;

    sqlx::query(
        "UPDATE entity_emails
         SET deleted_at = (SELECT deleted_at FROM entities WHERE id = $1), updated_at = now()
         WHERE entity_id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;

    Ok((tenant_id, revoked))
}

pub(super) async fn deleted_entity_tenant(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM entities WHERE id = $1 AND deleted_at IS NOT NULL"#)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn entity_restore_snapshot(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    expected_tenant_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, bool, DateTime<Utc>)>, AppError> {
    sqlx::query_as(
        "SELECT e.tenant_id, (t.deleted_at IS NOT NULL), e.deleted_at
         FROM entities e
         LEFT JOIN tenants t ON t.id = e.tenant_id
         WHERE e.id = $1
           AND e.tenant_id IS NOT DISTINCT FROM $2
           AND e.deleted_at IS NOT NULL",
    )
    .bind(id)
    .bind(expected_tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn restore_entity(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    entity_deleted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE entity_emails
         SET deleted_at = NULL, updated_at = now()
         WHERE entity_id = $1 AND deleted_at = $2",
    )
    .bind(id)
    .bind(entity_deleted_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    .execute(&mut *conn)
    .await
    .map_err(restore_conflict)?;

    sqlx::query(
        "UPDATE entities
         SET status = 'active', deleted_at = NULL, deleted_by = NULL, updated_at = now()
         WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(restore_conflict)?;

    Ok(())
}

pub(super) async fn purge_entity(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<(Option<Uuid>, Vec<Uuid>), AppError> {
    let credential_ids: Vec<Uuid> =
        sqlx::query_scalar(r#"SELECT id FROM credentials WHERE entity_id = $1"#)
            .bind(id)
            .fetch_all(&mut *conn)
            .await
            .map_err(db_err)?;

    // Enrollment counters intentionally have no FK because a scope may be
    // admitted before all subject reads finish. Purge them explicitly so a
    // one-time subject cannot leave durable abuse-control state behind.
    sqlx::query(
        "DELETE FROM pki_enrollment_rate_windows
         WHERE scope_kind = 'entity' AND scope_id = $1",
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;

    let purged_tenant_id: Option<Option<Uuid>> = sqlx::query_scalar(
        r#"DELETE FROM entities WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    let tenant_id = purged_tenant_id
        .ok_or_else(|| AppError::not_found(format!("no soft-deleted entity {id} to purge")))?;

    Ok((tenant_id, credential_ids))
}

pub(super) async fn group_tenant_ids(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Vec<Option<Uuid>>, AppError> {
    sqlx::query_scalar(
        r#"SELECT tenant_id FROM groups
           WHERE id = $1
           ORDER BY CASE group_type WHEN 'object' THEN 0 ELSE 1 END"#,
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn physical_group_types(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        r#"SELECT group_type FROM groups
           WHERE id = $1
           ORDER BY CASE group_type WHEN 'object' THEN 0 ELSE 1 END"#,
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn group_is_live(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM groups WHERE id = $1 AND deleted_at IS NULL)"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn live_group_tenant(
    conn: &mut sqlx::SqliteConnection,
    child_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM groups WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(child_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn lock_object_group(
    conn: &mut sqlx::SqliteConnection,
    child_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(r#"SELECT id FROM object_groups WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(child_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn lock_principal_group(
    conn: &mut sqlx::SqliteConnection,
    child_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(r#"SELECT id FROM principal_groups WHERE id = $1 AND deleted_at IS NULL"#)
        .bind(child_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn group_restore_snapshot(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Option<(Option<Uuid>, bool)>, AppError> {
    sqlx::query_as(
        "SELECT g.tenant_id, (t.deleted_at IS NOT NULL)
         FROM groups g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.id = $1 AND g.deleted_at IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn active_principal_group_tenant(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(
        r#"SELECT tenant_id FROM principal_groups
           WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
    )
    .bind(group_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn active_member_tenant(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(
        r#"SELECT tenant_id FROM entities
           WHERE id = $1 AND status = 'active' AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_active_member_group(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
    group_tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM principal_groups
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status = 'active'
             AND deleted_at IS NULL"#,
    )
    .bind(group_id)
    .bind(group_tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_active_member(
    conn: &mut sqlx::SqliteConnection,
    entity_id: Uuid,
    entity_tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM entities
           WHERE id = $1
             AND tenant_id IS NOT DISTINCT FROM $2
             AND status = 'active'
             AND deleted_at IS NULL"#,
    )
    .bind(entity_id)
    .bind(entity_tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn insert_member(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, AppError> {
    sqlx::query(
        r#"INSERT INTO principal_group_members (group_id, entity_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"#,
    )
    .bind(group_id)
    .bind(entity_id)
    .execute(&mut *conn)
    .await
    .map_err(db_err) .map(|r| r.rows_affected())
}

pub(super) async fn principal_group_tenant(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar(r#"SELECT tenant_id FROM principal_groups WHERE id = $1"#)
        .bind(group_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)
}

pub(super) async fn lock_member_group(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM principal_groups
           WHERE id = $1 AND tenant_id IS NOT DISTINCT FROM $2"#,
    )
    .bind(group_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn remove_member(
    conn: &mut sqlx::SqliteConnection,
    group_id: Uuid,
    entity_id: Uuid,
) -> Result<u64, AppError> {
    sqlx::query(r#"DELETE FROM principal_group_members WHERE group_id = $1 AND entity_id = $2"#)
        .bind(group_id)
        .bind(entity_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)
        .map(|r| r.rows_affected())
}

pub(super) async fn insert_group(
    conn: &mut sqlx::SqliteConnection,
    group: NewGroup<'_>,
) -> Result<Group, AppError> {
    let NewGroup {
        id,
        name,
        tenant_id,
        group_type,
        description,
        attributes: attrs,
    } = group;
    let group = match group_type {
        "principal" => sqlx::query_as::<_, Group>(
            r#"INSERT INTO principal_groups (id, name, tenant_id, description, attributes)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING id, name, tenant_id, 'principal' AS group_type, description,
                             NULL AS parent_id,
                             status, attributes, deleted_at, deleted_by, created_at, updated_at"#,
        )
        .bind(id)
        .bind(name)
        .bind(tenant_id)
        .bind(description)
        .bind(attrs.to_string())
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?,
        "object" => sqlx::query_as::<_, Group>(
            r#"INSERT INTO object_groups (id, name, tenant_id, description, attributes)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING id, name, tenant_id, 'object' AS group_type, description,
                             NULL AS parent_id,
                             status, attributes, deleted_at, deleted_by, created_at, updated_at"#,
        )
        .bind(id)
        .bind(name)
        .bind(tenant_id)
        .bind(description)
        .bind(attrs.to_string())
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?,
        _ => {
            return Err(AppError::bad_request(
                "groupType must be either 'object' or 'principal'",
            ))
        }
    };

    Ok(group)
}

pub(super) async fn update_group(
    conn: &mut sqlx::SqliteConnection,
    changes: GroupChanges,
) -> Result<Group, AppError> {
    let GroupChanges {
        id,
        request: req,
        attributes,
    } = changes;
    let row0 = sqlx::query_as::<_, Group>(r#"UPDATE principal_groups
             SET name        = COALESCE($2, name),
                 description = COALESCE($3, description),
                 status      = COALESCE($4, status),
                 attributes  = COALESCE($5, attributes),
                 updated_at  = now()
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, name, tenant_id, 'principal' AS group_type, description,
                       (SELECT parent_id FROM principal_group_hierarchy WHERE child_id = principal_groups.id) AS parent_id,
                       status, attributes, deleted_at, deleted_by, created_at, updated_at"#)
    .bind(id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.status)
    .bind(attributes.as_ref().map(Value::to_string))
    .fetch_optional(&mut *conn).await.map_err(db_err)?;
    let row1 = sqlx::query_as::<_, Group>(r#"UPDATE object_groups
             SET name        = COALESCE($2, name),
                 description = COALESCE($3, description),
                 status      = COALESCE($4, status),
                 attributes  = COALESCE($5, attributes),
                 updated_at  = now()
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id, name, tenant_id, 'object' AS group_type, description,
                       (SELECT parent_id FROM object_group_hierarchy WHERE child_id = object_groups.id) AS parent_id,
                       status, attributes, deleted_at, deleted_by, created_at, updated_at"#)
    .bind(id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.status)
    .bind(attributes.as_ref().map(Value::to_string))
    .fetch_optional(&mut *conn).await.map_err(db_err)?;
    row0.or(row1)
        .ok_or_else(|| AppError::not_found(format!("group {id} not found")))
}

pub(super) async fn remove_parent(
    conn: &mut sqlx::SqliteConnection,
    child_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(r#"DELETE FROM principal_group_hierarchy WHERE child_id = $1"#)
        .bind(child_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    sqlx::query(r#"DELETE FROM object_group_hierarchy WHERE child_id = $1"#)
        .bind(child_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

pub(super) async fn delete_group(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let row0 = sqlx::query_scalar(
        r#"UPDATE principal_groups SET deleted_at = now(), deleted_by = $2
             WHERE id = $1 AND deleted_at IS NULL RETURNING id"#,
    )
    .bind(id)
    .bind(deleted_by)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    let row1 = sqlx::query_scalar(
        r#"UPDATE object_groups SET deleted_at = now(), deleted_by = $2
             WHERE id = $1 AND deleted_at IS NULL RETURNING id"#,
    )
    .bind(id)
    .bind(deleted_by)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(row0.or(row1))
}

pub(super) async fn restore_group(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"UPDATE principal_groups SET deleted_at = NULL, deleted_by = NULL
             WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(restore_conflict)?;
    sqlx::query(
        r#"UPDATE object_groups SET deleted_at = NULL, deleted_by = NULL
             WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(restore_conflict)?;
    Ok(())
}

pub(super) async fn purge_group(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<Option<Option<Uuid>>, AppError> {
    let row0 = sqlx::query_scalar(
        r#"DELETE FROM principal_groups
             WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    let row1 = sqlx::query_scalar(
        r#"DELETE FROM object_groups
             WHERE id = $1 AND deleted_at IS NOT NULL RETURNING tenant_id"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(row0.or(row1))
}

pub(super) async fn ownership_entities(
    conn: &mut sqlx::SqliteConnection,
    owner_id: Uuid,
    owned_id: Uuid,
) -> Result<Vec<(Uuid, Option<Uuid>)>, AppError> {
    sqlx::query_as(
        r#"SELECT id, tenant_id FROM entities
           WHERE id IN (SELECT unhex(value) FROM json_each($1)) AND status = 'active' AND deleted_at IS NULL"#,
    )
    .bind(crate::db::native::uuid_array_json(&[owner_id, owned_id]))
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_ownership_entities(
    conn: &mut sqlx::SqliteConnection,
    entity_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"SELECT id FROM entities
           WHERE id IN (SELECT unhex(value) FROM json_each($1)) AND status = 'active' AND deleted_at IS NULL
           ORDER BY id"#,
    )
    .bind(crate::db::native::uuid_array_json(entity_ids))
    .fetch_all(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn upsert_ownership(
    conn: &mut sqlx::SqliteConnection,
    owner_id: Uuid,
    owned_id: Uuid,
    relation: String,
) -> Result<Ownership, AppError> {
    sqlx::query_as::<_, Ownership>(
        r#"INSERT INTO ownerships (owner_id, owned_id, relation)
           VALUES ($1, $2, $3)
           ON CONFLICT (owner_id, owned_id) DO UPDATE SET relation = EXCLUDED.relation
           RETURNING owner_id, owned_id, relation, created_at"#,
    )
    .bind(owner_id)
    .bind(owned_id)
    .bind(relation)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn hierarchy_group(
    conn: &mut sqlx::SqliteConnection,
    id: Uuid,
) -> Result<(Option<Uuid>, String), AppError> {
    sqlx::query_as::<_, (Option<Uuid>, String)>(
        r#"SELECT tenant_id, group_type
           FROM groups
           WHERE id = $1 AND deleted_at IS NULL
           ORDER BY CASE group_type WHEN 'object' THEN 0 ELSE 1 END
           LIMIT 1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)
}

pub(super) async fn lock_hierarchy_groups(
    conn: &mut sqlx::SqliteConnection,
    group_table: &str,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    let lock_sql = format!(
        "SELECT id FROM {group_table}
         WHERE id IN (SELECT unhex(value) FROM json_each($1)) AND deleted_at IS NULL
         ORDER BY id"
    );
    let locked_ids: Vec<Uuid> = sqlx::query_scalar(&lock_sql)
        .bind(crate::db::native::uuid_array_json(&[child_id, parent_id]))
        .fetch_all(&mut *conn)
        .await
        .map_err(db_err)?;

    Ok(locked_ids)
}

pub(super) async fn hierarchy_creates_cycle(
    conn: &mut sqlx::SqliteConnection,
    hierarchy_table: &str,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool, AppError> {
    let creates_cycle_sql = format!(
        r#"WITH RECURSIVE ancestors(id) AS (
               SELECT parent_id FROM {hierarchy_table} WHERE child_id = $1
               UNION ALL
               SELECT gh.parent_id
               FROM {hierarchy_table} gh
               JOIN ancestors a ON gh.child_id = a.id
           )
           SELECT EXISTS (SELECT 1 FROM ancestors WHERE id = $2)"#
    );
    let creates_cycle: bool = sqlx::query_scalar(&creates_cycle_sql)
        .bind(parent_id)
        .bind(child_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?;

    Ok(creates_cycle)
}

pub(super) async fn set_hierarchy_parent(
    conn: &mut sqlx::SqliteConnection,
    hierarchy_table: &str,
    parent_id: Uuid,
    child_id: Uuid,
    child_tenant_id: Option<Uuid>,
) -> Result<(), AppError> {
    let upsert_sql = format!(
        r#"INSERT INTO {hierarchy_table} (parent_id, child_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (child_id) DO UPDATE
           SET parent_id = EXCLUDED.parent_id,
               tenant_id = EXCLUDED.tenant_id,
               updated_at = now()"#
    );
    sqlx::query(&upsert_sql)
        .bind(parent_id)
        .bind(child_id)
        .bind(child_tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;

    Ok(())
}

pub(super) async fn credential_tenant_id(
    pool: &sqlx::SqlitePool,
    entity_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT e.tenant_id FROM credentials c JOIN entities e ON e.id = c.entity_id WHERE c.id = $1 AND c.entity_id = $2").bind(credential_id).bind(entity_id).fetch_optional(pool).await.map_err(db_err)?.ok_or_else(||AppError::not_found("credential not found"))
}
