use super::*;

pub(super) async fn select_doomed(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    // `table` is from the fixed PURGE_TABLES allowlist / literals, never input.
    let sql = format!(
        r#"SELECT id FROM {table}
           WHERE deleted_at IS NOT NULL AND deleted_at < $1
           ORDER BY deleted_at ASC
           LIMIT $2"#
    );
    Ok(sqlx::query_scalar(&sql)
        .bind(cutoff.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        .bind(batch_size)
        .fetch_all(&mut *conn)
        .await?)
}
pub(super) async fn delete_by_ids(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
    ids: &[Uuid],
) -> Result<i64, AppError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let sql =
        format!(r#"DELETE FROM {table} WHERE id IN (SELECT unhex(value) FROM json_each($1))"#);
    let result = sqlx::query(&sql)
        .bind(crate::db::native::uuid_array_json(ids))
        .execute(&mut *conn)
        .await?;
    Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
}
pub(super) async fn purge_roles(
    conn: &mut sqlx::SqliteConnection,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    let role_ids = select_doomed(conn, "roles", cutoff, batch_size).await?;
    if role_ids.is_empty() {
        return Ok(role_ids);
    }

    let candidate_block_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT DISTINCT permission_block_id
           FROM role_permission_blocks
           WHERE role_id IN (SELECT unhex(value) FROM json_each($1))"#,
    )
    .bind(crate::db::native::uuid_array_json(&role_ids))
    .fetch_all(&mut *conn)
    .await?;

    sqlx::query(r#"DELETE FROM roles WHERE id IN (SELECT unhex(value) FROM json_each($1))"#)
        .bind(crate::db::native::uuid_array_json(&role_ids))
        .execute(&mut *conn)
        .await?;

    if !candidate_block_ids.is_empty() {
        sqlx::query(
            r#"DELETE FROM permission_blocks AS pb WHERE pb.id IN (SELECT unhex(value) FROM json_each($1))
                 AND NOT EXISTS (
                     SELECT 1 FROM role_permission_blocks
                     WHERE permission_block_id = pb.id
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM direct_policies
                     WHERE permission_block_id = pb.id
                 )"#,
        )
        .bind(crate::db::native::uuid_array_json(&candidate_block_ids))
        .execute(&mut *conn)
        .await?;
    }

    Ok(role_ids)
}
pub(super) async fn claim_sweep(conn: &mut sqlx::SqliteConnection) -> Result<bool, AppError> {
    let _ = conn;
    Ok(true)
}

pub(super) async fn prepare_entity_purge(
    conn: &mut sqlx::SqliteConnection,
    ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query("DELETE FROM pki_enrollment_rate_windows WHERE scope_kind = 'entity' AND scope_id IN (SELECT unhex(value) FROM json_each($1))").bind(crate::db::native::uuid_array_json(ids)).execute(&mut *conn).await?;
    Ok(sqlx::query_scalar(
        "SELECT id FROM credentials WHERE entity_id IN (SELECT unhex(value) FROM json_each($1))",
    )
    .bind(crate::db::native::uuid_array_json(ids))
    .fetch_all(&mut *conn)
    .await?)
}
