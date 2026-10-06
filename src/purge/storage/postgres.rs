use super::*;

pub(super) async fn select_doomed(
    conn: &mut sqlx::PgConnection,
    table: &str,
    cutoff: chrono::DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<Uuid>, AppError> {
    // `table` is from the fixed PURGE_TABLES allowlist / literals, never input.
    let sql = format!(
        r#"SELECT id FROM {table}
           WHERE deleted_at IS NOT NULL AND deleted_at < $1
           ORDER BY deleted_at ASC
           LIMIT $2
           FOR UPDATE SKIP LOCKED"#
    );
    Ok(sqlx::query_scalar(&sql)
        .bind(cutoff)
        .bind(batch_size)
        .fetch_all(&mut *conn)
        .await?)
}
pub(super) async fn delete_by_ids(
    conn: &mut sqlx::PgConnection,
    table: &str,
    ids: &[Uuid],
) -> Result<i64, AppError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let sql = format!("DELETE FROM {table} WHERE id = ANY($1)");
    let result = sqlx::query(&sql).bind(ids).execute(&mut *conn).await?;
    Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
}
pub(super) async fn purge_roles(
    conn: &mut sqlx::PgConnection,
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
           WHERE role_id = ANY($1)"#,
    )
    .bind(&role_ids)
    .fetch_all(&mut *conn)
    .await?;

    sqlx::query("DELETE FROM roles WHERE id = ANY($1)")
        .bind(&role_ids)
        .execute(&mut *conn)
        .await?;

    if !candidate_block_ids.is_empty() {
        sqlx::query(
            r#"DELETE FROM permission_blocks pb
               WHERE pb.id = ANY($1)
                 AND NOT EXISTS (
                     SELECT 1 FROM role_permission_blocks
                     WHERE permission_block_id = pb.id
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM direct_policies
                     WHERE permission_block_id = pb.id
                 )"#,
        )
        .bind(&candidate_block_ids)
        .execute(&mut *conn)
        .await?;
    }

    Ok(role_ids)
}
pub(super) async fn claim_sweep(conn: &mut sqlx::PgConnection) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(0x4154_4f4d_5055_5247_i64)
        .fetch_one(&mut *conn)
        .await?)
}

pub(super) async fn prepare_entity_purge(
    conn: &mut sqlx::PgConnection,
    ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query("DELETE FROM pki_enrollment_rate_windows WHERE scope_kind = 'entity' AND scope_id = ANY($1)").bind(ids).execute(&mut *conn).await?;
    Ok(
        sqlx::query_scalar("SELECT id FROM credentials WHERE entity_id = ANY($1)")
            .bind(ids)
            .fetch_all(&mut *conn)
            .await?,
    )
}
