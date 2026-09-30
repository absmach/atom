use uuid::Uuid;
pub(super) async fn ensure_initial_password(
    conn: &mut sqlx::PgConnection,
    entity_id: Uuid,
    hash: &str,
) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = 'password' AND status = 'active'").bind(entity_id).fetch_one(&mut *conn).await?;
    if count > 0 {
        return Ok(false);
    }
    sqlx::query("INSERT INTO credentials (id, entity_id, kind, secret_hash) VALUES ($1, $2, 'password', $3)").bind(Uuid::new_v4()).bind(entity_id).bind(hash).execute(&mut *conn).await?;
    Ok(true)
}
