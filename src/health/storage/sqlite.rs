pub(super) async fn ping(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .map(|_| ())
}
pub(super) async fn migration_count(pool: &sqlx::SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE")
        .fetch_one(pool)
        .await
}
pub(super) async fn last_audit_cleanup(
    pool: &sqlx::SqlitePool,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar::<_, serde_json::Value>("SELECT details FROM audit_logs WHERE event = 'audit.retention_cleanup' ORDER BY created_at DESC LIMIT 1").fetch_optional(pool).await
}
