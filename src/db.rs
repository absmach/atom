use sqlx::{postgres::PgPoolOptions, PgPool};

pub async fn create_pool(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(url)
        .await?;
    Ok(pool)
}
