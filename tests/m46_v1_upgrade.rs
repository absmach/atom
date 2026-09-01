//! Upgrade regressions for the supported v0.50.0 -> v1.0 path.
//!
//! Run with a disposable PostgreSQL database:
//!
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m46_v1_upgrade -- --ignored
//! ```

use std::{borrow::Cow, path::Path};

use atom::{
    bootstrap::{
        preflight_product_applicability, BootstrapCapability, BootstrapCapabilityApplicability,
        BootstrapConfig,
    },
    models::enums::ObjectKind,
};
use sqlx::{migrate::Migrator, Connection, Executor, PgConnection, PgPool};
use url::Url;
use uuid::Uuid;

const PRE_PRODUCT_APPLICABILITY_STRIP_VERSION: i64 = 6;

#[tokio::test]
#[ignore]
async fn migration_007_preflight_requires_exact_replacement_for_every_removed_row() {
    let admin_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    let scratch = format!("atom_m46_{}", Uuid::new_v4().simple());
    let scratch_url = database_url_with_name(&admin_url, &scratch).expect("scratch database URL");

    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("connect for scratch database");
    admin
        .execute(format!(r#"CREATE DATABASE "{scratch}""#).as_str())
        .await
        .expect("create scratch database");

    let result = seed_and_migrate(&scratch_url).await;

    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)"#).as_str())
        .await;
    admin.close().await.expect("close admin connection");
    result.expect("migration 007 preflight protects every removed applicability row");
}

async fn seed_and_migrate(scratch_url: &str) -> Result<(), String> {
    let mut conn = PgConnection::connect(scratch_url)
        .await
        .map_err(|error| format!("connect scratch: {error}"))?;
    let migrator = Migrator::new(Path::new("./migrations"))
        .await
        .map_err(|error| format!("load migrations: {error}"))?;
    let pre_strip_migrations = migrator
        .iter()
        .filter(|migration| migration.version <= PRE_PRODUCT_APPLICABILITY_STRIP_VERSION)
        .cloned()
        .collect::<Vec<_>>();
    if pre_strip_migrations
        .last()
        .map(|migration| migration.version)
        != Some(PRE_PRODUCT_APPLICABILITY_STRIP_VERSION)
    {
        return Err(format!(
            "migration {PRE_PRODUCT_APPLICABILITY_STRIP_VERSION} must remain the pre-strip boundary"
        ));
    }
    Migrator {
        migrations: Cow::Owned(pre_strip_migrations),
        ..Migrator::DEFAULT
    }
    .run_direct(&mut conn)
    .await
    .map_err(|error| format!("apply pre-strip migrations: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO actions (name, description)
        VALUES
            ('archive', 'User-defined channel action'),
            ('trigger', 'User-defined rule action')
        "#,
    )
    .execute(&mut conn)
    .await
    .map_err(|error| format!("seed user-defined actions: {error}"))?;
    sqlx::query(
        r#"
        INSERT INTO action_applicability (action_id, object_kind, object_type)
        SELECT id, 'resource',
               CASE name
                   WHEN 'archive' THEN 'resource:channel'
                   WHEN 'trigger' THEN 'resource:rule'
               END
        FROM actions
        WHERE name IN ('archive', 'trigger')
        "#,
    )
    .execute(&mut conn)
    .await
    .map_err(|error| format!("seed user-defined applicability: {error}"))?;

    let pool = PgPool::connect(scratch_url)
        .await
        .map_err(|error| format!("connect preflight pool: {error}"))?;
    let error = preflight_product_applicability(&pool, None)
        .await
        .expect_err("undeclared applicability must block migration 007");
    let message = error.to_string();
    if !message.contains("archive on resource / resource:channel")
        || !message.contains("trigger on resource / resource:rule")
        || !message.contains("did not modify")
    {
        return Err(format!(
            "unexpected migration 007 preflight error: {message}"
        ));
    }
    let still_present: i64 = sqlx::query_scalar(
        r#"SELECT count(*)
           FROM action_applicability applicability
           JOIN actions ON actions.id = applicability.action_id
           WHERE actions.name IN ('archive', 'trigger')"#,
    )
    .fetch_one(&pool)
    .await
    .map_err(|error| format!("verify read-only preflight: {error}"))?;
    if still_present != 2 {
        return Err(format!(
            "migration preflight modified custom applicability: found {still_present} rows"
        ));
    }

    let replacement = replacement_bootstrap();
    preflight_product_applicability(&pool, Some(&replacement))
        .await
        .map_err(|error| format!("preflight with exact replacement: {error}"))?;
    pool.close().await;

    migrator
        .run_direct(&mut conn)
        .await
        .map_err(|error| format!("apply complete migration set: {error}"))?;

    // Equivalent to the post-migration declarative bootstrap restore.
    sqlx::query(
        r#"INSERT INTO action_applicability (action_id, object_kind, object_type)
           SELECT id, 'resource',
                  CASE
                      WHEN name IN ('archive', 'publish', 'subscribe') THEN 'resource:channel'
                      WHEN name IN ('execute', 'trigger') THEN 'resource:rule'
                  END
           FROM actions
           WHERE name IN ('archive', 'execute', 'publish', 'subscribe', 'trigger')"#,
    )
    .execute(&mut conn)
    .await
    .map_err(|error| format!("restore declared applicability: {error}"))?;

    let surviving: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT actions.name
        FROM action_applicability applicability
        JOIN actions ON actions.id = applicability.action_id
        WHERE (applicability.object_kind, applicability.object_type) IN (
            ('resource', 'resource:channel'),
            ('resource', 'resource:rule')
        )
        ORDER BY actions.name
        "#,
    )
    .fetch_all(&mut conn)
    .await
    .map_err(|error| format!("read upgraded applicability: {error}"))?;

    if surviving
        != vec![
            "archive".to_string(),
            "execute".to_string(),
            "publish".to_string(),
            "subscribe".to_string(),
            "trigger".to_string(),
        ]
    {
        return Err(format!(
            "migration 007 removed or retained the wrong applicability rows: {surviving:?}"
        ));
    }

    conn.close()
        .await
        .map_err(|error| format!("close scratch connection: {error}"))?;
    Ok(())
}

fn replacement_bootstrap() -> BootstrapConfig {
    let applicability = |object_type: &str| BootstrapCapabilityApplicability {
        object_kind: ObjectKind::Resource,
        object_type: Some(object_type.to_string()),
    };
    BootstrapConfig {
        capabilities: [
            ("archive", "resource:channel"),
            ("execute", "resource:rule"),
            ("publish", "resource:channel"),
            ("subscribe", "resource:channel"),
            ("trigger", "resource:rule"),
        ]
        .into_iter()
        .map(|(name, object_type)| BootstrapCapability {
            name: name.to_string(),
            description: None,
            applicability: vec![applicability(object_type)],
        })
        .collect(),
        ..BootstrapConfig::default()
    }
}

fn database_url_with_name(base: &str, database: &str) -> Result<String, String> {
    let mut url = Url::parse(base).map_err(|error| format!("parse DATABASE_URL: {error}"))?;
    url.set_path(&format!("/{database}"));
    Ok(url.to_string())
}
