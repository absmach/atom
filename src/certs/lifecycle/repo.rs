use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::error::{db_err, AppError};

use super::BulkRevocationSelector;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertificateWindowCandidate {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub window_kind: String,
    pub window_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorityWindowCandidate {
    pub issuer_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub kind: String,
    pub expires_at: DateTime<Utc>,
    pub window_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BulkCandidate {
    pub credential_id: Uuid,
    pub issuer_id: Option<Uuid>,
    pub entity_id: Uuid,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExpiryMetricRow {
    pub status: String,
    pub bucket: String,
    pub count: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorityMetricRow {
    pub kind: String,
    pub seconds: f64,
}

/// Select due certificate windows that do not already have a durable marker.
/// The stored PR-007 snapshot wins; pre-PR-007 rows fall back to their
/// referenced/effective profile, never to a process-wide renewal constant.
pub async fn due_certificate_windows(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
    expiry_warning_secs: u64,
    limit: i64,
) -> Result<Vec<CertificateWindowCandidate>, AppError> {
    let expiry_warning_secs = i64::try_from(expiry_warning_secs)
        .map_err(|_| AppError::bad_request("certificate expiry warning is too large"))?;
    sqlx::query_as::<_, CertificateWindowCandidate>(
        r#"
        WITH certificate_windows AS (
            SELECT c.id AS credential_id,
                   c.issuer_id,
                   c.entity_id,
                   e.tenant_id,
                   c.expires_at,
                   COALESCE(
                       CASE
                           WHEN jsonb_typeof(c.metadata -> 'renewal_due_at') = 'string'
                           THEN (c.metadata ->> 'renewal_due_at')::timestamptz
                       END,
                       c.expires_at - (
                           COALESCE(
                               CASE
                                   WHEN (c.metadata ->> 'renewal_threshold_seconds') ~ '^[0-9]+$'
                                   THEN (c.metadata ->> 'renewal_threshold_seconds')::bigint
                               END,
                               referenced.renewal_threshold_seconds,
                               effective.renewal_threshold_seconds
                           ) * interval '1 second'
                       )
                   ) AS renewal_at
            FROM credentials c
            JOIN entities e ON e.id = c.entity_id
            LEFT JOIN certificate_profiles referenced
                   ON referenced.id::text = c.metadata ->> 'profile_id'
            LEFT JOIN LATERAL (
                SELECT p.renewal_threshold_seconds
                FROM certificate_profiles p
                WHERE p.name = COALESCE(NULLIF(c.metadata ->> 'profile_name', ''), 'client')
                  AND (p.tenant_id IS NULL OR p.tenant_id = e.tenant_id)
                ORDER BY (p.tenant_id IS NULL) ASC
                LIMIT 1
            ) effective ON true
            WHERE c.kind = 'certificate'
              AND c.status = 'active'
              AND c.expires_at IS NOT NULL
        ), due AS (
            SELECT credential_id, issuer_id, entity_id, tenant_id, expires_at,
                   'renewal'::text AS window_kind, renewal_at AS window_at
            FROM certificate_windows w
            WHERE renewal_at IS NOT NULL
              AND renewal_at <= $1
              AND NOT EXISTS (
                  SELECT 1 FROM pki_lifecycle_notifications n
                  WHERE n.subject_kind = 'credential'
                    AND n.subject_id = w.credential_id
                    AND n.window_kind = 'renewal'
              )
            UNION ALL
            SELECT credential_id, issuer_id, entity_id, tenant_id, expires_at,
                   'expiry'::text AS window_kind,
                   expires_at - ($2 * interval '1 second') AS window_at
            FROM certificate_windows w
            WHERE expires_at - ($2 * interval '1 second') <= $1
              AND NOT EXISTS (
                  SELECT 1 FROM pki_lifecycle_notifications n
                  WHERE n.subject_kind = 'credential'
                    AND n.subject_id = w.credential_id
                    AND n.window_kind = 'expiry'
              )
        )
        SELECT credential_id, issuer_id, entity_id, tenant_id, expires_at,
               window_kind, window_at
        FROM due
        ORDER BY window_at ASC, credential_id ASC, window_kind ASC
        LIMIT $3
        "#,
    )
    .bind(now)
    .bind(expiry_warning_secs)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::Database)
}

pub async fn due_authority_windows(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
    warning_secs: u64,
    limit: i64,
) -> Result<Vec<AuthorityWindowCandidate>, AppError> {
    let warning_secs = i64::try_from(warning_secs)
        .map_err(|_| AppError::bad_request("authority expiry warning is too large"))?;
    sqlx::query_as::<_, AuthorityWindowCandidate>(
        r#"
        SELECT a.id AS issuer_id,
               a.tenant_id,
               a.kind,
               a.not_after AS expires_at,
               a.not_after - ($2 * interval '1 second') AS window_at
        FROM pki_authorities a
        WHERE a.status IN ('active', 'retiring')
          AND a.not_after - ($2 * interval '1 second') <= $1
          AND NOT EXISTS (
              SELECT 1 FROM pki_lifecycle_notifications n
              WHERE n.subject_kind = 'authority'
                AND n.subject_id = a.id
                AND n.window_kind = 'authority_expiry'
          )
        ORDER BY window_at ASC, a.id ASC
        LIMIT $3
        "#,
    )
    .bind(now)
    .bind(warning_secs)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::Database)
}

pub async fn claim_notification(
    tx: &mut Transaction<'_, Postgres>,
    subject_kind: &str,
    subject_id: Uuid,
    window_kind: &str,
    window_at: DateTime<Utc>,
) -> Result<bool, AppError> {
    let claimed: Option<bool> = sqlx::query_scalar(
        r#"
        INSERT INTO pki_lifecycle_notifications (
            subject_kind, subject_id, window_kind, window_at
        ) VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        RETURNING true
        "#,
    )
    .bind(subject_kind)
    .bind(subject_id)
    .bind(window_kind)
    .bind(window_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::Database)?;
    Ok(claimed.unwrap_or(false))
}

pub async fn expiry_metrics(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
) -> Result<Vec<ExpiryMetricRow>, AppError> {
    sqlx::query_as::<_, ExpiryMetricRow>(
        r#"
        SELECT c.status,
               CASE
                   WHEN c.expires_at <= $1 THEN 'expired'
                   WHEN c.expires_at <= $1 + interval '1 hour' THEN 'lt_1h'
                   WHEN c.expires_at <= $1 + interval '24 hours' THEN 'lt_24h'
                   WHEN c.expires_at <= $1 + interval '7 days' THEN 'lt_7d'
                   ELSE 'gte_7d'
               END AS bucket,
               COUNT(*)::bigint AS count
        FROM credentials c
        WHERE c.kind = 'certificate' AND c.expires_at IS NOT NULL
        GROUP BY c.status, bucket
        "#,
    )
    .bind(now)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::Database)
}

pub async fn authority_metrics(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
) -> Result<Vec<AuthorityMetricRow>, AppError> {
    sqlx::query_as::<_, AuthorityMetricRow>(
        r#"
        SELECT kind,
               GREATEST(MIN(EXTRACT(epoch FROM (not_after - $1))), 0)::float8 AS seconds
        FROM pki_authorities
        WHERE status IN ('active', 'retiring')
        GROUP BY kind
        "#,
    )
    .bind(now)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::Database)
}

pub async fn selector_tenant_id(
    pool: &PgPool,
    selector: BulkRevocationSelector,
) -> Result<Option<Uuid>, AppError> {
    match selector {
        BulkRevocationSelector::Tenant(tenant_id) => sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM tenants WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .map(Some)
        .map_err(db_err),
        BulkRevocationSelector::Issuer(issuer_id) => {
            sqlx::query_scalar("SELECT tenant_id FROM pki_authorities WHERE id = $1")
                .bind(issuer_id)
                .fetch_one(pool)
                .await
                .map_err(db_err)
        }
        BulkRevocationSelector::PrincipalGroup(group_id) => sqlx::query_scalar(
            "SELECT tenant_id FROM principal_groups WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(group_id)
        .fetch_one(pool)
        .await
        .map_err(db_err),
    }
}

/// Database-clock cutoff used to freeze the membership of a paginated bulk
/// operation. Credential creation also uses the database clock, avoiding
/// process/DB clock skew at the page boundary.
pub async fn bulk_snapshot_at(pool: &PgPool) -> Result<DateTime<Utc>, AppError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)
}

pub async fn bulk_candidates(
    pool: &PgPool,
    selector: BulkRevocationSelector,
    after: Option<Uuid>,
    snapshot_at: &DateTime<Utc>,
    limit: i64,
) -> Result<Vec<BulkCandidate>, AppError> {
    match selector {
        BulkRevocationSelector::PrincipalGroup(group_id) => sqlx::query_as::<_, BulkCandidate>(
            r#"
                WITH RECURSIVE root_group(id, tenant_id) AS (
                    SELECT id, tenant_id
                    FROM principal_groups
                    WHERE id = $1 AND deleted_at IS NULL
                ), selected_groups(id) AS (
                    SELECT id FROM root_group
                    UNION
                    SELECT h.child_id
                    FROM principal_group_hierarchy h
                    JOIN selected_groups parent ON parent.id = h.parent_id
                    JOIN principal_groups child ON child.id = h.child_id
                    CROSS JOIN root_group root
                    WHERE child.deleted_at IS NULL
                      AND child.tenant_id IS NOT DISTINCT FROM root.tenant_id
                )
                SELECT c.id AS credential_id, c.issuer_id, c.entity_id, e.tenant_id
                FROM credentials c
                JOIN entities e ON e.id = c.entity_id
                JOIN principal_group_members gm ON gm.entity_id = e.id
                JOIN selected_groups sg ON sg.id = gm.group_id
                CROSS JOIN root_group root
                WHERE c.kind = 'certificate'
                  AND c.status = 'active'
                  AND c.created_at <= $3
                  AND e.tenant_id IS NOT DISTINCT FROM root.tenant_id
                  AND ($2::uuid IS NULL OR c.id > $2)
                GROUP BY c.id, c.issuer_id, c.entity_id, e.tenant_id
                ORDER BY c.id ASC
                LIMIT $4
                "#,
        )
        .bind(group_id)
        .bind(after)
        .bind(snapshot_at)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database),
        selector => {
            let mut query = QueryBuilder::<Postgres>::new(
                r#"
                SELECT c.id AS credential_id, c.issuer_id, c.entity_id, e.tenant_id
                FROM credentials c
                JOIN entities e ON e.id = c.entity_id
                WHERE c.kind = 'certificate'
                  AND c.status = 'active'
                "#,
            );
            query.push(" AND c.created_at <= ");
            query.push_bind(snapshot_at);
            match selector {
                BulkRevocationSelector::Tenant(tenant_id) => {
                    query.push(" AND e.tenant_id = ");
                    query.push_bind(tenant_id);
                }
                BulkRevocationSelector::Issuer(issuer_id) => {
                    query.push(" AND c.issuer_id = ");
                    query.push_bind(issuer_id);
                    query.push(
                        " AND EXISTS (SELECT 1 FROM pki_authorities a WHERE a.id = c.issuer_id AND e.tenant_id IS NOT DISTINCT FROM a.tenant_id)",
                    );
                }
                BulkRevocationSelector::PrincipalGroup(_) => unreachable!(),
            }
            if let Some(after) = after {
                query.push(" AND c.id > ");
                query.push_bind(after);
            }
            query.push(" ORDER BY c.id ASC LIMIT ");
            query.push_bind(limit);
            query
                .build_query_as::<BulkCandidate>()
                .fetch_all(pool)
                .await
                .map_err(AppError::Database)
        }
    }
}
