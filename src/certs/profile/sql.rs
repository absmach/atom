//! SQL that is identical on both supported databases. Driver calls stay in the adapters.
pub(super) const PROFILE_COLUMNS: &str = r#"
    id,
    tenant_id,
    base_profile_id,
    name,
    permitted_key_algorithms,
    default_ttl_seconds,
    maximum_ttl_seconds,
    renewal_threshold_seconds,
    key_usages,
    extended_key_usages,
    san_policy,
    identity_uri_template,
    basic_constraints
"#;
pub(super) const LOAD_SUBJECT: &str = r#"
        SELECT e.id AS entity_id, e.tenant_id
        FROM entities e
        LEFT JOIN tenants t ON t.id = e.tenant_id
        WHERE e.id = $1
          AND e.status = 'active'
          AND e.deleted_at IS NULL
          AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))
        "#;
pub(super) fn resolve_profile() -> String {
    format!(
        r#"
        SELECT {PROFILE_COLUMNS}
        FROM certificate_profiles
        WHERE name = $1
          AND (tenant_id IS NULL OR tenant_id = $2)
        ORDER BY (tenant_id IS NULL) ASC
        LIMIT 1
        "#
    )
}
pub(super) fn profile_by_id() -> String {
    format!("SELECT {PROFILE_COLUMNS} FROM certificate_profiles WHERE id = $1")
}
