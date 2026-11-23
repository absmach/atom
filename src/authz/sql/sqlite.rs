/// Native SQLite grant relation. `subject` must be a trusted bind placeholder.
pub(crate) fn subject_effective_grants(subject: &str) -> String {
    include_str!("subject_effective_grants.sql").replace("{subject}", subject)
}
/// Canonical unconditional access-token ceiling used by authorized listings.
pub(crate) fn ceiling_cte(parameter: &str) -> String {
    format!("ceiling AS (SELECT s.scope_kind, s.scope_ref, l.tenant_id, la.action_id FROM credential_permission_limits l JOIN credential_permission_limit_scopes s ON s.limit_id = l.id JOIN credential_permission_limit_actions la ON la.limit_id = l.id WHERE l.credential_id = {parameter} AND atom_json_eq(l.conditions, '{{}}'))")
}

/// Predicate for `attributesIn`: `param` is a JSON object text mapping each key
/// to an array of scalars; a row matches when, for every key, the attribute
/// JSON-equals one of that key's values (numbers compare as numbers, strings
/// never equal numbers). Keys come from validated identifiers and are only
/// quoted into a JSON path, never into SQL text.
pub(crate) fn attributes_in_predicate(attrs: &str, param: &str) -> String {
    let path = "('$.\"' || f.key || '\"')";
    format!(
        "({param} IS NULL OR NOT EXISTS (\
            SELECT 1 FROM json_each({param}) f \
            WHERE NOT EXISTS (\
                SELECT 1 FROM json_each(f.value) v \
                WHERE (json_type({attrs}, {path}) = v.type \
                       OR (json_type({attrs}, {path}) IN ('integer', 'real') \
                           AND v.type IN ('integer', 'real'))) \
                  AND CASE WHEN v.type IN ('integer', 'real') \
                      THEN atom_json_number_key({attrs} -> {path}) \
                           = atom_json_number_key(f.value -> v.key) \
                      ELSE (v.type IN ('null', 'true', 'false') \
                            OR json_extract({attrs}, {path}) = v.value) END)))"
    )
}

/// `ORDER BY` body for `orderAttribute`; `path_param` is a bound JSON path
/// (`$.key`). Same semantics as the PostgreSQL adapter: text or numeric
/// comparison, non-numbers NULL under `Number`, nulls last in both directions,
/// then `created_at DESC, id ASC`.
pub(crate) fn attribute_order_by(
    attrs: &str,
    path_param: &str,
    value_type: crate::models::resource::AttributeValueType,
    dir: crate::models::enums::SortDir,
    created_at: &str,
    id: &str,
) -> String {
    use crate::models::{enums::SortDir, resource::AttributeValueType};
    let expr = match value_type {
        AttributeValueType::Text => format!(
            "CASE json_type({attrs}, {path_param}) \
             WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' WHEN 'null' THEN NULL \
             ELSE CAST(json_extract({attrs}, {path_param}) AS TEXT) END"
        ),
        AttributeValueType::Number => format!("atom_json_number_key({attrs} -> {path_param})"),
    };
    let dir = match dir {
        SortDir::Asc => "ASC",
        SortDir::Desc => "DESC",
    };
    format!("{expr} {dir} NULLS LAST, {created_at} DESC, {id} ASC")
}

/// JSON path selecting a top-level key. The key must already be validated by
/// `ResourceAttributeQuery::new`.
pub(crate) fn attribute_json_path(key: &str) -> String {
    debug_assert!(
        !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "attribute keys are validated by ResourceAttributeQuery"
    );
    format!("$.\"{key}\"")
}
