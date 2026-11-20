/// Canonical unconditional access-token ceiling used by authorized listings.
pub(crate) fn ceiling_cte(parameter: &str) -> String {
    format!("ceiling AS (SELECT s.scope_kind, s.scope_ref, l.tenant_id, la.action_id FROM credential_permission_limits l JOIN credential_permission_limit_scopes s ON s.limit_id = l.id JOIN credential_permission_limit_actions la ON la.limit_id = l.id WHERE l.credential_id = {parameter}::uuid AND l.conditions = '{{}}'::jsonb)")
}

/// Predicate for `attributesIn`: `param` is a jsonb object mapping each key to
/// an array of scalars; a row matches when, for every key, `attrs -> key`
/// JSON-equals one of that key's values. Keys and values stay bound data.
pub(crate) fn attributes_in_predicate(attrs: &str, param: &str) -> String {
    format!(
        "({param}::jsonb IS NULL OR NOT EXISTS (\
            SELECT 1 FROM jsonb_each({param}::jsonb) f \
            WHERE NOT EXISTS (\
                SELECT 1 FROM jsonb_array_elements(f.value) v \
                WHERE v.value = {attrs} -> f.key)))"
    )
}

/// `ORDER BY` body for `orderAttribute`: the value of `attrs -> key_param`
/// compared as text (`C` collation, matching SQLite's binary order) or number
/// (non-numbers become NULL), nulls last in both directions, then
/// `created_at DESC, id ASC` for stable paging. The key is a bound parameter.
pub(crate) fn attribute_order_by(
    attrs: &str,
    key_param: &str,
    value_type: crate::models::resource::AttributeValueType,
    dir: crate::models::enums::SortDir,
    created_at: &str,
    id: &str,
) -> String {
    use crate::models::{enums::SortDir, resource::AttributeValueType};
    let expr = match value_type {
        AttributeValueType::Text => format!("({attrs} ->> {key_param}::text) COLLATE \"C\""),
        AttributeValueType::Number => format!(
            "CASE WHEN jsonb_typeof({attrs} -> {key_param}::text) = 'number' \
             THEN ({attrs} ->> {key_param}::text)::numeric END"
        ),
    };
    let dir = match dir {
        SortDir::Asc => "ASC",
        SortDir::Desc => "DESC",
    };
    format!("{expr} {dir} NULLS LAST, {created_at} DESC, {id} ASC")
}
