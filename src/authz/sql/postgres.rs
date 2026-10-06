/// Canonical unconditional access-token ceiling used by authorized listings.
pub(crate) fn ceiling_cte(parameter: &str) -> String {
    format!("ceiling AS (SELECT s.scope_kind, s.scope_ref, l.tenant_id, la.action_id FROM credential_permission_limits l JOIN credential_permission_limit_scopes s ON s.limit_id = l.id JOIN credential_permission_limit_actions la ON la.limit_id = l.id WHERE l.credential_id = {parameter}::uuid AND l.conditions = '{{}}'::jsonb)")
}
