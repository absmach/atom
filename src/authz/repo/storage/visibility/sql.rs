//! Shared credential-ceiling query; interpretation lives in the parent module.
pub(super) const CREDENTIAL_CEILING: &str = r#"SELECT l.id        AS limit_id,
                  s.scope_kind AS scope_kind,
                  s.scope_ref  AS scope_ref,
                  l.tenant_id  AS tenant_id,
                  l.conditions AS conditions,
                  la.action_id AS action_id
           FROM credential_permission_limits l
           JOIN credential_permission_limit_scopes s ON s.limit_id = l.id
           JOIN credential_permission_limit_actions la ON la.limit_id = l.id
           WHERE l.credential_id = $1"#;
