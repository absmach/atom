-- Prevent duplicate equal-precedence guardrail rules.
--
-- tenant_id and object_type are nullable. A plain UNIQUE constraint would treat
-- NULL values as distinct, so use normalized expression keys.
CREATE UNIQUE INDEX idx_aar_unique_rule
    ON action_assignment_rules (
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
        entity_kind,
        action_name,
        object_kind,
        COALESCE(object_type, '')
    );
