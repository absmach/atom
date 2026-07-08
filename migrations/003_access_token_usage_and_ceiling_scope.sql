ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname
    INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'credential_permission_limits'::regclass
      AND contype = 'c'
      AND conname <> 'credential_permission_limits_conditions_is_object'
      AND pg_get_constraintdef(oid) LIKE '%scope_mode%'
      AND pg_get_constraintdef(oid) LIKE '%object_id IS NOT NULL%'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE credential_permission_limits DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

ALTER TABLE credential_permission_limits
    DROP CONSTRAINT IF EXISTS credential_permission_limits_scope_shape;

ALTER TABLE credential_permission_limits
    ADD CONSTRAINT credential_permission_limits_scope_shape
    CHECK (
        (scope_mode = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode = 'tenant' AND tenant_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode = 'object_kind' AND object_kind IS NOT NULL AND object_id IS NULL AND object_type IS NULL)
        OR (scope_mode = 'object_type' AND object_kind IS NOT NULL AND object_type IS NOT NULL AND object_id IS NULL)
        OR (scope_mode = 'object' AND object_id IS NOT NULL AND tenant_id IS NULL)
    );
