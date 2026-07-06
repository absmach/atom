DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname
    INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'permission_blocks'::regclass
      AND contype = 'c'
      AND conname <> 'permission_blocks_conditions_is_object'
      AND pg_get_constraintdef(oid) LIKE '%object_kind%'
      AND pg_get_constraintdef(oid) LIKE '%tenant_id IS NOT NULL%'
      AND pg_get_constraintdef(oid) LIKE '%group_descendant_groups%'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE permission_blocks DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

ALTER TABLE permission_blocks
    DROP CONSTRAINT IF EXISTS permission_blocks_scope_shape;

ALTER TABLE permission_blocks
    ADD CONSTRAINT permission_blocks_scope_shape
    CHECK (
        (scope_mode = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'tenant' AND tenant_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object_kind' AND object_kind IS NOT NULL AND object_id IS NULL AND object_type IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object_type' AND object_kind IS NOT NULL AND object_type IS NOT NULL AND object_id IS NULL AND group_id IS NULL)
        OR (scope_mode = 'object' AND object_id IS NOT NULL AND group_id IS NULL)
        OR (scope_mode = 'group' AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
        OR (scope_mode IN ('group_direct_objects', 'group_descendant_objects') AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_kind IN ('entity', 'resource') AND object_id IS NULL)
        OR (scope_mode IN ('group_child_groups', 'group_descendant_groups') AND tenant_id IS NOT NULL AND group_id IS NOT NULL AND object_id IS NULL AND object_kind IS NULL AND object_type IS NULL)
    );
