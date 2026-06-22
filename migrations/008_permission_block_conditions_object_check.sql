-- Enforce that permission_blocks.conditions is always a JSON object.
-- The PDP treats a non-object conditions value as malformed policy and fails
-- closed; this constraint prevents such a value from ever being stored.
-- (The column is already NOT NULL DEFAULT '{}', so existing rows are objects.)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'permission_blocks_conditions_is_object'
          AND conrelid = 'permission_blocks'::regclass
    ) THEN
        ALTER TABLE permission_blocks
            ADD CONSTRAINT permission_blocks_conditions_is_object
            CHECK (jsonb_typeof(conditions) = 'object');
    END IF;
END $$;
