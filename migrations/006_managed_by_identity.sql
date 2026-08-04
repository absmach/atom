-- Extends the `managed_by` marker from 005 to identity tables. Entities and
-- credentials created from a bootstrap file (`src/bootstrap.rs`) are stamped
-- 'config' so the API refuses to update, delete, revoke, or rotate them.
-- Config-managed credentials are additionally hidden from list/read responses
-- — the API pretends they don't exist so operator-planted tokens can never
-- leak through introspection.

ALTER TABLE entities
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');
