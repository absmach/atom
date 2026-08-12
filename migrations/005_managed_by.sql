-- Marks rows that were provisioned from a declarative bootstrap file (see
-- src/bootstrap.rs) so mutation endpoints can refuse to modify them out of
-- band. NULL = API-managed (default), 'config' = bootstrap-managed.
-- Config-managed rows can still be added to (e.g. extra applicability rows
-- attached to a config-managed capability), but they cannot be updated or
-- deleted via the API — the config file is the source of truth.

ALTER TABLE actions
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE action_applicability
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE action_assignment_rules
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');
