-- Extends the `managed_by` marker (introduced in 005/006) to the rest of the
-- tables the bootstrap YAML populates: tenants, resources, principal_groups,
-- object_groups, roles, permission_blocks, role_assignments, direct_policies.
-- Rows stamped 'config' are refused by update/delete/restore endpoints so the
-- deployment's declared graph can only be reshaped by editing the YAML and
-- restarting Atom.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE principal_groups
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE object_groups
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE permission_blocks
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

ALTER TABLE direct_policies
    ADD COLUMN IF NOT EXISTS managed_by TEXT
        CHECK (managed_by IS NULL OR managed_by = 'config');

-- The `groups` view unifies principal_groups and object_groups; recreate it
-- with managed_by carried through from either underlying table.
DROP VIEW IF EXISTS groups;
CREATE VIEW groups AS
SELECT id, name, tenant_id, 'object'::text AS group_type, description, status,
       attributes, deleted_at, deleted_by, created_at, updated_at, managed_by
FROM object_groups
UNION ALL
SELECT id, name, tenant_id, 'principal'::text AS group_type, description, status,
       attributes, deleted_at, deleted_by, created_at, updated_at, managed_by
FROM principal_groups;
