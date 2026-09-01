-- Persist deployment-defined tenant-admin defaults so tenant creation can
-- apply them after startup, and safely identify Atom-owned tenant-admin RBAC.

ALTER TABLE roles DROP CONSTRAINT roles_managed_by_check;
ALTER TABLE roles ADD CONSTRAINT roles_managed_by_check
    CHECK (managed_by IS NULL OR managed_by IN ('config', 'system:tenant-admin'));

ALTER TABLE permission_blocks DROP CONSTRAINT permission_blocks_managed_by_check;
ALTER TABLE permission_blocks ADD CONSTRAINT permission_blocks_managed_by_check
    CHECK (managed_by IS NULL OR managed_by IN ('config', 'system:tenant-admin'));

CREATE TABLE tenant_admin_default_actions (
    action_id UUID PRIMARY KEY REFERENCES actions(id) ON DELETE CASCADE
);

-- Adopt only the exact RBAC shape created by bootstrap_tenant_admin for the
-- tenant creator. A user role that merely shares the name is not adopted.
WITH generated AS (
    SELECT r.id AS role_id, pb.id AS permission_block_id
    FROM roles r
    JOIN tenants t ON t.id = r.tenant_id
    JOIN role_assignments ra
      ON ra.role_id = r.id
     AND ra.tenant_id = r.tenant_id
     AND ra.subject_kind = 'entity'
     AND ra.subject_id = t.created_by
    JOIN role_permission_blocks rpb ON rpb.role_id = r.id
    JOIN permission_blocks pb
      ON pb.id = rpb.permission_block_id
     AND pb.tenant_id = r.tenant_id
    WHERE r.name = 'tenant-admin'
      AND r.description = 'Default tenant administration role'
      AND r.deleted_at IS NULL
      AND r.managed_by IS NULL
      AND pb.scope_mode = 'tenant'
      AND pb.effect = 'allow'
      AND pb.conditions = '{}'::jsonb
      AND pb.managed_by IS NULL
      AND (SELECT count(*) FROM role_permission_blocks links WHERE links.role_id = r.id) = 1
)
UPDATE roles r
SET managed_by = 'system:tenant-admin'
FROM generated g
WHERE r.id = g.role_id;

UPDATE permission_blocks pb
SET managed_by = 'system:tenant-admin'
FROM role_permission_blocks rpb
JOIN roles r ON r.id = rpb.role_id
WHERE pb.id = rpb.permission_block_id
  AND r.managed_by = 'system:tenant-admin';
