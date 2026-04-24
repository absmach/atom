-- =============================================================
-- Admin bootstrap
--
-- Well-known UUIDs (all-zeros prefix for easy identification):
--   entity:  00000000-0000-0000-0000-000000000001
--   role:    00000000-0000-0000-0000-000000000002
--
-- The admin entity has no credentials by default.
-- Set ADMIN_SECRET on first boot to bootstrap a password.
-- =============================================================

INSERT INTO entities (id, kind, name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'service', 'atom-admin', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, name, description)
VALUES ('00000000-0000-0000-0000-000000000002', 'atom-admin', 'Full administrative access')
ON CONFLICT DO NOTHING;

-- Grant every seeded capability to the admin role
INSERT INTO role_capabilities (role_id, capability_id)
SELECT '00000000-0000-0000-0000-000000000002', id FROM capabilities
ON CONFLICT DO NOTHING;

-- Bind the admin role to the admin entity over all resources
INSERT INTO policy_bindings (id, subject_kind, subject_id, grant_kind, grant_id, scope_kind, effect)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'entity',
    '00000000-0000-0000-0000-000000000001',
    'role',
    '00000000-0000-0000-0000-000000000002',
    'all',
    'allow'
)
ON CONFLICT DO NOTHING;
