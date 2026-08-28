#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL to the v0.50.0 database}"

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required for the v1 upgrade readiness check" >&2
  exit 1
fi

# Read-only mirror of the startup checks that run before migrations 007 and
# 025. Keep this available for operators whose migration runner is separate
# from Atom.
psql "$DATABASE_URL" --set ON_ERROR_STOP=1 <<'SQL'
BEGIN TRANSACTION READ ONLY;

DO $preflight$
DECLARE
    affected text;
BEGIN
    IF to_regclass('public.actions') IS NULL
       OR to_regclass('public.action_applicability') IS NULL
       OR to_regclass('public._sqlx_migrations') IS NULL THEN
        RAISE NOTICE 'legacy Atom tables are absent; applicability preflight is not needed';
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM _sqlx_migrations WHERE version = 7 AND success
    ) THEN
        RAISE NOTICE 'migration 007 is already applied; reconcile any pre-release applicability loss from a pre-007 backup or intended bootstrap config';
        RETURN;
    END IF;

    SELECT string_agg(
               format('%s on %s / %s', actions.name,
                      applicability.object_kind, applicability.object_type),
               '; ' ORDER BY actions.name, applicability.object_kind,
                            applicability.object_type
           )
    INTO affected
    FROM action_applicability applicability
    JOIN actions ON actions.id = applicability.action_id
    WHERE (applicability.object_kind, applicability.object_type) IN (
              ('resource', 'resource:channel'),
              ('resource', 'resource:rule')
          );

    IF affected IS NOT NULL THEN
        RAISE EXCEPTION USING
            MESSAGE = 'v1 upgrade blocked: action applicability rows would be removed by migration 007: '
                      || affected,
            HINT = 'Declare every row under capabilities[].applicability in ATOM_BOOTSTRAP_FILE, then remove the copied rows from v0.50 and rerun this check before the external migration runner.';
    END IF;
END
$preflight$;

DO $preflight$
DECLARE
    collisions text;
BEGIN
    IF to_regclass('public.entities') IS NULL
       OR to_regclass('public.entity_emails') IS NULL
       OR to_regclass('public._sqlx_migrations') IS NULL THEN
        RAISE NOTICE 'legacy Atom tables are absent; email preflight is not needed';
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM _sqlx_migrations WHERE version = 25 AND success
    ) THEN
        RAISE NOTICE 'migration 025 is already applied; email preflight is not needed';
        RETURN;
    END IF;

    WITH prospective_active_emails AS (
        SELECT ee.entity_id, lower(ee.email) AS email
        FROM entity_emails ee
        WHERE ee.deleted_at IS NULL

        UNION ALL

        SELECT e.id, lower(trim(e.attributes->>'email')) AS email
        FROM entities e
        WHERE e.kind = 'human'
          AND e.deleted_at IS NULL
          AND NOT EXISTS (
                SELECT 1 FROM entity_emails ee WHERE ee.entity_id = e.id
          )
          AND e.attributes->>'email' IS NOT NULL
          AND trim(e.attributes->>'email') ~
              '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    ), duplicate_emails AS (
        SELECT email, array_agg(entity_id ORDER BY entity_id) AS entity_ids
        FROM prospective_active_emails
        GROUP BY email
        HAVING count(*) > 1
    )
    SELECT string_agg(format('%s => %s', email, entity_ids::text), '; ' ORDER BY email)
    INTO collisions
    FROM duplicate_emails;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION USING
            MESSAGE = 'v1 upgrade blocked: case-insensitive legacy email collisions: '
                      || collisions,
            HINT = 'Choose one owning entity per email and change or remove the other legacy email values in v0.50, then rerun this check.';
    END IF;
END
$preflight$;

DO $preflight$
DECLARE
    missing_tables text;
    collisions text;
BEGIN
    IF to_regclass('public._sqlx_migrations') IS NULL THEN
        RAISE NOTICE 'legacy Atom tables are absent; protected-object UUID preflight is not needed';
        RETURN;
    END IF;

    SELECT string_agg(table_name, ', ' ORDER BY table_name)
    INTO missing_tables
    FROM (
        VALUES
            ('api_endpoints'),
            ('credentials'),
            ('direct_policies'),
            ('entities'),
            ('object_groups'),
            ('principal_groups'),
            ('resources'),
            ('role_assignments'),
            ('roles'),
            ('tenants')
    ) AS expected(table_name)
    WHERE to_regclass('public.' || table_name) IS NULL;

    IF missing_tables IS NOT NULL THEN
        RAISE EXCEPTION USING
            MESSAGE = 'v1 upgrade blocked: partial legacy schema is missing protected-object table(s): '
                      || missing_tables,
            HINT = 'Restore a complete v0.50 database before running the v1 upgrade readiness check.';
    END IF;

    IF EXISTS (
        SELECT 1 FROM _sqlx_migrations WHERE version = 26 AND success
    ) THEN
        RAISE NOTICE 'migration 026 is already applied; protected-object UUID uniqueness is enforced';
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM role_assignments assignment
        JOIN permission_blocks block
          ON block.scope_mode = 'object'
         AND block.object_id = assignment.id
         AND block.object_kind IS NULL
        WHERE assignment.id = '00000000-0000-0000-0000-000000000001'
          AND assignment.tenant_id IS NULL
          AND assignment.subject_kind = 'entity'
          AND assignment.subject_id = '00000000-0000-0000-0000-000000000001'
          AND assignment.role_id = '00000000-0000-0000-0000-000000000002'
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'v1 upgrade blocked: an exact-object scope targets legacy UUID 00000000-0000-0000-0000-000000000001 without object_kind',
            HINT = 'Set each affected permission_blocks.object_kind to entity or policy, then rerun this read-only check.';
    END IF;

    WITH protected_objects AS (
        SELECT id, 'tenant'::text AS object_kind, 'tenants'::text AS source_table,
               id AS tenant_id
        FROM tenants
        UNION ALL
        SELECT id, 'entity', 'entities', tenant_id FROM entities
        UNION ALL
        SELECT id, 'resource', 'resources', tenant_id FROM resources
        UNION ALL
        SELECT id, 'group', 'principal_groups', tenant_id FROM principal_groups
        UNION ALL
        SELECT id, 'group', 'object_groups', tenant_id FROM object_groups
        UNION ALL
        SELECT id, 'role', 'roles', tenant_id FROM roles
        UNION ALL
        SELECT c.id, 'credential', 'credentials', e.tenant_id
        FROM credentials c
        JOIN entities e ON e.id = c.entity_id
        UNION ALL
        SELECT id, 'policy', 'direct_policies', tenant_id FROM direct_policies
        UNION ALL
        SELECT CASE
                   WHEN id = '00000000-0000-0000-0000-000000000001'
                    AND tenant_id IS NULL
                    AND subject_kind = 'entity'
                    AND subject_id = '00000000-0000-0000-0000-000000000001'
                    AND role_id = '00000000-0000-0000-0000-000000000002'
                   THEN '00000000-0000-0000-0000-00000000000a'::uuid
                   ELSE id
               END,
               'policy', 'role_assignments', tenant_id
        FROM role_assignments
        UNION ALL
        SELECT id, 'api_endpoint', 'api_endpoints', tenant_id FROM api_endpoints
    ), duplicate_ids AS (
        SELECT id,
               string_agg(
                   format('%s[%s, tenant=%s]', source_table, object_kind,
                          COALESCE(tenant_id::text, 'platform')),
                   ', ' ORDER BY source_table
               ) AS sources
        FROM protected_objects
        GROUP BY id
        HAVING count(*) > 1
    )
    SELECT string_agg(format('%s => %s', id, sources), '; ' ORDER BY id)
    INTO collisions
    FROM duplicate_ids;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION USING
            MESSAGE = 'v1 upgrade blocked: protected-object UUID collision(s): ' || collisions,
            HINT = 'Remap every reported duplicate in v0.50, including all referencing rows, then rerun this read-only check.';
    END IF;
END
$preflight$;

COMMIT;
SQL

echo "v1 upgrade applicability, email, and protected-object UUID preflights passed; no data was modified"
