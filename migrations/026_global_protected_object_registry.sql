-- Exact object scopes carry only a UUID.  Reserve that UUID globally across
-- every physical table that backs a first-class protected object so one scope
-- can never name two different objects.

LOCK TABLE tenants, entities, resources, principal_groups, object_groups, roles,
           credentials, direct_policies, role_assignments, api_endpoints,
           permission_blocks, credential_permission_limits
    IN SHARE ROW EXCLUSIVE MODE;

-- Migration 001 used ...0001 for both the seeded admin entity and that
-- entity's seeded role assignment. Resolve this one known legacy collision to
-- a permanently reserved assignment UUID before enforcing the global
-- namespace. Exact-object blocks and access-token ceilings declare their
-- target kind, so only policy references move with the assignment; an
-- unclassified/invalid legacy reference must be repaired by the operator
-- instead of being guessed here.
DO $seed_assignment_remap$
DECLARE
    occupied text;
    invalid_scopes text;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM role_assignments
        WHERE id = '00000000-0000-0000-0000-000000000001'
          AND tenant_id IS NULL
          AND subject_kind = 'entity'
          AND subject_id = '00000000-0000-0000-0000-000000000001'
          AND role_id = '00000000-0000-0000-0000-000000000002'
    ) THEN
        SELECT string_agg(source_table, ', ' ORDER BY source_table)
        INTO occupied
        FROM (
            SELECT 'tenants' AS source_table FROM tenants
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'entities' FROM entities
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'resources' FROM resources
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'principal_groups' FROM principal_groups
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'object_groups' FROM object_groups
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'roles' FROM roles
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'credentials' FROM credentials
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'direct_policies' FROM direct_policies
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'role_assignments' FROM role_assignments
            WHERE id = '00000000-0000-0000-0000-00000000000a'
            UNION ALL SELECT 'api_endpoints' FROM api_endpoints
            WHERE id = '00000000-0000-0000-0000-00000000000a'
        ) occupied_sources;

        IF occupied IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE = 'reserved v1 admin role-assignment UUID 00000000-0000-0000-0000-00000000000a is already used by: ' || occupied,
                HINT = 'Remap the reported custom row before rerunning migration 026.';
        END IF;

        SELECT string_agg(
                   format('%s[%s, object_kind=%s]', source_table, id,
                          COALESCE(object_kind, 'NULL')),
                   '; ' ORDER BY source_table, id
               )
        INTO invalid_scopes
        FROM (
            SELECT 'permission_blocks'::text AS source_table, id, object_kind
            FROM permission_blocks
            WHERE scope_mode = 'object'
              AND object_id = '00000000-0000-0000-0000-000000000001'
              AND (object_kind IS NULL OR object_kind NOT IN ('entity', 'policy'))

            UNION ALL

            SELECT 'credential_permission_limits', id, object_kind
            FROM credential_permission_limits
            WHERE scope_mode = 'object'
              AND object_id = '00000000-0000-0000-0000-000000000001'
              AND (object_kind IS NULL OR object_kind NOT IN ('entity', 'policy'))
        ) invalid;

        IF invalid_scopes IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'unclassified exact-object reference targets legacy UUID 00000000-0000-0000-0000-000000000001: ' || invalid_scopes,
                HINT = 'Set each reported permission_blocks.object_kind or credential_permission_limits.object_kind to entity or policy before rerunning migration 026.';
        END IF;

        UPDATE permission_blocks
        SET object_id = '00000000-0000-0000-0000-00000000000a'
        WHERE scope_mode = 'object'
          AND object_kind = 'policy'
          AND object_id = '00000000-0000-0000-0000-000000000001';

        UPDATE credential_permission_limits
        SET object_id = '00000000-0000-0000-0000-00000000000a'
        WHERE scope_mode = 'object'
          AND object_kind = 'policy'
          AND object_id = '00000000-0000-0000-0000-000000000001';

        UPDATE role_assignments
        SET id = '00000000-0000-0000-0000-00000000000a'
        WHERE id = '00000000-0000-0000-0000-000000000001'
          AND tenant_id IS NULL
          AND subject_kind = 'entity'
          AND subject_id = '00000000-0000-0000-0000-000000000001'
          AND role_id = '00000000-0000-0000-0000-000000000002';
    END IF;
END
$seed_assignment_remap$;

DO $preflight$
DECLARE
    collisions text;
BEGIN
    WITH protected_rows(id, source_table, object_kind) AS (
        SELECT id, 'tenants', 'tenant' FROM tenants
        UNION ALL SELECT id, 'entities', 'entity' FROM entities
        UNION ALL SELECT id, 'resources', 'resource' FROM resources
        UNION ALL SELECT id, 'principal_groups', 'group' FROM principal_groups
        UNION ALL SELECT id, 'object_groups', 'group' FROM object_groups
        UNION ALL SELECT id, 'roles', 'role' FROM roles
        UNION ALL SELECT id, 'credentials', 'credential' FROM credentials
        UNION ALL SELECT id, 'direct_policies', 'policy' FROM direct_policies
        UNION ALL SELECT id, 'role_assignments', 'policy' FROM role_assignments
        UNION ALL SELECT id, 'api_endpoints', 'api_endpoint' FROM api_endpoints
    ), duplicates AS (
        SELECT id,
               string_agg(source_table || ':' || object_kind, ', ' ORDER BY source_table) AS sources
        FROM protected_rows
        GROUP BY id
        HAVING count(*) > 1
    )
    SELECT string_agg(id::text || ' => ' || sources, '; ' ORDER BY id)
    INTO collisions
    FROM duplicates;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'global protected-object UUID collisions: ' || collisions,
            HINT = 'Assign a distinct UUID to every reported row before rerunning migration 026.';
    END IF;
END
$preflight$;

CREATE TABLE protected_object_ids (
    id           UUID        PRIMARY KEY,
    object_kind  TEXT        NOT NULL,
    source_table TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT protected_object_ids_source_kind_check CHECK (
        (source_table = 'tenants'          AND object_kind = 'tenant')
        OR (source_table = 'entities'          AND object_kind = 'entity')
        OR (source_table = 'resources'         AND object_kind = 'resource')
        OR (source_table = 'principal_groups'  AND object_kind = 'group')
        OR (source_table = 'object_groups'     AND object_kind = 'group')
        OR (source_table = 'roles'             AND object_kind = 'role')
        OR (source_table = 'credentials'       AND object_kind = 'credential')
        OR (source_table = 'direct_policies'   AND object_kind = 'policy')
        OR (source_table = 'role_assignments'  AND object_kind = 'policy')
        OR (source_table = 'api_endpoints'      AND object_kind = 'api_endpoint')
    )
);

INSERT INTO protected_object_ids (id, source_table, object_kind)
SELECT id, 'tenants', 'tenant' FROM tenants
UNION ALL SELECT id, 'entities', 'entity' FROM entities
UNION ALL SELECT id, 'resources', 'resource' FROM resources
UNION ALL SELECT id, 'principal_groups', 'group' FROM principal_groups
UNION ALL SELECT id, 'object_groups', 'group' FROM object_groups
UNION ALL SELECT id, 'roles', 'role' FROM roles
UNION ALL SELECT id, 'credentials', 'credential' FROM credentials
UNION ALL SELECT id, 'direct_policies', 'policy' FROM direct_policies
UNION ALL SELECT id, 'role_assignments', 'policy' FROM role_assignments
UNION ALL SELECT id, 'api_endpoints', 'api_endpoint' FROM api_endpoints;

CREATE FUNCTION register_protected_object_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    kind text;
BEGIN
    kind := CASE TG_TABLE_NAME
        WHEN 'tenants' THEN 'tenant'
        WHEN 'entities' THEN 'entity'
        WHEN 'resources' THEN 'resource'
        WHEN 'principal_groups' THEN 'group'
        WHEN 'object_groups' THEN 'group'
        WHEN 'roles' THEN 'role'
        WHEN 'credentials' THEN 'credential'
        WHEN 'direct_policies' THEN 'policy'
        WHEN 'role_assignments' THEN 'policy'
        WHEN 'api_endpoints' THEN 'api_endpoint'
        ELSE NULL
    END;
    IF kind IS NULL THEN
        RAISE EXCEPTION 'unsupported protected-object source table %', TG_TABLE_NAME;
    END IF;
    INSERT INTO protected_object_ids (id, object_kind, source_table)
    VALUES (NEW.id, kind, TG_TABLE_NAME);
    RETURN NEW;
END
$$;

CREATE FUNCTION unregister_protected_object_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM protected_object_ids
    WHERE id = OLD.id AND source_table = TG_TABLE_NAME;
    RETURN OLD;
END
$$;

CREATE FUNCTION reject_protected_object_id_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = format('%s.id is immutable once registered', TG_TABLE_NAME);
END
$$;

CREATE FUNCTION reject_protected_object_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = format('TRUNCATE is not supported for protected-object table %s; use DELETE', TG_TABLE_NAME);
END
$$;

DO $triggers$
DECLARE
    source text;
BEGIN
    FOREACH source IN ARRAY ARRAY[
        'tenants', 'entities', 'resources', 'principal_groups', 'object_groups',
        'roles', 'credentials', 'direct_policies', 'role_assignments', 'api_endpoints'
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER register_protected_object_id AFTER INSERT ON %I FOR EACH ROW EXECUTE FUNCTION register_protected_object_id()',
            source
        );
        EXECUTE format(
            'CREATE TRIGGER unregister_protected_object_id AFTER DELETE ON %I FOR EACH ROW EXECUTE FUNCTION unregister_protected_object_id()',
            source
        );
        EXECUTE format(
            'CREATE TRIGGER reject_protected_object_id_update BEFORE UPDATE OF id ON %I FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id) EXECUTE FUNCTION reject_protected_object_id_update()',
            source
        );
        EXECUTE format(
            'CREATE TRIGGER reject_protected_object_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION reject_protected_object_truncate()',
            source
        );
    END LOOP;
END
$triggers$;

ALTER TABLE action_applicability
    DROP CONSTRAINT action_applicability_object_kind_check;
ALTER TABLE action_applicability
    ADD CONSTRAINT action_applicability_object_kind_check
    CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy',
                           'credential', 'audit_log', 'signing_key', 'api_endpoint'));

ALTER TABLE action_assignment_rules
    DROP CONSTRAINT action_assignment_rules_object_kind_check;
ALTER TABLE action_assignment_rules
    ADD CONSTRAINT action_assignment_rules_object_kind_check
    CHECK (object_kind IN ('entity', 'resource', 'group', 'tenant', 'role', 'policy',
                           'credential', 'audit_log', 'signing_key', 'api_endpoint'));

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, object_kind, NULL
FROM actions
CROSS JOIN LATERAL (
    VALUES
        ('read', 'role'),
        ('read', 'policy'),
        ('manage', 'policy'),
        ('read', 'api_endpoint'),
        ('manage', 'api_endpoint'),
        ('execute', 'api_endpoint')
) AS additions(action_name, object_kind)
WHERE actions.name = additions.action_name
ON CONFLICT DO NOTHING;
