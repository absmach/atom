-- =============================================================
-- TENANTS
--
-- A tenant is an isolation boundary, not a principal. Entities,
-- groups, resources, and roles may be scoped to one tenant via
-- their tenant_id column. Platform/global objects keep tenant_id
-- NULL and are not constrained by tenant lifecycle.
--
-- Magistrala Domain maps directly to an Atom Tenant: the domain
-- UUID becomes tenants.id and is reused as tenant_id everywhere.
-- =============================================================
CREATE TABLE tenants (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    route       TEXT,
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'inactive', 'frozen', 'deleted')),
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    attributes  JSONB       NOT NULL DEFAULT '{}',
    created_by  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    updated_by  UUID        REFERENCES entities(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_tenants_name  ON tenants(name);
CREATE UNIQUE INDEX idx_tenants_route ON tenants(route) WHERE route IS NOT NULL;
CREATE INDEX        idx_tenants_status ON tenants(status);
CREATE INDEX        idx_tenants_attrs  ON tenants USING GIN(attributes);
CREATE INDEX        idx_tenants_tags   ON tenants USING GIN(tags);

-- =============================================================
-- Foreign keys from existing tenant_id columns to tenants(id).
--
-- NULL tenant_id remains valid for platform/global objects (e.g.
-- the seeded atom-admin entity). We use NOT VALID so the migration
-- does not fail on installations that already have non-NULL
-- tenant_id values pointing at tenants that were never modelled
-- as rows; new INSERTs/UPDATEs are still constrained.
-- =============================================================
ALTER TABLE entities
    ADD CONSTRAINT entities_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    ON DELETE SET NULL
    NOT VALID;

ALTER TABLE groups
    ADD CONSTRAINT groups_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    ON DELETE SET NULL
    NOT VALID;

ALTER TABLE resources
    ADD CONSTRAINT resources_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    ON DELETE SET NULL
    NOT VALID;

ALTER TABLE roles
    ADD CONSTRAINT roles_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    ON DELETE SET NULL
    NOT VALID;
