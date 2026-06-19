-- Keep database enforcement aligned with the application alias validator.
-- Aliases use the same character set as UUID text, so the slug CHECK alone
-- would otherwise allow canonical or compact UUID strings.

ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_alias_not_uuid
    CHECK (
        alias IS NULL OR alias !~ (
            '^([0-9a-f]{32}|'
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
        )
    );

ALTER TABLE entities
    ADD CONSTRAINT chk_entities_alias_not_uuid
    CHECK (
        alias IS NULL OR alias !~ (
            '^([0-9a-f]{32}|'
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
        )
    );

ALTER TABLE resources
    ADD CONSTRAINT chk_resources_alias_not_uuid
    CHECK (
        alias IS NULL OR alias !~ (
            '^([0-9a-f]{32}|'
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
        )
    );
