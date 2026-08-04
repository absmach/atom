-- Remove the two product-specific applicability rows migration 001 originally
-- seeded for magistrala (`publish`/`subscribe` on `resource:channel`,
-- `execute` on `resource:rule`). These are IoT-flavoured defaults that don't
-- belong in a generic authorization service — each product ships its own
-- vocabulary via the bootstrap config file (see src/bootstrap.rs
-- `capabilities` section, and the companion PR in magistrala).
--
-- Kept as a separate migration rather than editing 001 in place: modifying an
-- already-applied migration changes its checksum and makes sqlx refuse to
-- start against any existing deployment. This delta migration is safe both
-- for fresh installs (the rows are seeded by 001 and then removed here — a
-- few wasted inserts, no functional change) and for upgrades.

DELETE FROM action_applicability
WHERE (object_kind, object_type) IN (
    ('resource', 'resource:channel'),
    ('resource', 'resource:rule')
);
