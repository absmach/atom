-- Object group membership becomes many-to-many.
--
-- `object_group_entities` / `object_group_resources` keyed membership by the
-- member alone, so an entity or resource could belong to at most one object
-- group. That forbids overlapping object sets ("Customer A meters" and
-- "Building 5 meters" intersecting without either containing the other), which
-- a hierarchy cannot express. Membership is a grouping primitive; the
-- constraint is removed rather than any product semantics added.
--
-- Both member tables move together. Splitting them would leave a permanent
-- asymmetry in tables that are read by the same queries and the same scope
-- predicate.

-- Data-preserving: every existing row already has a distinct member id, so it
-- is trivially distinct under the wider key too.
ALTER TABLE object_group_entities
    DROP CONSTRAINT object_group_entities_pkey,
    ADD PRIMARY KEY (group_id, entity_id);

ALTER TABLE object_group_resources
    DROP CONSTRAINT object_group_resources_pkey,
    ADD PRIMARY KEY (group_id, resource_id);

-- The old member-keyed PK index served the member-side lookup ("which groups is
-- this entity in?"). The new PK leads with group_id, so that lookup needs its
-- own index; conversely the standalone group_id indexes are now redundant with
-- the PK's leading column.
DROP INDEX idx_object_group_entities_group;
DROP INDEX idx_object_group_resources_group;

CREATE INDEX idx_object_group_entities_entity ON object_group_entities(entity_id);
CREATE INDEX idx_object_group_resources_resource ON object_group_resources(resource_id);

-- ─── Scope predicate: one membership → a set of memberships ────────────────────
-- `grant_scope_matches` is the single scope predicate shared by every authorized
-- listing reader, mirroring the PDP's Rust `scope_values_match` (a parity test
-- pins them together). Its `p_parent_group UUID` argument assumed one membership
-- and would have silently ignored grants held through an object's other groups.
-- It becomes `p_parent_groups UUID[]`: a group scope matches when it names ANY
-- of the object's groups.
--
-- The group arms are rewritten from string equality against a single group id to
-- the split/`= ANY` form already used by the tree arms — still sublink-free, so
-- PostgreSQL can inline the function into the listing queries.
DROP FUNCTION grant_scope_matches(TEXT, TEXT, TEXT, TEXT, UUID, UUID, UUID, UUID[]);

CREATE FUNCTION grant_scope_matches(
    p_scope_kind    TEXT,
    p_scope_ref     TEXT,
    p_coarse_kind   TEXT,
    p_sub_kind      TEXT,
    p_object_id     UUID,
    p_object_tenant UUID,
    p_parent_groups UUID[],
    p_ancestors     UUID[]
)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE p_scope_kind
        WHEN 'platform' THEN TRUE
        WHEN 'tenant' THEN p_object_tenant IS NOT NULL AND p_scope_ref = p_object_tenant::text
        WHEN 'object_kind' THEN p_scope_ref = p_coarse_kind
        WHEN 'object_type' THEN p_scope_ref = p_coarse_kind || ':' || p_sub_kind
        WHEN 'object' THEN p_scope_ref = p_object_id::text
        WHEN 'group_object_type' THEN
            substr(p_scope_ref, strpos(p_scope_ref, ':') + 1) = p_coarse_kind || ':' || p_sub_kind
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_parent_groups)
        WHEN 'group_tree_object_type' THEN
            substr(p_scope_ref, strpos(p_scope_ref, ':') + 1) = p_coarse_kind || ':' || p_sub_kind
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_ancestors)
        WHEN 'group_child_kind' THEN
            p_coarse_kind = 'group'
            AND split_part(p_scope_ref, ':', 2) = 'group'
            AND split_part(p_scope_ref, ':', 1)::uuid = ANY(p_parent_groups)
        WHEN 'group_descendant_kind' THEN
            p_coarse_kind = 'group'
            AND split_part(p_scope_ref, ':', 2) = 'group'
            AND (
                split_part(p_scope_ref, ':', 1)::uuid = ANY(p_parent_groups)
                OR split_part(p_scope_ref, ':', 1)::uuid = ANY(p_ancestors)
            )
        ELSE FALSE
    END
$$;
