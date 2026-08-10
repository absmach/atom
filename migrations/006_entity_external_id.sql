-- `external_id` — an identifier assigned outside Atom (serial number, MAC
-- address, employee number, SKU). Purely additive: one nullable column plus
-- a partial unique index; existing rows get NULL.
--
-- Not `alias`: `alias` is a human-friendly slug Atom owns and constrains;
-- `external_id` is a foreign key into someone else's namespace and stays
-- opaque. The constraints below are sanity limits, not format validation.

ALTER TABLE entities ADD COLUMN external_id TEXT;

-- Case-sensitive: `ABC123` and `abc123` are different entities, unlike
-- `alias` (indexed on `lower(alias)`). Vendor schemes may distinguish case,
-- and folding is irreversible once two devices have merged under one value.
--
-- Whitespace is trimmed: `"ABC123 "` and `"ABC123"` are the same entity —
-- edge whitespace is a transport artifact, not data. Enforced both here and
-- in the application (`chk_entities_external_id_trimmed` below), so it holds
-- regardless of which client writes first. Interior whitespace is preserved.
--
-- Unique per tenant among live rows: NULLs and soft-deleted rows are excluded
-- (a retired serial is free for reuse; `restoreEntity` can then conflict if
-- it was reused during the retention window). `COALESCE(tenant_id, ...)`
-- mirrors `idx_entities_alias` so platform-level entities (`tenant_id IS
-- NULL`) get real uniqueness instead of every NULL comparing distinct. The
-- index leads with `external_id` rather than the tenant because lookups are
-- sometimes tenant-scoped and sometimes not (`entities(externalId:)` takes
-- an optional `tenantId`).
CREATE UNIQUE INDEX idx_entities_external_id
    ON entities (
        external_id,
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE external_id IS NOT NULL AND deleted_at IS NULL;

-- Sanity cap, not format validation — the value stays opaque (uppercase,
-- `/`, `.`, spaces, unicode all accepted). `length()` counts characters, to
-- match the application check.
ALTER TABLE entities ADD CONSTRAINT chk_entities_external_id_length
    CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 255);

ALTER TABLE entities ADD CONSTRAINT chk_entities_external_id_trimmed
    CHECK (external_id IS NULL OR external_id !~ '^\s|\s$');
