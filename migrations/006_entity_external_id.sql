-- Entity `external_id` — an identifier assigned outside Atom (serial number,
-- MAC address, employee number, SKU). Purely additive: one nullable column on
-- `entities` plus a partial unique index. Every existing row gets NULL, and
-- nothing reads the column until a client writes one.
--
-- `external_id` is deliberately NOT `alias`. `alias` is a human-friendly,
-- URL-safe handle that Atom constrains to a lowercase slug; `external_id` is a
-- foreign key into someone else's namespace that Atom must not constrain and
-- never interprets. The only rules below are sanity limits (length, no edge
-- whitespace), not format validation.

ALTER TABLE entities ADD COLUMN external_id TEXT;

-- ── Decision 1: CASE-SENSITIVE ───────────────────────────────────────────────
-- `ABC123` and `abc123` are two different entities.
--
-- This is a deliberate departure from the `alias` precedent two indexes up
-- (`idx_entities_alias`, which indexes `lower(alias)`) — it is not an oversight.
-- Aliases are case-folded handles Atom owns; external identifiers belong to a
-- vendor whose scheme may legitimately distinguish case, and folding them would
-- silently merge two physical devices into one row with no migration back.
--
-- Case-sensitive is the conservative direction: it can be tightened to
-- case-insensitive later (by rebuilding this index on `lower(external_id)` once
-- the data is known to be free of case-only collisions), whereas relaxing a
-- case-insensitive index after two devices have already merged is not
-- recoverable — the second write never happened.
--
-- ── Decision 2: WHITESPACE IS TRIMMED ────────────────────────────────────────
-- `"ABC123 "` and `"ABC123"` are the same entity, not two.
--
-- Leading/trailing whitespace in an external identifier is always a transport
-- artifact (a trailing newline off a serial console, a padded CSV cell), never
-- meaningful data. The application trims before storing and before comparing;
-- `chk_entities_external_id_trimmed` below enforces the same rule at the schema
-- level so the decision is a property of the data rather than of whichever
-- client happened to write the row first. Interior whitespace is preserved —
-- only the edges are a transport artifact.
--
-- ── Scoping ──────────────────────────────────────────────────────────────────
-- Unique per tenant, over live rows only:
--   * NULLs are excluded — most entities have no external identifier, and a
--     partial index costs nothing where the value is absent.
--   * Soft-deleted rows are excluded, so retiring a meter frees its serial for
--     the replacement unit. The cost is that `restoreEntity` can now fail on a
--     conflict if the serial was re-used during the retention window; the
--     application maps that 23505 to a comprehensible conflict rather than
--     letting a raw constraint violation surface.
--   * Two *different* tenants may hold the same serial — that is legitimate and
--     explicitly out of scope for uniqueness.
--
-- `COALESCE(tenant_id, ...)` mirrors `idx_entities_name_tenant` and
-- `idx_entities_alias`: `tenant_id` is nullable (platform-level entities), and
-- indexing it raw would make every NULL distinct under SQL NULL semantics, so
-- tenant-less entities would get no uniqueness at all — exactly the silent
-- double-claim this index exists to prevent. The zero UUID stands in for the
-- global namespace; it is not a real tenant id (`tenants.id` is
-- `gen_random_uuid()`), so it cannot collide with one.
--
-- `external_id` leads the index, unlike the tenant-leading `name`/`alias`
-- indexes. Column order does not affect what the index enforces — a unique
-- index on `(a, b)` and on `(b, a)` reject exactly the same rows — but it does
-- decide which lookups it can serve. The read pattern here is "find the entity
-- holding this serial", with the tenant sometimes narrowing it and sometimes
-- not (`entities(externalId:)` takes an optional `tenantId`); leading with
-- `external_id` serves both, whereas leading with the tenant would leave an
-- un-scoped serial lookup unable to seek.
CREATE UNIQUE INDEX idx_entities_external_id
    ON entities (
        external_id,
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE external_id IS NOT NULL AND deleted_at IS NULL;

-- Sanity limits only — deliberately not format validation. The value stays
-- opaque: uppercase, `/`, `.`, interior spaces, quotes and unicode are all
-- accepted, because consumers own their own namespaces (Magistrala rejects `/`
-- because the value travels verbatim in a topic; that is Magistrala's rule, not
-- Atom's).
--
-- Length: `TEXT` is unbounded and a btree index entry over a multi-kilobyte
-- value is pathological (and past ~2704 bytes Postgres refuses the insert
-- outright, which would surface as an incomprehensible index error rather than
-- a validation message). 255 characters is far beyond any real serial, MAC or
-- SKU. `length()` counts characters, not bytes, matching the application check.
ALTER TABLE entities ADD CONSTRAINT chk_entities_external_id_length
    CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 255);

-- Whitespace: enforces decision 2 at the schema level. Interior whitespace is
-- fine; an edge space, tab or newline is not.
ALTER TABLE entities ADD CONSTRAINT chk_entities_external_id_trimmed
    CHECK (external_id IS NULL OR external_id !~ '^\s|\s$');
