-- File storage (src/files/, src/storage/).
--
-- A file is a resource of kind `file`: tenant, owner, groups, attributes,
-- soft delete, audit and events are the resource's. This table holds what only
-- the server may set about its bytes -- above all where they are stored.
-- Attributes are client-writable (`updateResource`), so a storage key kept
-- there could be pointed at another tenant's object.
CREATE TABLE file_objects (
    resource_id  UUID PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    tenant_id    UUID,
    storage_key  TEXT NOT NULL UNIQUE,
    size_bytes   BIGINT NOT NULL CHECK (size_bytes >= 0),
    content_type TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    public       BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Quota sums a tenant's stored bytes on every upload.
CREATE INDEX idx_file_objects_tenant ON file_objects(tenant_id);

-- Bytes to delete from the store, once `queued_at` is older than the
-- deletion grace period. The store is outside every transaction, so bytes are
-- never deleted inline: a row here is written in the same transaction that
-- stops referring to them, and a worker deletes them after commit, retrying.
-- An upload queues its own key before writing and unqueues it when it
-- commits, so bytes whose upload never committed are collected too.
--
-- The worker claims a row (`claim_id`, `claimed_at`) before deleting its bytes
-- and removes it only after the delete succeeds, so a worker that dies
-- mid-batch leaves its claims to expire and be retried. An upload commits
-- only by removing an unclaimed row; one that finds its key claimed clears
-- the claim instead, so the worker's acknowledgement no longer matches and
-- the row stays to collect the late bytes.
CREATE TABLE blob_deletions (
    storage_key TEXT PRIMARY KEY,
    tenant_id   UUID,
    queued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    claim_id    UUID,
    claimed_at  TIMESTAMPTZ
);

CREATE INDEX idx_blob_deletions_queued ON blob_deletions(queued_at);

-- Every path that physically removes a file row -- purging the resource, the
-- retention purge, a tenant purge cascading through resources -- and every
-- replacement of a file's bytes queues the old key here, in the same
-- transaction, so no path can drop a row and leave its bytes behind.
CREATE FUNCTION queue_file_blob_deletion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO blob_deletions (storage_key, tenant_id)
    VALUES (OLD.storage_key, OLD.tenant_id)
    ON CONFLICT (storage_key) DO UPDATE SET queued_at = now();
    RETURN NULL;
END;
$$;

CREATE TRIGGER file_objects_queue_deleted_blob
    AFTER DELETE ON file_objects
    FOR EACH ROW EXECUTE FUNCTION queue_file_blob_deletion();

CREATE TRIGGER file_objects_queue_replaced_blob
    AFTER UPDATE OF storage_key ON file_objects
    FOR EACH ROW WHEN (OLD.storage_key IS DISTINCT FROM NEW.storage_key)
    EXECUTE FUNCTION queue_file_blob_deletion();
