-- SQLite counterpart of migrations/005_file_storage.sql (file storage). Same
-- tables, indexes and invariants; see the PostgreSQL file for the reasoning.
--
-- Encodings match the rest of the SQLite baseline: UUIDs are BLOBs, booleans
-- are INTEGER 0/1, timestamps are fixed-width TEXT.
CREATE TABLE file_objects (
    resource_id  BLOB PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    tenant_id    BLOB,
    storage_key  TEXT NOT NULL UNIQUE,
    size_bytes   INTEGER NOT NULL CHECK (size_bytes >= 0),
    content_type TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    public       INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')
);

CREATE INDEX idx_file_objects_tenant ON file_objects(tenant_id);

CREATE TABLE blob_deletions (
    storage_key TEXT PRIMARY KEY,
    tenant_id   BLOB,
    queued_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT
);

CREATE INDEX idx_blob_deletions_queued ON blob_deletions(queued_at);

-- Foreign-key cascades fire these too, so a resource or tenant purge queues
-- its files' bytes like a direct delete does.
CREATE TRIGGER file_objects_queue_deleted_blob AFTER DELETE ON file_objects FOR EACH ROW
BEGIN
    INSERT INTO blob_deletions (storage_key, tenant_id)
    VALUES (OLD.storage_key, OLD.tenant_id)
    ON CONFLICT (storage_key) DO UPDATE SET queued_at = excluded.queued_at;
END;

CREATE TRIGGER file_objects_queue_replaced_blob AFTER UPDATE OF storage_key ON file_objects FOR EACH ROW
WHEN OLD.storage_key IS NOT NEW.storage_key
BEGIN
    INSERT INTO blob_deletions (storage_key, tenant_id)
    VALUES (OLD.storage_key, OLD.tenant_id)
    ON CONFLICT (storage_key) DO UPDATE SET queued_at = excluded.queued_at;
END;
