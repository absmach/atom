-- SQLite counterpart of migrations/003_object_coordination.sql (object
-- revisions, leases, and the change-request journal). Same tables, indexes
-- and invariants; see the PostgreSQL file for the reasoning.
--
-- Encodings match the rest of the SQLite baseline: UUIDs are BLOBs, JSON
-- columns are TEXT, timestamps are TEXT.

ALTER TABLE entities ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE resources ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

-- PostgreSQL bumps the revision in a BEFORE UPDATE trigger by assigning to
-- NEW; SQLite triggers cannot assign to NEW, so bump in an AFTER UPDATE
-- trigger instead. The WHEN guard keeps the bump from re-firing on the
-- trigger's own UPDATE (and lets a statement set revision explicitly).
CREATE TRIGGER entities_revision AFTER UPDATE ON entities FOR EACH ROW
WHEN NEW.revision = OLD.revision
BEGIN
    UPDATE entities SET revision = OLD.revision + 1 WHERE id = NEW.id;
END;

CREATE TRIGGER resources_revision AFTER UPDATE ON resources FOR EACH ROW
WHEN NEW.revision = OLD.revision
BEGIN
    UPDATE resources SET revision = OLD.revision + 1 WHERE id = NEW.id;
END;

CREATE TABLE object_leases (
    object_kind TEXT NOT NULL CHECK (object_kind IN ('entity', 'resource')),
    object_id BLOB NOT NULL,
    actor_id BLOB NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    holder_id BLOB NOT NULL,
    operation TEXT NOT NULL,
    fence INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (object_kind, object_id)
);

CREATE TABLE object_change_requests (
    actor_id BLOB NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    request_id BLOB NOT NULL,
    request TEXT NOT NULL,
    response TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    PRIMARY KEY (actor_id, request_id)
);

CREATE INDEX object_change_requests_expiry ON object_change_requests(created_at);

-- Polymorphic lease targets must be removed on every physical purge path.
CREATE TRIGGER entities_purge_leases AFTER DELETE ON entities FOR EACH ROW
BEGIN
    DELETE FROM object_leases WHERE object_kind = 'entity' AND object_id = OLD.id;
END;

CREATE TRIGGER resources_purge_leases AFTER DELETE ON resources FOR EACH ROW
BEGIN
    DELETE FROM object_leases WHERE object_kind = 'resource' AND object_id = OLD.id;
END;
