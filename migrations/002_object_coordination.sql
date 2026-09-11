-- Revisions cover every writer, including the existing identity/resource APIs.
ALTER TABLE entities ADD COLUMN revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE resources ADD COLUMN revision BIGINT NOT NULL DEFAULT 1;
CREATE FUNCTION advance_object_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.revision := OLD.revision + 1; RETURN NEW; END;
$$;
CREATE TRIGGER entities_revision BEFORE UPDATE ON entities FOR EACH ROW EXECUTE FUNCTION advance_object_revision();
CREATE TRIGGER resources_revision BEFORE UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION advance_object_revision();

CREATE TABLE object_leases (
    object_kind TEXT NOT NULL CHECK (object_kind IN ('entity', 'resource')),
    object_id UUID NOT NULL,
    actor_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    holder_id UUID NOT NULL,
    operation TEXT NOT NULL,
    fence BIGINT NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (object_kind, object_id)
);
CREATE TABLE object_change_requests (
    actor_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    request JSONB NOT NULL,
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor_id, request_id)
);
CREATE INDEX object_change_requests_expiry ON object_change_requests(created_at);

-- Polymorphic lease targets must be removed on every physical purge path.
CREATE FUNCTION purge_object_leases() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM object_leases WHERE object_kind = TG_ARGV[0] AND object_id = OLD.id;
    RETURN OLD;
END;
$$;
CREATE TRIGGER entities_purge_leases AFTER DELETE ON entities FOR EACH ROW EXECUTE FUNCTION purge_object_leases('entity');
CREATE TRIGGER resources_purge_leases AFTER DELETE ON resources FOR EACH ROW EXECUTE FUNCTION purge_object_leases('resource');
