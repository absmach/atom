-- Distinguishes a structurally-invalid row (payload no longer matches
-- DomainEventPayload, e.g. left over from an older schema_version) from a
-- row that has simply failed to publish so far. Only the former is safe to
-- ever stop retrying: retrying a bad deserialize can never succeed, while a
-- publish failure may just be a broker outage that recovers, and must stay
-- retryable no matter how long that takes.

ALTER TABLE event_outbox
    ADD COLUMN unparseable BOOLEAN NOT NULL DEFAULT false;
