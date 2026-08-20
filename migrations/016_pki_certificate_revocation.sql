-- Issuer-aware, immediately authoritative certificate revocation state.
--
-- credentials.status remains the hot-path decision. This immutable companion
-- row records who revoked the exact credential, why, when, and which issuer's
-- publication artifacts must be refreshed. The trigger covers every lifecycle
-- path that transitions a certificate to revoked, including entity/tenant
-- deletion.

CREATE TABLE certificate_revocations (
    credential_id              UUID        PRIMARY KEY
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    -- issuer_id may become NULL only via the authority-purge FK cascade set
    -- up in migration 023. The record trigger enforces NOT NULL at INSERT.
    issuer_id                  UUID        REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    issuer_fingerprint_sha256  TEXT        NOT NULL
                                             CHECK (issuer_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    serial_number              TEXT        NOT NULL CHECK (serial_number ~ '^[0-9a-f]+$'),
    reason                     TEXT        NOT NULL CHECK (
                                             length(btrim(reason)) BETWEEN 1 AND 128
                                           ),
    -- Deliberately not an FK: revocation evidence must retain the actor UUID
    -- after that actor is purged, and an ON DELETE action would conflict with
    -- this table's immutability trigger.
    actor_entity_id            UUID,
    revoked_at                 TIMESTAMPTZ NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_certificate_revocations_issuer
    ON certificate_revocations(issuer_id, revoked_at DESC)
    WHERE issuer_id IS NOT NULL;

CREATE INDEX idx_certificate_revocations_issuer_fingerprint
    ON certificate_revocations(issuer_fingerprint_sha256, revoked_at DESC);

-- Preserve already-revoked data during rollout. Old rows did not have a
-- normalized actor column; that nullable field stays explicitly unknown
-- rather than being invented. Every revoked certificate must map to a
-- managed pki_authorities row — the join is INNER, so any orphan cert
-- fails migration loud.
INSERT INTO certificate_revocations (
    credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
    reason, actor_entity_id, revoked_at
)
SELECT c.id,
       c.issuer_id,
       a.fingerprint_sha256,
       c.identifier,
       left(COALESCE(NULLIF(btrim(c.metadata->>'revocation_reason'), ''), 'unspecified'), 128),
       CASE
           WHEN c.metadata->>'revoked_by_entity_id'
                ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
           THEN (c.metadata->>'revoked_by_entity_id')::uuid
       END,
       CASE
           WHEN c.metadata->>'revoked_at' ~ '^\d{4}-\d{2}-\d{2}[T ]'
           THEN (c.metadata->>'revoked_at')::timestamptz
           ELSE c.created_at
       END
  FROM credentials c
  JOIN pki_authorities a ON a.id = c.issuer_id
 WHERE c.kind = 'certificate'
   AND c.status = 'revoked'
   AND c.identifier IS NOT NULL
ON CONFLICT (credential_id) DO NOTHING;

-- Any existing per-issuer cache represented by a revoked credential is stale.
INSERT INTO certificate_crl_state (
    issuer_fingerprint_sha256, issuer_id, crl_number, dirty
)
SELECT DISTINCT ON (r.issuer_fingerprint_sha256)
       r.issuer_fingerprint_sha256, r.issuer_id, 0, TRUE
  FROM certificate_revocations r
 ORDER BY r.issuer_fingerprint_sha256, r.revoked_at DESC
ON CONFLICT (issuer_fingerprint_sha256) DO UPDATE
    SET dirty = TRUE,
        issuer_id = COALESCE(certificate_crl_state.issuer_id, EXCLUDED.issuer_id),
        updated_at = now();

CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time         TIMESTAMPTZ;
    event_reason       TEXT;
    event_actor        UUID;
    issuer_fingerprint TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    SELECT a.fingerprint_sha256
      INTO issuer_fingerprint
      FROM pki_authorities a
     WHERE a.id = NEW.issuer_id;
    IF issuer_fingerprint IS NULL THEN
        RAISE EXCEPTION 'revoked certificate % missing pki_authorities row for issuer_id %',
            NEW.id, NEW.issuer_id USING ERRCODE = '23514';
    END IF;

    event_time := COALESCE((NEW.metadata->>'revoked_at')::timestamptz, now());
    event_reason := left(
        COALESCE(NULLIF(btrim(NEW.metadata->>'revocation_reason'), ''), 'unspecified'),
        128
    );
    event_actor := NULLIF(NEW.metadata->>'revoked_by_entity_id', '')::uuid;

    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at
    ) VALUES (
        NEW.id, NEW.issuer_id, issuer_fingerprint, NEW.identifier,
        event_reason, event_actor, event_time
    )
    ON CONFLICT (credential_id) DO NOTHING;

    -- CRL/OCSP generation is deliberately outside this PR. Mark only the
    -- exact issuer cache stale; never fan out to unrelated tenants/issuers.
    INSERT INTO certificate_crl_state (
        issuer_fingerprint_sha256, issuer_id, crl_number, dirty
    ) VALUES (issuer_fingerprint, NEW.issuer_id, 0, TRUE)
    ON CONFLICT (issuer_fingerprint_sha256) DO UPDATE
        SET dirty = TRUE,
            issuer_id = COALESCE(
                certificate_crl_state.issuer_id,
                EXCLUDED.issuer_id
            ),
            updated_at = now();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_credentials_record_certificate_revocation
    AFTER INSERT OR UPDATE OF status ON credentials
    FOR EACH ROW EXECUTE FUNCTION record_certificate_revocation();

-- The ledger is immutable evidence. Credential deletion cascades it; all
-- other mutation attempts are rejected.
CREATE OR REPLACE FUNCTION prevent_certificate_revocation_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'certificate revocation records are immutable'
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_revocations_immutable
    BEFORE UPDATE ON certificate_revocations
    FOR EACH ROW EXECUTE FUNCTION prevent_certificate_revocation_mutation();
