-- Issuer-aware, immediately authoritative certificate revocation state.
--
-- credentials.status remains the hot-path decision. This immutable companion
-- row records who revoked the exact credential, why, when, and which issuer's
-- publication artifacts must be refreshed. The trigger covers every lifecycle
-- path that transitions a certificate to revoked, including entity/tenant
-- deletion and compatibility mutations.

CREATE TABLE certificate_revocations (
    credential_id              UUID        PRIMARY KEY
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    issuer_id                  UUID        REFERENCES pki_authorities(id) ON DELETE RESTRICT,
    issuer_fingerprint_sha256  TEXT        CHECK (
                                             issuer_fingerprint_sha256 IS NULL
                                             OR issuer_fingerprint_sha256 ~ '^[0-9a-f]{64}$'
                                           ),
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
    ON certificate_revocations(issuer_fingerprint_sha256, revoked_at DESC)
    WHERE issuer_fingerprint_sha256 IS NOT NULL;

-- Preserve already-revoked data during rollout. Old rows did not have a
-- normalized actor column and some historical fixtures lack issuer metadata;
-- those nullable fields stay explicitly unknown rather than being invented.
INSERT INTO certificate_revocations (
    credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
    reason, actor_entity_id, revoked_at
)
SELECT c.id,
       c.issuer_id,
       CASE
           WHEN a.fingerprint_sha256 ~ '^[0-9a-f]{64}$'
           THEN a.fingerprint_sha256
           WHEN c.metadata->>'issuer_fingerprint_sha256' ~ '^[0-9a-f]{64}$'
           THEN c.metadata->>'issuer_fingerprint_sha256'
       END,
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
  LEFT JOIN pki_authorities a ON a.id = c.issuer_id
 WHERE c.kind = 'certificate'
   AND c.status = 'revoked'
   AND c.identifier IS NOT NULL
ON CONFLICT (credential_id) DO NOTHING;

-- Any existing per-issuer cache represented by a revoked credential is stale.
UPDATE certificate_crl_state s
   SET dirty = TRUE,
       issuer_id = COALESCE(s.issuer_id, r.issuer_id),
       updated_at = now()
  FROM certificate_revocations r
 WHERE r.issuer_fingerprint_sha256 = s.issuer_fingerprint_sha256;

INSERT INTO certificate_crl_state (
    issuer_fingerprint_sha256, issuer_id, crl_number, dirty
)
SELECT DISTINCT ON (r.issuer_fingerprint_sha256)
       r.issuer_fingerprint_sha256, r.issuer_id, 0, TRUE
  FROM certificate_revocations r
 WHERE r.issuer_fingerprint_sha256 IS NOT NULL
   AND NOT EXISTS (
       SELECT 1 FROM certificate_crl_state s
        WHERE s.issuer_fingerprint_sha256 = r.issuer_fingerprint_sha256
   )
   AND (
       r.issuer_id IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM certificate_crl_state s WHERE s.issuer_id = r.issuer_id
       )
   )
 ORDER BY r.issuer_fingerprint_sha256, r.revoked_at DESC;

CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time       TIMESTAMPTZ;
    event_reason     TEXT;
    event_actor      UUID;
    issuer_fingerprint TEXT;
    existing_fingerprint TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    event_time := COALESCE((NEW.metadata->>'revoked_at')::timestamptz, now());
    event_reason := left(
        COALESCE(NULLIF(btrim(NEW.metadata->>'revocation_reason'), ''), 'unspecified'),
        128
    );
    event_actor := NULLIF(NEW.metadata->>'revoked_by_entity_id', '')::uuid;
    IF NEW.issuer_id IS NOT NULL THEN
        SELECT a.fingerprint_sha256
          INTO issuer_fingerprint
          FROM pki_authorities a
         WHERE a.id = NEW.issuer_id;
    END IF;
    issuer_fingerprint := COALESCE(
        issuer_fingerprint,
        NULLIF(NEW.metadata->>'issuer_fingerprint_sha256', '')
    );

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
    IF issuer_fingerprint IS NOT NULL THEN
        IF NEW.issuer_id IS NOT NULL THEN
            SELECT s.issuer_fingerprint_sha256
              INTO existing_fingerprint
              FROM certificate_crl_state s
             WHERE s.issuer_id = NEW.issuer_id
             FOR UPDATE;
            IF FOUND THEN
                IF existing_fingerprint <> issuer_fingerprint THEN
                    RAISE EXCEPTION 'certificate issuer artifact fingerprint mismatch'
                        USING ERRCODE = '23514';
                END IF;
                UPDATE certificate_crl_state
                   SET dirty = TRUE, updated_at = now()
                 WHERE issuer_id = NEW.issuer_id;
                RETURN NEW;
            END IF;
        END IF;

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
    END IF;

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
