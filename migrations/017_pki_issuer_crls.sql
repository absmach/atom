-- Issuer-keyed CRL publication state with a legacy fingerprint namespace.
--
-- Managed authorities move to a stable issuer UUID key without replacing the
-- physical row that already owns the last published CRL number. Legacy file
-- issuers keep their fingerprint key and cached artifact until their separate
-- migration is complete.

ALTER TABLE certificate_crl_state
    ADD COLUMN state_key TEXT GENERATED ALWAYS AS (
        CASE
            WHEN issuer_id IS NULL
            THEN 'fingerprint:' || issuer_fingerprint_sha256
            ELSE 'issuer:' || issuer_id::text
        END
    ) STORED,
    ADD COLUMN crl_sha256 TEXT;

UPDATE certificate_crl_state
   SET crl_sha256 = CASE
           WHEN crl_der IS NULL THEN NULL
           ELSE encode(digest(crl_der, 'sha256'), 'hex')
       END;

ALTER TABLE certificate_crl_state
    DROP CONSTRAINT certificate_crl_state_pkey,
    ADD CONSTRAINT certificate_crl_state_pkey PRIMARY KEY (state_key),
    ADD CONSTRAINT chk_certificate_crl_state_hash CHECK (
        (crl_der IS NULL AND crl_sha256 IS NULL)
        OR (
            crl_der IS NOT NULL
            AND crl_sha256 ~ '^[0-9a-f]{64}$'
            AND crl_sha256 = encode(digest(crl_der, 'sha256'), 'hex')
        )
    );

CREATE UNIQUE INDEX idx_certificate_crl_state_fingerprint
    ON certificate_crl_state(issuer_fingerprint_sha256);

-- PR-008 owns authoritative revocation. Replacing its trigger here changes
-- only the artifact-state representation: managed rows use issuer UUID keys,
-- while legacy rows continue to use fingerprint keys.
CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time             TIMESTAMPTZ;
    event_reason           TEXT;
    event_actor            UUID;
    issuer_fingerprint     TEXT;
    existing_fingerprint   TEXT;
    existing_issuer        UUID;
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

    IF issuer_fingerprint IS NULL THEN
        RETURN NEW;
    END IF;

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

    SELECT s.issuer_id
      INTO existing_issuer
      FROM certificate_crl_state s
     WHERE s.issuer_fingerprint_sha256 = issuer_fingerprint
     FOR UPDATE;
    IF FOUND
       AND existing_issuer IS NOT NULL
       AND existing_issuer IS DISTINCT FROM NEW.issuer_id THEN
        RAISE EXCEPTION 'certificate artifact fingerprint belongs to another issuer'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO certificate_crl_state (
        issuer_fingerprint_sha256, issuer_id, crl_number, dirty
    ) VALUES (
        issuer_fingerprint, NEW.issuer_id, 0, TRUE
    )
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
