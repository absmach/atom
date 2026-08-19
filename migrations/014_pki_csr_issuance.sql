-- Idempotency ledger for managed, CSR-based leaf issuance.
--
-- The public idempotency token and CSR are never stored.  Only keyed request
-- identity and payload digests are retained, and the row commits atomically
-- with the issuer-bound certificate credential.

CREATE TABLE certificate_issuance_requests (
    id                          UUID        PRIMARY KEY,
    entity_id                   UUID        NOT NULL
                                             REFERENCES entities(id) ON DELETE CASCADE,
    request_key_hash            TEXT        NOT NULL
                                             CHECK (request_key_hash ~ '^[0-9a-f]{64}$'),
    request_fingerprint_sha256  TEXT        NOT NULL
                                             CHECK (request_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    credential_id               UUID        UNIQUE
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at                TIMESTAMPTZ,

    CONSTRAINT uq_certificate_issuance_request_key
        UNIQUE (entity_id, request_key_hash),
    CONSTRAINT chk_certificate_issuance_request_state
        CHECK ((credential_id IS NULL AND completed_at IS NULL)
            OR (credential_id IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE INDEX idx_certificate_issuance_requests_credential
    ON certificate_issuance_requests(credential_id)
    WHERE credential_id IS NOT NULL;

-- A retry ledger may only resolve to the managed certificate created for the
-- same entity.  This repeats the service invariant at the database boundary.
CREATE OR REPLACE FUNCTION enforce_certificate_issuance_request_credential()
RETURNS trigger AS $$
DECLARE
    credential_entity_id UUID;
    credential_kind      TEXT;
    credential_issuer_id UUID;
BEGIN
    IF NEW.credential_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT entity_id, kind, issuer_id
      INTO credential_entity_id, credential_kind, credential_issuer_id
      FROM credentials
     WHERE id = NEW.credential_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    IF credential_entity_id <> NEW.entity_id
       OR credential_kind <> 'certificate'
       OR credential_issuer_id IS NULL THEN
        RAISE EXCEPTION 'issuance request must reference its issuer-bound entity certificate'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_issuance_request_credential
    BEFORE INSERT OR UPDATE OF entity_id, credential_id
    ON certificate_issuance_requests
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_issuance_request_credential();
