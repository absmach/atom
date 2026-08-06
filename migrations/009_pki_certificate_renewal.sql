-- Exact-credential renewal history and idempotency ledger.
--
-- A certificate may have at most one replacement. The public idempotency
-- token and CSR are never stored; only domain-separated digests are retained.
-- The pending row, replacement credential, optional old-certificate
-- revocation, and completion link are committed in one transaction.

CREATE TABLE certificate_renewals (
    id                          UUID        PRIMARY KEY,
    previous_credential_id      UUID        NOT NULL UNIQUE
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    request_key_hash            TEXT        NOT NULL
                                             CHECK (request_key_hash ~ '^[0-9a-f]{64}$'),
    request_fingerprint_sha256  TEXT        NOT NULL
                                             CHECK (request_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    key_mode                    TEXT        NOT NULL CHECK (key_mode IN ('csr', 'generated')),
    replacement_credential_id   UUID        UNIQUE
                                             REFERENCES credentials(id) ON DELETE CASCADE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at                TIMESTAMPTZ,

    CONSTRAINT chk_certificate_renewal_state
        CHECK ((replacement_credential_id IS NULL AND completed_at IS NULL)
            OR (replacement_credential_id IS NOT NULL AND completed_at IS NOT NULL))
);

CREATE INDEX idx_certificate_renewals_replacement
    ON certificate_renewals(replacement_credential_id)
    WHERE replacement_credential_id IS NOT NULL;

-- Keep the service's history invariants at the database boundary: both sides
-- are certificate credentials for one entity, the replacement is managed by
-- an explicit issuer, and its immutable metadata points back to the exact old
-- credential rather than an ambiguous serial.
CREATE OR REPLACE FUNCTION enforce_certificate_renewal_link()
RETURNS trigger AS $$
DECLARE
    previous_entity_id UUID;
    previous_kind      TEXT;
    replacement_entity_id UUID;
    replacement_kind      TEXT;
    replacement_issuer_id UUID;
    replacement_previous_id TEXT;
BEGIN
    SELECT entity_id, kind
      INTO previous_entity_id, previous_kind
      FROM credentials
     WHERE id = NEW.previous_credential_id;

    IF NOT FOUND OR previous_kind <> 'certificate' THEN
        RAISE EXCEPTION 'renewal source must be a certificate credential'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.replacement_credential_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.replacement_credential_id = NEW.previous_credential_id THEN
        RAISE EXCEPTION 'renewal replacement must differ from its source'
            USING ERRCODE = '23514';
    END IF;

    SELECT entity_id, kind, issuer_id,
           metadata->>'renewed_from_credential_id'
      INTO replacement_entity_id, replacement_kind,
           replacement_issuer_id, replacement_previous_id
      FROM credentials
     WHERE id = NEW.replacement_credential_id;

    IF NOT FOUND
       OR replacement_kind <> 'certificate'
       OR replacement_issuer_id IS NULL
       OR replacement_entity_id <> previous_entity_id
       OR replacement_previous_id IS DISTINCT FROM NEW.previous_credential_id::text THEN
        RAISE EXCEPTION 'renewal replacement must be an issuer-bound certificate for the same entity'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_renewal_link
    BEFORE INSERT OR UPDATE OF previous_credential_id, replacement_credential_id
    ON certificate_renewals
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_renewal_link();
