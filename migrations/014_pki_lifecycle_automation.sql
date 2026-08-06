-- PR-015: durable, replica-safe lifecycle notification ledger.
--
-- The marker and its event_outbox row are written in the same transaction.
-- A unique window identity makes retries, restarts, and concurrent replicas
-- converge on one notification without relying on process memory.
CREATE TABLE pki_lifecycle_notifications (
    subject_kind   TEXT        NOT NULL
                               CHECK (subject_kind IN ('credential', 'authority')),
    subject_id     UUID        NOT NULL
                               CHECK (subject_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    window_kind    TEXT        NOT NULL
                               CHECK (window_kind IN (
                                   'renewal',
                                   'expiry',
                                   'authority_expiry'
                               )),
    window_at      TIMESTAMPTZ NOT NULL,
    emitted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_kind, subject_id, window_kind, window_at)
);

CREATE INDEX idx_pki_lifecycle_notifications_emitted
    ON pki_lifecycle_notifications (emitted_at);

-- Supports stable expiry-window pagination independent of credential creation
-- order. Existing issuer/status indexes continue to serve the other filters.
CREATE INDEX idx_credentials_certificate_expiry_listing
    ON credentials (expires_at, id)
    WHERE kind = 'certificate' AND expires_at IS NOT NULL;

COMMENT ON TABLE pki_lifecycle_notifications IS
    'Exactly-once-per-window notification ledger for PR-015 lifecycle sweeps';
