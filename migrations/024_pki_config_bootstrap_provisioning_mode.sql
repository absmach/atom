-- Config-driven bootstrap of the platform intermediate authority uses a new
-- provisioning mode value to distinguish rows that came from disk-supplied
-- material at startup from the earlier interactive flows (imported/offline/
-- automated). The check constraint was defined in migration 012; widen it in
-- place instead of relaxing it, so previously-persisted rows keep their tight
-- lexical guarantee.

ALTER TABLE pki_authorities
    DROP CONSTRAINT IF EXISTS pki_authorities_provisioning_mode_check;

ALTER TABLE pki_authorities
    ADD CONSTRAINT pki_authorities_provisioning_mode_check
        CHECK (provisioning_mode IN ('imported', 'offline', 'automated', 'config_bootstrap'));
