-- Config-driven bootstrap of the platform intermediate authority uses a new
-- provisioning_mode value 'config_bootstrap' distinct from the other
-- interactive flows (imported/offline/automated).

ALTER TABLE pki_authorities
    DROP CONSTRAINT IF EXISTS pki_authorities_provisioning_mode_check;

ALTER TABLE pki_authorities
    ADD CONSTRAINT pki_authorities_provisioning_mode_check
        CHECK (provisioning_mode IN ('imported', 'offline', 'automated', 'config_bootstrap'));
