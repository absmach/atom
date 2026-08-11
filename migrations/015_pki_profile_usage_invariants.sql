-- An empty KeyUsage or ExtendedKeyUsage extension is not a restriction. When
-- rcgen receives an empty list it omits the extension, and relying parties can
-- interpret the certificate as valid for unrestricted purposes. Every stored
-- leaf profile must therefore name at least one usage in both categories.

ALTER TABLE certificate_profiles
    ADD CONSTRAINT chk_certificate_profiles_nonempty_key_usages
        CHECK (cardinality(key_usages) > 0),
    ADD CONSTRAINT chk_certificate_profiles_nonempty_extended_key_usages
        CHECK (cardinality(extended_key_usages) > 0);
