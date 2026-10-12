ALTER TABLE oauth_login_states ADD COLUMN client_state TEXT;
ALTER TABLE auth_exchange_codes ADD COLUMN client_state TEXT;
ALTER TABLE auth_exchange_codes ADD COLUMN email TEXT;
