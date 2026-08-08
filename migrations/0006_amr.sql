-- Carry `amr` from the session that authorised a request through to the tokens
-- issued for it.
--
-- `sessions.authenticated_with` (migration 0004) records how a login actually
-- happened. Until now it stopped there: a relying party reading an ID token
-- could not tell a password-only sign-in from one behind a passkey, which is
-- most of what `amr` is for.
--
-- The value has to travel, because the moments are separated. The session is
-- authenticated once; the authorization code is redeemed seconds later; a
-- refresh token mints new ID tokens for days afterwards. Recomputing at
-- issuance would be wrong twice over — the session may be gone, and what the
-- account has enrolled *now* is not what was presented *then*.
--
-- So it is copied forward, snapshot-style, at each hop. `{pwd}` is the default
-- for rows that predate this, matching migration 0004's reasoning.

ALTER TABLE authorization_codes
    ADD COLUMN authenticated_with text[] NOT NULL DEFAULT ARRAY['pwd']::text[];

ALTER TABLE refresh_tokens
    ADD COLUMN authenticated_with text[] NOT NULL DEFAULT ARRAY['pwd']::text[];
