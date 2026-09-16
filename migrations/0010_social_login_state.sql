-- The state a social sign-in leaves on the server between its two requests.
--
-- An OAuth client's callback is the mirror image of the provider endpoints
-- this server already offers, and it needs the same three things kept where
-- the browser cannot choose them.
--
--   * `state` defeats login CSRF. Without it an attacker completes a sign-in
--     with *their* provider account in *your* browser, and everything you do
--     afterwards happens in their account — including anything you paste into
--     it. Only the hash is stored, as for every other token here.
--   * `pkce_verifier` is the secret half of the PKCE challenge. It has to
--     outlive the redirect, and the browser must never see it.
--   * `nonce` is echoed in the provider's ID token, which is what stops a
--     token minted for one login being replayed into another.
--
-- Single-use and expiring, claimed by one atomic UPDATE, exactly like an
-- authorization code. A read-then-write would let two concurrent callbacks
-- both succeed.

CREATE TABLE federation_login_states (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id   uuid NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,

    -- SHA-256 of the `state` parameter. The parameter itself is never stored,
    -- so a database read does not let anyone complete a pending sign-in.
    state_hash    bytea NOT NULL UNIQUE,

    pkce_verifier text NOT NULL,
    nonce         text NOT NULL,

    -- The exact `redirect_uri` sent to the provider. Replayed verbatim at the
    -- token endpoint, because the provider compares them and a mismatch is
    -- the error that takes an afternoon to find.
    redirect_uri  text NOT NULL,

    -- Where to send the browser once signed in.
    --
    -- Constrained to a same-origin path here rather than checked in Rust,
    -- because this is the open redirect the previous tree actually shipped.
    --
    -- A single leading slash and no second one: `//evil.example` and
    -- `/\evil.example` are both protocol-relative to a browser and would send
    -- the visitor somewhere else entirely.
    --
    -- Control characters and spaces are refused as well, and that half is not
    -- decoration. Browsers strip tab, newline, and carriage return from a URL
    -- *before* parsing it, so `/<TAB>//evil.example` — which passes a rule
    -- that only looks at the second character — arrives at the parser as
    -- `//evil.example`. The first version of this constraint accepted it.
    return_to     text CHECK (
        return_to IS NULL
        OR return_to ~ '^/([^/\\[:cntrl:] ][^[:cntrl:] ]*)?$'
    ),

    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz
);

-- The retention sweep deletes by age, as for sessions and codes.
CREATE INDEX federation_login_states_expiry ON federation_login_states (expires_at);
