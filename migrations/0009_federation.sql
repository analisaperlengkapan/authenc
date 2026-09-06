-- Social login: signing in with an account held somewhere else.
--
-- Two tables, and the interesting decisions are both about *linking* rather
-- than about the protocol.
--
-- # Why the upstream subject, and not the email, is the identity
--
-- `federated_identities.subject` is the upstream `sub` claim, and the unique
-- index is on `(provider_id, subject)`. An email address is not an identity:
-- it can be reassigned, and at several providers it can be *changed by the
-- account holder*. Keying on it would mean that whoever holds an address today
-- inherits whatever the previous holder had linked.
--
-- # Why adopting an existing account is off by default
--
-- `link_by_verified_email` decides whether an upstream account whose address
-- matches a local user may take that user over. Left on, it is an account
-- takeover primitive: an attacker who can make a provider assert
-- `admin@yourcompany.example` gets the local administrator. Several providers
-- have historically returned addresses they never verified, and at least one
-- lets an account hold an address it has not proved. So it is off unless an
-- operator turns it on per provider, and even then `identity::federation`
-- refuses unless the upstream asserts the address is verified.
--
-- # Why the endpoints are stored rather than derived
--
-- A `kind` of `google` could imply Google's URLs in Rust. It does not, because
-- a provider that moves an endpoint would then need a release, and because the
-- same code has to serve a plain OIDC provider nobody here has heard of.
-- `kind` selects the *claim mapping*, which is the part that genuinely differs.

CREATE TABLE identity_providers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id      uuid NOT NULL REFERENCES realms (id) ON DELETE CASCADE,

    -- Appears in the callback path, so it is URL-safe and stable.
    alias         text NOT NULL CHECK (alias ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    -- Selects the claim mapping: 'google', 'github', 'microsoft', 'facebook',
    -- 'apple', or 'oidc' for anything standards-compliant.
    kind          text NOT NULL,
    display_name  text NOT NULL CHECK (length(trim(display_name)) > 0),

    client_id     text NOT NULL,
    -- AES-256-GCM under the master key, with the provider id as associated
    -- data, exactly like an OAuth signing key. A secret readable from a
    -- database dump is a secret shared with whoever takes the backup.
    client_secret_ciphertext bytea NOT NULL,
    client_secret_nonce      bytea NOT NULL,

    authorization_endpoint text NOT NULL,
    token_endpoint         text NOT NULL,
    -- Absent for a provider that returns everything in the ID token.
    userinfo_endpoint      text,
    -- Present for a real OIDC provider; used to verify the ID token's `iss`.
    issuer                 text,
    scopes                 text[] NOT NULL,

    enabled       boolean NOT NULL DEFAULT true,
    -- Whether an upstream account nobody here has seen may create a local one.
    allow_provisioning     boolean NOT NULL DEFAULT true,
    -- See the note above. Off by default, deliberately.
    link_by_verified_email boolean NOT NULL DEFAULT false,

    created_at    timestamptz NOT NULL DEFAULT now(),

    UNIQUE (realm_id, alias)
);

CREATE TABLE federated_identities (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id   uuid NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- The upstream `sub`. The identity; see above.
    subject       text NOT NULL,

    -- What the upstream said at link time, kept for display and for an
    -- operator answering "which Google account is this?". Never consulted
    -- when resolving a sign-in.
    upstream_email text,
    upstream_name  text,

    linked_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,

    -- One upstream account signs in as exactly one local account.
    UNIQUE (provider_id, subject),
    -- And one local account holds at most one identity per provider, so
    -- "which link is authoritative?" has no answer to get wrong.
    UNIQUE (provider_id, user_id)
);

CREATE INDEX federated_identities_user ON federated_identities (user_id);

-- ---------------------------------------------------------------------------
-- A note for anyone upgrading
-- ---------------------------------------------------------------------------
--
-- This release adds the `identity_provider:read` and `identity_provider:write`
-- permissions. As with `audit:read` in migration 0005, they are **not** granted
-- to roles that already exist: quietly widening what a role can do is how a
-- permission model stops meaning anything. Grant them through
-- `/api/v1/roles/{id}/permissions` or the console.

-- ---------------------------------------------------------------------------
-- `amr` has to tell the truth about a federated sign-in
-- ---------------------------------------------------------------------------
--
-- A social sign-in behind a second factor takes the same two steps as a
-- password one, and goes through the same `mfa_challenges` row — deliberately,
-- because the alternative is a federated path that skips MFA, which would make
-- adding a provider a way around it.
--
-- But the two are not the same event. `mfa::amr_for` used to hardcode `pwd` as
-- the first element, so a Google sign-in would have told a relying party that
-- this server verified a password. It did not. The challenge therefore records
-- which first factor was actually satisfied, and `open_session` reads it.
--
-- `pwd` is the default for rows that predate this, matching migrations 0004
-- and 0006.

ALTER TABLE mfa_challenges
    ADD COLUMN first_factor text NOT NULL DEFAULT 'pwd'
        CHECK (first_factor IN ('pwd', 'fed'));
