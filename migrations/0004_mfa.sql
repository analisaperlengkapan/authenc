-- Multi-factor authentication.
--
-- Five tables, and the shape of them is most of the security:
--
--   * `mfa_challenges` exists so that a correct password does *not* produce a
--     session when a second factor is enrolled. It is a separate table from
--     `sessions` on purpose — a half-finished login is not a weak session, it
--     is not a session at all, and nothing that reads the session cookie can
--     ever be handed one of these by mistake.
--   * `totp_credentials.last_step` is the anti-replay record. A TOTP code is
--     valid for a whole time step, so without it an observed code can be spent
--     twice.
--   * `recovery_codes.used_at` makes each code single-use, claimed by an
--     atomic UPDATE rather than a read-then-write.
--   * `passkeys.credential` holds the signature counter that `webauthn-rs`
--     compares against, so it has to be written back after every assertion.
--   * `webauthn_ceremonies` keeps the challenge on the server. A challenge the
--     client can choose is not a challenge.

-- ---------------------------------------------------------------------------
-- TOTP
-- ---------------------------------------------------------------------------

CREATE TABLE totp_credentials (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    label        text NOT NULL,
    -- AES-256-GCM under the master key, with this row's id as associated data.
    -- The secret has to be recoverable to check a code, so it is encrypted
    -- rather than hashed; see `identity::sealed`.
    secret       bytea NOT NULL,
    secret_nonce bytea NOT NULL,
    -- NULL until the user has proved they can produce a code from it. An
    -- unconfirmed credential must never gate a login, or a failed enrolment
    -- locks the account out.
    confirmed_at timestamptz,
    -- Highest time step already spent. Any code from this step or earlier is
    -- refused even when it is arithmetically correct.
    last_step    bigint,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- One per user. More than one authenticator is what passkeys are for; a second
-- TOTP secret only widens the guessing surface.
CREATE UNIQUE INDEX totp_credentials_user_key ON totp_credentials (user_id);

-- ---------------------------------------------------------------------------
-- Recovery codes
-- ---------------------------------------------------------------------------

CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256, not Argon2: these carry full CSPRNG entropy, so there is no
    -- dictionary to slow down, and the login path would otherwise pay ten
    -- Argon2 verifications to find which code was presented.
    code_hash  bytea NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX recovery_codes_hash_key ON recovery_codes (code_hash);
CREATE INDEX recovery_codes_unused ON recovery_codes (user_id) WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- Passkeys
-- ---------------------------------------------------------------------------

CREATE TABLE passkeys (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The authenticator's own credential id, extracted so it can be indexed.
    credential_id bytea NOT NULL,
    label         text NOT NULL,
    -- The `webauthn_rs::prelude::Passkey`, which carries the public key and
    -- the signature counter. Written back after every successful assertion.
    credential    jsonb NOT NULL,
    last_used_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Globally unique: a credential id identifies one authenticator, and the same
-- one registered against two accounts would make the counter check meaningless.
CREATE UNIQUE INDEX passkeys_credential_id_key ON passkeys (credential_id);
CREATE INDEX passkeys_user ON passkeys (user_id);

-- ---------------------------------------------------------------------------
-- WebAuthn ceremony state
-- ---------------------------------------------------------------------------

CREATE TABLE webauthn_ceremonies (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL for a ceremony begun before the user is known. Every ceremony this
    -- server starts today names its user, but the column does not force it.
    user_id     uuid REFERENCES users (id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('registration', 'authentication')),
    -- Opaque handle given to the client. Only its hash is stored.
    token_hash  bytea NOT NULL,
    -- `PasskeyRegistration` or `PasskeyAuthentication`, holding the challenge.
    state       jsonb NOT NULL,
    consumed_at timestamptz,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX webauthn_ceremonies_token_hash_key ON webauthn_ceremonies (token_hash);
CREATE INDEX webauthn_ceremonies_expiry ON webauthn_ceremonies (expires_at);

-- ---------------------------------------------------------------------------
-- Pending logins
-- ---------------------------------------------------------------------------

CREATE TABLE mfa_challenges (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    realm_id    uuid NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    -- Opaque handle given to the client. Only its hash is stored, exactly as
    -- for a session token.
    token_hash  bytea NOT NULL,
    -- Wrong second factors so far. The challenge dies at a fixed budget, which
    -- is what stops a six-digit code from being guessed.
    attempts    integer NOT NULL DEFAULT 0,
    user_agent  text,
    ip_address  inet,
    consumed_at timestamptz,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX mfa_challenges_token_hash_key ON mfa_challenges (token_hash);
CREATE INDEX mfa_challenges_expiry ON mfa_challenges (expires_at);

-- ---------------------------------------------------------------------------
-- How a session was authenticated
-- ---------------------------------------------------------------------------

-- OIDC calls this `amr` — authentication methods references. Recorded on the
-- session so that how a login happened is settled at the moment it happens,
-- rather than inferred later from what the account has enrolled — which would
-- be wrong for every session opened before a factor was added.
--
-- It is not yet carried into ID tokens: doing that needs the value to travel
-- with the authorization code and the refresh family, which is protocol work
-- for a later stage. Until then this is the audit record, not a claim.
-- Defaulted to `{pwd}` because every session that exists when this migration
-- runs was opened by a password.
ALTER TABLE sessions
    ADD COLUMN authenticated_with text[] NOT NULL DEFAULT ARRAY['pwd']::text[];
