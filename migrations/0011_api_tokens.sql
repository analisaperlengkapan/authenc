-- Machine-to-machine API tokens.
--
-- `/api/v1` is authenticated by the same session cookie the console uses, so
-- an automated client has to sign in as a person and echo the CSRF token. That
-- works and is wrong: it means a Terraform provider holds somebody's password,
-- and the audit trail records their name for everything it does.
--
-- # A token is never more than the person who made it
--
-- `api_tokens.permissions` is checked against the creator's own permissions at
-- creation, so a token cannot be a privilege escalation. That check alone is
-- not enough, though, because permissions change: the resolved authority is
-- the **intersection** of this column and what the bound user holds *now*.
-- Losing a role therefore narrows every token that user made, immediately and
-- without anybody remembering to go and revoke them.
--
-- The alternative — a token that keeps what it was granted — produces exactly
-- the failure an offboarding process is supposed to prevent: the account is
-- disabled, and the automation it created carries on with the authority it
-- used to have.
--
-- # Why it is bound to a user at all
--
-- Because something has to be answerable for it. A token with no owner is one
-- nobody notices is still live, and an audit line reading "a token did this"
-- names nothing an incident can act on. A service account is a user; making it
-- one means every existing rule — realm isolation, disabled accounts,
-- suspended organisations — applies to it without being restated.

CREATE TABLE api_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id    uuid NOT NULL REFERENCES realms (id) ON DELETE CASCADE,

    -- The account this token acts as.
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- What an operator calls it, so a list of tokens is readable.
    name        text NOT NULL CHECK (length(trim(name)) > 0),

    -- SHA-256 of the presented token, as for every other credential here. The
    -- token itself exists once, at creation.
    token_hash  bytea NOT NULL UNIQUE,

    -- A visible, non-secret prefix, so an operator reading a log or a CI
    -- configuration can tell *which* token it is without holding the token.
    prefix      text NOT NULL,

    -- The permission names this token may use, narrowed further at every
    -- request by what the bound user currently holds.
    permissions text[] NOT NULL,

    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),

    -- Optional. A token with no expiry is a decision, not an oversight, and
    -- the console shows which ones are like that.
    expires_at  timestamptz,

    -- Written on use, so "is anything still using this?" has an answer before
    -- somebody revokes it. Deliberately not written on every request in a
    -- transaction the request waits for; see `identity::api_token`.
    last_used_at timestamptz,

    revoked_at  timestamptz,

    -- One name per account, so revoking "ci" is unambiguous.
    UNIQUE (user_id, name)
);

-- Lookup is by hash on every authenticated API request.
CREATE INDEX api_tokens_hash ON api_tokens (token_hash) WHERE revoked_at IS NULL;

-- "What does this account have outstanding?" — the offboarding question.
CREATE INDEX api_tokens_user ON api_tokens (user_id);
