-- Password reset and email verification.
--
-- Both follow the same shape as sessions: a high-entropy token goes to the
-- user, only its hash is stored, and consumption is a single atomic UPDATE so
-- a token cannot be redeemed twice even under concurrent requests.

CREATE TABLE password_reset_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- Set when redeemed. A row is spent, not deleted, so a second attempt can
    -- be distinguished from an unknown token in the audit trail.
    used_at    TIMESTAMPTZ,

    CONSTRAINT password_reset_tokens_hash_unique UNIQUE (token_hash)
);

CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens (user_id);
CREATE INDEX password_reset_tokens_expires_at_idx ON password_reset_tokens (expires_at);

CREATE TABLE email_verification_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The address being proven, recorded separately from `users.email` so that
    -- changing the address mid-flight cannot cause an old link to verify the
    -- new one.
    email      TEXT        NOT NULL,
    token_hash BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,

    CONSTRAINT email_verification_tokens_hash_unique UNIQUE (token_hash)
);

CREATE INDEX email_verification_tokens_user_id_idx ON email_verification_tokens (user_id);
CREATE INDEX email_verification_tokens_expires_at_idx ON email_verification_tokens (expires_at);
