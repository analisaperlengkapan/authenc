-- Organisations: a tenant boundary *inside* a realm.
--
-- The question worth answering before adding this table at all is what an
-- organisation does that a group does not, because "a group with a different
-- name" is exactly the kind of ceremony this repository is meant to be free of.
-- Three things:
--
--   1. **It can be suspended.** Disabling an organisation stops its members
--      signing in, without touching a single user row. That is the "suspend
--      this customer" control a B2B deployment needs, and groups have no
--      equivalent.
--   2. **People join it by invitation**, through a link sent to an email
--      address, rather than by an administrator adding them.
--   3. **Membership carries a role inside the organisation** — owner, admin,
--      member — which is about who runs the customer's account, and is
--      deliberately separate from the realm's RBAC.
--
-- A group remains what it was: a bucket for realm role assignment, arranged in
-- a hierarchy. The two do not overlap and neither replaces the other.

CREATE TABLE organizations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id   uuid NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    -- URL-safe handle, unique within the realm.
    slug       text NOT NULL,
    name       text NOT NULL,
    -- False suspends every member's ability to sign in. See the rule in
    -- `identity::organization::blocks_sign_in`, which is more careful than
    -- "any disabled organisation blocks you".
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX organizations_slug ON organizations (realm_id, lower(slug));
CREATE INDEX organizations_realm ON organizations (realm_id);

CREATE TABLE organization_members (
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Who runs the customer's account. Not realm RBAC: an organisation owner
    -- has no permissions over the realm, and a realm administrator does not
    -- become an organisation owner by being one.
    role            text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX organization_members_user ON organization_members (user_id);

-- ---------------------------------------------------------------------------
-- Invitations
-- ---------------------------------------------------------------------------
--
-- The token is a credential: possession of the link is the proof that the
-- invited mailbox received it. Only its hash is stored, exactly as for session
-- tokens and password-reset links, so a database disclosure yields nothing
-- anyone can redeem.
--
-- `accepted_by` is recorded separately from `email` on purpose. An invitation
-- forwarded to somebody else and accepted by them is a real thing that
-- happens; it cannot be prevented by a link, but it must be *visible*, and a
-- row that only recorded the invited address would hide it.

CREATE TABLE organization_invitations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email           text NOT NULL,
    role            text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    token_hash      bytea NOT NULL,
    invited_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    accepted_at     timestamptz,
    accepted_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX organization_invitations_token ON organization_invitations (token_hash);
CREATE INDEX organization_invitations_org ON organization_invitations (organization_id);
CREATE INDEX organization_invitations_expiry ON organization_invitations (expires_at);

-- One open invitation per address per organisation. Re-inviting replaces the
-- old one rather than leaving two live links to the same seat.
CREATE UNIQUE INDEX organization_invitations_pending
    ON organization_invitations (organization_id, lower(email))
    WHERE accepted_at IS NULL;
