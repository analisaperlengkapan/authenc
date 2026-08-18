-- Groups: a hierarchy of users within a realm, carrying role grants.
--
-- The tree is the easy part. What makes groups mean anything is that
-- `user::permissions` resolves *through* it — a member of `/engineering/backend`
-- holds the roles granted to `backend` and to `engineering` above it. A group
-- feature that stores a hierarchy and never consults it during authorisation is
-- an org chart, not access control.
--
-- Inheritance runs upward, from a group to its ancestors. That direction is the
-- one people expect and the safer of the two: adding a child group cannot widen
-- what its parent's members can do, so nesting is never a privilege escalation.

CREATE TABLE groups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id    uuid NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    -- Deleting a group deletes its whole subtree. Stated because it is a real
    -- decision: the alternative — orphaning children to the root — silently
    -- promotes them, and a group that quietly gains a new parent's roles is
    -- exactly the surprise access control must not produce.
    parent_id   uuid REFERENCES groups (id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    -- Cheap guard; the trigger below catches the rest.
    CONSTRAINT groups_not_own_parent CHECK (parent_id IS DISTINCT FROM id)
);

-- Names are unique among siblings, not globally: two teams may both have a
-- `backend` group as long as they sit under different parents. Two partial
-- indexes rather than one over `COALESCE(parent_id, …)`, because a sentinel
-- UUID standing in for "no parent" is a value that can also be a real id.
CREATE UNIQUE INDEX groups_root_name ON groups (realm_id, lower(name))
    WHERE parent_id IS NULL;
CREATE UNIQUE INDEX groups_child_name ON groups (parent_id, lower(name))
    WHERE parent_id IS NOT NULL;

CREATE INDEX groups_realm ON groups (realm_id);
CREATE INDEX groups_parent ON groups (parent_id) WHERE parent_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- No cycles
-- ---------------------------------------------------------------------------
--
-- Enforced in the database rather than in Rust, because a cycle is not merely
-- invalid data: every ancestry walk over it is a query that does not terminate
-- on its own, and the permission resolver runs one on every request. A rule
-- whose violation hangs the authorisation path belongs where nothing can route
-- around it.
--
-- The recursive walk inside the trigger is itself safe: it can only run on a
-- tree this trigger has already kept acyclic.

CREATE FUNCTION groups_reject_cycle() RETURNS trigger AS $$
BEGIN
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        WITH RECURSIVE ancestry AS (
            SELECT id, parent_id FROM groups WHERE id = NEW.parent_id
            UNION
            SELECT g.id, g.parent_id
              FROM groups g
              JOIN ancestry a ON g.id = a.parent_id
        )
        SELECT 1 FROM ancestry WHERE id = NEW.id
    ) THEN
        RAISE EXCEPTION 'that would make % an ancestor of itself', NEW.id
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER groups_no_cycles
    BEFORE INSERT OR UPDATE OF parent_id ON groups
    FOR EACH ROW EXECUTE FUNCTION groups_reject_cycle();

-- ---------------------------------------------------------------------------
-- Membership and grants
-- ---------------------------------------------------------------------------

CREATE TABLE group_members (
    group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX group_members_user ON group_members (user_id);

CREATE TABLE group_roles (
    group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    role_id  uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX group_roles_role ON group_roles (role_id);
