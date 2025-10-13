-- Groups Table
-- Provides hierarchical group management for organizing users
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id) ON DELETE CASCADE, -- For hierarchical groups
    
    -- Group identity
    name VARCHAR(255) NOT NULL,
    path TEXT NOT NULL, -- Full hierarchical path (e.g., /parent/child)
    
    -- Group metadata
    description TEXT,
    attributes JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Ensure unique names within realm and parent
    CONSTRAINT uq_groups_name_parent UNIQUE (realm_id, parent_id, name),
    CONSTRAINT uq_groups_path UNIQUE (realm_id, path)
);

-- User Groups Junction Table
-- Links users to groups with optional metadata
CREATE TABLE user_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    
    -- Membership metadata
    joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP, -- Optional group membership expiration
    
    -- Additional attributes (e.g., role within group)
    attributes JSONB DEFAULT '{}'::jsonb,
    
    -- Ensure a user can only be in a group once
    CONSTRAINT uq_user_groups UNIQUE (user_id, group_id)
);

-- Group Roles Junction Table
-- Assigns roles to groups (all members inherit these roles)
CREATE TABLE group_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    
    -- Assignment metadata
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Ensure a role can only be assigned to a group once
    CONSTRAINT uq_group_roles UNIQUE (group_id, role_id)
);

-- Group Attributes Table (normalized attributes for complex queries)
-- Stores group attributes in a searchable format
CREATE TABLE group_attributes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    
    name VARCHAR(255) NOT NULL,
    value TEXT,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Allow multiple values for the same attribute name
    CONSTRAINT uq_group_attributes UNIQUE (group_id, name, value)
);

-- Performance Indexes
CREATE INDEX idx_groups_realm_id ON groups(realm_id);
CREATE INDEX idx_groups_parent_id ON groups(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_groups_path ON groups(path);
CREATE INDEX idx_groups_name ON groups(name);
CREATE INDEX idx_groups_path_gin ON groups USING gin(to_tsvector('english', path));

CREATE INDEX idx_user_groups_user_id ON user_groups(user_id);
CREATE INDEX idx_user_groups_group_id ON user_groups(group_id);
CREATE INDEX idx_user_groups_active ON user_groups(user_id, group_id) 
    WHERE expires_at IS NULL OR expires_at > NOW();

CREATE INDEX idx_group_roles_group_id ON group_roles(group_id);
CREATE INDEX idx_group_roles_role_id ON group_roles(role_id);

CREATE INDEX idx_group_attributes_group_id ON group_attributes(group_id);
CREATE INDEX idx_group_attributes_name ON group_attributes(name);
CREATE INDEX idx_group_attributes_value ON group_attributes(value);

-- Function to automatically update group path when parent changes
CREATE OR REPLACE FUNCTION update_group_path() RETURNS TRIGGER AS $$
DECLARE
    parent_path TEXT;
BEGIN
    IF NEW.parent_id IS NULL THEN
        NEW.path := '/' || NEW.name;
    ELSE
        SELECT path INTO parent_path FROM groups WHERE id = NEW.parent_id;
        NEW.path := parent_path || '/' || NEW.name;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_group_path
    BEFORE INSERT OR UPDATE OF name, parent_id ON groups
    FOR EACH ROW
    EXECUTE FUNCTION update_group_path();

-- Function to update child group paths when parent path changes
CREATE OR REPLACE FUNCTION update_child_group_paths() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.path != NEW.path THEN
        UPDATE groups
        SET path = REPLACE(path, OLD.path, NEW.path)
        WHERE path LIKE OLD.path || '/%';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_child_group_paths
    AFTER UPDATE OF path ON groups
    FOR EACH ROW
    WHEN (OLD.path IS DISTINCT FROM NEW.path)
    EXECUTE FUNCTION update_child_group_paths();

-- Prevent circular parent-child relationships
CREATE OR REPLACE FUNCTION prevent_circular_groups() RETURNS TRIGGER AS $$
DECLARE
    ancestor_id UUID;
BEGIN
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;
    
    -- Check if the new parent is a descendant of this group
    ancestor_id := NEW.parent_id;
    WHILE ancestor_id IS NOT NULL LOOP
        IF ancestor_id = NEW.id THEN
            RAISE EXCEPTION 'Circular group hierarchy detected';
        END IF;
        SELECT parent_id INTO ancestor_id FROM groups WHERE id = ancestor_id;
    END LOOP;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_circular_groups
    BEFORE INSERT OR UPDATE OF parent_id ON groups
    FOR EACH ROW
    EXECUTE FUNCTION prevent_circular_groups();
