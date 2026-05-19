-- Add authorization_permissions table for fine-grained authorization

CREATE TABLE IF NOT EXISTS authorization_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    scopes TEXT[], -- Array of scope names
    policies UUID[], -- Array of policy IDs
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_authorization_permissions_resource_id ON authorization_permissions(resource_id);
CREATE INDEX IF NOT EXISTS idx_authorization_permissions_name ON authorization_permissions(name);

-- Trigger for updated_at
CREATE TRIGGER update_authorization_permissions_updated_at
    BEFORE UPDATE ON authorization_permissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
