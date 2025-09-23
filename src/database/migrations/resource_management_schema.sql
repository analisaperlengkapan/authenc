-- Resource Management Migration
-- Adds tables for fine-grained authorization and resource management
-- Compatible with Keycloak's resource management features

-- ============================================================================
-- RESOURCE MANAGEMENT TABLES
-- ============================================================================

-- Resource servers (authorization servers for resources)
CREATE TABLE IF NOT EXISTS resource_servers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    policy_enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'enforcing' CHECK (policy_enforcement_mode IN ('enforcing', 'permissive', 'disabled')),
    decision_strategy VARCHAR(20) NOT NULL DEFAULT 'unanimous' CHECK (decision_strategy IN ('unanimous', 'affirmative', 'consensus')),
    allow_remote_resource_management BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(realm_id, client_id)
);

-- Scopes (permissions that can be granted on resources)
CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    icon_uri VARCHAR(500),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(resource_server_id, name)
);

-- Resources (protected objects)
CREATE TABLE IF NOT EXISTS resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    uris TEXT[], -- Array of URIs this resource protects
    icon_uri VARCHAR(500),
    resource_type VARCHAR(255),
    owner VARCHAR(255) NOT NULL, -- User ID of the resource owner
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    scopes TEXT[], -- Array of scope names
    attributes JSONB, -- Additional attributes as key-value pairs
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(resource_server_id, name)
);

-- Permission tickets (requests for resource access)
CREATE TABLE IF NOT EXISTS permission_tickets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    owner VARCHAR(255) NOT NULL, -- User ID of the resource owner
    requester VARCHAR(255) NOT NULL, -- User ID of the requester
    granted BOOLEAN NOT NULL DEFAULT false,
    granted_timestamp TIMESTAMPTZ,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(resource_id, scope_id, requester)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Resource servers indexes
CREATE INDEX IF NOT EXISTS idx_resource_servers_realm_id ON resource_servers(realm_id);
CREATE INDEX IF NOT EXISTS idx_resource_servers_client_id ON resource_servers(client_id);

-- Scopes indexes
CREATE INDEX IF NOT EXISTS idx_scopes_resource_server_id ON scopes(resource_server_id);
CREATE INDEX IF NOT EXISTS idx_scopes_realm_id ON scopes(realm_id);
CREATE INDEX IF NOT EXISTS idx_scopes_name ON scopes(name);

-- Resources indexes
CREATE INDEX IF NOT EXISTS idx_resources_resource_server_id ON resources(resource_server_id);
CREATE INDEX IF NOT EXISTS idx_resources_realm_id ON resources(realm_id);
CREATE INDEX IF NOT EXISTS idx_resources_owner ON resources(owner);
CREATE INDEX IF NOT EXISTS idx_resources_name ON resources(name);
CREATE INDEX IF NOT EXISTS idx_resources_uris ON resources USING GIN(uris);
CREATE INDEX IF NOT EXISTS idx_resources_scopes ON resources USING GIN(scopes);
CREATE INDEX IF NOT EXISTS idx_resources_attributes ON resources USING GIN(attributes);

-- Permission tickets indexes
CREATE INDEX IF NOT EXISTS idx_permission_tickets_resource_id ON permission_tickets(resource_id);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_scope_id ON permission_tickets(scope_id);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_owner ON permission_tickets(owner);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_requester ON permission_tickets(requester);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_granted ON permission_tickets(granted);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_realm_id ON permission_tickets(realm_id);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_resource_server_id ON permission_tickets(resource_server_id);

-- ============================================================================
-- TRIGGERS FOR UPDATED_AT
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_resource_servers_updated_at BEFORE UPDATE ON resource_servers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scopes_updated_at BEFORE UPDATE ON scopes FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_resources_updated_at BEFORE UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_permission_tickets_updated_at BEFORE UPDATE ON permission_tickets FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
