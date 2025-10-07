-- Protocol Mappers Table
-- Maps user/client attributes to protocol-specific claims/attributes
CREATE TABLE protocol_mappers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Mapper identification
    name VARCHAR(255) NOT NULL,
    protocol VARCHAR(50) NOT NULL, -- oidc, saml
    mapper_type VARCHAR(100) NOT NULL, -- user-attribute, user-property, role-list, hardcoded-claim, group-membership, audience
    
    -- Mapper configuration
    config JSONB NOT NULL, -- Mapper-specific configuration
    
    -- State
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(client_id, name)
);

-- Indexes
CREATE INDEX idx_protocol_mappers_client ON protocol_mappers(client_id);
CREATE INDEX idx_protocol_mappers_realm ON protocol_mappers(realm_id);
CREATE INDEX idx_protocol_mappers_protocol ON protocol_mappers(protocol);
CREATE INDEX idx_protocol_mappers_type ON protocol_mappers(mapper_type);
CREATE INDEX idx_protocol_mappers_enabled ON protocol_mappers(client_id, enabled) WHERE enabled = TRUE;
