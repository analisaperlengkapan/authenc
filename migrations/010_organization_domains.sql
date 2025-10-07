-- Organization domain verification for B2B SSO
CREATE TABLE IF NOT EXISTS organization_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    verification_token VARCHAR(255) UNIQUE,
    verification_method VARCHAR(50) NOT NULL DEFAULT 'dns', -- dns, email, http
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain)
);

-- Organization-scoped identity providers
CREATE TABLE IF NOT EXISTS organization_identity_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL, -- References identity providers
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0, -- Order for provider selection
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, identity_provider_id)
);

-- Indexes for performance
CREATE INDEX idx_org_domains_org_id ON organization_domains(organization_id);
CREATE INDEX idx_org_domains_domain ON organization_domains(domain);
CREATE INDEX idx_org_domains_verified ON organization_domains(verified);
CREATE INDEX idx_org_idps_org_id ON organization_identity_providers(organization_id);
CREATE INDEX idx_org_members_user_id ON organization_members(user_id);
CREATE INDEX idx_org_invitations_email ON organization_invitations(email);
CREATE INDEX idx_org_invitations_token ON organization_invitations(token_hash);
