-- OAuth2 Provider Configurations Table
-- Stores OAuth2/OIDC provider settings for social login
CREATE TABLE oauth2_provider_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Provider identification
    provider_name VARCHAR(100) NOT NULL, -- google, github, facebook, microsoft, etc.
    alias VARCHAR(100) NOT NULL, -- unique alias per realm
    display_name VARCHAR(255),
    
    -- OAuth2 endpoints
    authorization_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    user_info_url TEXT,
    jwks_url TEXT, -- For OIDC providers
    issuer TEXT, -- OIDC issuer
    
    -- Client credentials
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    
    -- OAuth2 configuration
    scopes TEXT NOT NULL DEFAULT 'openid email profile',
    response_type VARCHAR(50) DEFAULT 'code',
    response_mode VARCHAR(50) DEFAULT 'query',
    grant_type VARCHAR(50) DEFAULT 'authorization_code',
    
    -- PKCE support
    pkce_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    pkce_method VARCHAR(10) DEFAULT 'S256', -- S256 or plain
    
    -- Additional configuration
    additional_parameters JSONB, -- Extra OAuth2 params
    user_info_mapping JSONB, -- Map provider fields to user attributes
    
    -- Features
    trust_email BOOLEAN NOT NULL DEFAULT FALSE,
    link_only BOOLEAN NOT NULL DEFAULT FALSE, -- Only allow account linking, not registration
    store_tokens BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Status
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(realm_id, alias)
);

-- OAuth2 State Table
-- Tracks OAuth2 authorization states for CSRF protection
CREATE TABLE oauth2_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_token VARCHAR(255) NOT NULL UNIQUE,
    provider_config_id UUID NOT NULL REFERENCES oauth2_provider_configs(id) ON DELETE CASCADE,
    
    -- PKCE challenge
    code_verifier VARCHAR(128),
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    
    -- Request context
    redirect_uri TEXT NOT NULL,
    nonce VARCHAR(255),
    
    -- Session info
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_session_id UUID,
    
    -- Security
    ip_address INET,
    user_agent TEXT,
    
    -- Expiration
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- OAuth2 Token Exchange History
-- Audit log for token exchanges
CREATE TABLE oauth2_token_exchanges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_config_id UUID NOT NULL REFERENCES oauth2_provider_configs(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    -- Exchange details
    authorization_code TEXT,
    access_token_hash VARCHAR(64), -- SHA256 hash for security
    refresh_token_hash VARCHAR(64),
    token_type VARCHAR(50),
    expires_in INTEGER,
    scope TEXT,
    
    -- User info received
    provider_user_id TEXT,
    provider_email TEXT,
    provider_name TEXT,
    user_info_raw JSONB, -- Full response from provider
    
    -- Result
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Social Login Configurations per Provider
-- Extended configuration for specific social providers
CREATE TABLE social_login_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oauth2_config_id UUID NOT NULL REFERENCES oauth2_provider_configs(id) ON DELETE CASCADE,
    
    -- Provider-specific settings
    provider_type VARCHAR(50) NOT NULL, -- google, github, facebook, microsoft, apple
    
    -- Google-specific
    google_hosted_domain TEXT, -- G Suite domain restriction
    google_prompt VARCHAR(50), -- none, consent, select_account
    
    -- GitHub-specific  
    github_allow_signup BOOLEAN DEFAULT TRUE,
    github_allowed_organizations TEXT[], -- Array of org names
    
    -- Facebook-specific
    facebook_fields TEXT, -- Comma-separated fields to request
    facebook_graph_api_version VARCHAR(20) DEFAULT 'v18.0',
    
    -- Microsoft-specific
    microsoft_tenant_id TEXT,
    microsoft_admin_consent BOOLEAN DEFAULT FALSE,
    
    -- Apple-specific
    apple_team_id TEXT,
    apple_key_id TEXT,
    apple_private_key TEXT,
    
    -- Button customization
    button_text VARCHAR(255),
    button_icon_url TEXT,
    button_class VARCHAR(100),
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(oauth2_config_id)
);

-- Indexes
CREATE INDEX idx_oauth2_configs_realm ON oauth2_provider_configs(realm_id);
CREATE INDEX idx_oauth2_configs_provider ON oauth2_provider_configs(provider_name);
CREATE INDEX idx_oauth2_configs_enabled ON oauth2_provider_configs(realm_id, enabled) WHERE enabled = TRUE;

CREATE INDEX idx_oauth2_states_token ON oauth2_states(state_token);
CREATE INDEX idx_oauth2_states_expires ON oauth2_states(expires_at) WHERE NOT used;
CREATE INDEX idx_oauth2_states_provider ON oauth2_states(provider_config_id);

CREATE INDEX idx_oauth2_exchanges_provider ON oauth2_token_exchanges(provider_config_id);
CREATE INDEX idx_oauth2_exchanges_user ON oauth2_token_exchanges(user_id);
CREATE INDEX idx_oauth2_exchanges_created ON oauth2_token_exchanges(created_at);

CREATE INDEX idx_social_login_configs_oauth ON social_login_configs(oauth2_config_id);
CREATE INDEX idx_social_login_configs_type ON social_login_configs(provider_type);
