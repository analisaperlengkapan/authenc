-- User Sessions Table
-- Stores active user authentication sessions with tokens and metadata
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE SET NULL,
    
    -- Token information
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA256 hash of the access token
    refresh_token_hash VARCHAR(64) UNIQUE, -- SHA256 hash of refresh token (if present)
    offline_token_hash VARCHAR(64) UNIQUE, -- SHA256 hash of offline token (if present)
    
    -- Session lifecycle
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_accessed TIMESTAMP NOT NULL DEFAULT NOW(),
    idle_expires_at TIMESTAMP, -- For idle timeout
    
    -- Token rotation tracking
    refresh_count INTEGER NOT NULL DEFAULT 0,
    refresh_token_expires_at TIMESTAMP,
    offline_token_expires_at TIMESTAMP,
    
    -- Client information
    ip_address INET,
    user_agent TEXT,
    
    -- Session state
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revoked_reason TEXT,
    
    -- Additional metadata
    authentication_method VARCHAR(50), -- password, otp, webauthn, etc.
    protocol VARCHAR(20), -- openid-connect, saml, etc.
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Device Sessions Table
-- Tracks device-specific session information for security and analytics
CREATE TABLE device_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_session_id UUID REFERENCES user_sessions(id) ON DELETE CASCADE,
    
    -- Session information
    session_identifier VARCHAR(255) NOT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Location and context
    ip_address INET,
    location JSONB, -- { country, city, latitude, longitude }
    
    -- Risk assessment
    risk_score DOUBLE PRECISION DEFAULT 0.0,
    risk_factors JSONB, -- Array of detected risk factors
    
    -- Session state
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ended_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Offline Tokens Table
-- Stores long-lived offline tokens for background access
CREATE TABLE offline_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    
    -- Token information
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    
    -- Offline token lifecycle
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    
    -- Metadata
    scope TEXT,
    data JSONB,
    
    -- State
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP,
    
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Refresh Token Rotation History
-- Tracks refresh token rotation for security auditing
CREATE TABLE refresh_token_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_session_id UUID NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    
    old_token_hash VARCHAR(64) NOT NULL,
    new_token_hash VARCHAR(64) NOT NULL,
    
    rotated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    client_ip INET,
    user_agent TEXT,
    
    -- Detection flags
    suspicious BOOLEAN NOT NULL DEFAULT FALSE,
    reason TEXT
);

-- Indexes for performance
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_realm_id ON user_sessions(realm_id);
CREATE INDEX idx_user_sessions_client_id ON user_sessions(client_id);
CREATE INDEX idx_user_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX idx_user_sessions_refresh_token_hash ON user_sessions(refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;
CREATE INDEX idx_user_sessions_offline_token_hash ON user_sessions(offline_token_hash) WHERE offline_token_hash IS NOT NULL;
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at) WHERE NOT revoked;
CREATE INDEX idx_user_sessions_idle_expires_at ON user_sessions(idle_expires_at) WHERE NOT revoked AND idle_expires_at IS NOT NULL;
CREATE INDEX idx_user_sessions_active ON user_sessions(user_id, realm_id) WHERE NOT revoked AND expires_at > NOW();

CREATE INDEX idx_device_sessions_device_id ON device_sessions(device_id);
CREATE INDEX idx_device_sessions_user_id ON device_sessions(user_id);
CREATE INDEX idx_device_sessions_user_session_id ON device_sessions(user_session_id);
CREATE INDEX idx_device_sessions_active ON device_sessions(user_id) WHERE is_active;
CREATE INDEX idx_device_sessions_last_activity ON device_sessions(last_activity) WHERE is_active;
CREATE INDEX idx_device_sessions_risk_score ON device_sessions(risk_score) WHERE is_active AND risk_score > 0.5;

CREATE INDEX idx_offline_tokens_user_id ON offline_tokens(user_id);
CREATE INDEX idx_offline_tokens_realm_id ON offline_tokens(realm_id);
CREATE INDEX idx_offline_tokens_client_id ON offline_tokens(client_id);
CREATE INDEX idx_offline_tokens_token_hash ON offline_tokens(token_hash);
CREATE INDEX idx_offline_tokens_active ON offline_tokens(user_id, realm_id) WHERE NOT revoked AND (expires_at IS NULL OR expires_at > NOW());

CREATE INDEX idx_refresh_token_history_session_id ON refresh_token_history(user_session_id);
CREATE INDEX idx_refresh_token_history_rotated_at ON refresh_token_history(rotated_at);
CREATE INDEX idx_refresh_token_history_suspicious ON refresh_token_history(user_session_id) WHERE suspicious;
