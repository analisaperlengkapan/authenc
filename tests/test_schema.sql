-- Minimal schema for WebAuthn testing
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Realms table (required for users)
CREATE TABLE IF NOT EXISTS realms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Drop and recreate users table with all required columns
DROP TABLE IF EXISTS users CASCADE;

-- Users table with all required columns
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    phone_number VARCHAR(255),
    phone_verified BOOLEAN NOT NULL DEFAULT false,
    password_hash VARCHAR(255),
    totp_secret VARCHAR(255),
    totp_backup_codes TEXT[],
    webauthn_enabled BOOLEAN NOT NULL DEFAULT false,
    account_locked BOOLEAN NOT NULL DEFAULT false,
    account_locked_until TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    password_expires_at TIMESTAMPTZ,
    require_password_change BOOLEAN NOT NULL DEFAULT false,
    organization_id UUID,
    attributes JSONB,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    federated BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    login_count INTEGER NOT NULL DEFAULT 0
);

-- WebAuthn challenges table
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    challenge_type VARCHAR(50) NOT NULL, -- 'registration' or 'authentication'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false
);

-- WebAuthn credentials table
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    public_key_algorithm INTEGER NOT NULL,
    signature_counter BIGINT NOT NULL DEFAULT 0,
    attestation_object TEXT,
    authenticator_data TEXT,
    user_handle TEXT,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    transports TEXT[], -- Array of transport types
    aaguid UUID,
    attestation_format VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(user_id, credential_id)
);

-- User consents table for GDPR compliance
CREATE TABLE IF NOT EXISTS user_consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL, -- Array of consented scopes
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ, -- Optional expiration
    metadata JSONB, -- Additional consent metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, client_id) -- One consent record per user-client pair
);

-- Authentication flows table for pluggable authentication flows
CREATE TABLE IF NOT EXISTS authentication_flows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alias VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    flow_type VARCHAR(50) NOT NULL, -- 'browser', 'direct_grant', 'client_authentication', 'registration', 'reset_credentials', 'docker', 'custom'
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authentication executions table for flow steps
CREATE TABLE IF NOT EXISTS authentication_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    flow_id UUID NOT NULL REFERENCES authentication_flows(id) ON DELETE CASCADE,
    alias VARCHAR(255) NOT NULL,
    description TEXT,
    execution_type VARCHAR(100) NOT NULL, -- authenticator type or 'condition'
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    configuration JSONB, -- Configuration parameters
    requirements TEXT[], -- Conditional requirements
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authentication sessions table for ongoing authentication
CREATE TABLE IF NOT EXISTS authentication_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_session_id UUID,
    client_id VARCHAR(255) NOT NULL,
    flow_id UUID NOT NULL REFERENCES authentication_flows(id) ON DELETE CASCADE,
    current_execution_id UUID REFERENCES authentication_executions(id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_data JSONB, -- Temporary session data
    auth_notes JSONB, -- Authentication notes and metadata
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 minutes'),
    completed BOOLEAN NOT NULL DEFAULT false,
    success BOOLEAN,
    error_message TEXT
);

-- Insert a default realm for testing
INSERT INTO realms (id, name, display_name, enabled)
VALUES ('550e8400-e29b-41d4-a716-446655440000', 'test-realm', 'Test Realm', true)
ON CONFLICT (name) DO NOTHING;
