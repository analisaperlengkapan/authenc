-- Authenc Database Schema
-- This file contains all database tables and indexes for Authenc

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Realms (multi-tenancy support)
CREA-- Admin events table (admin actions)
CREATE TABLE IF NOT EXISTS admin_events (
    id VARCHAR(36) PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    realm_id VARCHAR(36) NOT NULL,
    auth_user_id VARCHAR(36),
    auth_ip_address INET,
    auth_user_agent TEXT,
    resource_type VARCHAR(50) NOT NULL,
    operation_type VARCHAR(50) NOT NULL,
    resource_path TEXT,
    representation TEXT,
    error TEXT
);ISTS realms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    email_verified BOOLEAN NOT NULL DEFAULT false,
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    -- Federation fields
    federated BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    login_count INTEGER NOT NULL DEFAULT 0
);

-- Federated identities (links users to external identity providers)
CREATE TABLE IF NOT EXISTS federated_identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL, -- External user ID from the identity provider
    external_username VARCHAR(255), -- External username from the identity provider
    external_email VARCHAR(255), -- External email from the identity provider
    external_attributes JSONB, -- Additional attributes from the identity provider
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(identity_provider_id, external_id)
);

-- ============================================================================
-- DEVICE MANAGEMENT TABLES
-- ============================================================================

-- Device information and trust scoring
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(255),
    device_fingerprint TEXT NOT NULL, -- JSON fingerprint data
    trust_score DOUBLE PRECISION NOT NULL DEFAULT 0.5 CHECK (trust_score >= 0 AND trust_score <= 1),
    risk_level VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    os VARCHAR(100),
    os_version VARCHAR(100),
    browser VARCHAR(100),
    browser_version VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    location_data JSONB, -- Geographic location data
    security_features JSONB, -- Device security capabilities
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

-- Device trust score history
CREATE TABLE IF NOT EXISTS device_trust_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    previous_score DECIMAL(3,2),
    new_score DECIMAL(3,2) NOT NULL,
    factors JSONB NOT NULL, -- Trust calculation factors
    changed_by UUID REFERENCES users(id), -- NULL for system changes
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- WEBAUTHN TABLES
-- ============================================================================

-- WebAuthn credentials storage
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
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL, -- Device binding
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(user_id, credential_id)
);

-- ============================================================================
-- ORGANIZATION MANAGEMENT TABLES
-- ============================================================================

-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    description TEXT,
    domain VARCHAR(255),
    logo_url TEXT,
    website_url TEXT,
    owner_id UUID NOT NULL REFERENCES users(id),
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Organization members
CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    invited_by UUID REFERENCES users(id),
    invited_at TIMESTAMPTZ,
    joined_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

-- Organization invitations
CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    invited_by UUID NOT NULL REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, email)
);

-- ============================================================================
-- OAUTH2 TABLES
-- ============================================================================

-- OAuth2 clients
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(20) NOT NULL DEFAULT 'confidential' CHECK (client_type IN ('confidential', 'public')),
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{}',
    response_types TEXT[] NOT NULL DEFAULT '{}',
    token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
    owner_id UUID REFERENCES users(id),
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- OAuth2 authorization codes
CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(255) NOT NULL UNIQUE,
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    code_challenge TEXT,
    code_challenge_method VARCHAR(10) CHECK (code_challenge_method IN ('plain', 'S256')),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OAuth2 access tokens
CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(255) UNIQUE,
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

-- ============================================================================
-- USER CONSENT TABLES
-- ============================================================================

-- User consents for GDPR compliance
CREATE TABLE IF NOT EXISTS user_consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    metadata JSONB,
    UNIQUE(user_id, client_id)
);

-- ============================================================================
-- SOCIAL ACCOUNT TABLES
-- ============================================================================

-- Social account links for identity brokering
CREATE TABLE IF NOT EXISTS user_social_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- Social provider (google, github, etc.)
    provider_user_id VARCHAR(255) NOT NULL, -- User ID on the social provider
    display_name VARCHAR(255), -- Display name from social provider
    email VARCHAR(255), -- Email from social provider
    profile_picture_url TEXT, -- Profile picture URL from social provider
    access_token TEXT, -- Encrypted access token
    refresh_token TEXT, -- Encrypted refresh token
    token_expires_at TIMESTAMPTZ, -- When the access token expires
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- When the account was linked
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(user_id, provider), -- One social account per provider per user
    UNIQUE(provider, provider_user_id) -- One user per social provider account
);

-- ============================================================================
-- SAML TABLES
-- ============================================================================

-- SAML service providers
CREATE TABLE IF NOT EXISTS saml_service_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id TEXT NOT NULL UNIQUE,
    metadata_url TEXT,
    metadata_xml TEXT,
    signing_certificate TEXT,
    encryption_certificate TEXT,
    assertion_consumer_service_url TEXT NOT NULL,
    single_logout_service_url TEXT,
    name_id_format TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- SAML identity providers
CREATE TABLE IF NOT EXISTS saml_identity_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id TEXT NOT NULL UNIQUE,
    metadata_url TEXT,
    metadata_xml TEXT,
    sso_url TEXT NOT NULL,
    slo_url TEXT,
    signing_certificate TEXT NOT NULL,
    encryption_certificate TEXT,
    name_id_format TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- SAML sessions
CREATE TABLE IF NOT EXISTS saml_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES saml_identity_providers(id) ON DELETE CASCADE,
    service_provider_id UUID REFERENCES saml_service_providers(id) ON DELETE CASCADE,
    name_id TEXT NOT NULL,
    name_id_format TEXT NOT NULL,
    session_index TEXT,
    authn_instant TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- SESSION MANAGEMENT TABLES
-- ============================================================================

-- User sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    location_data JSONB,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    terminated BOOLEAN NOT NULL DEFAULT false,
    terminated_at TIMESTAMPTZ,
    terminated_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- AUDIT LOGGING TABLES
-- ============================================================================

-- Comprehensive audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    client_id UUID REFERENCES oauth2_clients(id) ON DELETE SET NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'failure', 'warning')),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    location_data JSONB,
    error_message TEXT,
    request_id VARCHAR(100),
    correlation_id VARCHAR(100)
);

-- User events table (login, logout, registration, etc.)
CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(36) PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    realm_id VARCHAR(36) NOT NULL,
    realm_name VARCHAR(255),
    client_id VARCHAR(36),
    user_id VARCHAR(36),
    session_id VARCHAR(36),
    ip_address INET,
    error TEXT,
    details JSONB
);

-- Admin events table (admin actions)
CREATE TABLE IF NOT EXISTS admin_events (
    id VARCHAR(36) PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    realm_id VARCHAR(36) NOT NULL,
    realm_name VARCHAR(255),
    auth_user_id VARCHAR(36),
    auth_username VARCHAR(255),
    auth_realm VARCHAR(255),
    auth_client VARCHAR(255),
    auth_ip_address INET,
    auth_user_agent TEXT,
    resource_type VARCHAR(50) NOT NULL,
    operation_type VARCHAR(50) NOT NULL,
    resource_path TEXT NOT NULL,
    representation TEXT,
    error TEXT
);

-- Resource servers table (for fine-grained authorization)
CREATE TABLE IF NOT EXISTS resource_servers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    policy_enforcement_mode VARCHAR(50) NOT NULL DEFAULT 'enforcing',
    decision_strategy VARCHAR(50) NOT NULL DEFAULT 'unanimous',
    allow_remote_resource_management BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scopes table (for resource permissions)
CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    icon_uri VARCHAR(1000),
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID REFERENCES resource_servers(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Resources table (for fine-grained authorization)
CREATE TABLE IF NOT EXISTS resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    uris TEXT[] NOT NULL DEFAULT '{}',
    icon_uri VARCHAR(1000),
    resource_type VARCHAR(255),
    owner VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID REFERENCES resource_servers(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    attributes JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Permission tickets table (for resource sharing)
CREATE TABLE IF NOT EXISTS permission_tickets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_id UUID REFERENCES resources(id) ON DELETE CASCADE,
    scope_id UUID REFERENCES scopes(id) ON DELETE CASCADE,
    owner VARCHAR(255) NOT NULL,
    requester VARCHAR(255) NOT NULL,
    granted BOOLEAN NOT NULL DEFAULT false,
    granted_timestamp TIMESTAMPTZ,
    realm_id UUID REFERENCES realms(id) ON DELETE CASCADE,
    resource_server_id UUID REFERENCES resource_servers(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Core indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_realm_id ON users(realm_id) WHERE deleted_at IS NULL;

-- Device management indexes
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_trust_score ON devices(trust_score);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_device_trust_history_device_id ON device_trust_history(device_id);

-- WebAuthn indexes
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);

-- Organization indexes
CREATE INDEX IF NOT EXISTS idx_organizations_owner_id ON organizations(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_organization_members_org_id ON organization_members(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_members_user_id ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_organization_invitations_org_id ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_invitations_token ON organization_invitations(token_hash);

-- OAuth2 indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_id ON oauth2_clients(client_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_codes_code ON oauth2_authorization_codes(code);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_codes_expires ON oauth2_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_token ON oauth2_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_refresh ON oauth2_access_tokens(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_expires ON oauth2_access_tokens(expires_at);

-- SAML indexes
CREATE INDEX IF NOT EXISTS idx_saml_sp_entity_id ON saml_service_providers(entity_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_saml_idp_entity_id ON saml_identity_providers(entity_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_saml_sessions_user_id ON saml_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_expires ON saml_sessions(expires_at);

-- Federated identities indexes
CREATE INDEX IF NOT EXISTS idx_federated_identities_user_id ON federated_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_federated_identities_provider_id ON federated_identities(identity_provider_id);
CREATE INDEX IF NOT EXISTS idx_federated_identities_external_id ON federated_identities(identity_provider_id, external_id);

-- Identity provider indexes
CREATE INDEX IF NOT EXISTS idx_identity_providers_realm_id ON identity_providers(realm_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_identity_providers_type ON identity_providers(provider_type) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_identity_providers_enabled ON identity_providers(enabled) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_identity_provider_mappers_provider_id ON identity_provider_mappers(identity_provider_id);

-- Session indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_session_id ON user_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);

-- Audit indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);

-- Event indexes
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_realm_id ON events(realm_id);
CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_client_id ON events(client_id);

-- Admin event indexes
CREATE INDEX IF NOT EXISTS idx_admin_events_time ON admin_events(time DESC);
CREATE INDEX IF NOT EXISTS idx_admin_events_realm_id ON admin_events(realm_id);
CREATE INDEX IF NOT EXISTS idx_admin_events_auth_user_id ON admin_events(auth_user_id);
CREATE INDEX IF NOT EXISTS idx_admin_events_resource_type ON admin_events(resource_type);
CREATE INDEX IF NOT EXISTS idx_admin_events_operation_type ON admin_events(operation_type);

-- Resource server indexes
CREATE INDEX IF NOT EXISTS idx_resource_servers_client_id ON resource_servers(client_id);
CREATE INDEX IF NOT EXISTS idx_resource_servers_realm_id ON resource_servers(realm_id);

-- Scope indexes
CREATE INDEX IF NOT EXISTS idx_scopes_name ON scopes(name);
CREATE INDEX IF NOT EXISTS idx_scopes_realm_id ON scopes(realm_id);
CREATE INDEX IF NOT EXISTS idx_scopes_resource_server_id ON scopes(resource_server_id);

-- Resource indexes
CREATE INDEX IF NOT EXISTS idx_resources_name ON resources(name);
CREATE INDEX IF NOT EXISTS idx_resources_owner ON resources(owner);
CREATE INDEX IF NOT EXISTS idx_resources_realm_id ON resources(realm_id);
CREATE INDEX IF NOT EXISTS idx_resources_resource_server_id ON resources(resource_server_id);

-- Permission ticket indexes
CREATE INDEX IF NOT EXISTS idx_permission_tickets_resource_id ON permission_tickets(resource_id);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_scope_id ON permission_tickets(scope_id);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_owner ON permission_tickets(owner);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_requester ON permission_tickets(requester);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_realm_id ON permission_tickets(realm_id);
CREATE INDEX IF NOT EXISTS idx_permission_tickets_resource_server_id ON permission_tickets(resource_server_id);

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
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
CREATE TRIGGER update_realms_updated_at BEFORE UPDATE ON realms FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_organization_members_updated_at BEFORE UPDATE ON organization_members FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_oauth2_clients_updated_at BEFORE UPDATE ON oauth2_clients FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_saml_service_providers_updated_at BEFORE UPDATE ON saml_service_providers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_saml_identity_providers_updated_at BEFORE UPDATE ON saml_identity_providers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- IDENTITY BROKERING TABLES
-- ============================================================================

-- Identity providers (supports SAML, OIDC, OAuth2, LDAP, Kerberos, Social)
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL CHECK (provider_type IN ('SAML', 'OIDC', 'OAuth2', 'LDAP', 'Kerberos', 'SocialLogin', 'Custom')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    config JSONB NOT NULL DEFAULT '{}',
    truststore_path TEXT,
    keystore_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(name, realm_id)
);

-- Identity provider mappers (for attribute mapping)
CREATE TABLE IF NOT EXISTS identity_provider_mappers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    mapper_type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(identity_provider_id, name)
);

-- Update triggers for identity providers
CREATE TRIGGER update_identity_providers_updated_at BEFORE UPDATE ON identity_providers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_identity_provider_mappers_updated_at BEFORE UPDATE ON identity_provider_mappers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_federated_identities_updated_at BEFORE UPDATE ON federated_identities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Update triggers for resource management
CREATE TRIGGER update_resource_servers_updated_at BEFORE UPDATE ON resource_servers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scopes_updated_at BEFORE UPDATE ON scopes FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_resources_updated_at BEFORE UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_permission_tickets_updated_at BEFORE UPDATE ON permission_tickets FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired tokens and sessions
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS void AS $$
BEGIN
    -- Clean up expired OAuth2 authorization codes
    DELETE FROM oauth2_authorization_codes WHERE expires_at < NOW();

    -- Clean up expired OAuth2 access tokens
    UPDATE oauth2_access_tokens SET revoked = true, revoked_at = NOW()
    WHERE expires_at < NOW() AND revoked = false;

    -- Clean up expired user sessions
    UPDATE user_sessions SET terminated = true, terminated_at = NOW(), terminated_reason = 'expired'
    WHERE expires_at < NOW() AND terminated = false;

    -- Clean up expired SAML sessions
    DELETE FROM saml_sessions WHERE expires_at < NOW();

    -- Clean up old audit logs (keep last 90 days)
    DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default realm
INSERT INTO realms (id, name, display_name, description)
VALUES ('00000000-0000-0000-0000-000000000000', 'master', 'Master Realm', 'Default master realm')
ON CONFLICT (id) DO NOTHING;

-- Insert default admin user (password should be changed in production)
-- Password hash for 'admin123' - this should be changed immediately
INSERT INTO users (id, username, email, password_hash, realm_id, email_verified, enabled)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'admin@authenc.local',
    '$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpams$MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=',
    '00000000-0000-0000-0000-000000000000',
    true,
    true
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SPI CONFIGURATION TABLES
-- ============================================================================

-- SPI provider configurations
CREATE TABLE IF NOT EXISTS spi_provider_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spi_name VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(spi_name, provider_id)
);

-- Update trigger for spi_provider_configs
CREATE TRIGGER update_spi_provider_configs_updated_at BEFORE UPDATE ON spi_provider_configs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
