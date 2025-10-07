-- Authentication flows and executions persistence

-- Authentication flows table
CREATE TABLE IF NOT EXISTS authentication_flows (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    alias VARCHAR(255) NOT NULL,
    description TEXT,
    provider_id VARCHAR(255) NOT NULL,
    top_level BOOLEAN NOT NULL DEFAULT false,
    built_in BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(realm_id, alias)
);

-- Authentication executions table
CREATE TABLE IF NOT EXISTS authentication_executions (
    id UUID PRIMARY KEY,
    flow_id UUID NOT NULL REFERENCES authentication_flows(id) ON DELETE CASCADE,
    authenticator VARCHAR(255),
    authenticator_config UUID,
    authenticator_flow BOOLEAN NOT NULL DEFAULT false,
    requirement VARCHAR(50) NOT NULL DEFAULT 'DISABLED', -- REQUIRED, ALTERNATIVE, DISABLED, CONDITIONAL
    priority INT NOT NULL DEFAULT 0,
    parent_flow UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Authentication sessions table
CREATE TABLE IF NOT EXISTS authentication_sessions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    user_id UUID,
    client_id VARCHAR(255),
    flow_id UUID REFERENCES authentication_flows(id) ON DELETE SET NULL,
    auth_state VARCHAR(50) NOT NULL DEFAULT 'STARTED', -- STARTED, IN_PROGRESS, COMPLETED, FAILED
    protocol VARCHAR(50) NOT NULL DEFAULT 'openid-connect',
    redirect_uri TEXT,
    current_execution UUID,
    execution_status JSONB DEFAULT '{}',
    authentication_notes JSONB DEFAULT '{}',
    client_notes JSONB DEFAULT '{}',
    required_actions JSONB DEFAULT '[]',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_auth_flows_realm ON authentication_flows(realm_id);
CREATE INDEX IF NOT EXISTS idx_auth_flows_alias ON authentication_flows(alias);
CREATE INDEX IF NOT EXISTS idx_auth_flows_provider ON authentication_flows(provider_id);

CREATE INDEX IF NOT EXISTS idx_auth_executions_flow ON authentication_executions(flow_id);
CREATE INDEX IF NOT EXISTS idx_auth_executions_priority ON authentication_executions(flow_id, priority);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_realm ON authentication_sessions(realm_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON authentication_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_client ON authentication_sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_flow ON authentication_sessions(flow_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_state ON authentication_sessions(auth_state);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON authentication_sessions(expires_at);
