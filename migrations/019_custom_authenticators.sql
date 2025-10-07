-- Custom Authenticator Support for Authenc
-- Provides extensible authentication flow execution with custom authenticators

-- Authenticator configurations
CREATE TABLE IF NOT EXISTS authenticator_configs (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    alias VARCHAR(255) NOT NULL,
    authenticator_type VARCHAR(100) NOT NULL, -- username-password, otp, conditional, webauthn, custom
    config JSONB NOT NULL DEFAULT '{}',
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(realm_id, alias)
);

-- Authenticator executions (flow steps)
CREATE TABLE IF NOT EXISTS authenticator_executions (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    flow_id UUID NOT NULL, -- References authentication flows
    authenticator_id UUID REFERENCES authenticator_configs(id) ON DELETE CASCADE,
    requirement VARCHAR(50) NOT NULL DEFAULT 'REQUIRED', -- REQUIRED, ALTERNATIVE, DISABLED, CONDITIONAL
    priority INTEGER NOT NULL DEFAULT 100,
    parent_flow_id UUID, -- For subflows
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Execution results tracking
CREATE TABLE IF NOT EXISTS authenticator_execution_results (
    id UUID PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES authenticator_executions(id) ON DELETE CASCADE,
    session_id UUID,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL, -- SUCCESS, FAILED, SKIPPED, ATTEMPTED
    error_message TEXT,
    duration_ms INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for authenticator configs
CREATE INDEX idx_authenticator_configs_realm ON authenticator_configs(realm_id);
CREATE INDEX idx_authenticator_configs_type ON authenticator_configs(authenticator_type);
CREATE INDEX idx_authenticator_configs_enabled ON authenticator_configs(realm_id, enabled) WHERE enabled = TRUE;
CREATE INDEX idx_authenticator_configs_priority ON authenticator_configs(realm_id, priority);

-- Indexes for executions
CREATE INDEX idx_authenticator_executions_realm ON authenticator_executions(realm_id);
CREATE INDEX idx_authenticator_executions_flow ON authenticator_executions(flow_id);
CREATE INDEX idx_authenticator_executions_authenticator ON authenticator_executions(authenticator_id);
CREATE INDEX idx_authenticator_executions_priority ON authenticator_executions(flow_id, priority);
CREATE INDEX idx_authenticator_executions_requirement ON authenticator_executions(requirement);

-- Indexes for execution results
CREATE INDEX idx_authenticator_results_execution ON authenticator_execution_results(execution_id);
CREATE INDEX idx_authenticator_results_session ON authenticator_execution_results(session_id);
CREATE INDEX idx_authenticator_results_user ON authenticator_execution_results(user_id);
CREATE INDEX idx_authenticator_results_status ON authenticator_execution_results(status);
CREATE INDEX idx_authenticator_results_created ON authenticator_execution_results(created_at);
