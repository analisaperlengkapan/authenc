-- Event Listeners Configuration Table
-- Defines event listeners and their configurations
CREATE TABLE event_listeners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Listener identification
    name VARCHAR(255) NOT NULL,
    listener_type VARCHAR(100) NOT NULL, -- logging, metrics, webhook, email, custom
    
    -- Configuration
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config JSONB, -- Listener-specific configuration
    
    -- Event filtering
    event_types TEXT[], -- Array of event types to listen to, NULL = all events
    
    -- Priority (lower number = higher priority)
    priority INTEGER NOT NULL DEFAULT 100,
    
    -- Execution settings
    is_async BOOLEAN NOT NULL DEFAULT TRUE, -- Whether to execute asynchronously
    retry_on_failure BOOLEAN NOT NULL DEFAULT FALSE,
    max_retries INTEGER DEFAULT 3,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(realm_id, name)
);

-- Event Log Table
-- Stores all events for audit trail and replay
CREATE TABLE event_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Event identification
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL, -- USER, ADMIN, AUTH, SESSION, RESOURCE
    
    -- Event details
    resource_type VARCHAR(100), -- USER, ROLE, CLIENT, REALM, etc.
    resource_id VARCHAR(255),
    resource_name VARCHAR(255),
    
    -- User context
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(255),
    
    -- Event data
    event_data JSONB, -- Full event payload
    old_value JSONB, -- Previous state (for UPDATE events)
    new_value JSONB, -- New state (for CREATE/UPDATE events)
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    
    -- Result
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    
    -- Metadata
    operation_id UUID, -- Link to admin_audit_log
    correlation_id UUID, -- For tracking related events
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Event Listener Executions Table
-- Tracks listener execution results
CREATE TABLE event_listener_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_log_id UUID NOT NULL REFERENCES event_log(id) ON DELETE CASCADE,
    listener_id UUID NOT NULL REFERENCES event_listeners(id) ON DELETE CASCADE,
    
    -- Execution details
    executed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    -- Performance
    duration_ms INTEGER,
    
    -- Retry tracking
    retry_count INTEGER DEFAULT 0,
    next_retry_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Event Webhooks Table
-- Configuration for webhook event listeners
CREATE TABLE event_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listener_id UUID NOT NULL REFERENCES event_listeners(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Webhook details
    url TEXT NOT NULL,
    http_method VARCHAR(10) NOT NULL DEFAULT 'POST',
    
    -- Authentication
    auth_type VARCHAR(50), -- none, basic, bearer, hmac
    auth_credentials JSONB, -- Encrypted credentials
    
    -- Headers
    custom_headers JSONB, -- Custom HTTP headers
    
    -- Payload customization
    payload_template TEXT, -- Handlebars template for custom payload
    
    -- Security
    secret_key VARCHAR(255), -- For HMAC signature
    verify_ssl BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Retry settings
    timeout_seconds INTEGER DEFAULT 30,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(listener_id)
);

-- Indexes
CREATE INDEX idx_event_listeners_realm ON event_listeners(realm_id);
CREATE INDEX idx_event_listeners_type ON event_listeners(listener_type);
CREATE INDEX idx_event_listeners_enabled ON event_listeners(realm_id, enabled) WHERE enabled = TRUE;
CREATE INDEX idx_event_listeners_priority ON event_listeners(priority);

CREATE INDEX idx_event_log_realm ON event_log(realm_id);
CREATE INDEX idx_event_log_type ON event_log(event_type, event_category);
CREATE INDEX idx_event_log_resource ON event_log(resource_type, resource_id);
CREATE INDEX idx_event_log_user ON event_log(user_id);
CREATE INDEX idx_event_log_created ON event_log(created_at DESC);
CREATE INDEX idx_event_log_correlation ON event_log(correlation_id);
CREATE INDEX idx_event_log_category_time ON event_log(event_category, created_at DESC);

CREATE INDEX idx_listener_executions_event ON event_listener_executions(event_log_id);
CREATE INDEX idx_listener_executions_listener ON event_listener_executions(listener_id);
CREATE INDEX idx_listener_executions_success ON event_listener_executions(success);
CREATE INDEX idx_listener_executions_retry ON event_listener_executions(next_retry_at) WHERE next_retry_at IS NOT NULL AND success = FALSE;

CREATE INDEX idx_webhooks_listener ON event_webhooks(listener_id);
CREATE INDEX idx_webhooks_realm ON event_webhooks(realm_id);
