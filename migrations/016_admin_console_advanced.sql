-- Admin Console Audit Log Table
-- Comprehensive audit logging for all admin operations
CREATE TABLE admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Admin user information
    admin_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    admin_username VARCHAR(255),
    admin_ip_address INET,
    
    -- Operation details
    operation_type VARCHAR(100) NOT NULL, -- CREATE, UPDATE, DELETE, READ, EXECUTE, LOGIN, LOGOUT
    resource_type VARCHAR(100) NOT NULL, -- USER, ROLE, REALM, CLIENT, GROUP, POLICY, etc.
    resource_id VARCHAR(255),
    resource_name VARCHAR(255),
    
    -- Operation context
    action VARCHAR(255) NOT NULL, -- Specific action performed
    status VARCHAR(50) NOT NULL DEFAULT 'SUCCESS', -- SUCCESS, FAILURE, PARTIAL
    error_message TEXT,
    
    -- Request details
    request_method VARCHAR(10), -- GET, POST, PUT, DELETE, PATCH
    request_path TEXT,
    request_body JSONB, -- Sanitized request payload (passwords removed)
    
    -- Response details
    response_status INTEGER,
    response_body JSONB, -- Sanitized response
    
    -- Metadata
    duration_ms INTEGER, -- Operation duration in milliseconds
    user_agent TEXT,
    session_id UUID,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Admin Dashboard Metrics Table
-- Real-time metrics for admin console dashboard
CREATE TABLE admin_dashboard_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Metric identification
    metric_type VARCHAR(100) NOT NULL, -- USER_COUNT, SESSION_COUNT, LOGIN_RATE, ERROR_RATE, etc.
    metric_name VARCHAR(255) NOT NULL,
    
    -- Metric values
    metric_value NUMERIC NOT NULL,
    metric_unit VARCHAR(50), -- count, percentage, milliseconds, etc.
    
    -- Aggregation
    aggregation_period VARCHAR(50) NOT NULL, -- REALTIME, MINUTE, HOUR, DAY, WEEK, MONTH
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    
    -- Metadata
    metadata JSONB, -- Additional metric-specific data
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(realm_id, metric_type, metric_name, period_start)
);

-- Admin Console Sessions Table
-- Track admin user sessions for security and monitoring
CREATE TABLE admin_console_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Admin user
    admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    
    -- Session details
    session_token VARCHAR(512) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    
    -- Session state
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_activity_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Security
    login_method VARCHAR(50), -- PASSWORD, MFA, SSO, SAML, OIDC
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Expiration
    expires_at TIMESTAMP NOT NULL,
    
    -- Logout
    logout_reason VARCHAR(100), -- USER_INITIATED, TIMEOUT, ADMIN_TERMINATED, SECURITY
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    terminated_at TIMESTAMP
);

-- Admin Notifications Table
-- System notifications and alerts for administrators
CREATE TABLE admin_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Notification details
    notification_type VARCHAR(100) NOT NULL, -- INFO, WARNING, ERROR, CRITICAL, SUCCESS
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    
    -- Targeting
    target_admin_user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- Specific admin or NULL for all
    target_role VARCHAR(255), -- Target specific admin role
    
    -- Status
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMP,
    read_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Action
    action_url TEXT, -- Optional link to related resource
    action_label VARCHAR(100), -- Button text
    
    -- Priority
    priority INTEGER NOT NULL DEFAULT 5, -- 1 (highest) to 10 (lowest)
    
    -- Expiration
    expires_at TIMESTAMP,
    
    -- Metadata
    metadata JSONB,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Admin Console Preferences Table
-- User preferences and settings for admin console
CREATE TABLE admin_console_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- UI Preferences
    theme VARCHAR(50) DEFAULT 'light', -- light, dark, auto
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(100) DEFAULT 'UTC',
    
    -- Display preferences
    items_per_page INTEGER DEFAULT 25,
    compact_mode BOOLEAN DEFAULT FALSE,
    sidebar_collapsed BOOLEAN DEFAULT FALSE,
    
    -- Notification preferences
    email_notifications BOOLEAN DEFAULT TRUE,
    desktop_notifications BOOLEAN DEFAULT TRUE,
    notification_frequency VARCHAR(50) DEFAULT 'realtime', -- realtime, hourly, daily
    
    -- Dashboard preferences
    dashboard_layout JSONB, -- Custom dashboard widget configuration
    favorite_pages TEXT[], -- Array of frequently accessed pages
    
    -- Advanced
    developer_mode BOOLEAN DEFAULT FALSE,
    show_advanced_options BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    preferences JSONB, -- Additional custom preferences
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(admin_user_id, realm_id)
);

-- Indexes
CREATE INDEX idx_admin_audit_log_realm ON admin_audit_log(realm_id);
CREATE INDEX idx_admin_audit_log_admin_user ON admin_audit_log(admin_user_id);
CREATE INDEX idx_admin_audit_log_resource ON admin_audit_log(resource_type, resource_id);
CREATE INDEX idx_admin_audit_log_operation ON admin_audit_log(operation_type, status);
CREATE INDEX idx_admin_audit_log_created ON admin_audit_log(created_at DESC);
CREATE INDEX idx_admin_audit_log_action ON admin_audit_log(action);

CREATE INDEX idx_dashboard_metrics_realm ON admin_dashboard_metrics(realm_id);
CREATE INDEX idx_dashboard_metrics_type ON admin_dashboard_metrics(metric_type, metric_name);
CREATE INDEX idx_dashboard_metrics_period ON admin_dashboard_metrics(period_start, period_end);
CREATE INDEX idx_dashboard_metrics_aggregation ON admin_dashboard_metrics(aggregation_period);

CREATE INDEX idx_admin_sessions_realm ON admin_console_sessions(realm_id);
CREATE INDEX idx_admin_sessions_user ON admin_console_sessions(admin_user_id);
CREATE INDEX idx_admin_sessions_token ON admin_console_sessions(session_token);
CREATE INDEX idx_admin_sessions_active ON admin_console_sessions(is_active, last_activity_at) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_expires ON admin_console_sessions(expires_at) WHERE is_active = TRUE;

CREATE INDEX idx_admin_notifications_realm ON admin_notifications(realm_id);
CREATE INDEX idx_admin_notifications_target ON admin_notifications(target_admin_user_id, is_read);
CREATE INDEX idx_admin_notifications_type ON admin_notifications(notification_type, priority);
CREATE INDEX idx_admin_notifications_created ON admin_notifications(created_at DESC);
CREATE INDEX idx_admin_notifications_unread ON admin_notifications(target_admin_user_id) WHERE is_read = FALSE;

CREATE INDEX idx_admin_preferences_user ON admin_console_preferences(admin_user_id);
CREATE INDEX idx_admin_preferences_realm ON admin_console_preferences(realm_id);
