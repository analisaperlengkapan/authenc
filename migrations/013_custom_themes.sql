-- Custom Themes Table
-- Stores custom theme configurations for realms
CREATE TABLE custom_themes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    
    -- Theme type: login, account, admin, email
    theme_type VARCHAR(50) NOT NULL,
    
    -- Parent theme for inheritance
    parent_theme VARCHAR(255),
    
    -- CSS customization
    css_content TEXT,
    css_variables JSONB, -- { "--primary-color": "#007bff", "--font-family": "Arial" }
    
    -- Template overrides
    templates JSONB, -- { "login.ftl": "custom content", "error.ftl": "custom content" }
    
    -- Resources (images, fonts, etc.)
    resources JSONB, -- { "logo.png": "base64...", "background.jpg": "url" }
    
    -- Localization
    messages JSONB, -- { "en": { "login.title": "Welcome" }, "id": { "login.title": "Selamat Datang" } }
    
    -- Theme metadata
    description TEXT,
    version VARCHAR(50),
    author VARCHAR(255),
    
    -- Active status
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Theme Resources Table
-- Stores theme-related assets (images, fonts, CSS files, etc.)
CREATE TABLE theme_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    theme_id UUID NOT NULL REFERENCES custom_themes(id) ON DELETE CASCADE,
    
    -- Resource identification
    resource_name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- css, image, font, javascript
    mime_type VARCHAR(100),
    
    -- Resource content
    content_url TEXT, -- URL if hosted externally
    content_data BYTEA, -- Binary data if stored in DB
    content_size BIGINT,
    
    -- Cache control
    cache_key VARCHAR(255),
    etag VARCHAR(255),
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(theme_id, resource_name)
);

-- Theme Templates Table  
-- Stores FreeMarker template overrides
CREATE TABLE theme_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    theme_id UUID NOT NULL REFERENCES custom_themes(id) ON DELETE CASCADE,
    
    -- Template identification
    template_name VARCHAR(255) NOT NULL, -- login.ftl, error.ftl, etc.
    template_type VARCHAR(50) NOT NULL, -- login, account, email
    
    -- Template content
    content TEXT NOT NULL,
    
    -- Validation
    is_valid BOOLEAN NOT NULL DEFAULT TRUE,
    validation_errors JSONB,
    
    -- Version control
    version INTEGER NOT NULL DEFAULT 1,
    previous_version_id UUID,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(theme_id, template_name)
);

-- Theme Inheritance Table
-- Tracks theme inheritance relationships
CREATE TABLE theme_inheritance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    theme_id UUID NOT NULL REFERENCES custom_themes(id) ON DELETE CASCADE,
    parent_theme_id UUID REFERENCES custom_themes(id) ON DELETE SET NULL,
    
    -- Inheritance order (for multiple inheritance)
    inheritance_order INTEGER NOT NULL DEFAULT 0,
    
    -- Override settings
    override_css BOOLEAN NOT NULL DEFAULT TRUE,
    override_templates BOOLEAN NOT NULL DEFAULT TRUE,
    override_messages BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Realm Theme Settings Table
-- Maps realms to their active themes
CREATE TABLE realm_theme_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    
    -- Theme assignments per type
    login_theme_id UUID REFERENCES custom_themes(id) ON DELETE SET NULL,
    account_theme_id UUID REFERENCES custom_themes(id) ON DELETE SET NULL,
    admin_theme_id UUID REFERENCES custom_themes(id) ON DELETE SET NULL,
    email_theme_id UUID REFERENCES custom_themes(id) ON DELETE SET NULL,
    
    -- Fallback to default themes
    use_default_on_error BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(realm_id)
);

-- Indexes for performance
CREATE INDEX idx_custom_themes_realm_id ON custom_themes(realm_id);
CREATE INDEX idx_custom_themes_type ON custom_themes(theme_type);
CREATE INDEX idx_custom_themes_active ON custom_themes(realm_id, theme_type) WHERE is_active = TRUE;
CREATE INDEX idx_custom_themes_default ON custom_themes(theme_type) WHERE is_default = TRUE;

CREATE INDEX idx_theme_resources_theme_id ON theme_resources(theme_id);
CREATE INDEX idx_theme_resources_type ON theme_resources(resource_type);
CREATE INDEX idx_theme_resources_name ON theme_resources(theme_id, resource_name);

CREATE INDEX idx_theme_templates_theme_id ON theme_templates(theme_id);
CREATE INDEX idx_theme_templates_type ON theme_templates(template_type);
CREATE INDEX idx_theme_templates_name ON theme_templates(theme_id, template_name);

CREATE INDEX idx_theme_inheritance_theme_id ON theme_inheritance(theme_id);
CREATE INDEX idx_theme_inheritance_parent_id ON theme_inheritance(parent_theme_id);

CREATE INDEX idx_realm_theme_settings_realm_id ON realm_theme_settings(realm_id);
