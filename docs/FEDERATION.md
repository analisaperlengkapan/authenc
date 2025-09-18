# Federated Authentication and Identity Brokering

This document provides comprehensive information about Authenc's federated authentication system, which enables seamless integration with external identity providers through SAML, OIDC, and OAuth2 protocols.

## Overview

Authenc's federation system provides enterprise-grade identity brokering capabilities similar to Keycloak, allowing users to authenticate through external identity providers while maintaining centralized user management and access control.

### Key Features

- **Multi-Protocol Support**: SAML 2.0, OpenID Connect, OAuth 2.0
- **JIT User Provisioning**: Just-In-Time user creation from external providers
- **Identity Provider Management**: Centralized configuration and management
- **Federated Identity Linking**: Link external identities to internal users
- **Protocol-Agnostic API**: Unified interface for all federation protocols
- **Enterprise Security**: Cryptographic validation and secure token handling

## Architecture

### Core Components

1. **Identity Broker Registry**: Manages multiple identity providers
2. **JIT Provisioning Service**: Handles automatic user creation
3. **Federation Handlers**: Protocol-specific authentication endpoints
4. **Federated Identity Storage**: Database operations for external identities

### Service Layer

```rust
// Core federation services
pub trait JITProvisioningService: Send + Sync {
    async fn provision_user(&self, request: JITUserProvisioningRequest)
        -> Result<JITUserProvisioningResponse, String>;
}

pub trait IdentityBroker: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str)
        -> Result<Option<User>, String>;
}
```

## SAML Federation

### Configuration

SAML identity providers require the following configuration:

```json
{
  "entity_id": "https://idp.example.com",
  "sso_url": "https://idp.example.com/sso",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "name_id_policy": "emailAddress",
  "want_assertions_signed": true,
  "want_response_signed": true
}
```

### Authentication Flow

1. **SP-Initiated SSO**:
   ```
   User → Authenc Login → SAML Request → IdP → SAML Response → Authenc → User Authenticated
   ```

2. **IdP-Initiated SSO**:
   ```
   User → IdP Login → SAML Response → Authenc ACS → User Authenticated
   ```

### SAML Endpoints

- `POST /auth/realms/{realm}/broker/saml/login` - Initiate SAML login
- `POST /auth/realms/{realm}/broker/saml/endpoint` - SAML Assertion Consumer Service (ACS)

### SAML Response Processing

The system validates SAML responses including:
- Digital signatures
- Timestamps and validity windows
- Audience restrictions
- Subject confirmation
- Attribute extraction and mapping

## OIDC Federation

### Configuration

OIDC identity providers require:

```json
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://accounts.google.com/o/oauth2/v2/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scopes": ["openid", "email", "profile"]
}
```

### Authentication Flow

1. **Authorization Code Flow**:
   ```
   User → Authenc → Authorization Request → IdP → Authorization Code → Authenc → Token Request → IdP → ID Token → User Authenticated
   ```

### OIDC Endpoints

- `GET /auth/realms/{realm}/broker/oidc/login` - Initiate OIDC login
- `GET /auth/realms/{realm}/broker/oidc/callback` - OIDC callback handler

## JIT User Provisioning

### Overview

Just-In-Time (JIT) provisioning automatically creates user accounts when users authenticate through external identity providers for the first time.

### Provisioning Process

1. **External Authentication**: User authenticates with identity provider
2. **User Lookup**: System checks if user already exists
3. **User Creation**: If not found, creates new user with external attributes
4. **Identity Linking**: Links external identity to internal user
5. **Attribute Mapping**: Maps external attributes to internal user fields

### Provisioning Request

```rust
pub struct JITUserProvisioningRequest {
    pub identity_provider_id: Uuid,
    pub external_id: String,
    pub external_username: Option<String>,
    pub external_email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub external_attributes: Option<serde_json::Value>,
    pub realm_id: Uuid,
}
```

### Attribute Mapping

The system supports flexible attribute mapping:

```rust
// SAML attribute mapping
let username = saml_response.get_attribute("username").or_else(|| saml_response.get_attribute("urn:oid:0.9.2342.19200300.100.1.1"));
let email = saml_response.get_attribute("email").or_else(|| saml_response.get_attribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"));
let first_name = saml_response.get_attribute("firstName").or_else(|| saml_response.get_attribute("urn:oid:2.5.4.42"));
let last_name = saml_response.get_attribute("lastName").or_else(|| saml_response.get_attribute("urn:oid:2.5.4.4"));
```

## Identity Provider Management

### Provider Types

- **SAML**: SAML 2.0 identity providers (e.g., ADFS, Shibboleth, Okta)
- **OIDC**: OpenID Connect providers (e.g., Google, Azure AD, Auth0)
- **OAuth2**: OAuth 2.0 providers (e.g., GitHub, Facebook, Twitter)
- **LDAP**: LDAP directory servers
- **Social**: Social login providers

### Provider Configuration

```rust
pub struct IdentityProviderConfig {
    pub id: Uuid,
    pub name: String,
    pub provider_type: IdentityProviderType,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub realm_id: Uuid,
}
```

### Management Endpoints

- `GET /auth/admin/realms/{realm}/identity-providers` - List providers
- `POST /auth/admin/realms/{realm}/identity-providers` - Create provider
- `PUT /auth/admin/realms/{realm}/identity-providers/{id}` - Update provider
- `DELETE /auth/admin/realms/{realm}/identity-providers/{id}` - Delete provider
- `POST /auth/admin/realms/{realm}/identity-providers/{id}/test` - Test provider

## Federated Identity Linking

### Overview

Federated identity linking connects external identities to internal Authenc users, enabling single sign-on across multiple identity providers.

### Linking Process

1. **Authentication**: User authenticates through identity provider
2. **Identity Lookup**: System searches for existing federated identity
3. **User Association**: Links external identity to internal user
4. **Profile Sync**: Optionally syncs profile attributes

### Database Schema

```sql
CREATE TABLE federated_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    identity_provider_id UUID NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    external_username VARCHAR(255),
    external_email VARCHAR(255),
    external_attributes JSONB,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    UNIQUE(identity_provider_id, external_id)
);
```

## Security Considerations

### SAML Security

- **Digital Signatures**: All SAML messages should be signed
- **Encryption**: Sensitive attributes can be encrypted
- **Timestamps**: Strict validation of NotBefore/NotOnOrAfter
- **Audience**: Validate assertion audience matches SP entity ID
- **Replay Prevention**: Implement assertion ID tracking

### OIDC Security

- **State Parameter**: Prevent CSRF attacks
- **PKCE**: Use Proof Key for Code Exchange
- **Nonce**: Prevent replay attacks
- **Token Validation**: Validate ID tokens and access tokens
- **Redirect URI**: Strict redirect URI validation

### General Security

- **Certificate Validation**: Validate IdP certificates
- **Attribute Validation**: Sanitize and validate user attributes
- **Rate Limiting**: Implement rate limiting on federation endpoints
- **Audit Logging**: Log all federation activities
- **Session Management**: Secure session handling for federated users

## Error Handling

### Common Errors

- **Invalid SAML Response**: Malformed or invalid SAML assertions
- **Expired Tokens**: Tokens that have exceeded their validity period
- **Invalid Signatures**: Cryptographic signature validation failures
- **Unknown Providers**: Requests for non-existent identity providers
- **Attribute Mapping**: Failures in mapping external attributes

### Error Responses

```json
{
  "error": "invalid_saml_response",
  "error_description": "SAML response validation failed",
  "error_details": {
    "validation_errors": ["Invalid signature", "Expired assertion"]
  }
}
```

## Integration Examples

### SAML Integration

```rust
// Configure SAML identity provider
let saml_config = json!({
  "entity_id": "https://idp.example.com",
  "sso_url": "https://idp.example.com/sso",
  "certificate": "...",
  "attribute_mapping": {
    "username": "username",
    "email": "email",
    "firstName": "firstName",
    "lastName": "lastName"
  }
});

// Create identity provider
let provider = IdentityProviderConfig {
    name: "Example SAML IdP".to_string(),
    provider_type: IdentityProviderType::SAML,
    enabled: true,
    config: saml_config,
    realm_id: realm_id,
};
```

### OIDC Integration

```rust
// Configure OIDC identity provider
let oidc_config = json!({
  "issuer": "https://accounts.google.com",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scopes": ["openid", "email", "profile"]
});

// Create identity provider
let provider = IdentityProviderConfig {
    name: "Google OIDC".to_string(),
    provider_type: IdentityProviderType::OIDC,
    enabled: true,
    config: oidc_config,
    realm_id: realm_id,
};
```

## Monitoring and Metrics

### Federation Metrics

- **Authentication Success Rate**: Percentage of successful authentications
- **JIT Provisioning Rate**: Number of users created via JIT
- **Provider Response Times**: Average response time per provider
- **Error Rates**: Error rates by provider and protocol
- **Active Sessions**: Number of active federated sessions

### Logging

All federation activities are logged including:
- Authentication attempts
- JIT provisioning events
- Identity linking operations
- Token validation results
- Error conditions

## Troubleshooting

### Common Issues

1. **SAML Signature Validation**: Ensure IdP certificates are properly configured
2. **OIDC Token Validation**: Verify client credentials and token endpoints
3. **Attribute Mapping**: Check attribute names and mapping configuration
4. **Redirect URIs**: Ensure redirect URIs match IdP configuration
5. **Certificate Expiry**: Monitor certificate expiration dates

### Debug Mode

Enable debug logging for detailed federation traces:

```rust
env_logger::init();
std::env::set_var("RUST_LOG", "authenc::handlers::federated_auth=debug,authenc::services::federation=debug");
```

## API Reference

### Authentication Endpoints

#### SAML Authentication
```http
POST /auth/realms/{realm}/broker/saml/login
Content-Type: application/x-www-form-urlencoded

SAMLRequest={base64-encoded-saml-request}
```

#### OIDC Authentication
```http
GET /auth/realms/{realm}/broker/oidc/login?redirect_uri={uri}&state={state}
```

### Administration Endpoints

#### List Identity Providers
```http
GET /auth/admin/realms/{realm}/identity-providers
Authorization: Bearer {admin-token}
```

#### Create Identity Provider
```http
POST /auth/admin/realms/{realm}/identity-providers
Authorization: Bearer {admin-token}
Content-Type: application/json

{
  "name": "Example Provider",
  "provider_type": "SAML",
  "enabled": true,
  "config": { ... }
}
```

## Migration Guide

### From Keycloak

If migrating from Keycloak:

1. Export identity provider configurations
2. Map SAML/OIDC settings to Authenc format
3. Configure attribute mappings
4. Test authentication flows
5. Migrate user identities if needed

### From Other Systems

For migration from other identity systems:

1. Extract provider configurations
2. Convert to Authenc's configuration format
3. Set up attribute mappings
4. Configure certificates and keys
5. Test end-to-end authentication

## Best Practices

### Configuration
- Use HTTPS for all federation endpoints
- Implement proper certificate management
- Configure appropriate timeouts
- Enable signature validation
- Set up monitoring and alerting

### Security
- Regularly rotate certificates
- Implement rate limiting
- Enable audit logging
- Validate all inputs
- Use secure random generators

### Performance
- Implement caching for provider configurations
- Use connection pooling for external calls
- Monitor response times
- Implement circuit breakers
- Cache JWKS documents

### Maintenance
- Regularly review and update provider configurations
- Monitor certificate expiration
- Keep dependencies updated
- Review and rotate secrets
- Backup configurations regularly
