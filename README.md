# 🔐 Authenc

> **Identity and Access Management (IAM) Platform in Rust**

[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.0-green.svg)](Cargo.toml)
[![Tests](https://img.shields.io/badge/tests-119-blue.svg)](tests/)

---

## ⚠️ PROJECT STATUS

> [!CAUTION]
> **DEVELOPMENT VERSION - NOT FOR PRODUCTION**
>
> This project is actively developed. While core features are implemented and tested:
> - Some APIs may change between versions
> - Security audits are ongoing
> - Documentation is evolving
>
> **Current Use:** Development, testing, and experimentation only.

---

## 📖 About Authenc

**Authenc** is an identity and access management (IAM) platform written in Rust. It provides modern authentication and authorization capabilities for applications, with a focus on security and performance.

### ✅ What Works

#### Core Authentication
- ✅ **OAuth 2.0** - Standard grant types (Authorization Code, Client Credentials, Refresh Token)
  - PKCE support for public clients
  - Token introspection and revocation endpoints
- ✅ **OpenID Connect (OIDC)** - Discovery, ID tokens, userinfo endpoints
  - Ed25519-signed JWTs throughout
- ✅ **SAML 2.0** - SP functionality with assertion validation
- ✅ **TOTP/2FA** - Time-based one-time passwords for multi-factor authentication

#### Security Features
- ✅ **Cryptography** - Ed25519 for signing, AES-256-GCM for encryption, Argon2id for passwords
- ✅ **Rate Limiting** - Brute force protection and DDoS mitigation
- ✅ **Middleware** - CSRF protection, security headers, input validation
- ✅ **Audit Logging** - Comprehensive event tracking and persistence

#### Enterprise Basics
- ✅ **Multi-tenancy** - Realm-based tenant isolation
- ✅ **RBAC** - Role-based access control with permissions
- ✅ **Federation** - SAML and OIDC identity provider integration
- ✅ **PostgreSQL Backend** - Persistent user, token, and event storage

### 🟡 Partially Implemented

- 🟡 **WebAuthn/FIDO2** - Structure exists, functionality being completed
- 🟡 **Social Login** - Framework ready, individual providers need configuration
- 🟡 **OID4VC** - Verifiable credentials support (experimental)
- 🟡 **Zero Trust** - Basic device trust scoring implemented

### ❌ Not Yet Implemented

- ❌ **Admin Web UI** - REST API exists, UI pending
- ❌ **Clustering** - Single-instance only, no distributed caching yet
- ❌ **LDAP/AD Sync** - Federation structure exists, sync not implemented
- ❌ **Social Provider SDKs** - Google, GitHub, etc. need individual integration

---

## 📊 Project Stats

- **~74K** lines of Rust code
- **251** Rust source files  
- **119** test files
- **15** database migrations (v0.8+)
- **416** git commits

---

## 🏗️ Codebase Organization

```
src/
├── app.rs              # Application state, service initialization
├── main.rs             # Server entry point
├── error.rs            # Error handling and types
│
├── models/             # Data models (users, tokens, sessions, etc)
├── config/             # Configuration management
├── database/           # PostgreSQL operations & migrations
│
├── crypto/             # Cryptographic operations
│   ├── ed25519_keys.rs     # Ed25519 key generation/signing
│   ├── ecdsa_*.rs          # ECDSA variants (P-256, P-384, P-521)
│   ├── aes_gcm.rs          # AES-256-GCM encryption
│   └── pqc.rs              # Post-quantum crypto (experimental)
│
├── handlers/           # HTTP request handlers
│   ├── oauth2.rs           # OAuth2 authorize/token endpoints
│   ├── oidc_*.rs           # OIDC discovery, userinfo, jwks
│   ├── saml.rs             # SAML assertion processing
│   ├── webauthn.rs         # WebAuthn registration/auth
│   └── api/                # Admin REST API routes
│
├── services/           # Business logic
│   ├── auth_flow.rs        # Authentication orchestration
│   ├── device.rs           # Device trust management
│   ├── saml.rs             # SAML processing
│   ├── webauthn.rs         # WebAuthn credential handling
│   ├── federation/         # SAML & OIDC IdP integration
│   ├── sso/                # Single Sign-On logic
│   ├── zero_trust/         # Device trust scoring
│   └── stores/             # Data access layer
│
├── middleware/         # HTTP middleware
│   ├── auth.rs             # JWT validation
│   ├── rate_limit.rs       # Rate limiting
│   ├── csrf_protection.rs  # CSRF tokens
│   └── security_headers.rs # Security headers
│
└── spi/                # Service Provider Interface (extensibility)
    ├── authenticator.rs    # Custom auth providers
    └── protocol_mappers.rs # Claim mapping

migrations/            # Database schema (v0.8 - v0.21)
tests/                # 119 test files covering:
                      # - OAuth2/OIDC flows
                      # - SAML federation
                      # - API endpoints
                      # - Cryptography
                      # - Device trust
```

**Key Metrics:**
- ~250 source files
- 74K lines of code
- 1 main server (Axum web framework)
- PostgreSQL for persistence
- Tokio for async runtime

---

## 🚀 Getting Started

### Requirements

- **Rust 1.90+** - Install from [rustup.rs](https://rustup.rs)
- **PostgreSQL 14+** - For data persistence
- **OpenSSL** - For cryptographic operations

### Setup

```bash
# Clone repository
git clone https://github.com/analisaperlengkapan/authenc.git
cd authenc

# Configure environment
export DATABASE_URL="postgresql://user:password@localhost/authenc"
export JWT_SECRET="change-me-in-production"
export SERVER_PORT=3000

# Run migrations
sqlx migrate run

# Start server
cargo run
```

Server will start on `http://localhost:3000`

### Quick Test

```bash
# Health check
curl http://localhost:3000/health

# OIDC discovery
curl http://localhost:3000/.well-known/openid-configuration

# Create a test user
curl -X POST http://localhost:3000/api/v1/auth/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"Test123!"}'
```

---

## 📚 API Overview

### Health & Status
```
GET  /health              # Basic health check
GET  /health/ready        # Ready to accept requests
GET  /health/live         # Liveness probe
```

### OAuth 2.0 & OIDC
```
GET  /.well-known/openid-configuration    # OIDC metadata
GET  /oauth2/authorize                    # Authorization endpoint
POST /oauth2/token                        # Token endpoint
POST /oauth2/introspect                   # Token introspection
POST /oauth2/revoke                       # Token revocation
GET  /oauth2/jwks                         # Public key set
GET  /oauth2/userinfo                     # Get user info
```

### SAML
```
POST /saml/acs                            # Assertion Consumer Service
GET  /saml/metadata                       # SP metadata
GET  /saml/logout                         # Logout endpoint
```

### Admin API
```
CRUD /api/v1/auth/realms                 # Realm management
CRUD /api/v1/auth/users                  # User CRUD
CRUD /api/v1/auth/roles                  # Role management
CRUD /api/v1/auth/clients                # OAuth client management
GET  /api/v1/admin/stats                 # System statistics
```

See `tests/` directory for complete API examples.

---

## 🧪 Running Tests

```bash
# Run all tests
cargo test

# Run specific test module  
cargo test --test api_integration_tests

# Run with output
cargo test -- --nocapture --test-threads=1

# Run only unit tests
cargo test --lib
```

Test files:
- **119** test files total
- Unit tests for crypto, stores, models
- Integration tests for OAuth2, OIDC, SAML flows
- Admin API endpoint tests

---

## 🎯 Feature Status

| Feature | Status | Notes |
|---------|--------|-------|
| **OAuth 2.0** | ✅ Working | Authorization Code, Client Credentials, Refresh Token with PKCE |
| **OIDC** | ✅ Working | Discovery, ID tokens, userinfo - Ed25519 signed JWTs |
| **SAML 2.0** | ✅ Working | SP-initiated SSO with assertion validation |
| **TOTP/2FA** | ✅ Working | Time-based one-time passwords |
| **Crypto** | ✅ Working | Ed25519, ECDSA, AES-256-GCM, Argon2id |
| **Rate Limiting** | ✅ Working | Brute force & DDoS protection |
| **Audit Logging** | ✅ Working | Event persistence to PostgreSQL |
| **WebAuthn** | 🟡 Partial | Framework in place, testing underway |
| **Social Login** | 🟡 Partial | Framework ready, providers need setup |
| **OID4VC** | 🟡 Partial | Verifiable credentials support (experimental) |
| **Zero Trust** | 🟡 Partial | Device trust scoring implemented |
| **Admin Web UI** | ❌ Missing | REST API complete, web console needed |
| **Clustering** | ❌ Missing | Single-instance only |
| **LDAP Sync** | ❌ Missing | Federation framework exists |

**Key:** ✅ = Ready | 🟡 = Partial | ❌ = Not yet | 🔬 = Experimental

---

## 🔐 Security Model

### Cryptography
- **JWT Signing:** Ed25519 (default), ECDSA P-256/384/521 (configurable)
- **Encryption:** AES-256-GCM for sensitive data
- **Passwords:** Argon2id hashing
- **Key Storage:** In-memory with optional Vault integration

### Authentication Flow
1. User authenticates (username/password or federated)
2. JWT token issued with Ed25519 signature
3. Token includes user ID, realm, roles, device info
4. Middleware validates token signature on each request
5. Device trust score evaluated during auth

### Rate Limiting
- Login attempts: 5 per minute per user
- Token endpoints: 100 per minute per client
- API endpoints: Configurable per route

### Audit Trail
- All authentication events logged to database
- Failed login attempts tracked
- Token issuance/revocation logged
- Configuration changes audited

---

## 🚨 Important Notes

### Before Using

1. ⚠️ **Not Production Ready** - This is a development/learning project
2. ⚠️ **Change All Secrets** - JWT_SECRET, encryption keys must be unique
3. ⚠️ **No Security Audit** - This code has not undergone professional security review
4. ⚠️ **HTTPS Required** - Always use TLS/HTTPS in any non-local deployment
5. ⚠️ **Database Security** - Use strong passwords, encrypted connections

### What You Should Know

- Single-instance only (no clustering yet)
- PostgreSQL required (no in-memory mode)
- Some OAuth2 flows may not match all RFC nuances exactly
- WebAuthn implementation is incomplete
- SPI extensions require code modification

---

## � Documentation

- **[README.md](README.md)** - This file
- **[TODO.md](TODO.md)** - Detailed roadmap
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contributing guidelines
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** - Community guidelines
- **[SECURITY.md](SECURITY.md)** - Security policies

---

## 🔗 Related Resources

- [Rust Book](https://doc.rust-lang.org/book/) - Learn Rust
- [Tokio Documentation](https://tokio.rs/) - Async runtime
- [Axum Web Framework](https://github.com/tokio-rs/axum) - Web framework
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0)
- [WebAuthn Spec](https://www.w3.org/TR/webauthn-2/)

---

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) file

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/description`
3. Make changes with tests
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

<p align="center">
  <b>Built with Rust 🦀</b><br>
  <sub>An open source identity and access management platform</sub>
</p>

