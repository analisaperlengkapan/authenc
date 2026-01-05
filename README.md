# 🔐 Authenc

> **Enterprise-grade Identity and Access Management (IAM) Platform**

[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.0-green.svg)](Cargo.toml)

---

## ⚠️ IMPORTANT NOTICE

> [!CAUTION]
> **🚧 THIS PROJECT IS UNDER ACTIVE DEVELOPMENT 🚧**
>
> - ❌ **NOT PRODUCTION READY**
> - ❌ **UNSTABLE API** - Breaking changes may occur at any time
> - ❌ **NOT FULLY SECURITY AUDITED**
> - ❌ **INCOMPLETE DOCUMENTATION**
>
> Use only for development and testing purposes. **DO NOT USE FOR SENSITIVE DATA OR PRODUCTION SYSTEMS.**

---

## 📖 About Authenc

**Authenc** is an enterprise-grade Identity and Access Management (IAM) platform built with Rust, providing comprehensive authentication and authorization solutions for modern applications.

### 🎯 Key Features

#### 🔑 Authentication
- **OAuth 2.0** - Authorization Code, Client Credentials, PKCE, Device Flow
- **OpenID Connect (OIDC)** - Discovery, JWKS, Userinfo endpoints
- **SAML 2.0** - SP-Initiated, IdP-Initiated SSO
- **WebAuthn/FIDO2** - Passwordless authentication
- **TOTP/HOTP** - Two-factor authentication
- **Social Login** - Google, GitHub, Facebook, Microsoft, and more

#### 🛡️ Security
- **Zero Trust Architecture** - Continuous verification
- **Brute Force Protection** - Rate limiting and account lockout
- **CSRF Protection** - Token-based protection
- **mTLS** - Mutual TLS for client authentication
- **DPoP** - Demonstrating Proof of Possession

#### 🔐 Cryptography
| Algorithm | Usage |
|-----------|-------|
| Ed25519 | JWT signing, default key type |
| ECDSA P-256/P-384/P-521 | Token signing |
| Ed448 | High-security signing |
| AES-256-GCM | Encryption at rest |
| Argon2id | Password hashing |
| Shamir Secret Sharing | Key splitting |
| **Post-Quantum (Experimental)** | ML-DSA, ML-KEM, Falcon |

#### 🏢 Enterprise Features
- **Multi-tenancy** - Realm-based isolation
- **Federation** - LDAP, Active Directory, External IdP
- **Identity Brokering** - External identity provider integration
- **Protocol Mappers** - Custom claim mapping
- **Event System** - Audit logging, webhooks
- **OID4VC** - OpenID for Verifiable Credentials

---

## 🏗️ Architecture

```
authenc/
├── src/
│   ├── app.rs              # Application state & configuration
│   ├── main.rs             # Entry point
│   ├── lib.rs              # Library exports
│   │
│   ├── crypto/             # 🔐 Cryptographic operations
│   │   ├── ed25519_keys.rs     # Ed25519 key management
│   │   ├── ecdsa_*.rs          # ECDSA key variants
│   │   ├── aes_gcm.rs          # AES-GCM encryption
│   │   ├── shamir.rs           # Secret sharing
│   │   ├── pqc.rs              # Post-quantum crypto
│   │   └── xmldsig.rs          # XML signature for SAML
│   │
│   ├── database/           # 💾 Database layer
│   │   ├── operations.rs       # CRUD operations
│   │   └── migrations/         # Schema files
│   │
│   ├── handlers/           # 🌐 HTTP handlers
│   │   ├── api/                # REST API endpoints
│   │   ├── oauth2_*.rs         # OAuth2 endpoints
│   │   ├── oidc_*.rs           # OIDC endpoints
│   │   ├── saml.rs             # SAML endpoints
│   │   └── health.rs           # Health checks
│   │
│   ├── services/           # ⚙️ Business logic
│   │   ├── auth_flow.rs        # Authentication flows
│   │   ├── webauthn.rs         # WebAuthn service
│   │   ├── device.rs           # Device management
│   │   ├── oid4vc.rs           # Verifiable Credentials
│   │   ├── saml.rs             # SAML processing
│   │   ├── password_policy.rs  # Password policies
│   │   ├── federation/         # Identity federation
│   │   ├── sso/                # Single Sign-On
│   │   └── zero_trust/         # Zero Trust
│   │
│   ├── middleware/         # 🔧 HTTP middleware
│   │   ├── auth_middleware.rs  # JWT validation
│   │   ├── rate_limit.rs       # Rate limiting
│   │   ├── csrf_protection.rs  # CSRF protection
│   │   └── security_headers.rs # Security headers
│   │
│   ├── spi/                # 🔌 Service Provider Interface
│   │   ├── authenticator.rs    # Custom authenticators
│   │   ├── protocol_mappers.rs # Protocol mapping
│   │   └── federation.rs       # Federation SPI
│   │
│   └── vault/              # 🔒 Secret management
│       └── hashicorp.rs        # HashiCorp Vault integration
│
├── migrations/             # 📁 Database migrations (008-021)
├── tests/                  # 🧪 Integration tests
└── Cargo.toml              # 📦 Dependencies
```

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.90+
- **PostgreSQL** 14+
- **OpenSSL** (for crypto operations)

### Installation

```bash
# Clone repository
git clone https://github.com/analisaperlengkapan/authenc.git
cd authenc

# Copy environment file
cp .env.example .env

# Edit configuration
nano .env
```

### Configuration (.env)

```env
# Database
DATABASE_URL=postgresql://postgres:password@localhost/authenc

# Server
SERVER_PORT=3000
SERVER_HOST=0.0.0.0

# Security
JWT_SECRET=your-super-secret-key-change-in-production
ENCRYPTION_KEY=32-byte-encryption-key-here

# Features (optional)
ENABLE_RATE_LIMITING=true
ENABLE_CSRF_PROTECTION=true
```

### Running

```bash
# Development mode
cargo run

# Production build
cargo build --release
./target/release/authenc

# With specific features
cargo run --features "quantum,admin_console"
```

### Docker (Coming Soon)

```bash
docker-compose up -d
```

---

## 🔌 API Endpoints

### Health & Monitoring
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Basic health check |
| `/health/ready` | GET | Readiness check (DB) |
| `/health/live` | GET | Liveness check |

### OAuth 2.0 / OIDC
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid_configuration` | GET | OIDC Discovery |
| `/oauth2/authorize` | GET | Authorization endpoint |
| `/oauth2/token` | POST | Token endpoint |
| `/oauth2/introspect` | POST | Token introspection |
| `/oauth2/revoke` | POST | Token revocation |
| `/oauth2/jwks` | GET | JSON Web Key Set |
| `/oauth2/userinfo` | GET | User info endpoint |

### Admin API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/admin/stats` | GET | System statistics |
| `/api/v1/auth/realms` | CRUD | Realm management |
| `/api/v1/auth/users` | CRUD | User management |
| `/api/v1/auth/roles` | CRUD | Role management |
| `/api/v1/auth/clients` | CRUD | Client management |

### Advanced Features
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/realms/{id}/event-listeners` | CRUD | Event listeners |
| `/api/v1/realms/{id}/protocol-mappers` | CRUD | Protocol mappers |
| `/api/v1/realms/{id}/authenticators` | CRUD | Authenticators |
| `/oid4vc/.well-known/openid-credential-issuer` | GET | VC Issuer metadata |

---

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test session5_rest_api_tests

# Run with output
cargo test -- --nocapture
```

---

## 📊 Features Matrix

| Feature | Status | Notes |
|---------|--------|-------|
| OAuth 2.0 | ✅ Implemented | Core flows working |
| OIDC | ✅ Implemented | Ed25519 signing |
| SAML 2.0 | ✅ Implemented | SP & IdP modes |
| WebAuthn | 🔶 Partial | Basic support |
| TOTP | ✅ Implemented | RFC 6238 compliant |
| Social Login | 🔶 Partial | Requires configuration |
| Zero Trust | 🔶 Partial | Policy engine WIP |
| OID4VC | ✅ Implemented | 4 credential types |
| Post-Quantum | 🔬 Experimental | ML-DSA, ML-KEM |
| Clustering | ⏳ Planned | HA support |
| Admin UI | ⏳ Planned | Web console |

**Legend:** ✅ Ready | 🔶 Partial | 🔬 Experimental | ⏳ Planned

---

## 🔒 Security Considerations

1. **Change default secrets** - Always update JWT_SECRET and ENCRYPTION_KEY
2. **Use TLS** - Always enable HTTPS in production environments
3. **Database encryption** - Enable PostgreSQL encryption at rest
4. **Regular updates** - Keep dependencies updated for security patches
5. **Audit logs** - Enable and monitor event logging for security incidents

---

## 📝 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📞 Support

- 📧 Email: security@kejaksaan.go.id
- 📖 Documentation: [docs.simpel.kejaksaan.go.id/authenc](https://docs.simpel.kejaksaan.go.id/authenc)
- 🐛 Issues: [GitHub Issues](https://github.com/analisaperlengkapan/authenc/issues)

---

<p align="center">
  <b>Built with ❤️ in Rust</b><br>
  <sub>© 2024-2026 SIMPelv2 Team</sub>
</p>
