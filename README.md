# Authenc by Cipherce

**Authenc** is a high-performance authentication and authorization server built in Rust with modern security practices. Fully migrated to Axum framework with Ed25519 cryptography and native mTLS support.

## 🔒 Security Features

- **Zero Vulnerabilities**: Clean cargo audit with no security issues
- **Ed25519 Cryptography**: Modern, timing-attack-resistant JWT signing
- **Native mTLS**: Built-in mutual TLS client certificate validation
- **No Unsafe Code**: Completely safe Rust implementation
- **ECDSA P-256**: Alternative elliptic curve cryptography support

## 🚀 Framework Migration

**Authenc** has been completely migrated from Actix-web to **Axum** for better performance, security, and maintainability:

- **Modern HTTP Framework**: Axum with tower middleware ecosystem
- **Type-Safe Routing**: Compile-time route validation
- **Better Error Handling**: Structured error responses with IntoResponse
- **Improved Testing**: Native Axum test utilities

## 🔐 Cryptographic Security

### Ed25519 JWT Signing
- **Timing Attack Immunity**: Ed25519 is inherently resistant to timing attacks
- **Performance**: Faster signing and verification than RSA
- **Smaller Keys**: 32-byte keys vs 2048+ bit RSA keys
- **Standards Compliance**: RFC 8037 EdDSA support

### Native mTLS Support
- **Client Certificate Validation**: Built-in certificate fingerprint validation
- **Header-based Integration**: Works with reverse proxies (X-SSL-Client-Cert)
- **Configurable Trust**: SHA-256 fingerprint allowlists
- **Production Ready**: Supports both development and production environments

[![Build Status](https://github.com/cipherce/authenc/workflows/CI/badge.svg)](https://github.com/cipherce/authenc/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-blue.svg)](https://www.rust-lang.org)

## 🏗️ Architecture Overview

Built with modern Rust practices and enterprise-grade security, Authenc provides comprehensive identity and access management (IAM) capabilities with a focus on performance and scalability.

## 🚀 Features

### Core Authentication & Authorization
- **Multi-tenant support** - Realm-based isolation for multiple organizations
- **Role-Based Access Control (RBAC)** - Granular permissions with user, group, and role management
- **JWT & Session management** - Secure token-based and session-based authentication
- **Multi-Factor Authentication (MFA)** - TOTP support with pure Rust implementation

### Secret Management & Vault
- **Modular Vault Abstraction** - Pluggable secret store interface for maximum security
- **File-based Vault Provider** - Secure file-based secret backend (Kubernetes/OpenShift compatible)
- **Secreton Provider** - Integration point for custom Rust-based secret manager
- **Zero trust, forever unknown secret** - No secrets ever written to disk/log; runtime secret fetch from vault

### Security & Middleware
- **Axum Middleware Stack** - Modern tower-based middleware ecosystem
- **Rate limiting** - Global and path-specific request throttling
- **Security headers** - Comprehensive HTTP security headers (CSP, HSTS, XSS protection)
- **Request sanitization** - SQL injection and payload validation
- **Brute force protection** - Automatic lockout mechanisms
- **mTLS Authentication** - Native client certificate validation
- **Ed25519 JWT** - Timing-attack-resistant token signing

### Storage & Persistence
- **PostgreSQL audit logging** - Persistent, queryable audit trails
- **Configurable backends** - Support for multiple database configurations
- **Session storage** - Scalable session management

### Developer Experience
- **Comprehensive test coverage** - Unit and integration tests for all components
- **Configuration-driven** - Environment variable and file-based configuration
- **Metrics & observability** - Built-in health checks and metrics endpoints
- **API documentation** - OpenAPI/Swagger documentation (OpenAPI 3.1.0 compliant)

## 🔒 Vault & Secret Management
- Modular vault abstraction: file, keystore, HashiCorp Vault, KMS, Secreton
- File-based vault: mount secrets as files (Kubernetes/OpenShift)
- Secreton: custom Rust-based secret manager integration
- No secrets ever written to disk/log; always fetched at runtime

### Secreton Vault Configuration
To use Secreton as your secret backend, set the following environment variables:

```bash
SECRETON_ENDPOINT=https://secreton.example.com
SECRETON_TOKEN=your-access-token
```

These can be set in your environment, `.env` file, or deployment configuration. Authenc will automatically use SecretonVault if these are set.

## 📁 Architecture

```
src/
├── app.rs              # Application builder and server configuration
├── config.rs           # Configuration management
├── error.rs            # Error handling and custom error types
├── handlers/           # HTTP request handlers
├── middleware/         # Security and authentication middleware
├── models/             # Data models and schemas
├── services/           # Business logic and data access layer
└── utils/              # Utility functions and helpers

tests/                  # Integration and unit tests
```

## 🛠 Quick Start

### Prerequisites
- Rust 1.75+
- PostgreSQL 12+

#### Optional (for Vault/Secret Management)
- File-based vault: directory for secrets (Kubernetes/OpenShift compatible)
- Secreton: running Secreton server and credentials

### Installation

```bash
git clone https://github.com/cipherce/authenc.git
cd authenc
cargo build --release
```

### Configuration


Set environment variables or create a `.env` file:

```bash
# Server configuration
AUTHENC_HOST=0.0.0.0
AUTHENC_PORT=8080

# TLS/mTLS configuration
# Enable TLS (set to true to enable HTTPS)
TLS_ENABLE=false
# Path to TLS certificate and key (PEM format)
TLS_CERT_FILE=/etc/ssl/certs/authenc.crt
TLS_KEY_FILE=/etc/ssl/private/authenc.key
# Enable mutual TLS (set to true to require client certificates)
MTLS_ENABLE=false
# Path to CA truststore file (PEM, for mTLS)
TLS_TRUSTSTORE_FILE=/etc/ssl/certs/ca.pem
# Password for truststore file (optional)
TLS_TRUSTSTORE_PASSWORD=your-truststore-password

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/authenc

# Security
JWT_SECRET=your-secret-key-change-in-production
PASSWORD_MIN_LENGTH=8

# Features
ENABLE_AUDIT_LOGGING=true
ENABLE_RATE_LIMITING=true
ENABLE_TOTP=true

# Secreton Vault (optional)
SECRETON_ENDPOINT=https://secreton.example.com
SECRETON_TOKEN=your-access-token
```

### Running

```bash
cargo run
```

The server will start on `http://localhost:8080`

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test category
cargo test rate_limit
cargo test security
```

## 📊 Health & Monitoring

- **Health check**: `GET /health`
- **Readiness check**: `GET /ready`
- **Metrics**: `GET /metrics` (if enabled)

## 🔧 Configuration Options

| Environment Variable        | Default         | Description |
|----------------------------|-----------------|-------------|
| `AUTHENC_HOST`             | `0.0.0.0`       | Server bind address |
| `AUTHENC_PORT`             | `8080`          | Server port |
| `DATABASE_URL`             | `postgresql://...` | PostgreSQL connection string |
| `JWT_SECRET`               | `change-me`     | JWT signing secret |
| `LOG_LEVEL`                | `info`          | Logging level |
| `ENABLE_METRICS`           | `true`          | Enable metrics endpoint |
| `TLS_ENABLE`               | `false`         | Enable TLS/HTTPS |
| `TLS_CERT_FILE`            | *(none)*        | Path to TLS certificate file (PEM) |
| `TLS_KEY_FILE`             | *(none)*        | Path to TLS private key file (PEM) |
| `MTLS_ENABLE`              | `false`         | Enable mutual TLS (client cert required) |
| `TLS_TRUSTSTORE_FILE`      | *(none)*        | Path to CA truststore file (PEM, for mTLS) |
| `TLS_TRUSTSTORE_PASSWORD`  | *(none)*        | Password for truststore file (optional) |
| `SECRETON_ENDPOINT`        | *(none)*        | Secreton API endpoint (optional) |
| `SECRETON_TOKEN`           | *(none)*        | Secreton API token (optional) |

## 🆕 What's New in 0.3.0
- **Endpoint separation:** Public, admin, and internal API scopes (`PUBLIC_PREFIX`, `ADMIN_PREFIX`, `INTERNAL_PREFIX`)
- **Feature flags:** OIDC, SAML, UI, MultiDb, and more (see below)
- **Config stubs:** OIDC, SAML, UI, MultiDb for future extensibility
- **Metrics endpoint:** Now feature-flagged
- **All configuration:** Now environment-driven, with robust defaults

## 🔀 Endpoint Separation
- Public endpoints: `${PUBLIC_PREFIX}` (default `/api/public`)
- Admin endpoints: `${ADMIN_PREFIX}` (default `/api/admin`)
- Internal endpoints: `${INTERNAL_PREFIX}` (default `/api/internal`)

## 🏁 Feature Flags & Advanced Config
| Environment Variable        | Default         | Description |
|----------------------------|-----------------|-------------|
| `ENABLE_OIDC`              | `false`         | Enable OIDC provider stub |
| `ENABLE_SAML`              | `false`         | Enable SAML provider stub |
| `ENABLE_UI`                | `false`         | Enable UI stub |
| `ENABLE_MULTI_DB`          | `false`         | Enable multi-database config |
| `OIDC_ISSUER`              | *(none)*        | OIDC issuer URL (if enabled) |
| `OIDC_CLIENT_ID`           | *(none)*        | OIDC client ID (if enabled) |
| `OIDC_CLIENT_SECRET`       | *(none)*        | OIDC client secret (if enabled) |
| `OIDC_REDIRECT_URI`        | *(none)*        | OIDC redirect URI (if enabled) |
| `SAML_ENTITY_ID`           | *(none)*        | SAML entity ID (if enabled) |
| `SAML_SSO_URL`             | *(none)*        | SAML SSO URL (if enabled) |
| `SAML_CERTIFICATE`         | *(none)*        | SAML certificate (if enabled) |
| `UI_THEME`                 | *(none)*        | UI theme (if enabled) |
| `MULTI_DB_URLS`            | *(none)*        | Comma-separated DB URLs (if enabled) |
| `PUBLIC_PREFIX`            | `/api/public`   | Public API prefix |
| `ADMIN_PREFIX`             | `/api/admin`    | Admin API prefix |
| `INTERNAL_PREFIX`          | `/api/internal` | Internal API prefix |

See [CHANGELOG.md](CHANGELOG.md) for full details.

## Contributing
Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk panduan kontribusi.

## Contoh Endpoint
- `/v1/login` - Login user
- `/v1/users` - CRUD user
- `/v1/groups` - CRUD group
- `/v1/roles` - CRUD role
- `/v1/permissions` - CRUD permission
- `/v1/sessions` - List session user
- `/v1/logout` - Logout
- `/v1/audit/logs` - List audit log (admin)
- `/v1/audit/logs/export` - Export audit log CSV (admin)
- `/v1/users/{id}/totp` - Enable/disable TOTP
- `/v1/users/{id}/totp/verify` - Verify TOTP
## Build & Test
```bash
# Authenc by Cipherce

[![CI](https://github.com/your-org/authence/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/authence/actions/workflows/ci.yml)

Authenc adalah authentication & authorization server berbasis Rust, terinspirasi best practice Keycloak. Kini mendukung:



## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- 📧 Email: support@cipherce.com
- 🐛 Issues: [GitHub Issues](https://github.com/cipherce/authenc/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/cipherce/authenc/discussions)

## 🗺 Roadmap

- [ ] OpenID Connect (OIDC) provider implementation
- [ ] SAML 2.0 support
- [ ] Redis session backend
- [ ] Kubernetes operator
- [ ] Multi-database support (MySQL, SQLite)
- [ ] Web UI for administration
- [ ] Social login providers (Google, GitHub, etc.)

---

Built with ❤️ in Rust by the Cipherce team.
- `/v1/users/{id}/totp/verify` - Verify TOTP

## Build & Test
```bash
cd authenc
cargo build
cargo test
```

## CI/CD
- Otomatis build & test di GitHub Actions setiap push/PR ke `main`.

## Keamanan
- Zero trust, session & token revocation, forever unknown secret
- Tidak ada secret yang pernah ditulis ke disk/log
- Siap untuk audit, compliance, dan deployment production

## Lisensi
MIT
cargo build
cargo test
```

## CI/CD
- Otomatis build & test di GitHub Actions setiap push/PR ke `main`.


## Keamanan
- Zero trust, session & token revocation, forever unknown secret
- Tidak ada secret yang pernah ditulis ke disk/log
- Siap untuk audit, compliance, dan deployment production

## Lisensi
MIT
