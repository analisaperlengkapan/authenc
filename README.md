# Authenc by Cipherce

[![Build Status](https://github.com/cipherce/authenc/workflows/CI/badge.svg)](https://github.com/cipherce/authenc/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-blue.svg)](https://www.rust-lang.org)

**Authenc** is a high-performance authentication and authorization server built in Rust, inspired by enterprise-grade solutions like Keycloak. It provides comprehensive identity and access management (IAM) capabilities with a focus on security, performance, and scalability.

## 🚀 Features

### Core Authentication & Authorization
- **Multi-tenant support** - Realm-based isolation for multiple organizations
- **Role-Based Access Control (RBAC)** - Granular permissions with user, group, and role management
- **JWT & Session management** - Secure token-based and session-based authentication
- **Multi-Factor Authentication (MFA)** - TOTP support with pure Rust implementation

### Security & Middleware
- **Rate limiting** - Global and path-specific request throttling
- **Security headers** - Comprehensive HTTP security headers (CSP, HSTS, XSS protection)
- **Request sanitization** - SQL injection and payload validation
- **Brute force protection** - Automatic lockout mechanisms
- **Zero-trust middleware** - JWT validation and RBAC enforcement

### Storage & Persistence
- **PostgreSQL audit logging** - Persistent, queryable audit trails
- **Configurable backends** - Support for multiple database configurations
- **Session storage** - Scalable session management

### Developer Experience
- **Comprehensive test coverage** - Unit and integration tests for all components
- **Configuration-driven** - Environment variable and file-based configuration
- **Metrics & observability** - Built-in health checks and metrics endpoints
- **API documentation** - OpenAPI/Swagger documentation

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

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/authenc

# Security
JWT_SECRET=your-secret-key-change-in-production
PASSWORD_MIN_LENGTH=8

# Features
ENABLE_AUDIT_LOGGING=true
ENABLE_RATE_LIMITING=true
ENABLE_TOTP=true
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

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `AUTHENC_HOST` | `0.0.0.0` | Server bind address |
| `AUTHENC_PORT` | `8080` | Server port |
| `DATABASE_URL` | `postgresql://...` | PostgreSQL connection string |
| `JWT_SECRET` | `change-me` | JWT signing secret |
| `LOG_LEVEL` | `info` | Logging level |
| `ENABLE_METRICS` | `true` | Enable metrics endpoint |

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
