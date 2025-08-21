# Authence

[![CI](https://github.com/your-org/authence/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/authence/actions/workflows/ci.yml)

Authence adalah authentication & authorization server berbasis Rust, terinspirasi best practice Keycloak. Kini mendukung:
- Audit log persisten PostgreSQL
- RBAC granular (middleware, scope per endpoint)
- Session & TOTP endpoint
- Group management
- OIDC endpoints
- Modularisasi dan plugin system


- Multi-tenant (realm)
- User, group, role, permission, RBAC granular (middleware)
- Audit log (persisten PostgreSQL)
- API documented (OpenAPI)
- Modular & testable
- JWT & session management (login, logout, revoke, list)
- MFA (TOTP, pure Rust, endpoint enable/disable/verify)
- Middleware autentikasi JWT (zero trust)
- Rate limiting, i18n, metrics, plugin system
- Advanced error handling & compliance
## Fitur
- Multi-tenant (realm)
- User, group, role, permission, RBAC granular (middleware)
- Audit log persisten PostgreSQL (async)
- API documented (OpenAPI)
- Modular & testable
- JWT & session management (login, logout, revoke, list)
- MFA (TOTP, pure Rust, endpoint enable/disable/verify)
- Middleware autentikasi JWT (zero trust)
- Rate limiting, i18n, metrics, plugin system
- Advanced error handling & compliance
- Group management (API, model, service)
- OIDC endpoints (discovery, authorize, token, userinfo, jwks)
- Extensible plugin system
- Multi-tenant (realm)
- User, group, role, permission, RBAC granular (middleware)
- Audit log (persisten PostgreSQL)
- API documented (OpenAPI)
- Modular & testable
- JWT & session management (login, logout, revoke, list)
- MFA (TOTP, pure Rust, endpoint enable/disable/verify)
- Middleware autentikasi JWT (zero trust)
- Rate limiting, i18n, metrics, plugin system
- Advanced error handling & compliance

- `core/` - Core authentication and authorization logic
- `api/` - REST API endpoints (user, group, role, permission, session, TOTP, audit, RBAC, OIDC, dsb)
- `model/` - Data models and schema (user, group, audit_log, dsb)
- `crypto/` - Cryptographic utilities
- `services/` - Business logic and service layer (user_store, group_store, session_store, totp_store, dsb)
- `integration/` - Integration with external identity providers
- `tests/` - Integration and unit tests
- `migrations/` - Database migrations
## Struktur
- `core/` - Core authentication and authorization logic
- `api/` - REST API endpoints (user, group, role, permission, session, TOTP, audit, RBAC, OIDC, dsb)
- `model/` - Data models and schema (user, group, audit_log, dsb)
- `crypto/` - Cryptographic utilities
- `services/` - Business logic and service layer (user_store, group_store, session_store, totp_store, dsb)
- `integration/` - Integration with external identity providers
- `tests/` - Integration and unit tests
- `migrations/` - Database migrations
- `core/` - Core authentication and authorization logic
- `api/` - REST API endpoints (user, group, role, permission, session, TOTP, audit, RBAC, OIDC, dsb)
- `model/` - Data models and schema (user, group, audit_log, dsb)
- `crypto/` - Cryptographic utilities
- `services/` - Business logic and service layer (user_store, group_store, session_store, totp_store, dsb)
- `integration/` - Integration with external identity providers
- `tests/` - Integration and unit tests
- `migrations/` - Database migrations

- [Contoh API](docs/EXAMPLES.md)
- [Kontribusi](CONTRIBUTING.md)
## Dokumentasi
- [Contoh API](docs/EXAMPLES.md)
- [Kontribusi](CONTRIBUTING.md)
- [Contoh API](docs/EXAMPLES.md)
- [Kontribusi](CONTRIBUTING.md)

- [CHANGELOG.md](CHANGELOG.md)
## Changelog
- [CHANGELOG.md](CHANGELOG.md)
- [CHANGELOG.md](CHANGELOG.md)

- [LICENSE](LICENSE)
## License
- [LICENSE](LICENSE)
- [LICENSE](LICENSE)

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
# Authence

[![CI](https://github.com/your-org/authence/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/authence/actions/workflows/ci.yml)

Authence adalah authentication & authorization server berbasis Rust, terinspirasi best practice Keycloak. Kini mendukung:

- Multi-tenant (realm)
- User, group, role, permission, RBAC granular (middleware)
- Audit log persisten PostgreSQL (async)
- API documented (OpenAPI)
- Modular & testable
- JWT & session management (login, logout, revoke, list)
- MFA (TOTP, pure Rust, endpoint enable/disable/verify)
- Middleware autentikasi JWT (zero trust)
- Rate limiting, i18n, metrics, plugin system
- Advanced error handling & compliance
- Group management (API, model, service)
- OIDC endpoints (discovery, authorize, token, userinfo, jwks)
- Extensible plugin system

## Struktur
- `core/` - Core authentication and authorization logic
- `api/` - REST API endpoints (user, group, role, permission, session, TOTP, audit, RBAC, OIDC, dsb)
- `model/` - Data models and schema (user, group, audit_log, dsb)
- `crypto/` - Cryptographic utilities
- `services/` - Business logic and service layer (user_store, group_store, session_store, totp_store, dsb)
- `integration/` - Integration with external identity providers
- `tests/` - Integration and unit tests
- `migrations/` - Database migrations

## Dokumentasi
- [Contoh API](docs/EXAMPLES.md)
- [Kontribusi](CONTRIBUTING.md)
- [CHANGELOG.md](CHANGELOG.md)
- [LICENSE](LICENSE)

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
cd authence
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
