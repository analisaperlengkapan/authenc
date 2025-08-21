# Authence

[![CI](https://github.com/your-org/authence/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/authence/actions/workflows/ci.yml)

Authence adalah authentication & authorization server berbasis Rust, terinspirasi best practice Keycloak.


## Fitur
- Multi-tenant (realm)
- User, group, role, permission, RBAC
- Audit log
- API documented (OpenAPI)
- Modular & testable
- JWT & session management (login, logout, revoke, list)
- MFA (TOTP, pure Rust)
- Middleware autentikasi JWT (zero trust)
- Rate limiting, i18n, metrics, plugin system
- Advanced error handling & compliance

## Struktur
- `core/` - Core authentication and authorization logic
- `api/` - REST/gRPC API endpoints
- `model/` - Data models and schema
- `crypto/` - Cryptographic utilities
- `services/` - Business logic and service layer
- `integration/` - Integration with external identity providers
- `tests/` - Integration and unit tests
- `migrations/` - Database migrations

## Dokumentasi
- [Contoh API](docs/EXAMPLES.md)
- [Kontribusi](CONTRIBUTING.md)

## Changelog
- [CHANGELOG.md](CHANGELOG.md)

## License
- [LICENSE](LICENSE)

## Contributing
- [CONTRIBUTING.md](CONTRIBUTING.md)

cargo build
cargo test

## Build & Test
```bash
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
