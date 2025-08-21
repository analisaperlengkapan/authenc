# Authence

[![CI](https://github.com/your-org/authence/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/authence/actions/workflows/ci.yml)

Authence adalah authentication & authorization server berbasis Rust, terinspirasi best practice Keycloak.

## Fitur
- Multi-tenant (realm)
- User, role, permission, RBAC
- Audit log
- API documented (OpenAPI)
- Modular & testable

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

## Build & Test
```
cargo build
cargo test
```

## CI/CD
- Otomatis build & test di GitHub Actions setiap push/PR ke `main`.

## Lisensi
MIT
