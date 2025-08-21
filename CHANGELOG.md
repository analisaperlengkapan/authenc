# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- PostgreSQL audit log store (persisten, async)
- RBAC granular (middleware, scope per endpoint)
- Modularisasi API: user, group, role, permission, session, TOTP, audit, OIDC
- Session management (list, logout, revoke)
- Group management (API, model, service)
- TOTP endpoint (enable, disable, verify)
- Auth middleware JWT/session
- OIDC endpoints (discovery, authorize, token, userinfo, jwks)
- Plugin system extensibility
- Perbaikan error handling, compliance, dan best practice
- Refactor: pemisahan audit_log, group, session, totp, dsb
- Test suite komprehensif (59+ coverage, OIDC, TOTP, audit, brute-force, RBAC, dsb)
- Refaktor struktur, idiom Rust, modularisasi, dokumentasi, dan keamanan

## [0.1.0] - 2025-08-21
- First public release: user CRUD, login, modular structure, best practice docs
