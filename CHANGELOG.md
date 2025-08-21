# Changelog

All notable changes to this project will be documented in this file.


## [Unreleased]
- Initial project structure and best practices
- Implement user CRUD, authentication, RBAC, audit log, i18n, metrics, plugin system
- Add OpenAPI, CI/CD, deployment, zero trust, compliance docs
- Real business logic for user endpoints
- Group management (model, API, service)
- MFA (TOTP, pure Rust, integrated with login)
- JWT issuance, session management (list, revoke, logout)
- Auth middleware (JWT validation, session check)
- Security: zero trust, no secret ever written to disk/log
- Advanced error handling, compliance, and extensibility

## [0.1.0] - 2025-08-21
- First public release: user CRUD, login, modular structure, best practice docs
