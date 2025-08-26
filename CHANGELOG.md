# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security & Deployment
- **[IMPORTANT]** Native mTLS support is not available due to Rust/actix-web ecosystem limitations. For production-grade mTLS, deploy Authenc behind a reverse proxy (Nginx/Envoy) that enforces client certificate validation. See README for best-practice configuration.

## [0.3.0] - 2025-08-26

### Added
- Endpoint separation: public, admin, and internal API scopes
- Feature flags for OIDC, SAML, UI, MultiDb, and more
- OIDC, SAML, UI, MultiDb config stubs for future extensibility
- Metrics endpoint is now feature-flagged
- Environment-driven configuration for all features and endpoints

### Changed
- Major refactor of `AppConfig` and `ServerConfig` for modularity and extensibility
- ApplicationBuilder and AppState initialization are now explicit and robust
- Removed legacy/experimental files (`app_corrupted.rs`, `app_new.rs`)
- Cleaned up duplicate test modules and unused imports

### Fixed
- All build-blocking errors and warnings resolved
- Codebase is now clean, modular, and ready for incremental feature growth

### Migration Guide
- Review new environment variables for endpoint prefixes and feature flags
- See README for updated configuration and feature documentation

## [0.2.1] - 2025-08-26

### Added
- **Vault/Secret Store Abstraction**: Modular vault trait for pluggable secret providers (file, keystore, HashiCorp Vault, KMS, Secreton)
- **File-based Vault Provider**: Secure file-based secret backend (Kubernetes/OpenShift compatible)
- **Secreton Provider Stub**: Integration point for custom Rust-based secret manager
- **Async Test Infrastructure**: Added async test support and integration test for file vault
- **Copilot Instructions**: `.github/copilot-instructions.md` for next-gen security and secret management

### Changed
- **OpenAPI Spec**: Upgraded to OpenAPI 3.1.0 for improved standards compliance
- **Public API**: Exposed `vault` module in crate root for integration testing and extensibility

### Fixed
- Integration test visibility for new modules


## [0.2.0] - 2025-08-22

### Added
- **Major Architecture Refactor**: Restructured entire codebase from mixed `authence` to unified `authenc` namespace
- **Comprehensive Test Suite**: Added 19+ test files covering all core functionality
  - Rate limiting tests (global and path-specific)
  - Security middleware tests (headers, request sanitization)  
  - Brute force protection tests
  - Configuration management tests
  - Application state initialization tests
  - Health/readiness/metrics endpoint tests
- **Enhanced Middleware Stack**:
  - `SecurityHeaders` middleware with CSP, HSTS, XSS protection
  - `RequestSanitizer` for SQL injection prevention and payload validation
  - `RateLimiter` with global and per-path rate limiting
  - Unified `BoxBody` response type across all middleware
- **Robust Application Builder**: 
  - `ApplicationBuilder` with full server lifecycle management
  - Configuration validation and error handling
  - Graceful service initialization with proper error propagation
- **Security Enhancements**:
  - Content-Length validation (10MB limit)
  - User-Agent pattern detection for suspicious tools
  - Query parameter sanitization for SQL injection attempts
  - Comprehensive security headers (X-Frame-Options, CSP, etc.)

### Changed
- **BREAKING**: Renamed crate from `authence` to `authenc`
- **BREAKING**: Restructured module layout from `api/`, `model/`, `services/` to `src/handlers/`, `src/models/`, `src/services/`
- **BREAKING**: Updated all import paths and module references
- **BREAKING**: Middleware now returns `ServiceResponse<BoxBody>` instead of `EitherBody`
- Improved error handling with custom `AuthencError` types and consistent error responses
- Enhanced configuration management with environment variable fallbacks
- Updated dependencies: added `num_cpus`, enhanced `uuid` and `chrono` with serde features

### Fixed
- Middleware compilation issues with Actix-web 4.x body types
- Module visibility and re-export inconsistencies
- Audit handler attribute macro conflicts
- Import resolution for internal crate modules
- Rate limiter mutex poisoning handling

### Removed
- Legacy API endpoints and handlers (will be reintroduced incrementally)
- Duplicate and inconsistent module declarations
- Unused imports and variables throughout codebase

### Technical Details
- Total test coverage: 19 passing tests (8 unit + 11 integration)
- Clean `cargo check` and `cargo test` execution
- Comprehensive middleware test coverage for security scenarios
- Configuration testing for environment variable overrides
- Service initialization validation for all store types

### Migration Guide
For users upgrading from 0.1.x:
1. Update import statements from `authence::` to `authenc::`
2. Review middleware integration - new unified body types may require updates
3. Check configuration - some environment variables may have changed
4. API endpoints are being restructured - refer to updated documentation

## [0.1.0] - 2024-XX-XX
### Added
- Initial release with basic authentication and authorization features
- Multi-tenant realm support
- User, group, role, and permission management
- JWT and session-based authentication
- TOTP multi-factor authentication
- Basic audit logging
- PostgreSQL backend support
- Initial API endpoints and middleware
