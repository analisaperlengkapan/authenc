# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
