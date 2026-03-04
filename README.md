# 🔐 Authenc

> **Identity and Access Management (IAM) Service in Rust**

[![Rust Version](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.0-green.svg)](Cargo.toml)

---

## ⚠️ PROJECT STATUS

> [!CAUTION]
> **DEVELOPMENT VERSION - NOT FOR PRODUCTION**
>
> This project is actively developed. While core features are implemented, it has **not undergone a professional security review**.
> - Always change default secrets and keys.
> - Always use HTTPS/TLS in deployment.
>
> **Current Use:** Development, testing, and experimentation only.

---

## 📖 About

**Authenc** is an Identity and Access Management (IAM) platform built in Rust. It provides modern, secure authentication and authorization capabilities for web and enterprise applications. Built on top of the Axum web framework and PostgreSQL, it focuses on performance, modularity, and strong security defaults.

## ✨ Features

- **Standard Protocols:** Full support for OAuth 2.0, OpenID Connect (OIDC), and SAML 2.0 (SP/IdP).
- **Federation & Integrations:** Social login integration, LDAP/AD synchronization, and federated SSO.
- **Modern Authentication:** Passwordless login via WebAuthn/Passkeys (Experimental/In Development) and Multi-Factor Authentication (MFA) via TOTP.
- **Account Management:** Multi-tenant realms, user lifecycle management, robust Groups and Organization hierarchies, and email verification.
- **Advanced Authorization:** Fine-grained Role-Based Access Control (RBAC) and explicit consent workflows.
- **Security-First:** Built-in rate limiting, brute-force protection, device trust scoring (Zero Trust), and verifiable credentials (OID4VC).
- **Compliance & Audit:** FIPS-mode capabilities, comprehensive audit logging (with export and webhook support), and risk analytics.
- **Admin Console:** A lightweight, static Single Page Application (SPA) for managing realms, users, and configurations.

## 📚 API Overview

The following endpoint areas are fully supported (see `tests/` and `src/handlers/` for full details):

### Core Authentication & Identity Protocols
- **OAuth 2.0 / OIDC:** `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/jwks`, `/oauth2/revoke`, `/oauth2/consent`
- **SAML 2.0:** `/saml/acs`, `/saml/metadata`, `/slo`
- **Federated Auth & Social Login:** `/federated-auth`, `/social/auth`, `/social/callback`, `/social/initiate`, `/social/providers`, `/federation/ldap/auth`, `/federation/idp/metadata`
- **SSO:** `/sso/login`, `/sso/callback`, `/sso/logout`, `/sso/sessions`

### Admin & Management API
- **Realms:** `CRUD /api/v1/auth/realms`, `GET /api/v1/auth/realms/{id}/status`
- **Users & Groups:** `CRUD /api/v1/auth/realms/{realm}/users`, `CRUD /api/v1/auth/realms/{realm}/groups`
- **Roles & Permissions:** `CRUD /api/v1/auth/realms/{realm}/roles`, `/authz/evaluate`, `/check-permission`
- **Clients & Providers:** `CRUD /api/v1/auth/realms/{realm}/clients`, `CRUD /api/v1/providers`
- **Organizations & Members:** `/organization/{id}`, `/organization/{id}/members`, `/organization/{id}/invitations`

### Advanced Security & Features
- **MFA / TOTP:** `/users/{id}/totp`, `/users/{id}/totp/verify`
- **WebAuthn (Passkeys):** `/webauthn/login/challenge`, `/webauthn/login/verify`, `/webauthn/register/challenge` *(Experimental)*
- **Zero Trust & Device Trust:** `/zero-trust/risk/assess`, `/zero-trust/status`, `/device/{id}/trust`
- **Audit & Monitoring:** `/logs`, `/logs/export`, `/events`, `/dashboard`, `/stats`
- **Verifiable Credentials:** `/oid4vc/credentials`, `/vp/verify`
- **FIPS Mode:** `/fips/enable`, `/fips/disable`, `/fips/status`

---

## 🏗️ Architecture & Workspace

The project is structured as a Cargo workspace to maintain clean boundaries between concerns:

- `authenc-core` — Shared types, errors, and common configurations.
- `authenc-models` — Domain models and DTOs.
- `authenc-crypto` — Cryptographic primitives and operations.
- `authenc-database` — PostgreSQL interactions and storage abstractions.
- `authenc-services` — Core business logic, authentication flows, and policies.
- `authenc-spi` — Service Provider Interfaces for extensible plugins.
- `authenc-vault` — Secret management integrations.
- `ui` — UI workspace crate (alongside the active `static/index.html` Admin UI).

## 🛠️ Tech Stack

- **Language:** Rust
- **Web Framework:** Axum & Tower
- **Async Runtime:** Tokio
- **Database:** PostgreSQL (via `tokio-postgres`)
- **Frontend:** Static HTML/JS/CSS

## 🚀 Getting Started

### Prerequisites

- **Rust** (v1.90 or higher)
- **PostgreSQL** (v14 or higher)

### Setup & Run

1. **Clone the repository:**
   ```bash
   git clone https://github.com/analisaperlengkapan/authenc.git
   cd authenc
   ```

2. **Configure Environment:**
   Set the necessary environment variables:
   ```bash
   export DATABASE_URL="postgresql://user:password@localhost/authenc"
   export JWT_SECRET="your-secure-jwt-secret"
   ```

3. **Run Database Migrations:**
   Ensure your PostgreSQL instance is running and apply the schema:
   ```bash
   cargo install sqlx-cli
   sqlx migrate run
   ```

4. **Start the Server:**
   ```bash
   cargo run --release
   ```
   The API and static Admin UI will be available at `http://localhost:3000`.

## 🧪 Testing

The codebase includes comprehensive unit and integration tests.

Run all tests:
```bash
cargo test
```

Run tests for a specific workspace crate:
```bash
cargo test -p authenc-services
```

## 📚 Documentation & Links

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [TODO.md](TODO.md)

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
