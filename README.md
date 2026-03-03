# 🔐 Authenc

> **Identity and Access Management (IAM) Service in Rust**

[![Rust Version](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.0-green.svg)](Cargo.toml)

---

## 📖 About

**Authenc** is an Identity and Access Management (IAM) platform built in Rust. It provides modern, secure authentication and authorization capabilities for web and enterprise applications. Built on top of the Axum web framework and PostgreSQL, it focuses on performance, modularity, and strong security defaults.

## ✨ Features

- **Standard Protocols:** Support for OAuth 2.0, OpenID Connect (OIDC), and SAML 2.0.
- **Modern Authentication:** Passwordless login via WebAuthn (Passkeys) and Multi-Factor Authentication (MFA) via TOTP.
- **Account Management:** User lifecycle management, email verification, and Role-Based Access Control (RBAC).
- **Security-First:** Built-in rate limiting, brute-force protection, audit logging, and modern cryptography (Ed25519, AES-256-GCM, Argon2id).
- **Admin Console:** A lightweight, static Single Page Application (SPA) for managing realms, users, and configurations.

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
   git clone https://github.com/authenc/authenc.git
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

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
