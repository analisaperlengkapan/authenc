# Authenc

Authenc is a modular Identity and Access Management (IAM) service developed for the SIMPelv2 platform. It provides a comprehensive set of authentication and authorization protocols, including OAuth 2.0, OpenID Connect, SAML 2.0, and WebAuthn.

## Features

*   **OAuth 2.0 & OpenID Connect (OIDC)**
    *   Supports standard flows: Authorization Code, Client Credentials, Device Flow.
    *   JWT-based tokens signed with Ed25519 (high-performance Edwards-curve Digital Signature Algorithm).
    *   OIDC Discovery endpoints (`/.well-known/openid-configuration`).
*   **SAML 2.0**
    *   Functions as both Identity Provider (IdP) and Service Provider (SP).
    *   Supports SSO (Single Sign-On) flows.
*   **WebAuthn / FIDO2**
    *   Passwordless authentication support.
    *   Hardware security key integration.
*   **Multi-Factor Authentication (MFA)**
    *   TOTP (Time-based One-Time Password) support (RFC 6238).
*   **Security & Compliance**
    *   FIPS-compliant cryptography options.
    *   Audit logging with Kafka and Splunk HEC support.
    *   Zero Trust architecture components.
    *   Post-Quantum Cryptography (experimental support for ML-DSA, ML-KEM).
*   **Infrastructure**
    *   Built in Rust for performance and memory safety.
    *   Clustering support via Raft/Infinispan.
    *   Kubernetes Operator support.

## Tech Stack

*   **Language:** Rust 1.90+
*   **Web Framework:** Axum 0.8
*   **Database:** PostgreSQL (via `tokio-postgres` and `deadpool`)
*   **Runtime:** Tokio
*   **Cryptography:** `ed25519-dalek`, `ring`, `p256`, `aes-gcm`, `pqcrypto` (optional)

## Prerequisites

*   **Rust Toolchain:** Version 1.90 or later.
*   **PostgreSQL:** Version 14 or later.
*   **OpenSSL:** Required for certain cryptographic operations (PKCS12).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/analisaperlengkapan/simpel2.git
    cd authenc
    ```

2.  **Set up the database:**
    Ensure you have a PostgreSQL instance running. Create a database named `authenc` (or as configured).

3.  **Configure Environment Variables:**
    Create a `.env` file in the root directory. You can use the example below as a template.

## Configuration

The application is configured via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server host address | `0.0.0.0` |
| `PORT` | Server port | `3000` |
| `BASE_URL` | Public base URL of the service | `http://localhost:3000` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://postgres:postgres@localhost:5432/authenc` |
| `JWT_SECRET` | Secret key for JWT signing | *Required* |
| `LOG_LEVEL` | Logging verbosity (trace, debug, info, warn, error) | `INFO` |
| `TLS_ENABLED` | Enable HTTPS | `false` |
| `TLS_CERT_PATH` | Path to TLS certificate | - |
| `TLS_KEY_PATH` | Path to TLS private key | - |
| `ENABLED_FEATURES` | Comma-separated list of enabled features | - |

**Example `.env`:**

```env
HOST=0.0.0.0
PORT=3000
DATABASE_URL=postgres://user:password@localhost:5432/authenc
JWT_SECRET=change_this_to_a_secure_random_string
LOG_LEVEL=info
```

## Running the Application

**Development Mode:**
```bash
cargo run
```

**Production Build:**
```bash
cargo build --release
./target/release/authenc
```

**With Specific Features:**
To enable optional features like the admin console or post-quantum crypto:
```bash
cargo run --features "admin_console,quantum"
```

## Testing

Run the test suite using `cargo test`.

```bash
# Run all tests
cargo test

# Run tests for a specific package/module
cargo test --package authenc --lib
```

## License

This project is licensed under the Apache-2.0 License.
