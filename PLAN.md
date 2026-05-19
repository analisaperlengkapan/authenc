# Plan: Pecah Authenc Menjadi Multi-Crate Workspace

## Latar Belakang

Saat ini `authenc` adalah satu crate monolitik besar dengan ~100+ file source code. Ini menyebabkan:
- Compile time lambat (semua di-compile ulang saat ada perubahan kecil)
- Separation of concerns kurang jelas
- Sulit untuk re-use komponen secara independen (misal hanya pakai crypto tanpa full server)
- Testing scope terlalu luas

## Struktur Crate yang Diusulkan

Akan dipecah menjadi **7 crates** dalam satu Cargo workspace:

```
authenc/                          # Workspace root
├── Cargo.toml                    # Workspace manifest
├── crates/
│   ├── authenc-core/             # 1. Foundation types
│   ├── authenc-models/           # 2. Domain models
│   ├── authenc-crypto/           # 3. Cryptographic operations
│   ├── authenc-database/         # 4. Persistence layer
│   ├── authenc-vault/            # 5. Secret management
│   ├── authenc-spi/              # 6. Service Provider Interface
│   └── authenc-services/         # 7. Business logic & stores
├── src/                          # 8. Main app (binary + facade lib)
│   ├── main.rs
│   ├── lib.rs
│   ├── app.rs
│   ├── handlers/
│   ├── middleware/
│   ├── axum_app/
│   └── admin_console/
├── tests/
├── migrations/
└── fuzz/
```

## Detail Setiap Crate

### 1. `authenc-core` (Foundation)

**Isi:**
- `error.rs` — `AuthencError`, `Result<T>`
- `config/` — `AppConfig` dan semua konfigurasi
- `utils/` — auth_context, i18n, plugin system, crypto utilities (password, jwt helpers)

**Dependencies utama:** `serde`, `thiserror`, `tracing`, `chrono`, `uuid`, `once_cell`

**Tidak bergantung** pada crate authenc lainnya.

---

### 2. `authenc-models` (Domain Models)

**Isi:**
- `models/` — Semua struct domain: User, Session, Token, OAuth2, OIDC Client, SAML, Role, Permission, Policy, Consent, Device, Group, Organization, Realm, Audit, WebAuthn, Events, dll.

**Dependencies:** `authenc-core`

---

### 3. `authenc-crypto` (Cryptographic Operations)

**Isi:**
- `crypto/aes_gcm.rs` — AES-256-GCM encryption
- `crypto/ed25519_keys.rs` — Ed25519 signatures & JWK
- `crypto/ecdsa_keys.rs` — ECDSA P-256
- `crypto/ecdsa_p384_keys.rs` — ECDSA P-384
- `crypto/ecdsa_p521_keys.rs` — ECDSA P-521
- `crypto/eddsa_ed448_keys.rs` — EdDSA Ed448
- `crypto/pqc.rs` — ML-DSA, ML-KEM, FALCON, Hybrid (feature-gated: `quantum`)
- `crypto/shamir.rs` — Shamir Secret Sharing
- `crypto/mtls.rs` — Mutual TLS
- `crypto/xmldsig.rs` — XML Digital Signatures
- `crypto/dpop/` — DPoP token handling
- `crypto/sdjwt/` — SD-JWT
- `crypto/debug_pem.rs`

**Dependencies:** `authenc-core`
**Feature flags:** `quantum` (PQC), `tpm`

---

### 4. `authenc-database` (Persistence Layer)

**Isi:**
- `database/` — Connection pool, queries, transactions, batch ops, migrations
- `database/ops/` — User, OAuth2, audit, device, admin operations

**Dependencies:** `authenc-core`, `authenc-models`
**Feature flags:** `db` (tokio-postgres + deadpool-postgres), `redis-store`

---

### 5. `authenc-vault` (Secret Management)

**Isi:**
- `vault/` — Vault trait + semua implementasi:
  - File vault, Keystore vault, HashiCorp Vault, KMS vault, Secreton vault
  - HSM integration trait

**Dependencies:** `authenc-core`, `authenc-crypto`

---

### 6. `authenc-spi` (Service Provider Interface)

**Isi:**
- `spi/` — Core SPI traits (Spi, Provider, ProviderFactory)
- SPI implementations: authenticator, credential, admin_console, component, events, hostname, keys, ldap_federation, locale, migration, organization, policy, protocol_mappers, required_actions, rich_authorization, sessions, social, storage, theme, userprofile, validation
- `protocol/` — Protocol mapper extensions
- `authenticator/` — Custom authenticator support

**Dependencies:** `authenc-core`, `authenc-models`, `authenc-crypto`

---

### 7. `authenc-services` (Business Logic)

**Isi:**
- `services/` — Semua business services:
  - Auth flow, authorization, OAuth2, realm, organization
  - Security: brute force, anomaly detection, password policy, client policy, zero-trust
  - Federation: LDAP, OIDC, SAML
  - Protocols: OID4VC, SAML, WebAuthn
  - Stores: user, session, OIDC client, TOTP, audit, consent, resource, permission, scope, role, event, realm
  - Events, audit, compliance, clustering, SSO, PAR, token management
  - Vault service, observability, FIPS, Kubernetes, delegated admin
  - Managers: authentication, user_session
- `events/` — Event system (listeners, retention, event bus)

**Dependencies:** `authenc-core`, `authenc-models`, `authenc-crypto`, `authenc-database`, `authenc-vault`, `authenc-spi`

---

### 8. `authenc` (Main Application — root crate)

**Tetap di root**, berisi:
- `main.rs` — Binary entry point
- `app.rs` — AppState initialization
- `handlers/` — Semua HTTP request handlers
- `middleware/` — Semua HTTP middleware (auth, rate_limit, rbac, cors, csrf, mtls, security_headers, dll)
- `axum_app/` — Axum framework integration & routing
- `admin_console/` — Admin UI (feature-gated)
- `lib.rs` — Facade yang re-export semua sub-crates

**Dependencies:** Semua crate di atas

## Dependency Graph

```
authenc-core          (tidak ada dependency internal)
    ↑
authenc-models        (→ core)
    ↑
authenc-crypto        (→ core)
    ↑
authenc-database      (→ core, models)
    ↑
authenc-vault         (→ core, crypto)
    ↑
authenc-spi           (→ core, models, crypto)
    ↑
authenc-services      (→ core, models, crypto, database, vault, spi)
    ↑
authenc               (→ semua crate di atas)
```

## Migrasi Feature Flags

| Feature | Pindah ke Crate |
|---------|-----------------|
| `quantum` | `authenc-crypto` |
| `tpm` | `authenc-crypto` |
| `db` | `authenc-database` |
| `redis-store` | `authenc-database` |
| `auth` | `authenc` (root) — menyalakan `authenc-crypto` auth features |
| `oidc` | `authenc` (root) |
| `axum` | `authenc` (root) |
| `metrics` | `authenc-services` |
| `admin_console` | `authenc` (root) |
| `rbac` | `authenc-services` |
| `rdkafka` | `authenc-services` |

## Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    ".",
    "crates/authenc-core",
    "crates/authenc-models",
    "crates/authenc-crypto",
    "crates/authenc-database",
    "crates/authenc-vault",
    "crates/authenc-spi",
    "crates/authenc-services",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.90"
authors = ["Authenc Team <security@authenc.dev>"]
license = "Apache-2.0"
repository = "https://github.com/authenc/authenc"

[workspace.dependencies]
# Shared dependencies yang dipakai banyak crate
authenc-core = { path = "crates/authenc-core" }
authenc-models = { path = "crates/authenc-models" }
authenc-crypto = { path = "crates/authenc-crypto" }
authenc-database = { path = "crates/authenc-database" }
authenc-vault = { path = "crates/authenc-vault" }
authenc-spi = { path = "crates/authenc-spi" }
authenc-services = { path = "crates/authenc-services" }

serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.140"
thiserror = "2.0.17"
tracing = "0.1.41"
tokio = { version = "1.47.1", features = ["rt-multi-thread", "macros", "full"] }
async-trait = "0.1.85"
uuid = { version = "1.11.1", features = ["v4", "serde", "js"] }
chrono = { version = "0.4", features = ["serde"] }
# ... (dependencies lainnya)
```

## Langkah Eksekusi

1. **Buat directory structure** — `crates/authenc-{core,models,crypto,database,vault,spi,services}/`
2. **Pindahkan source files** ke masing-masing crate
3. **Buat Cargo.toml** untuk setiap crate dengan dependencies yang tepat
4. **Update imports** — Ganti `crate::error` → `authenc_core::error`, dll.
5. **Update root lib.rs** — Re-export semua sub-crate
6. **Update workspace Cargo.toml** — Definisikan workspace members dan shared dependencies
7. **Migrasi feature flags** sesuai tabel di atas
8. **Pastikan `cargo build` dan `cargo test` lulus**

## Keuntungan

- **Compile time lebih cepat**: Perubahan di `handlers/` tidak perlu recompile `crypto/`
- **Separation of concerns**: Boundary yang jelas antar layer
- **Reusability**: Bisa pakai `authenc-crypto` tanpa pull seluruh server
- **Testing**: Bisa test setiap crate secara independen
- **Paralelisme compile**: Cargo bisa compile crate yang tidak saling bergantung secara paralel
