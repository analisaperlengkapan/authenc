# Task runner. `just --list` shows everything.
#
# Every recipe is a plain command, so you can run them by hand if you would
# rather not install `just` (cargo install just).

set dotenv-load := true

default:
    @just --list

# First-time setup: toolchain targets, tools, and a database.
setup:
    rustup target add wasm32-unknown-unknown
    cargo install cargo-leptos --locked
    cargo install sqlx-cli --no-default-features --features rustls,postgres --locked
    @test -f .env || cp .env.example .env
    just db-up
    just migrate

# Start PostgreSQL (and MailHog) via compose.
db-up:
    docker compose up -d postgres

# Stop the compose stack.
db-down:
    docker compose down

# Apply pending migrations.
migrate:
    sqlx migrate run --source migrations

# Create a new migration file.
migration name:
    sqlx migrate add --source migrations {{name}}

# Regenerate the offline query metadata that lets CI build without a database.
# Run this after adding or changing any sqlx query, and commit `.sqlx/`.
sqlx-prepare:
    cargo sqlx prepare --workspace -- --all-targets --features ssr

# Run the app with hot reload on http://localhost:3000.
dev:
    cargo leptos watch

# Production build: server binary plus the optimised wasm bundle.
build:
    cargo leptos build --release

# Everything CI checks, in the order CI checks it.
check: fmt-check lint test boundaries

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# Clippy on both halves. Never `--all-features`: `hydrate` and `ssr` cannot
# both be on.
lint:
    cargo clippy --workspace --all-targets --features ssr --locked -- -D warnings
    cargo clippy -p authenc-web --no-default-features --features hydrate \
        --target wasm32-unknown-unknown --locked -- -D warnings

test:
    cargo test --workspace --locked

# Fail if a crate has picked up a dependency its layer forbids.
boundaries:
    #!/usr/bin/env bash
    set -euo pipefail
    fail() { echo "boundary violation: $1"; exit 1; }
    tree_has() { cargo tree -p "$1" --edges normal --prefix none 2>/dev/null | awk '{print $1}' | grep -qx "$2"; }
    for forbidden in axum sqlx leptos; do
        tree_has authenc-contract "$forbidden" && fail "authenc-contract depends on $forbidden"
    done
    for forbidden in axum leptos; do
        tree_has authenc-identity "$forbidden" && fail "authenc-identity depends on $forbidden"
    done
    echo "layer boundaries hold"

# Supply-chain checks.
audit:
    cargo deny check
    cargo audit

# End-to-end tests against a running stack.
e2e:
    cd e2e && npx playwright test
