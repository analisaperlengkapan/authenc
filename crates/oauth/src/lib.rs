//! OAuth 2.0 and OpenID Connect.
//!
//! The protocol layer: signing keys, tokens, clients, authorization codes, and
//! refresh-token rotation. It knows nothing about HTTP — the endpoints live in
//! `authenc-server` — so every rule here is testable without a request.
//!
//! The previous tree had two OIDC implementations. The 857-line one, which had
//! the correct discovery path and a real login form, was dead code; the
//! 406-line one that was actually mounted issued a valid signed token for
//! `demo_user` to anyone who asked, with no credentials, no code validation,
//! and no client authentication.

pub mod keyring;
pub mod token;

pub use keyring::MasterKey;
