//! Single Sign-On (SSO) Service
//!
//! Provides unified SSO orchestration across multiple authentication protocols:
//! - OpenID Connect (OIDC)
//! - OAuth 2.0
//! - SAML 2.0
//! - Social Login (Google, Facebook, GitHub, etc.)
//!
//! Features:
//! - Unified session management across protocols
//! - SSO cookie generation and validation
//! - Single Logout (SLO) support
//! - Cross-domain SSO
//! - Session timeout and lifecycle management

pub mod cookie;
pub mod service;
pub mod session;

pub use cookie::SsoCookieManager;
pub use service::{
    DefaultSsoService, SsoCallbackRequest, SsoInitiateRequest, SsoProvider, SsoService,
};
pub use session::{SsoSession, SsoSessionManager};
