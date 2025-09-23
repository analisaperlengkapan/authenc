//! Service Managers
//!
//! This module provides various service managers for coordinating
//! complex operations across different components of the authentication system.

pub mod authentication;
pub mod user_session;

// Re-export commonly used managers
pub use authentication::{AuthenticationManager, DefaultAuthenticationManager, AuthenticationSessionState};
pub use user_session::{UserSessionManager, DefaultUserSessionManager, UserSessionState, ClientSessionState};
