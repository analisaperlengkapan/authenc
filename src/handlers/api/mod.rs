/// Audit logging API handlers for security monitoring and compliance
pub mod audit;
pub use audit::{add_audit_log, create_audit_routes, get_audit_logs};
/// Authentication API handlers for login/logout
pub mod auth;
pub use auth::create_auth_routes;
/// Permission checking handlers for authorization decisions
pub mod permission_check;
pub use permission_check::{check_user_permission, create_permission_check_routes};
/// User permission management handlers
pub mod user_permission;
pub use user_permission::get_user_permissions;
// API endpoints (REST/gRPC) will be implemented here
/// Authentication flow management API handlers
pub mod auth_flow;
pub use auth_flow::create_auth_flow_routes;
/// User management API handlers for CRUD operations
pub mod user;
pub use user::create_user_routes;
/// Bearer token authentication middleware
pub mod auth_bearer;
/// Realm management API handlers for multi-tenancy
pub mod realm;
pub use realm::create_realm_routes;
/// Role-based access control API handlers
pub mod role;
pub use role::create_role_routes;
/// User-role assignment management handlers
pub mod user_role;
pub use user_role::{assign_role, create_user_role_routes, unassign_role};
/// Permission management API handlers
pub mod permission;
pub use permission::create_permission_routes;
/// Resource management API handlers for fine-grained authorization
pub mod resource;
pub use resource::create_resource_routes;
/// Resources collection management API handlers
pub mod resources;
pub use resources::create_resources_routes;
/// Account management API handlers for user self-service
pub mod account;
pub use account::create_account_routes;
/// Account credentials management API handlers
pub mod account_credentials;
pub use account_credentials::create_account_credentials_routes;
/// Client management API handlers for OAuth2/OIDC clients
pub mod client;
pub use client::create_client_routes;
/// Event querying API handlers for audit logs
pub mod events;
pub use events::create_event_routes;
