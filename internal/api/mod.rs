// Re-export all submodules for the api module
pub mod auth;
pub mod user;
pub mod realm;
pub mod role;
pub mod permission;
pub mod audit;
pub mod group;
pub mod totp;
pub mod totp_verify;
pub mod session;
pub mod auth_middleware;

pub use auth::login;
pub use user::{get_users, create_user, get_user_by_id, update_user, delete_user, update_password};
pub use realm::{get_realms, get_realm_by_name, create_realm, delete_realm};
pub use role::{get_roles, create_role, delete_role, assign_role, unassign_role};
pub use permission::{get_permissions, create_permission, delete_permission, assign_permission_to_role, unassign_permission_from_role, get_user_permissions, check_user_permission};
pub use audit::{add_audit_log, get_audit_logs};
