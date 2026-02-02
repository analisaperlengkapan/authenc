use async_trait::async_trait;
use uuid::Uuid;
use authenc_api::error::Result;
use authenc_api::models::{
    session::Session,
    user::{User, CreateUserRequest, UpdateUserRequest},
    oidc_client::OidcClient,
    role::Role,
    group::Group,
};

#[async_trait]
pub trait SessionStoreTrait: Send + Sync {
    async fn store_session(&self, session: Session) -> Result<()>;
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>>;
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>>;
    async fn delete_session(&self, session_id: Uuid) -> Result<()>;
    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<()>;
    async fn cleanup_expired(&self) -> Result<()>;
}

#[async_trait]
pub trait UserStoreTrait: Send + Sync {
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>>;
    async fn get_user_by_username(&self, realm_id: &Uuid, username: &str) -> Result<Option<User>>;
    async fn get_user_by_email(&self, realm_id: &Uuid, email: &str) -> Result<Option<User>>;
    async fn get_all(&self) -> Result<Vec<User>>;
    async fn add_user(&self, request: CreateUserRequest) -> Result<User>;
    async fn update_user(&self, user_id: Uuid, request: UpdateUserRequest) -> Result<User>;
    // Optional methods can have default impls returning "not implemented"
}

#[async_trait]
pub trait OidcClientStoreTrait: Send + Sync {
    async fn get(&self, client_id: &str) -> Result<Option<OidcClient>>;
    async fn all(&self) -> Result<Vec<OidcClient>>;
    async fn add(&self, client: OidcClient) -> Result<()>;
    async fn delete(&self, client_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait RoleStoreTrait: Send + Sync {
    fn get_by_name(&self, name: &str) -> Option<Role>;
    fn get_all(&self) -> Vec<Role>; // Assuming it returns a vector
    fn add_role(&self, role: Role);
}

#[async_trait]
pub trait GroupStoreTrait: Send + Sync {
    fn get(&self, group_id: &Uuid) -> Option<Group>;
    fn all(&self) -> Vec<Group>;
    fn create(&self, realm_id: Uuid, name: &str, description: Option<String>) -> Option<Group>;
    fn delete(&self, group_id: &Uuid) -> bool;
}

#[async_trait]
pub trait TotpStoreTrait: Send + Sync {
    // Methods for TOTP store (inferred from generic usage)
    async fn save_secret(&self, user_id: Uuid, secret: &str) -> Result<()>;
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<String>>;
    async fn delete_secret(&self, user_id: Uuid) -> Result<()>;
}
