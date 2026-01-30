use async_trait::async_trait;
use authenc::models::user::{User, Role, CreateUserRequest, UpdateUserRequest};
use authenc::services::stores::user_store::UserStoreTrait;
use authenc::error::{AuthencError, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct MockUserStore {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    roles: Arc<RwLock<HashMap<Uuid, Vec<Role>>>>,
}

impl MockUserStore {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_role(&self, user_id: Uuid, role_name: &str) {
        let mut roles_lock = self.roles.write().unwrap();
        let user_roles = roles_lock.entry(user_id).or_insert_with(Vec::new);
        user_roles.push(Role {
            id: Uuid::new_v4(),
            name: role_name.to_string(),
            description: None,
            realm_id: Some(Uuid::new_v4()), // Assuming mocked realm ID
            composite: false,
            client_role: false,
            client_id: None,
            attributes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
    }
}

#[async_trait]
impl UserStoreTrait for MockUserStore {
    async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        let users = self.users.read().unwrap();
        Ok(users.get(&id).cloned())
    }

    async fn get_user_by_username(&self, _realm_id: &Uuid, username: &str) -> Result<Option<User>> {
        let users = self.users.read().unwrap();
        Ok(users.values().find(|u| u.username == username).cloned())
    }

    async fn get_user_by_email(&self, _realm_id: &Uuid, email: &str) -> Result<Option<User>> {
        let users = self.users.read().unwrap();
        Ok(users.values().find(|u| u.email == email).cloned())
    }

    async fn add_user(&self, req: CreateUserRequest) -> Result<User> {
         let mut users = self.users.write().unwrap();
         let user = User {
             id: Uuid::new_v4(),
             username: req.username,
             email: req.email,
             email_verified: false,
             enabled: true,
             created_at: chrono::Utc::now(),
             updated_at: chrono::Utc::now(),
             first_name: req.first_name,
             last_name: req.last_name,
             realm_id: req.realm_id.or_else(|| Some(Uuid::new_v4())),
             attributes: req.attributes,
             password_hash: req.password, // For mock, store directly
             phone_number: req.phone_number,
             phone_verified: false,
             deleted_at: None,
             totp_secret: None,
             totp_backup_codes: None,
             webauthn_enabled: false,
             account_locked: false,
             account_locked_until: None,
             failed_login_attempts: 0,
             last_login_at: None,
             last_failed_login_at: None,
             password_changed_at: None,
             password_expires_at: None,
             require_password_change: false,
             organization_id: req.organization_id,
             federated: false,
             login_count: 0,
         };
         users.insert(user.id, user.clone());
         Ok(user)
    }

    async fn update_user(&self, id: Uuid, req: UpdateUserRequest) -> Result<User> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&id) {
            if let Some(email) = req.email {
                user.email = email;
            }
            if let Some(first_name) = req.first_name {
                user.first_name = Some(first_name);
            }
            if let Some(last_name) = req.last_name {
                user.last_name = Some(last_name);
            }
             if let Some(enabled) = req.enabled {
                user.enabled = enabled;
            }
             if let Some(email_verified) = req.email_verified {
                user.email_verified = email_verified;
            }
             if let Some(attributes) = req.attributes {
                user.attributes = Some(attributes);
            }
            Ok(user.clone())
        } else {
            Err(AuthencError::not_found("User not found"))
        }
    }

    async fn delete_user(&self, id: Uuid) -> Result<()> {
        let mut users = self.users.write().unwrap();
        users.remove(&id);
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<User>> {
         let users = self.users.read().unwrap();
        Ok(users.values().cloned().collect())
    }

    async fn get_users_by_realm(&self, realm_id: Uuid) -> Result<Vec<User>> {
         let users = self.users.read().unwrap();
         Ok(users.values().filter(|u| u.realm_id == Some(realm_id)).cloned().collect())
    }

    async fn update_password(&self, user_id: Uuid, password_hash: String) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&user_id) {
            user.password_hash = Some(password_hash);
            Ok(())
        } else {
            Err(AuthencError::not_found("User not found"))
        }
    }

    async fn record_login(&self, user_id: Uuid) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&user_id) {
            user.last_login_at = Some(chrono::Utc::now());
            user.failed_login_attempts = 0;
            user.account_locked = false;
            user.account_locked_until = None;
            Ok(())
        } else {
            Err(AuthencError::not_found("User not found"))
        }
    }

    async fn record_failed_login(&self, user_id: Uuid) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&user_id) {
            user.failed_login_attempts += 1;
            user.last_failed_login_at = Some(chrono::Utc::now());
            Ok(())
        } else {
            Err(AuthencError::not_found("User not found"))
        }
    }

    async fn lock_account(
        &self,
        user_id: Uuid,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&user_id) {
            user.account_locked = true;
            user.account_locked_until = until;
            Ok(())
        } else {
            Err(AuthencError::not_found("User not found"))
        }
    }

    async fn unlock_account(&self, user_id: Uuid) -> Result<()> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&user_id) {
            user.account_locked = false;
            user.account_locked_until = None;
            user.failed_login_attempts = 0;
            Ok(())
        } else {
            Err(AuthencError::not_found("User not found"))
        }
    }
}
