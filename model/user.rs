use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
    pub roles: Vec<String>, // list of role names in this realm
    pub realm: String, // realm name or id
}
