use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub realm: String,
    pub permissions: Vec<String>, // list of permission names
}
