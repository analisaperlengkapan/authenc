use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<String>, // user IDs
    pub roles: Vec<String>,   // role IDs
}
