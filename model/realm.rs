use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub enabled: bool,
}
