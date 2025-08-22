//! Group model for Authenc
//! 
//! Represents a group of users with associated roles and metadata.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Unique group ID (UUID)
    pub id: String,
    /// Group name (unique within realm)
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// User IDs belonging to this group
    pub members: Vec<String>,
    /// Role IDs assigned to this group
    pub roles: Vec<String>,
}
