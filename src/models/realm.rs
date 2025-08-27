use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Realm entity representing a tenant or namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Realm creation request
#[derive(Debug, Deserialize)]
pub struct CreateRealmRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

/// Realm update request
#[derive(Debug, Deserialize)]
pub struct UpdateRealmRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

/// Realm response
#[derive(Debug, Serialize)]
pub struct RealmResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Realm> for RealmResponse {
    fn from(realm: Realm) -> Self {
        Self {
            id: realm.id,
            name: realm.name,
            display_name: realm.display_name,
            description: realm.description,
            enabled: realm.enabled,
            created_at: realm.created_at,
            updated_at: realm.updated_at,
        }
    }
}

impl Realm {
    /// Create a new realm
    pub fn new(name: String, display_name: String, description: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            display_name,
            description,
            enabled: true,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Check if realm is active
    pub fn is_active(&self) -> bool {
        self.enabled && self.deleted_at.is_none()
    }

    /// Soft delete the realm
    pub fn delete(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Update realm fields
    pub fn update(&mut self, request: UpdateRealmRequest) {
        if let Some(display_name) = request.display_name {
            self.display_name = display_name;
        }
        if let Some(description) = request.description {
            self.description = Some(description);
        }
        if let Some(enabled) = request.enabled {
            self.enabled = enabled;
        }
        self.updated_at = Utc::now();
    }
}
