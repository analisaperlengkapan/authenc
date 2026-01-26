use async_trait::async_trait;
use authenc::models::events::{Event, EventType};
use authenc::error::{AuthencError, Result};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct MockEventStore {
    events: Arc<RwLock<Vec<Event>>>,
}

impl MockEventStore {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }
}
