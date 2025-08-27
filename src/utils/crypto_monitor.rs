use std::time::Instant;
use tracing::{warn, info};

/// Monitor RSA operations for timing anomalies to detect potential timing attacks
pub struct CryptoMonitor;

impl CryptoMonitor {
    /// Monitor an RSA operation and log timing anomalies
    pub fn monitor_rsa_operation<F, R>(operation_name: &str, operation: F) -> R 
    where 
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        
        // Log timing information for security monitoring
        info!(
            operation = operation_name,
            duration_ms = duration.as_millis(),
            "RSA operation completed"
        );
        
        // Alert on unusually long operations (potential timing attack indicator)
        if duration.as_millis() > 100 {
            warn!(
                operation = operation_name,
                duration_ms = duration.as_millis(),
                "RSA operation took longer than expected - potential timing attack"
            );
        }
        
        // Alert on unusually fast operations (potential cache timing)
        if duration.as_micros() < 100 {
            warn!(
                operation = operation_name,
                duration_us = duration.as_micros(),
                "RSA operation completed unusually fast - potential cache timing"
            );
        }
        
        result
    }
    
    /// Add random delay to RSA operations to mitigate timing attacks
    pub async fn add_random_delay() {
        use tokio::time::{sleep, Duration};
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let delay_ms = rng.gen_range(1..=5); // 1-5ms random delay
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_monitor_normal_operation() {
        let result = CryptoMonitor::monitor_rsa_operation("test", || {
            std::thread::sleep(Duration::from_millis(50));
            42
        });
        assert_eq!(result, 42);
    }
    
    #[tokio::test]
    async fn test_random_delay() {
        let start = Instant::now();
        CryptoMonitor::add_random_delay().await;
        let duration = start.elapsed();
        assert!(duration.as_millis() >= 1);
        assert!(duration.as_millis() <= 10); // Allow some overhead
    }
}
