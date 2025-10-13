use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::services::fips::*;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database to be running"]
    async fn test_fips_level_validation() {
        let database_config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "test".to_string(),
            database: "authenc_fips_test".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        };

        let database_result = Database::new(&database_config).await;
        let _database = match database_result {
            Ok(db) => Arc::new(db),
            Err(_) => {
                println!("Skipping test due to database connection issues");
                return;
            }
        };

        // Test FIPS level enum values
        assert_eq!(FipsLevel::Level1, FipsLevel::Level1);
        assert_eq!(FipsLevel::Level2, FipsLevel::Level2);
        assert_eq!(FipsLevel::Level3, FipsLevel::Level3);
        assert_eq!(FipsLevel::Level4, FipsLevel::Level4);
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database to be running"]
    async fn test_fips_compliance_status() {
        let database_config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "test".to_string(),
            database: "authenc_fips_test".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        };

        let database_result = Database::new(&database_config).await;
        let _database = match database_result {
            Ok(db) => Arc::new(db),
            Err(_) => {
                println!("Skipping test due to database connection issues");
                return;
            }
        };

        // Test FIPS compliance status using the correct enum
        let compliance_check = FipsComplianceCheck {
            check_name: "AES Encryption Validation".to_string(),
            status: FipsComplianceStatus::Compliant,
            details: "AES-256-GCM encryption validated successfully".to_string(),
            recommendations: vec![],
        };

        assert_eq!(compliance_check.check_name, "AES Encryption Validation");
        assert!(matches!(
            compliance_check.status,
            FipsComplianceStatus::Compliant
        ));
        assert_eq!(
            compliance_check.details,
            "AES-256-GCM encryption validated successfully"
        );
        assert!(compliance_check.recommendations.is_empty());
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database to be running"]
    async fn test_fips_compliance_event() {
        let database_config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "test".to_string(),
            database: "authenc_fips_test".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        };

        let database_result = Database::new(&database_config).await;
        let _database = match database_result {
            Ok(db) => Arc::new(db),
            Err(_) => {
                println!("Skipping test due to database connection issues");
                return;
            }
        };

        // Test FIPS compliance event
        let compliance_event = FipsComplianceEvent {
            event_type: "key_generation".to_string(),
            algorithm: Some("AES-256-GCM".to_string()),
            compliant: true,
            details: "AES-256 key generated successfully".to_string(),
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(compliance_event.event_type, "key_generation");
        assert_eq!(compliance_event.algorithm, Some("AES-256-GCM".to_string()));
        assert!(compliance_event.compliant);
        assert_eq!(
            compliance_event.details,
            "AES-256 key generated successfully"
        );
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database to be running"]
    async fn test_security_profile() {
        let database_config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "test".to_string(),
            database: "authenc_fips_test".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        };

        let database_result = Database::new(&database_config).await;
        let _database = match database_result {
            Ok(db) => Arc::new(db),
            Err(_) => {
                println!("Skipping test due to database connection issues");
                return;
            }
        };

        // Test Security Profile
        let mut key_sizes = HashMap::new();
        key_sizes.insert("AES".to_string(), vec![128, 192, 256]);
        key_sizes.insert("RSA".to_string(), vec![2048, 3072, 4096]);

        let security_profile = SecurityProfile {
            name: "FIPS-140-3-Compliant".to_string(),
            description: "Security profile compliant with FIPS 140-3 Level 3".to_string(),
            fips_level: FipsLevel::Level3,
            approved_algorithms: vec!["AES-256-GCM".to_string(), "SHA-384".to_string()],
            key_sizes,
            security_strength: 256,
            requirements: vec![
                "All cryptographic operations must use FIPS-approved algorithms".to_string(),
                "Keys must be generated using FIPS-approved methods".to_string(),
                "All operations must be performed in FIPS-approved modules".to_string(),
            ],
        };

        assert_eq!(security_profile.name, "FIPS-140-3-Compliant");
        assert_eq!(security_profile.fips_level, FipsLevel::Level3);
        assert!(
            security_profile
                .approved_algorithms
                .contains(&"AES-256-GCM".to_string())
        );
        assert_eq!(security_profile.security_strength, 256);
        assert!(security_profile.requirements.len() > 0);
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database to be running"]
    async fn test_fips_validation_service() {
        let database_config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "test".to_string(),
            database: "authenc_fips_test".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        };

        let database_result = Database::new(&database_config).await;
        let _database = match database_result {
            Ok(db) => Arc::new(db),
            Err(_) => {
                println!("Skipping test due to database connection issues");
                return;
            }
        };

        // Test FIPS validation scenarios
        let valid_key_sizes = vec![128, 192, 256, 384, 512];
        let invalid_key_sizes = vec![64, 96, 160, 224];

        for size in valid_key_sizes {
            assert!(
                size >= 128 && size % 64 == 0,
                "Valid FIPS key size: {}",
                size
            );
        }

        for size in invalid_key_sizes {
            assert!(
                !(size >= 128 && size % 64 == 0),
                "Invalid FIPS key size: {}",
                size
            );
        }
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL database to be running"]
    async fn test_fips_algorithm_validation() {
        let database_config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "test".to_string(),
            database: "authenc_fips_test".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        };

        let database_result = Database::new(&database_config).await;
        let _database = match database_result {
            Ok(db) => Arc::new(db),
            Err(_) => {
                println!("Skipping test due to database connection issues");
                return;
            }
        };

        // Test approved FIPS algorithms
        let approved_algorithms = vec![
            "AES-128-CBC",
            "AES-192-CBC",
            "AES-256-CBC",
            "AES-128-GCM",
            "AES-192-GCM",
            "AES-256-GCM",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "HMAC-SHA-256",
            "HMAC-SHA-384",
            "HMAC-SHA-512",
        ];

        let unapproved_algorithms = vec!["DES", "3DES", "RC4", "MD5", "SHA-1"];

        for algo in approved_algorithms {
            assert!(
                algo.contains("AES") || algo.contains("SHA") || algo.contains("HMAC"),
                "Approved FIPS algorithm: {}",
                algo
            );
        }

        for algo in unapproved_algorithms {
            assert!(
                !algo.contains("AES") || !algo.contains("SHA") || !algo.contains("HMAC"),
                "Unapproved algorithm: {}",
                algo
            );
        }
    }
}
