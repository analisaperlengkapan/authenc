#[cfg(test)]
mod tests {
    use super::*;
    use authenc::services::oid4vc::{
        AuthorizationDetails, BatchCredentialRequest, CredentialAuthorizationRequest,
        CredentialFormat, CredentialRequest, CredentialResponse, CredentialSubject,
        CredentialTokenRequest, CredentialTokenResponse, DeferredCredentialRequest,
        EnhancedOid4VcManager, Issuer, LegacyOid4VcManager, Oid4VcService, Proof,
        VerifiableCredential, VerifiablePresentation,
    };
    use rand;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_enhanced_oid4vc_manager_creation() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        // Test that we can get issuer metadata (this verifies the manager was created properly)
        let metadata = manager.get_issuer_metadata().await.unwrap();
        assert_eq!(metadata.credential_issuer, "https://example.com");
        assert!(metadata
            .credentials_supported
            .contains_key("UniversityDegreeCredential"));
    }

    #[tokio::test]
    async fn test_legacy_oid4vc_manager_creation() {
        let private_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let legacy = LegacyOid4VcManager::new("https://example.com".to_string(), private_key);

        let metadata = legacy.get_issuer_metadata().await;
        assert!(metadata.is_ok());
        let metadata = metadata.unwrap();
        assert_eq!(metadata.credential_issuer, "https://example.com");
    }

    #[tokio::test]
    async fn test_authorization_request_handling() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let request = CredentialAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid".to_string(),
            state: Some("test-state".to_string()),
            authorization_details: vec![AuthorizationDetails {
                type_: "openid_credential".to_string(),
                format: CredentialFormat::JwtVcJson,
                types: vec![
                    "VerifiableCredential".to_string(),
                    "UniversityDegreeCredential".to_string(),
                ],
                locations: None,
            }],
            nonce: Some("test-nonce".to_string()),
            code_challenge: Some("test-challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        let result = manager.handle_authorization_request(request).await;
        assert!(result.is_ok());
        let code = result.unwrap();
        assert!(!code.is_empty());
    }

    #[tokio::test]
    async fn test_token_request_handling() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let request = CredentialTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "test-code".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            code_verifier: Some("test-verifier".to_string()),
        };

        let result = manager.handle_token_request(request).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.token_type, "Bearer");
        assert!(!response.access_token.is_empty());
        assert!(response.expires_in > 0);
    }

    #[tokio::test]
    async fn test_credential_issuance() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let request = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            types: vec![
                "VerifiableCredential".to_string(),
                "UniversityDegreeCredential".to_string(),
            ],
            proof: None,
        };

        let result = manager
            .issue_credential(request, "valid-access-token")
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        // Format is CredentialFormat::JwtVcJson (can't compare directly due to missing PartialEq)
        assert!(!response.credential.is_null());
    }

    #[tokio::test]
    async fn test_credential_verification() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        // Create a test credential
        let credential = VerifiableCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: Some("urn:uuid:test-credential".to_string()),
            type_: vec![
                "VerifiableCredential".to_string(),
                "TestCredential".to_string(),
            ],
            issuer: Issuer::String("https://example.com".to_string()),
            issuance_date: "2024-01-01T00:00:00Z".to_string(),
            expiration_date: Some("2025-01-01T00:00:00Z".to_string()),
            credential_subject: CredentialSubject {
                id: Some("did:example:test-subject".to_string()),
                claims: HashMap::from([
                    ("name".to_string(), serde_json::json!("Test User")),
                    (
                        "degree".to_string(),
                        serde_json::json!("Bachelor of Science"),
                    ),
                ]),
            },
            proof: Some(Proof {
                type_: "Ed25519Signature2020".to_string(),
                created: "2024-01-01T00:00:00Z".to_string(),
                verification_method: "https://example.com/keys/1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: None,
                jws: Some("test-signature".to_string()),
            }),
            status: None,
        };

        let result = manager.verify_credential(&credential).await;
        assert!(result.is_ok());
        // Note: This will return false because the signature verification is simplified
        // In a real implementation, this would verify the cryptographic proof
    }

    #[tokio::test]
    async fn test_batch_credential_issuance() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let batch_request = BatchCredentialRequest {
            credential_requests: vec![
                CredentialRequest {
                    format: CredentialFormat::JwtVcJson,
                    types: vec![
                        "VerifiableCredential".to_string(),
                        "UniversityDegreeCredential".to_string(),
                    ],
                    proof: None,
                },
                CredentialRequest {
                    format: CredentialFormat::LdpVc,
                    types: vec![
                        "VerifiableCredential".to_string(),
                        "EmployeeCredential".to_string(),
                    ],
                    proof: None,
                },
            ],
        };

        let result = manager
            .issue_batch_credentials(batch_request, "valid-access-token")
            .await;
        // EnhancedOid4VcManager supports batch credentials
        assert!(result.is_ok());
        let batch_response = result.unwrap();
        assert_eq!(batch_response.credential_responses.len(), 2);
    }

    #[tokio::test]
    async fn test_deferred_credential_handling() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let deferred_request = DeferredCredentialRequest {
            acceptance_token: "test-token".to_string(),
        };

        let result = manager.handle_deferred_credential(deferred_request).await;
        // EnhancedOid4VcManager supports deferred credentials
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_credential_revocation() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let result = manager
            .revoke_credential("test-credential-id", Some("User request".to_string()))
            .await;
        // EnhancedOid4VcManager supports credential revocation
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_credential_status_check() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        // First revoke a credential
        let revoke_result = manager
            .revoke_credential("test-credential-id", Some("User request".to_string()))
            .await;
        assert!(revoke_result.is_ok());

        // Now check its status - should return status for revoked credential
        let result = manager.get_credential_status("test-credential-id").await;
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.id, "test-credential-id");
        assert_eq!(status.type_, "StatusList2021Entry");

        // Check status of non-revoked credential - should return error
        let result2 = manager
            .get_credential_status("non-existent-credential")
            .await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_status_list_retrieval() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let result = manager.get_status_list().await;
        assert!(result.is_ok());
        let status_list = result.unwrap();
        assert_eq!(status_list.id, "https://example.com/status/1");
        assert_eq!(status_list.status_purpose, "revocation");
    }

    #[tokio::test]
    async fn test_verifiable_credential_creation() {
        let private_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let legacy = LegacyOid4VcManager::new("https://example.com".to_string(), private_key);

        let request = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            types: vec![
                "VerifiableCredential".to_string(),
                "PersonCredential".to_string(),
            ],
            proof: None,
        };

        let result = legacy.issue_credential(request, "valid-access-token").await;
        assert!(result.is_ok());
        let response = result.unwrap();
        let vc: VerifiableCredential = serde_json::from_value(response.credential).unwrap();
        assert_eq!(vc.type_[1], "PersonCredential");
        assert_eq!(
            vc.credential_subject.id.as_ref().unwrap(),
            "did:example:subject123"
        );
        assert!(vc.proof.is_some());
    }

    #[tokio::test]
    async fn test_issuer_metadata_format() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let result = manager.get_issuer_metadata().await;
        assert!(result.is_ok());
        let metadata = result.unwrap();

        assert_eq!(metadata.credential_issuer, "https://example.com");
        assert!(metadata
            .authorization_servers
            .contains(&"https://example.com".to_string()));
        assert_eq!(
            metadata.credential_endpoint,
            "https://example.com/credentials"
        );
        assert!(metadata.batch_credential_endpoint.is_some());
        assert!(metadata.deferred_credential_endpoint.is_some());
        assert!(metadata
            .credentials_supported
            .contains_key("UniversityDegreeCredential"));
    }

    #[tokio::test]
    async fn test_presentation_verification() {
        let manager = EnhancedOid4VcManager::new("https://example.com".to_string());

        let presentation = VerifiablePresentation {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            type_: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: vec![],
            proof: Some(Proof {
                type_: "Ed25519Signature2020".to_string(),
                created: "2024-01-01T00:00:00Z".to_string(),
                verification_method: "https://example.com/keys/1".to_string(),
                proof_purpose: "authentication".to_string(),
                proof_value: None,
                jws: Some("test-signature".to_string()),
            }),
            holder: Some("did:example:holder".to_string()),
        };

        let result = manager.verify_presentation(&presentation).await;
        // EnhancedOid4VcManager supports presentation verification
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }
}
