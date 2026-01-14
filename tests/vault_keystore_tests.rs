
#[cfg(test)]
mod tests {
    use authenc::services::vault::{KeyStoreVaultProvider, VaultProvider};
    use openssl::rsa::Rsa;
    use openssl::x509::X509;
    use openssl::pkey::PKey;
    use openssl::pkcs12::Pkcs12;
    use openssl::asn1::Asn1Time;
    use std::path::PathBuf;

    async fn create_test_keystore(path: &PathBuf, password: &str, secret_key: &str) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut x509 = X509::builder().unwrap();
        x509.set_version(2).unwrap();
        x509.set_pubkey(&pkey).unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        x509.set_not_before(&not_before).unwrap();
        x509.set_not_after(&not_after).unwrap();

        // Subject name containing the secret key/value for the "placeholder" logic
        let mut name = openssl::x509::X509Name::builder().unwrap();
        name.append_entry_by_text("CN", secret_key).unwrap();
        let name = name.build();
        x509.set_subject_name(&name).unwrap();

        x509.sign(&pkey, openssl::hash::MessageDigest::sha256()).unwrap();
        let cert = x509.build();

        let p12 = Pkcs12::builder()
            .build(password, "test", &pkey, &cert)
            .unwrap();
        let der = p12.to_der().unwrap();

        tokio::fs::write(path, &der).await.unwrap();
    }

    #[tokio::test]
    async fn test_keystore_vault_flow() {
        let dir = tempfile::tempdir().unwrap();
        let keystore_path = dir.path().join("test_keystore.p12");
        let password = "password";
        let secret_key = "my_secret_key";

        // 1. Create a valid keystore
        create_test_keystore(&keystore_path, password, secret_key).await;

        // 2. Initialize provider
        let provider = KeyStoreVaultProvider::new(
            keystore_path.to_str().unwrap().to_string(),
            password.to_string(),
            password.to_string(),
        );

        // 3. Test get_secret
        // The implementation looks for a certificate subject entry containing the key
        let result = provider.get_secret(secret_key).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), format!("secret_for_{}", secret_key));

        // 4. Test list_secrets
        let secrets = provider.list_secrets().await.unwrap();
        assert!(!secrets.is_empty());
        // The implementation pushes the UTF8 data of entries.
        // Our CN entry "my_secret_key" should be in there.
        assert!(secrets.iter().any(|s| s.contains(secret_key)));

        // 5. Test set_secret (Placeholder)
        // Just verify it doesn't crash
        let result = provider.set_secret("new_key", "new_value").await;
        assert!(result.is_ok());

        // Cleanup handled by tempdir
    }
}
