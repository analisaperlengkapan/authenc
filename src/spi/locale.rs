//! Locale Service Provider Interface
//!
//! Provides internationalization and localization support.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;

/// Locale SPI implementation
pub struct LocaleSpi;

impl Spi for LocaleSpi {
    fn get_name(&self) -> &'static str {
        "locale"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.locale.LocaleProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.locale.LocaleProviderFactory"
    }
}

/// Locale provider interface
#[async_trait]
pub trait LocaleProvider: Provider {
    /// Get available locales
    async fn get_available_locales(&self) -> Result<Vec<String>, LocaleError>;

    /// Get the default locale
    async fn get_default_locale(&self) -> Result<String, LocaleError>;

    /// Get localized message
    async fn get_message(
        &self,
        key: &str,
        locale: Option<&str>,
        params: Option<&HashMap<String, String>>,
    ) -> Result<String, LocaleError>;

    /// Get multiple localized messages
    async fn get_messages(
        &self,
        keys: &[String],
        locale: Option<&str>,
        params: Option<&HashMap<String, String>>,
    ) -> Result<HashMap<String, String>, LocaleError> {
        let mut results = HashMap::new();
        for key in keys {
            let message = self.get_message(key, locale, params).await?;
            results.insert(key.clone(), message);
        }
        Ok(results)
    }

    /// Check if locale is supported
    async fn is_locale_supported(&self, locale: &str) -> Result<bool, LocaleError> {
        let available = self.get_available_locales().await?;
        Ok(available.contains(&locale.to_string()))
    }
}

/// Locale provider factory
#[async_trait]
pub trait LocaleProviderFactory: ProviderFactory<dyn LocaleProvider> {
    /// Get supported locales
    fn get_supported_locales(&self) -> Vec<String>;
}

/// Locale-related errors
#[derive(Debug, thiserror::Error)]
pub enum LocaleError {
    /// Locale not found
    #[error("Locale not found: {0}")]
    LocaleNotFound(String),

    /// Message not found
    #[error("Message not found: {0}")]
    MessageNotFound(String),

    /// Localization error
    #[error("Localization error: {0}")]
    LocalizationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Default locale provider implementation
pub struct DefaultLocaleProvider {
    messages: HashMap<String, HashMap<String, String>>,
    default_locale: String,
    available_locales: Vec<String>,
}

impl Default for DefaultLocaleProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultLocaleProvider {
    /// Create a new default locale provider
    pub fn new() -> Self {
        let mut messages = HashMap::new();

        // English messages
        let mut en_messages = HashMap::new();
        en_messages.insert("loginTitle".to_string(), "Login".to_string());
        en_messages.insert("username".to_string(), "Username".to_string());
        en_messages.insert("password".to_string(), "Password".to_string());
        en_messages.insert("login".to_string(), "Sign In".to_string());
        en_messages.insert("logout".to_string(), "Logout".to_string());
        en_messages.insert("register".to_string(), "Register".to_string());
        en_messages.insert("forgotPassword".to_string(), "Forgot Password?".to_string());
        en_messages.insert("backToLogin".to_string(), "Back to Login".to_string());
        en_messages.insert(
            "invalidUserMessage".to_string(),
            "Invalid username or password".to_string(),
        );
        en_messages.insert(
            "invalidCredentialsMessage".to_string(),
            "Invalid credentials".to_string(),
        );
        en_messages.insert(
            "accountDisabledMessage".to_string(),
            "Account is disabled, contact admin".to_string(),
        );
        en_messages.insert(
            "accountTemporarilyDisabledMessage".to_string(),
            "Account is temporarily disabled".to_string(),
        );
        en_messages.insert(
            "accountManagementWelcomeMessage".to_string(),
            "Welcome to Authenc Account Management".to_string(),
        );
        en_messages.insert(
            "accountManagementTitle".to_string(),
            "Account Management".to_string(),
        );
        en_messages.insert("personalInfo".to_string(), "Personal Info".to_string());
        en_messages.insert(
            "accountSecurity".to_string(),
            "Account Security".to_string(),
        );
        en_messages.insert("signingIn".to_string(), "Signing In".to_string());
        en_messages.insert("deviceActivity".to_string(), "Device Activity".to_string());
        en_messages.insert("linkedAccounts".to_string(), "Linked Accounts".to_string());
        en_messages.insert(
            "accountManagement".to_string(),
            "Account Management".to_string(),
        );

        messages.insert("en".to_string(), en_messages);

        // Spanish messages
        let mut es_messages = HashMap::new();
        es_messages.insert("loginTitle".to_string(), "Iniciar Sesión".to_string());
        es_messages.insert("username".to_string(), "Nombre de usuario".to_string());
        es_messages.insert("password".to_string(), "Contraseña".to_string());
        es_messages.insert("login".to_string(), "Iniciar Sesión".to_string());
        es_messages.insert("logout".to_string(), "Cerrar Sesión".to_string());
        es_messages.insert("register".to_string(), "Registrarse".to_string());
        es_messages.insert(
            "forgotPassword".to_string(),
            "¿Olvidaste tu contraseña?".to_string(),
        );
        es_messages.insert(
            "backToLogin".to_string(),
            "Volver al inicio de sesión".to_string(),
        );
        es_messages.insert(
            "invalidUserMessage".to_string(),
            "Nombre de usuario o contraseña inválidos".to_string(),
        );
        es_messages.insert(
            "invalidCredentialsMessage".to_string(),
            "Credenciales inválidas".to_string(),
        );
        es_messages.insert(
            "accountDisabledMessage".to_string(),
            "Cuenta deshabilitada, contacta al administrador".to_string(),
        );
        es_messages.insert(
            "accountTemporarilyDisabledMessage".to_string(),
            "Cuenta temporalmente deshabilitada".to_string(),
        );
        es_messages.insert(
            "accountManagementWelcomeMessage".to_string(),
            "Bienvenido a la gestión de cuentas de Authenc".to_string(),
        );
        es_messages.insert(
            "accountManagementTitle".to_string(),
            "Gestión de Cuenta".to_string(),
        );
        es_messages.insert(
            "personalInfo".to_string(),
            "Información Personal".to_string(),
        );
        es_messages.insert(
            "accountSecurity".to_string(),
            "Seguridad de la Cuenta".to_string(),
        );
        es_messages.insert("signingIn".to_string(), "Iniciando Sesión".to_string());
        es_messages.insert(
            "deviceActivity".to_string(),
            "Actividad del Dispositivo".to_string(),
        );
        es_messages.insert(
            "linkedAccounts".to_string(),
            "Cuentas Vinculadas".to_string(),
        );
        es_messages.insert(
            "accountManagement".to_string(),
            "Gestión de Cuenta".to_string(),
        );

        messages.insert("es".to_string(), es_messages);

        Self {
            messages,
            default_locale: "en".to_string(),
            available_locales: vec!["en".to_string(), "es".to_string()],
        }
    }
}

#[async_trait]
impl LocaleProvider for DefaultLocaleProvider {
    async fn get_available_locales(&self) -> Result<Vec<String>, LocaleError> {
        Ok(self.available_locales.clone())
    }

    async fn get_default_locale(&self) -> Result<String, LocaleError> {
        Ok(self.default_locale.clone())
    }

    async fn get_message(
        &self,
        key: &str,
        locale: Option<&str>,
        _params: Option<&HashMap<String, String>>,
    ) -> Result<String, LocaleError> {
        let locale = locale.unwrap_or(&self.default_locale);

        // Try the requested locale first
        if let Some(locale_messages) = self.messages.get(locale) {
            if let Some(message) = locale_messages.get(key) {
                return Ok(message.clone());
            }
        }

        // Fallback to English if locale not found or message not found
        if locale != "en" {
            if let Some(en_messages) = self.messages.get("en") {
                if let Some(message) = en_messages.get(key) {
                    return Ok(message.clone());
                }
            }
        }

        // Return key if message not found
        Ok(key.to_string())
    }
}

impl Provider for DefaultLocaleProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Default locale provider factory
pub struct DefaultLocaleProviderFactory;

impl Default for DefaultLocaleProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultLocaleProviderFactory {
    /// Create a new default locale provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn LocaleProvider> for DefaultLocaleProviderFactory {
    fn create(&self, _config: &ProviderConfig) -> Result<Box<dyn LocaleProvider>, SpiError> {
        Ok(Box::new(DefaultLocaleProvider::new()))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

impl LocaleProviderFactory for DefaultLocaleProviderFactory {
    fn get_supported_locales(&self) -> Vec<String> {
        vec!["en".to_string(), "es".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_locale_provider() {
        let provider = DefaultLocaleProvider::new();

        let locales = provider.get_available_locales().await.unwrap();
        assert!(locales.contains(&"en".to_string()));
        assert!(locales.contains(&"es".to_string()));

        let default = provider.get_default_locale().await.unwrap();
        assert_eq!(default, "en");

        let message = provider
            .get_message("loginTitle", Some("en"), None)
            .await
            .unwrap();
        assert_eq!(message, "Login");

        let message = provider
            .get_message("loginTitle", Some("es"), None)
            .await
            .unwrap();
        assert_eq!(message, "Iniciar Sesión");

        // Test fallback to English
        let message = provider
            .get_message("nonexistent", Some("es"), None)
            .await
            .unwrap();
        assert_eq!(message, "nonexistent");

        let supported = provider.is_locale_supported("en").await.unwrap();
        assert!(supported);

        let supported = provider.is_locale_supported("fr").await.unwrap();
        assert!(!supported);
    }

    #[tokio::test]
    async fn test_default_locale_factory() {
        let factory = DefaultLocaleProviderFactory::new();

        assert_eq!(factory.get_id(), "default");

        let supported = factory.get_supported_locales();
        assert!(supported.contains(&"en".to_string()));
        assert!(supported.contains(&"es".to_string()));
    }
}
