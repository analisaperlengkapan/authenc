#[cfg(test)]
mod tests {
    use authenc::spi::theme::*;
    use authenc::spi::Spi;

    #[test]
    fn test_theme_spi() {
        let _spi = ThemeSpi;
        // Test that ThemeSpi can be instantiated
        assert!(true);
    }

    #[test]
    fn test_theme_type_as_str() {
        assert_eq!(ThemeType::Login.as_str(), "login");
        assert_eq!(ThemeType::Account.as_str(), "account");
        assert_eq!(ThemeType::Admin.as_str(), "admin");
        assert_eq!(ThemeType::Email.as_str(), "email");
        assert_eq!(ThemeType::Welcome.as_str(), "welcome");
        assert_eq!(ThemeType::Common.as_str(), "common");
    }

    #[test]
    fn test_default_theme_provider() {
        let provider = DefaultThemeProvider::new("test-theme".to_string());
        assert_eq!(provider.get_theme_name(), "test-theme");
        // Test that DefaultThemeProvider can be created
        assert!(true);
    }

    #[test]
    fn test_theme_error_display() {
        let error = ThemeError::ThemeNotFound("test".to_string());
        assert_eq!(error.to_string(), "Theme not found: test");

        let error = ThemeError::ResourceNotFound("resource".to_string());
        assert_eq!(error.to_string(), "Theme resource not found: resource");
    }
}
