pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub blacklist: Vec<String>,
}

impl PasswordPolicy {
    pub fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec!["password".into(), "123456".into(), "qwerty".into()],
        }
    }

    pub fn validate(&self, password: &str) -> Result<(), String> {
        if password.len() < self.min_length {
            return Err(format!("Password must be at least {} characters", self.min_length));
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err("Password must contain an uppercase letter".into());
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err("Password must contain a lowercase letter".into());
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err("Password must contain a digit".into());
        }
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err("Password must contain a special character".into());
        }
        for bad in &self.blacklist {
            if password.to_lowercase().contains(bad) {
                return Err("Password is too common or blacklisted".into());
            }
        }
        Ok(())
    }
}
