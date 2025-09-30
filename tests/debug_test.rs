use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub blacklist: Vec<String>,
}

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<(), String> {
        if password.len() < self.min_length {
            return Err(format!(
                "Password must be at least {} characters",
                self.min_length
            ));
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
            if !bad.is_empty() && password.to_lowercase().contains(&bad.to_lowercase()) {
                return Err("Password is too common or blacklisted".into());
            }
        }
        Ok(())
    }
}

fn main() {
    let policy = PasswordPolicy {
        min_length: 8,
        require_uppercase: false,
        require_lowercase: false,
        require_digit: false,
        require_special: false,
        blacklist: vec!["bad".to_string(), "   ".to_string(), "\t".to_string()],
    };

    let result = policy.validate("excellent");
    println!("'excellent' result: {:?}", result);

    let result2 = policy.validate("   password   ");
    println!("'   password   ' result: {:?}", result2);
}
