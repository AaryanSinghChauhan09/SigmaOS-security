//! Authentication and authorization mechanisms
//! Follows: Least Privilege, Authentication, Authorization

use std::collections::HashMap;

/// User credential
#[derive(Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
}

/// Authentication manager
pub struct AuthManager {
    users: HashMap<String, Credential>,
    sessions: HashMap<String, String>,
}

impl AuthManager {
    pub fn new() -> Self {
        AuthManager {
            users: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Register user
    pub fn register(&mut self, username: String, password_hash: Vec<u8>, salt: Vec<u8>) -> Result<(), &'static str> {
        if self.users.contains_key(&username) {
            return Err("User already exists");
        }
        let credential = Credential {
            username: username.clone(),
            password_hash,
            salt,
        };
        self.users.insert(username, credential);
        log::info!("User registered successfully");
        Ok(())
    }

    /// Authenticate user
    pub fn authenticate(&mut self, username: &str, password_hash: &[u8]) -> Result<String, &'static str> {
        let user = self.users.get(username)
            .ok_or("User not found")?;
        
        if user.password_hash != password_hash {
            return Err("Invalid credentials");
        }
        
        let session_token = format!("session_{}", username);
        self.sessions.insert(session_token.clone(), username.to_string());
        log::info!("User authenticated: {}", username);
        Ok(session_token)
    }

    /// Verify session
    pub fn verify_session(&self, token: &str) -> Result<&str, &'static str> {
        self.sessions.get(token)
            .map(|s| s.as_str())
            .ok_or("Invalid session")
    }

    /// Logout user
    pub fn logout(&mut self, token: &str) -> Result<(), &'static str> {
        self.sessions.remove(token)
            .ok_or("Invalid session")?;
        log::info("User logged out");
        Ok(())
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication() {
        let mut auth = AuthManager::new();
        auth.register("user".to_string(), vec![1, 2, 3], vec![4, 5, 6]).unwrap();
        let token = auth.authenticate("user", &[1, 2, 3]).unwrap();
        assert!(auth.verify_session(&token).is_ok());
    }
}
